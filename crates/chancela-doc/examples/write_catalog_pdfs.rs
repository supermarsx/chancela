//! Render **real catalog documents** — one ata and one termo de abertura per entity family —
//! through the product's own render pipeline and write each to a PDF/A-2u file.
//!
//! This is the corpus for the *template-level* half of the external veraPDF gate. The sibling
//! example `write_pdfua_fixture` hand-builds a [`DocumentModel`] and so proves only that the
//! **writer** can emit conformant output; it cannot catch a *template* whose authored structure
//! renders into non-conformant PDF. This example closes that gap by going through the real
//! two-stage seam the API uses on seal / book-open:
//!
//! ```text
//! record (chancela-core) --serde--> ctx --chancela_templates::render--> DocumentModel
//!                                                --chancela_doc::pdfa::write--> PDF/A-2u bytes
//! ```
//!
//! Both stages are the shipped code: the templates come from the embedded catalog
//! (`chancela_templates::load_registry`), and the template ids are the family spines that
//! `chancela-api`'s `spine_template_id` auto-generates.
//!
//! **The render contexts are mirrored, not imported.** `chancela-api`'s `act_ctx` / `termo_ctx`
//! (`crates/chancela-api/src/documents.rs`) are private to that crate, and depending on it here
//! would drag the whole server into a PDF-only CI job. The ata context is therefore built the way
//! `act_ctx` builds it — `serde_json::to_value(&Act)` plus the reserved envelope overlay — from a
//! genuine [`Act`], so the record's serde shape is the real one; the termo context mirrors
//! `termo_ctx`'s literal. If those builders change shape, this example needs the same change.
//!
//! Fictional entities and people throughout.
//!
//! Usage: `write_catalog_pdfs <output-dir>` — writes `<family>-ata.pdf` and
//! `<family>-termo-abertura.pdf` per family and prints one path per line.

use std::path::PathBuf;

use chancela_core::{
    Act, ActId, AgendaItem, AttendanceWeight, Attendee, BookId, BookKind, DeliberationItem,
    DocumentReference, MeetingChannel, MemberStatement, Mesa, NumberingScheme, PresenceMode,
    SignatoryCapacity, SignatorySlot, TermoDeAbertura, VoteResult,
};
use serde_json::{Value, json};
use time::macros::{date, time};

/// One family's worth of the corpus: which spine templates to render and the identity /
/// vocabulary that distinguishes this family's documents from the others'.
struct FamilyCase {
    /// File-name prefix, matching the template asset family prefix.
    slug: &'static str,
    /// The family's spine `Ata` template id (mirrors `spine_template_id`).
    ata_template: &'static str,
    /// The family's spine `TermoAbertura` template id (mirrors `spine_template_id`).
    termo_template: &'static str,
    entity_name: &'static str,
    entity_nipc: &'static str,
    entity_seat: &'static str,
    /// The organ the book serves — drives the termo's "Órgão" row.
    book_kind: BookKind,
    /// Free-text purpose recited by the termo de abertura.
    purpose: &'static str,
    /// Meeting channel, varied across families so the `channel_label` filter and the
    /// telematic-evidence recitals are both exercised somewhere in the corpus.
    channel: MeetingChannel,
    /// Condomínios weight by permilagem; the condomínio ata renders a per-attendee lista from it.
    weighted_attendance: bool,
}

fn cases() -> Vec<FamilyCase> {
    vec![
        FamilyCase {
            slug: "csc",
            ata_template: "csc-ata-ag/v1",
            termo_template: "csc-termo-abertura/v1",
            entity_name: "Encosto Estratégico Lda",
            entity_nipc: "515202030",
            entity_seat: "Rua das Amoreiras, n.º 12, 1250-020 Lisboa",
            book_kind: BookKind::AssembleiaGeral,
            purpose: "livro de atas da assembleia geral",
            channel: MeetingChannel::Physical,
            weighted_attendance: false,
        },
        FamilyCase {
            slug: "condominio",
            ata_template: "condominio-ata-assembleia/v1",
            termo_template: "condominio-termo-abertura/v1",
            entity_name: "Condomínio do Edifício Alvorada",
            entity_nipc: "515303040",
            entity_seat: "Avenida da Liberdade, n.º 214, 1250-148 Lisboa",
            book_kind: BookKind::Condominio,
            purpose: "livro de atas da assembleia de condóminos",
            // Exercises the art. 377.º / telematic recitals and the `channel_label` filter.
            channel: MeetingChannel::Telematic,
            weighted_attendance: true,
        },
        FamilyCase {
            slug: "assoc",
            ata_template: "assoc-ata-ga/v1",
            termo_template: "assoc-termo-abertura/v1",
            entity_name: "Associação Ribeira Viva",
            entity_nipc: "515404050",
            entity_seat: "Rua do Almada, n.º 7, 4050-036 Porto",
            book_kind: BookKind::AssembleiaGeral,
            purpose: "livro de atas da assembleia geral de associados",
            channel: MeetingChannel::Hybrid,
            weighted_attendance: false,
        },
        FamilyCase {
            slug: "fundacao",
            ata_template: "fundacao-ata-ca/v1",
            termo_template: "fundacao-termo-abertura/v1",
            entity_name: "Fundação Serra do Caramulo",
            entity_nipc: "515505060",
            entity_seat: "Largo da Sé, n.º 3, 3000-138 Coimbra",
            book_kind: BookKind::GerenciaAdministracao,
            purpose: "livro de atas do conselho de administração",
            channel: MeetingChannel::Physical,
            weighted_attendance: false,
        },
        FamilyCase {
            slug: "cooperativa",
            ata_template: "cooperativa-ata-ag/v1",
            termo_template: "cooperativa-termo-abertura/v1",
            entity_name: "Cooperativa Agrícola do Vale Claro CRL",
            entity_nipc: "515606070",
            entity_seat: "Estrada Nacional 2, n.º 88, 5100-190 Lamego",
            book_kind: BookKind::AssembleiaGeral,
            purpose: "livro de atas da assembleia geral de cooperadores",
            channel: MeetingChannel::Physical,
            weighted_attendance: false,
        },
    ]
}

/// The reserved `entity` object every template reads (mirrors `documents::entity_object`).
fn entity_object(case: &FamilyCase) -> Value {
    json!({
        "name": case.entity_name,
        "nipc": case.entity_nipc,
        "seat": case.entity_seat,
    })
}

/// A realistically-populated sealed act: agenda, structured deliberations with both a recorded
/// tally and a unanimous vote, a declaração de voto, referenced documents, an attendance list and
/// signature slots. Every array the ata templates iterate is non-empty, so every block kind the
/// catalog can emit (`Heading`/`Paragraph`/`KeyValue`/`VoteTable`/`Rule`/`SignatureBlock`) reaches
/// the writer — which is the point of validating real documents rather than a minimal one.
fn act(case: &FamilyCase) -> Act {
    let mut act = Act::draft(
        BookId::new(),
        "Aprovação das contas do exercício e eleição dos órgãos sociais",
        case.channel,
    );
    act.id = ActId::new();
    act.meeting_date = Some(date!(2026 - 07 - 08));
    act.meeting_time = Some(time!(15:00));
    act.place = Some(case.entity_seat.to_owned());
    act.mesa = Mesa {
        presidente: Some("Amélia Marques".to_owned()),
        secretarios: vec!["Bruno Cardoso".to_owned(), "Carla Neves".to_owned()],
    };
    act.agenda = vec![
        AgendaItem {
            number: 1,
            text: "Apreciação e votação do relatório de gestão e das contas do exercício de 2025."
                .to_owned(),
        },
        AgendaItem {
            number: 2,
            text: "Aplicação dos resultados do exercício.".to_owned(),
        },
        AgendaItem {
            number: 3,
            text: "Eleição dos titulares dos órgãos sociais para o triénio de 2026 a 2028."
                .to_owned(),
        },
    ];
    act.attendance_reference = Some("Lista de presenças anexa (Anexo I)".to_owned());
    act.members_present = Some(7);
    act.members_represented = Some(2);
    act.referenced_documents = vec![
        DocumentReference {
            label: "Relatório de gestão 2025".to_owned(),
            reference: Some("Anexo II — arquivo interno RG-2025".to_owned()),
        },
        DocumentReference {
            label: "Balanço e demonstração de resultados".to_owned(),
            reference: Some("Anexo III".to_owned()),
        },
    ];
    act.deliberations =
        "Aprovadas as contas do exercício e eleitos os titulares dos órgãos sociais.".to_owned();
    act.deliberation_items = vec![
        DeliberationItem {
            agenda_number: Some(1),
            text: "Aprovar o relatório de gestão e as contas do exercício de 2025, tal como \
                   apresentados pelo órgão de administração, incluindo o balanço, a demonstração \
                   de resultados e o respetivo anexo."
                .to_owned(),
            vote: Some(VoteResult::Recorded {
                em_favor: 7,
                contra: 1,
                abstencoes: 1,
            }),
            statements: vec![MemberStatement {
                member: "Duarte Antunes".to_owned(),
                text: "Voto contra por entender que a provisão constituída é insuficiente face \
                       ao litígio pendente descrito no anexo."
                    .to_owned(),
            }],
        },
        DeliberationItem {
            agenda_number: Some(2),
            text: "Transitar integralmente o resultado líquido do exercício para resultados \
                   transitados, não havendo lugar a distribuição."
                .to_owned(),
            vote: Some(VoteResult::Unanimous),
            statements: Vec::new(),
        },
        DeliberationItem {
            agenda_number: Some(3),
            text: "Eleger Amélia Marques, Bruno Cardoso e Carla Neves para os órgãos sociais, \
                   pelo período de três anos."
                .to_owned(),
            vote: Some(VoteResult::Recorded {
                em_favor: 9,
                contra: 0,
                abstencoes: 0,
            }),
            statements: Vec::new(),
        },
    ];
    act.telematic_evidence = Some(
        "Reunião realizada em plataforma de videoconferência com autenticação prévia dos \
         participantes por chave móvel digital, ligação cifrada ponto-a-ponto e gravação \
         integral arquivada sob a referência VC-2026-07-08."
            .to_owned(),
    );
    act.attendees = vec![
        Attendee {
            name: "Amélia Marques".to_owned(),
            quality: if case.weighted_attendance {
                SignatoryCapacity::CondoOwner
            } else {
                SignatoryCapacity::Member
            },
            quality_note: None,
            presence: PresenceMode::InPerson,
            represented_by: None,
            weight: case
                .weighted_attendance
                .then_some(AttendanceWeight::Permilage(125)),
        },
        Attendee {
            name: "Bruno Cardoso".to_owned(),
            quality: if case.weighted_attendance {
                SignatoryCapacity::CondoOwner
            } else {
                SignatoryCapacity::Member
            },
            quality_note: None,
            presence: PresenceMode::Represented,
            represented_by: Some("Carla Neves".to_owned()),
            weight: case
                .weighted_attendance
                .then_some(AttendanceWeight::Permilage(90)),
        },
        Attendee {
            // The free-text escape hatch, exercised end-to-end in the catalog corpus: a
            // qualidade outside the closed vocabulary is carried in `quality_note` and the
            // templates print it in place of the structured label. Usufruto over a quota
            // (CSC art. 23.º) and over a fração autónoma are both real, and neither is a
            // membership capacity, so `Other` is the honest structured value.
            name: "Duarte Antunes".to_owned(),
            quality: SignatoryCapacity::Other,
            quality_note: Some(
                if case.weighted_attendance {
                    "usufrutuário da fração autónoma"
                } else {
                    "usufrutuário da quota"
                }
                .to_owned(),
            ),
            presence: PresenceMode::Absent,
            represented_by: None,
            weight: case
                .weighted_attendance
                .then_some(AttendanceWeight::Permilage(60)),
        },
    ];
    act.signatories = vec![
        SignatorySlot {
            name: "Amélia Marques".to_owned(),
            email: None,
            capacity: SignatoryCapacity::Chair,
            signed: true,
            permilage: None,
        },
        SignatorySlot {
            name: "Bruno Cardoso".to_owned(),
            email: None,
            capacity: SignatoryCapacity::Secretary,
            signed: true,
            permilage: None,
        },
    ];
    act.ata_number = Some(7);
    act
}

/// Mirrors `documents::act_ctx`: the act's serde form overlaid with the reserved envelope keys
/// and the date/time wire strings the `long_date` filter and `{{ meeting_time }}` expect.
fn act_ctx(act: &Act, case: &FamilyCase) -> Value {
    let mut ctx = serde_json::to_value(act).expect("act serializes");
    let map = ctx.as_object_mut().expect("act is a JSON object");
    map.insert("meeting_date".to_owned(), json!("2026-07-08"));
    map.insert("meeting_time".to_owned(), json!("15:00"));
    map.insert("title".to_owned(), json!(act.title));
    map.insert("created_at".to_owned(), json!("2026-07-08"));
    map.insert("entity".to_owned(), entity_object(case));
    map.insert(
        "payload_digest".to_owned(),
        json!("2f1c9b5a4d3e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8"),
    );
    ctx
}

/// Mirrors `documents::book_kind_label`.
fn book_kind_label(kind: BookKind) -> &'static str {
    match kind {
        BookKind::AssembleiaGeral => "Assembleia geral",
        BookKind::GerenciaAdministracao => "Gerência / administração",
        BookKind::ConselhoFiscal => "Conselho fiscal",
        BookKind::Condominio => "Condomínio",
    }
}

/// Mirrors `documents::numbering_label`.
fn numbering_label(scheme: NumberingScheme) -> &'static str {
    match scheme {
        NumberingScheme::Sequential => "Numeração sequencial",
        NumberingScheme::LooseLeaf => "Folhas soltas (numeração e encadeamento de páginas)",
    }
}

fn termo(case: &FamilyCase) -> TermoDeAbertura {
    TermoDeAbertura {
        entity_name: case.entity_name.to_owned(),
        entity_nipc: case.entity_nipc.to_owned(),
        entity_seat: case.entity_seat.to_owned(),
        purpose: case.purpose.to_owned(),
        // LooseLeaf so the termo templates' `{% if numbering_scheme == 'LooseLeaf' %}` recital
        // renders — the branch a Sequential-only corpus would never reach.
        numbering_scheme: NumberingScheme::LooseLeaf,
        opening_date: date!(2026 - 01 - 02),
        required_signatories: vec![
            "Amélia Marques".to_owned(),
            "Bruno Cardoso".to_owned(),
            "Carla Neves".to_owned(),
        ],
        required_signatory_records: Vec::new(),
        ..Default::default()
    }
}

/// Mirrors `documents::termo_ctx`.
fn termo_ctx(termo: &TermoDeAbertura, kind: BookKind) -> Value {
    let signatories: Vec<Value> = termo
        .required_signatories
        .iter()
        .map(|role| json!({ "role": role, "name": "" }))
        .collect();
    json!({
        "title": "Termo de abertura do livro de atas",
        "created_at": "2026-01-02",
        "entity": {
            "name": termo.entity_name,
            "nipc": termo.entity_nipc,
            "seat": termo.entity_seat,
        },
        "book": { "kind": book_kind_label(kind) },
        "purpose": termo.purpose,
        "numbering_scheme": format!("{:?}", termo.numbering_scheme),
        "numbering_label": numbering_label(termo.numbering_scheme),
        "opening_date": "2026-01-02",
        "required_signatories": signatories,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: write_catalog_pdfs <output-dir>")?;
    std::fs::create_dir_all(&out_dir)?;

    let registry = chancela_templates::load_registry()?;
    let mut written = 0usize;

    for case in cases() {
        let act = act(&case);
        let termo = termo(&case);
        let jobs: [(&str, &str, Value); 2] = [
            ("ata", case.ata_template, act_ctx(&act, &case)),
            (
                "termo-abertura",
                case.termo_template,
                termo_ctx(&termo, case.book_kind),
            ),
        ];

        for (label, template_id, ctx) in jobs {
            let spec = registry
                .get(template_id)
                .ok_or_else(|| format!("template {template_id} is not in the catalog"))?;
            let model = chancela_templates::render(spec, &ctx)
                .map_err(|e| format!("{template_id}: render failed: {e}"))?;
            // `pdfa::write` runs the crate's structural PDF/A + PDF/UA self-check before returning.
            let bytes = chancela_doc::pdfa::write(&model)
                .map_err(|e| format!("{template_id}: PDF/A write failed: {e}"))?;
            let path = out_dir.join(format!("{}-{label}.pdf", case.slug));
            std::fs::write(&path, bytes)?;
            println!("{}\t{}", path.display(), template_id);
            written += 1;
        }
    }

    eprintln!("wrote {written} catalog documents to {}", out_dir.display());
    Ok(())
}
