//! Unit tests for the PDF/A-2u writer (structural self-check, determinism, pagination, and the
//! diacritic `/ToUnicode` round-trip). The generate→pades-sign round-trip lives in `tests/` and is
//! owned by e3.
//!
//! Fixtures use the fictional "Encosto Estratégico Lda" / "Amélia Marques" — never a real entity.

use chancela_core::{Block, DocumentModel, KvRow, Run, SignatureSlot, VoteRow};
use lopdf::{Dictionary, Document, Object};

use crate::pdfa;

/// A representative CSC general-meeting ata exercising every block type, with pt-PT diacritics.
fn fixture() -> DocumentModel {
    let mut doc = DocumentModel::new(
        "Ata da Assembleia Geral",
        "Encosto Estratégico Lda",
        "Deliberação sobre contas e distribuição de resultados",
    );
    doc.entity_nipc = Some("500123456".to_string());
    doc.created_at = Some("2026-07-06T10:30:00Z".to_string());
    doc.blocks = vec![
        Block::Heading {
            level: 1,
            text: "Ata número três".to_string(),
        },
        Block::Paragraph {
            runs: vec![
                Run {
                    text: "Aos seis dias do mês de julho reuniu a assembleia geral da sociedade, \
                           com a presença de "
                        .to_string(),
                    bold: false,
                    italic: false,
                },
                Run {
                    text: "todos os sócios".to_string(),
                    bold: true,
                    italic: false,
                },
                Run {
                    text: ", para deliberação dos pontos da ordem de trabalhos. A reunião \
                           decorreu na sede social, sita na Rua das Oliveiras."
                        .to_string(),
                    bold: false,
                    italic: true,
                },
            ],
        },
        Block::KeyValue {
            rows: vec![
                KvRow {
                    key: "Presidente da mesa".to_string(),
                    value: "Amélia Marques".to_string(),
                },
                KvRow {
                    key: "Data".to_string(),
                    value: "6 de julho de 2026".to_string(),
                },
            ],
        },
        Block::Heading {
            level: 2,
            text: "Votação".to_string(),
        },
        Block::VoteTable {
            rows: vec![
                VoteRow {
                    label: "Aprovação das contas".to_string(),
                    favor: 3,
                    against: 0,
                    abstain: 1,
                },
                VoteRow {
                    label: "Distribuição de resultados".to_string(),
                    favor: 4,
                    against: 0,
                    abstain: 0,
                },
            ],
        },
        Block::Rule,
        Block::SignatureBlock {
            slots: vec![
                SignatureSlot {
                    role: "Presidente da mesa".to_string(),
                    name: "Amélia Marques".to_string(),
                },
                SignatureSlot {
                    role: "Secretário".to_string(),
                    name: "João Nogueira".to_string(),
                },
            ],
        },
    ];
    doc
}

fn catalog(parsed: &Document) -> &Dictionary {
    let root = parsed
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .unwrap();
    parsed.get_object(root).and_then(Object::as_dict).unwrap()
}

fn xmp_text(parsed: &Document) -> String {
    let catalog = catalog(parsed);
    let meta_ref = catalog
        .get(b"Metadata")
        .and_then(Object::as_reference)
        .unwrap();
    let meta = parsed
        .get_object(meta_ref)
        .and_then(Object::as_stream)
        .unwrap();
    String::from_utf8_lossy(&meta.content).into_owned()
}

#[test]
fn fixture_writes_and_self_checks() {
    let bytes = pdfa::write(&fixture()).expect("write PDF/A");
    // The writer runs the self-check internally; assert the output parses and re-verify shape.
    let parsed = Document::load_mem(&bytes).expect("output parses via lopdf");
    assert_eq!(parsed.version, "1.7");
    assert!(bytes.starts_with(b"%PDF-1.7"));
    // Binary header marker (byte > 127 on the second line).
    assert!(bytes[9..16].iter().any(|&b| b > 127));
    // Classic xref table, not a stream.
    assert!(bytes.windows(6).any(|w| w == b"\nxref\n"));
    // pades shape: no AcroForm, /Root + /ID present, no /Encrypt.
    assert!(!bytes.windows(9).any(|w| w == b"/AcroForm"));
    assert!(parsed.trailer.has(b"Root"));
    assert!(parsed.trailer.has(b"ID"));
    assert!(!parsed.trailer.has(b"Encrypt"));
}

/// The pades byte-shape contract (C1–C12): the guarantees `chancela-pades::sign_pdf` relies on
/// when it appends its incremental signature update. This is the Wave-D-unblock surface e3 exercises
/// end-to-end.
#[test]
fn pades_signable_shape_holds() {
    let bytes = pdfa::write(&fixture()).expect("write");

    // The signer scans for its OWN "/Contents <" and "/ByteRange [0 " placeholders (first match).
    // The base document must contain neither, or the scan would latch onto our content.
    assert!(
        !bytes.windows(11).any(|w| w == b"/Contents <"),
        "base doc must not contain a `/Contents <` sequence"
    );
    assert!(
        !bytes.windows(10).any(|w| w == b"/ByteRange"),
        "base doc must not contain `/ByteRange`"
    );

    let parsed = Document::load_mem(&bytes).expect("load_mem (C11)");
    // C4: trailer /Root reference. C5: catalog /Pages reference.
    let root = parsed
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .expect("C4 /Root");
    let catalog = parsed.get_object(root).and_then(Object::as_dict).unwrap();
    let pages_ref = catalog
        .get(b"Pages")
        .and_then(Object::as_reference)
        .expect("C5 /Pages ref");
    // C6/C7: /Kids[0] is an indirect ref resolving to a /Page dictionary.
    let pages = parsed
        .get_object(pages_ref)
        .and_then(Object::as_dict)
        .unwrap();
    let first_kid = pages
        .get(b"Kids")
        .and_then(Object::as_array)
        .ok()
        .and_then(|k| k.first())
        .and_then(|k| k.as_reference().ok())
        .expect("C6 first kid ref");
    let page = parsed
        .get_object(first_kid)
        .and_then(Object::as_dict)
        .unwrap();
    assert_eq!(
        page.get(b"Type").and_then(Object::as_name).ok(),
        Some(&b"Page"[..])
    );
    // C2: no AcroForm. C3: no /Annots (absent is best). C12: no /Encrypt.
    assert!(!catalog.has(b"AcroForm"));
    assert!(!page.has(b"Annots"));
    assert!(!parsed.trailer.has(b"Encrypt"));
}

#[test]
fn output_is_deterministic() {
    let a = pdfa::write(&fixture()).expect("write a");
    let b = pdfa::write(&fixture()).expect("write b");
    assert_eq!(
        a, b,
        "same DocumentModel must produce byte-identical output"
    );
}

#[test]
fn pagination_produces_multiple_pages() {
    let mut doc = DocumentModel::new(
        "Documento Longo",
        "Encosto Estratégico Lda",
        "Teste de paginação",
    );
    // Enough paragraphs to overflow a single A4 page.
    doc.blocks = (0..120)
        .map(|i| Block::Paragraph {
            runs: vec![Run {
                text: format!(
                    "Parágrafo número {i}: texto de preenchimento com acentuação para forçar a \
                     mudança de página e exercitar a quebra de linha do motor de composição."
                ),
                bold: false,
                italic: false,
            }],
        })
        .collect();
    let bytes = pdfa::write(&doc).expect("write long doc");
    let parsed = Document::load_mem(&bytes).expect("parse");
    assert!(
        parsed.get_pages().len() > 1,
        "expected multiple pages, got {}",
        parsed.get_pages().len()
    );
}

#[test]
fn explicit_page_break_starts_a_new_page() {
    let mut doc = DocumentModel::new("Quebra", "Encosto Estratégico Lda", "PageBreak");
    doc.blocks = vec![
        Block::Paragraph {
            runs: vec![Run {
                text: "Primeira página.".to_string(),
                bold: false,
                italic: false,
            }],
        },
        Block::PageBreak,
        Block::Paragraph {
            runs: vec![Run {
                text: "Segunda página.".to_string(),
                bold: false,
                italic: false,
            }],
        },
    ];
    let bytes = pdfa::write(&doc).expect("write");
    let parsed = Document::load_mem(&bytes).expect("parse");
    assert_eq!(parsed.get_pages().len(), 2);
}

#[test]
fn diacritics_survive_via_tounicode() {
    let mut doc = DocumentModel::new("Diacríticos", "Encosto Estratégico Lda", "ç ã õ á");
    doc.blocks = vec![Block::Paragraph {
        runs: vec![Run {
            text: "coração melão sótão látex ç ã õ á à â é ê í ó ô ú «aspas»".to_string(),
            bold: false,
            italic: false,
        }],
    }];
    let bytes = pdfa::write(&doc).expect("write");
    let parsed = Document::load_mem(&bytes).expect("parse");
    // Find the uncompressed ToUnicode CMap stream.
    let cmap = parsed
        .objects
        .values()
        .filter_map(|o| o.as_stream().ok())
        .find(|s| s.content.windows(11).any(|w| w == b"beginbfchar"))
        .expect("a /ToUnicode bfchar CMap stream");
    let text = String::from_utf8_lossy(&cmap.content);
    // Each Portuguese diacritic must be recoverable (mapped to its UTF-16BE scalar).
    for (ch, hex) in [('ç', "00E7"), ('ã', "00E3"), ('õ', "00F5"), ('á', "00E1")] {
        assert!(
            text.contains(hex),
            "ToUnicode CMap is missing a mapping to U+{hex} ({ch})"
        );
    }
}

#[test]
fn metadata_is_uncompressed_pdfa2u() {
    let bytes = pdfa::write(&fixture()).expect("write");
    let parsed = Document::load_mem(&bytes).expect("parse");
    let catalog = catalog(&parsed);
    let meta_ref = catalog
        .get(b"Metadata")
        .and_then(Object::as_reference)
        .unwrap();
    let meta = parsed
        .get_object(meta_ref)
        .and_then(Object::as_stream)
        .unwrap();
    assert!(!meta.dict.has(b"Filter"), "XMP must not be compressed");
    let xmp = String::from_utf8_lossy(&meta.content);
    assert!(xmp.contains("<pdfaid:part>2</pdfaid:part>"));
    assert!(xmp.contains("<pdfaid:conformance>U</pdfaid:conformance>"));
}

#[test]
fn accessibility_metadata_falls_back_for_missing_title_language() {
    let mut doc = DocumentModel::new(" \t\n", "Encosto Estratégico Lda", "Sem título");
    doc.language = "  ".to_string();

    let report = pdfa::accessibility_report(&doc);
    assert_eq!(report.metadata.title.value, "Untitled Chancela document");
    assert!(!report.metadata.title.source_present);
    assert!(report.metadata.title.fallback_used);
    assert_eq!(report.metadata.language.value, "und");
    assert!(!report.metadata.language.source_present);
    assert!(report.metadata.language.fallback_used);
    assert!(!report.pdf_ua_claimed);

    let bytes = pdfa::write(&doc).expect("write");
    let parsed = Document::load_mem(&bytes).expect("parse");
    let catalog = catalog(&parsed);
    assert_eq!(
        catalog.get(b"Lang").and_then(Object::as_str).unwrap(),
        b"und"
    );
    let xmp = xmp_text(&parsed);
    assert!(xmp.contains("<rdf:li xml:lang=\"x-default\">Untitled Chancela document</rdf:li>"));
    assert!(xmp.contains("<rdf:li>und</rdf:li>"));
}

#[test]
fn implausible_language_metadata_is_reported_and_falls_back() {
    let mut doc = fixture();
    doc.language = "pt_PT".to_string();

    let report = pdfa::accessibility_report(&doc);
    assert_eq!(report.metadata.language.value, "und");
    assert!(report.metadata.language.source_present);
    assert!(report.metadata.language.fallback_used);
    assert!(!report.pdf_ua_claimed);
    assert!(
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::MissingStructTreeRoot)
    );

    let bytes = pdfa::write(&doc).expect("write");
    assert!(
        !bytes.windows(7).any(|w| w == b"pdfuaid"),
        "fallback metadata must not introduce PDF/UA identification"
    );
    let parsed = Document::load_mem(&bytes).expect("parse");
    let catalog = catalog(&parsed);
    assert_eq!(
        catalog.get(b"Lang").and_then(Object::as_str).unwrap(),
        b"und"
    );
    let xmp = xmp_text(&parsed);
    assert!(xmp.contains("<rdf:li>und</rdf:li>"));
    assert!(!xmp.contains("pt_PT"));
}

#[test]
fn long_non_ascii_title_is_preserved_in_report_and_xmp() {
    let title = format!(
        "São Tomé & Príncipe: ata extraordinária <revisão> \"final\" {}",
        vec!["ação"; 32].join(" ")
    );
    let doc = DocumentModel::new(format!("  {title}  "), "Encosto Estratégico Lda", "Teste");

    let report = pdfa::accessibility_report(&doc);
    assert_eq!(report.metadata.title.value, title);
    assert!(report.metadata.title.source_present);
    assert!(!report.metadata.title.fallback_used);
    assert!(report.to_json().contains("São Tomé & Príncipe"));
    assert!(report.to_json().contains("\\\"final\\\""));

    let bytes = pdfa::write(&doc).expect("write");
    let parsed = Document::load_mem(&bytes).expect("parse");
    let xmp = xmp_text(&parsed);
    assert!(xmp.contains("São Tomé &amp; Príncipe"));
    assert!(xmp.contains("&lt;revisão&gt;"));
    assert!(xmp.contains("&quot;final&quot;"));
}

#[test]
fn accessibility_default_fixture_reports_no_alt_text_model() {
    let report = pdfa::accessibility_report(&fixture());

    assert!(!report.alt_text_model_present);
    assert!(!report.pdf_ua_claimed);
    assert!(
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::NoAltTextModel)
    );
}

#[test]
fn accessibility_explicit_alt_text_decorative_model_clears_only_alt_text_blocker() {
    let mut doc = DocumentModel::new(
        "Ata com metadados de acessibilidade",
        "Encosto Estratégico Lda",
        "Modelo explicito",
    );
    doc.blocks = vec![
        Block::Paragraph {
            runs: vec![Run {
                text: "Conteudo textual principal.".to_string(),
                bold: false,
                italic: false,
            }],
        },
        Block::Rule,
    ];
    let alt_text_model = pdfa::AltTextModel {
        all_non_text_content_accounted_for: true,
        text_alternatives: vec![pdfa::TextAlternative::new(
            "asset:company-seal",
            "Company seal",
        )],
        decorative_artifacts: vec![pdfa::DecorativeArtifact::block(1)],
    };

    let report = pdfa::accessibility_report(
        pdfa::AccessibilityInput::new(&doc).with_alt_text_model(&alt_text_model),
    );

    assert!(report.alt_text_model_present);
    assert!(!report.pdf_ua_claimed);
    assert!(
        !report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::NoAltTextModel)
    );
    assert!(
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::MissingStructTreeRoot)
    );
    assert!(
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::ContentIsNotTagged)
    );
    assert!(
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::MissingRoleMap)
    );
    assert!(
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::LayoutArtifactsNotMarked)
    );
}

#[test]
fn accessibility_report_json_is_deterministic() {
    let a = pdfa::accessibility_report(&fixture()).to_json();
    let b = pdfa::accessibility_report(&fixture()).to_json();
    assert_eq!(a, b);
    assert_eq!(
        a,
        "{\"version\":1,\"pdf_ua_claimed\":false,\"metadata\":{\"title\":{\"value\":\"Ata da Assembleia Geral\",\"source_present\":true,\"fallback_used\":false},\"language\":{\"value\":\"pt-PT\",\"source_present\":true,\"fallback_used\":false},\"catalog_lang\":true,\"xmp_title\":true,\"xmp_language\":true},\"text\":{\"embedded_fonts\":true,\"to_unicode_cmaps\":true},\"reading_order\":{\"content_streams_follow_model_order\":true,\"structure_tree_present\":false,\"tagged_content_present\":false,\"layout_artifacts_marked\":false},\"alt_text_model_present\":false,\"pdf_ua_blockers\":[\"missing_struct_tree_root\",\"content_is_not_tagged\",\"missing_role_map\",\"no_alt_text_model\",\"layout_artifacts_not_marked\"]}"
    );
}

#[test]
fn pdf_ua_is_not_claimed_without_tagging() {
    let report = pdfa::accessibility_report(&fixture());
    assert!(!report.pdf_ua_claimed);
    assert!(
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::MissingStructTreeRoot)
    );
    assert!(
        report
            .pdf_ua_blockers
            .contains(&pdfa::PdfUaBlocker::ContentIsNotTagged)
    );

    let bytes = pdfa::write(&fixture()).expect("write");
    assert!(
        !bytes.windows(7).any(|w| w == b"pdfuaid"),
        "writer must not emit PDF/UA identification metadata"
    );
    let parsed = Document::load_mem(&bytes).expect("parse");
    let catalog = catalog(&parsed);
    assert!(!catalog.has(b"StructTreeRoot"));
    let mark_info = catalog
        .get(b"MarkInfo")
        .and_then(Object::as_dict)
        .expect("honest MarkInfo dictionary");
    assert!(matches!(
        mark_info.get(b"Marked"),
        Ok(Object::Boolean(false))
    ));
}
