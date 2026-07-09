//! Offline end-to-end tests for `chancela-registry`: fixture parsing + client round-trip over the
//! mock transport. No network — the live seam lives in `tests/network.rs` behind `network-tests`.

use chancela_registry::mock::{FIXTURE_EXPIRED, FIXTURE_SPQ};
use chancela_registry::model::{ConstitutionPayload, InscriptionPayload};
use chancela_registry::{
    AccessCode, CaeRef, CaeRole, LegalForm, MockRegistryTransport, RegistryClient, RegistryError,
    RegistryEvent, RegistryExtract, RegistryTransport, parse_certidao,
};

fn cae(code: &str, role: CaeRole) -> CaeRef {
    CaeRef {
        code: code.to_owned(),
        role,
    }
}

const TEST_CODE: &str = "7110-6727-7477";

fn lookup(transport: MockRegistryTransport) -> RegistryExtract {
    let code = AccessCode::parse(TEST_CODE).expect("valid code");
    RegistryClient::new(transport)
        .lookup(&code, None)
        .expect("lookup succeeds")
}

/// The `ConstitutionPayload` of an event's structured detail (panics if it is not a constitution).
fn constitution(event: &RegistryEvent) -> &ConstitutionPayload {
    match event
        .detail
        .as_ref()
        .expect("detail present")
        .payload
        .as_ref()
        .expect("payload present")
    {
        InscriptionPayload::Constitution(c) => c,
        other => panic!("expected a Constitution payload, got {other:?}"),
    }
}

#[test]
fn parses_sociedade_por_quotas_fixture() {
    let extract = lookup(MockRegistryTransport::from_fixture_spq());

    // Matrícula block — preserved byte-for-byte (the summary block still drives identity/CAE).
    assert_eq!(extract.matricula.as_deref(), Some("12045/20200115"));
    assert_eq!(extract.nipc.as_deref(), Some("500002020"));
    assert_eq!(extract.firma.as_deref(), Some("Encosto Estratégico, Lda"));
    assert_eq!(
        extract.forma_juridica.as_deref(),
        Some("Sociedade por quotas")
    );
    assert_eq!(extract.legal_form, Some(LegalForm::SociedadePorQuotas));
    assert!(
        extract
            .sede
            .as_deref()
            .unwrap()
            .contains("Rua das Amoreiras")
    );
    assert_eq!(
        extract.cae,
        vec![
            cae("70220", CaeRole::Principal),
            cae("82990", CaeRole::Secundario),
            cae("63110", CaeRole::Secundario),
        ]
    );
    assert!(extract.objeto.as_deref().unwrap().contains("Consultoria"));
    assert_eq!(extract.capital.as_deref(), Some("5.000,00 EUR"));
    assert_eq!(extract.data_constituicao.as_deref(), Some("2020-01-15"));

    // Ordered inscrições feed (DOC-30 raw timeline) — numbers preserved.
    let numbers: Vec<_> = extract
        .inscricoes
        .iter()
        .map(|e| e.number.clone())
        .collect();
    assert_eq!(
        numbers,
        vec![
            Some("1".to_string()),
            Some("2".to_string()),
            Some("3 Av. 1".to_string()),
            Some("4".to_string()),
        ]
    );
    assert!(
        extract.inscricoes[0]
            .kind_hint
            .as_deref()
            .unwrap()
            .contains("CONSTITUIÇÃO")
    );
    assert_eq!(extract.inscricoes[0].date.as_deref(), Some("2020-01-15"));
    assert_eq!(
        extract.inscricoes[0].apresentacao.as_deref(),
        Some("AP. 1/20200115")
    );

    // Officers rolled up off the structured detail: constitution gerente (still serving) + a
    // designated-then-ceased gerente.
    let amelia = extract
        .orgaos
        .iter()
        .find(|o| o.name.contains("Amélia Marques"))
        .expect("gerente Amélia present");
    assert_eq!(amelia.role.as_deref(), Some("Gerente"));
    assert_eq!(amelia.appointment_date.as_deref(), Some("2026-05-11"));
    assert_eq!(amelia.cessation_date, None);
    assert_eq!(amelia.source_event.as_deref(), Some("1"));

    let bruno = extract
        .orgaos
        .iter()
        .find(|o| o.name.contains("Bruno Alves"))
        .expect("gerente Bruno present");
    assert_eq!(bruno.role.as_deref(), Some("Gerente"));
    assert_eq!(bruno.appointment_date.as_deref(), Some("2021-03-05"));
    assert_eq!(bruno.cessation_date.as_deref(), Some("2023-06-20"));
    assert_eq!(bruno.source_event.as_deref(), Some("2"));
}

#[test]
fn spq_constitution_detail_is_fully_structured() {
    let extract = lookup(MockRegistryTransport::from_fixture_spq());
    let insc1 = &extract.inscricoes[0];

    // Apresentação parsed off the raw header (act kind on the next line — fallback path).
    let ap = insc1
        .detail
        .as_ref()
        .unwrap()
        .apresentacao
        .as_ref()
        .unwrap();
    assert_eq!(ap.number.as_deref(), Some("1"));
    assert_eq!(ap.date.as_deref(), Some("2020-01-15"));
    assert_eq!(ap.act_kinds.len(), 1);

    let c = constitution(insc1);
    assert_eq!(c.firma.as_deref(), Some("Encosto Estratégico, Lda"));
    assert_eq!(c.nipc.as_deref(), Some("500002020"));
    assert_eq!(c.natureza_juridica.as_deref(), Some("Sociedade por quotas"));

    // Multi-line SEDE folded into a structured address (admin line + postal line).
    let sede = c.sede.as_ref().expect("sede");
    assert_eq!(sede.lines, vec!["Rua do Exemplo, n.º 11, Lugar de Cima"]);
    assert_eq!(sede.distrito.as_deref(), Some("Lisboa"));
    assert_eq!(sede.concelho.as_deref(), Some("Lisboa"));
    assert_eq!(sede.freguesia.as_deref(), Some("Santo António"));
    assert_eq!(sede.postal_code.as_deref(), Some("1250-096"));
    assert_eq!(sede.locality.as_deref(), Some("LISBOA"));

    // Multi-sentence objecto joined; the two CAPITAL lines disambiguated by value.
    assert!(
        c.objecto
            .as_deref()
            .unwrap()
            .contains("Actividades conexas")
    );
    let capital = c.capital.as_ref().expect("capital money");
    assert_eq!(capital.amount_text, "5.000,00");
    assert_eq!(capital.currency.as_deref(), Some("Euros"));
    assert!(
        c.capital_realization_note
            .as_deref()
            .unwrap()
            .contains("A entregar")
    );
    assert_eq!(c.fiscal_year_end.as_deref(), Some("31 Dezembro"));

    // Two quota blocks with their titulares.
    assert_eq!(c.socios.len(), 2);
    assert_eq!(c.socios[0].amount.amount_text, "4.500,00");
    assert_eq!(c.socios[0].titular.name, "Rui Tavares Nogueira");
    assert_eq!(c.socios[0].titular.nif.as_deref(), Some("999999990"));
    assert_eq!(c.socios[0].titular.estado_civil.as_deref(), Some("casado"));
    assert_eq!(c.socios[1].titular.name, "Amélia Marques");
    assert_eq!(c.socios[1].titular.nif.as_deref(), Some("999999982"));

    // Gerência organ + its member.
    assert_eq!(c.orgaos.len(), 1);
    assert_eq!(c.orgaos[0].name, "GERÊNCIA");
    assert_eq!(c.orgaos[0].members.len(), 1);
    assert_eq!(c.orgaos[0].members[0].name, "Amélia Marques");
    assert_eq!(c.orgaos[0].members[0].cargo.as_deref(), Some("Gerente"));

    assert!(c.forma_de_obrigar.as_deref().unwrap().contains("gerente"));
    // The "11 da maio de 2026" long-date quirk (sic "da") normalized.
    assert_eq!(c.deliberation_date.as_deref(), Some("2026-05-11"));

    // Never lossy: the raw text still carries every line the detail was read from.
    assert!(insc1.text.contains("TITULAR: Rui Tavares Nogueira"));
    assert!(
        insc1
            .text
            .contains("Data da deliberação: 11 da maio de 2026")
    );
}

#[test]
fn spq_anotacoes_and_certidao_meta_parsed() {
    let extract = lookup(MockRegistryTransport::from_fixture_spq());

    assert_eq!(extract.anotacoes.len(), 1);
    let an = &extract.anotacoes[0];
    assert_eq!(an.number.as_deref(), Some("1"));
    assert_eq!(an.date.as_deref(), Some("2024-09-02"));
    assert_eq!(
        an.publication_url.as_deref(),
        Some("http://publicacoes.mj.pt")
    );

    let p = &extract.provenance;
    assert!(
        p.conservatoria
            .as_deref()
            .unwrap()
            .contains("Registo Comercial de Lisboa")
    );
    assert_eq!(p.oficial.as_deref(), Some("Amélia Marques"));
    assert_eq!(p.subscribed_on.as_deref(), Some("2026-07-05"));
    assert_eq!(p.valid_until.as_deref(), Some("2027-07-05"));
}

#[test]
fn spq_amendment_and_cessation_payloads() {
    let extract = lookup(MockRegistryTransport::from_fixture_spq());

    // Insc.3 cessation — multi-act apresentação on the AP line, member + cause.
    let cess = &extract.inscricoes[2];
    let ap = cess.detail.as_ref().unwrap().apresentacao.as_ref().unwrap();
    assert_eq!(ap.time.as_deref(), Some("09:30:00 UTC"));
    match cess.detail.as_ref().unwrap().payload.as_ref().unwrap() {
        InscriptionPayload::Cessation(c) => {
            assert_eq!(c.members[0].name, "Bruno Alves Ferreira");
            assert_eq!(c.cause.as_deref(), Some("renúncia"));
        }
        other => panic!("expected Cessation, got {other:?}"),
    }

    // Insc.4 contract amendment — a new SEDE with its admin/postal breakdown.
    let amend = &extract.inscricoes[3];
    match amend.detail.as_ref().unwrap().payload.as_ref().unwrap() {
        InscriptionPayload::ContractAmendment(a) => {
            let sede = a.new_sede.as_ref().expect("new sede");
            assert_eq!(sede.postal_code.as_deref(), Some("1250-142"));
            assert_eq!(a.deliberation_date.as_deref(), Some("2024-08-28"));
        }
        other => panic!("expected ContractAmendment, got {other:?}"),
    }
}

#[test]
fn constituicao_specimen_every_field_and_backfill() {
    let extract = lookup(MockRegistryTransport::from_fixture_constituicao());

    // The matrícula summary block is intentionally minimal → the extract-level identity is blank
    // and must be backfilled from the constitution body.
    assert_eq!(extract.firma, None);
    assert_eq!(extract.nipc, None);
    assert_eq!(extract.sede, None);
    assert_eq!(
        extract.effective_firma().as_deref(),
        Some("Encosto Estratégico, Lda")
    );
    assert_eq!(extract.effective_nipc().as_deref(), Some("503004642"));
    assert!(
        extract
            .effective_sede()
            .as_deref()
            .unwrap()
            .contains("Rua do Comércio")
    );
    assert!(
        extract
            .effective_sede()
            .as_deref()
            .unwrap()
            .contains("4000-111 PORTO")
    );
    assert!(
        extract
            .effective_objecto()
            .as_deref()
            .unwrap()
            .contains("Prestação")
    );
    assert_eq!(extract.effective_capital().as_deref(), Some("100,00 Euros"));
    assert_eq!(
        extract.effective_data_constituicao().as_deref(),
        Some("2026-05-11")
    );

    // Multi-act apresentação: the two act kinds on the AP line, plus the UTC timestamp.
    let insc1 = &extract.inscricoes[0];
    let ap = insc1
        .detail
        .as_ref()
        .unwrap()
        .apresentacao
        .as_ref()
        .unwrap();
    assert_eq!(ap.number.as_deref(), Some("1"));
    assert_eq!(ap.date.as_deref(), Some("2026-05-01"));
    assert_eq!(ap.time.as_deref(), Some("00:55:25 UTC"));
    assert_eq!(ap.act_kinds.len(), 2);
    assert!(ap.act_kinds[0].contains("CONSTITUIÇÃO"));
    assert!(ap.act_kinds[1].contains("DESIGNAÇÃO"));

    // Constitution absorbs the co-listed designação organ; every sub-field present.
    let c = constitution(insc1);
    assert_eq!(c.nipc.as_deref(), Some("503004642"));
    assert_eq!(
        c.sede.as_ref().unwrap().freguesia.as_deref(),
        Some("Cedofeita")
    );
    assert_eq!(c.capital.as_ref().unwrap().amount_text, "100,00");
    assert_eq!(c.socios.len(), 2);
    assert_eq!(c.socios[0].amount.amount_text, "99,00");
    assert_eq!(c.socios[1].amount.amount_text, "1,00");
    assert_eq!(c.orgaos[0].members[0].name, "Amélia Marques");
    assert_eq!(c.deliberation_date.as_deref(), Some("2026-05-11"));

    // The gerente rolled up into the flat officers list.
    let gerente = extract
        .orgaos
        .iter()
        .find(|o| o.name.contains("Amélia"))
        .expect("gerente present");
    assert_eq!(gerente.role.as_deref(), Some("Gerente"));
    assert_eq!(gerente.appointment_date.as_deref(), Some("2026-05-11"));
}

#[test]
fn parses_sociedade_anonima_fixture() {
    let extract = lookup(MockRegistryTransport::from_fixture_sa());

    assert_eq!(extract.nipc.as_deref(), Some("503341200"));
    assert_eq!(extract.firma.as_deref(), Some("Encosto Estratégico, S.A."));
    assert_eq!(extract.legal_form, Some(LegalForm::SociedadeAnonima));
    assert_eq!(extract.cae, vec![cae("68100", CaeRole::Principal)]);
    assert_eq!(extract.capital.as_deref(), Some("50.000,00 EUR"));
    assert_eq!(extract.data_constituicao.as_deref(), Some("2015-09-22"));
    assert_eq!(extract.inscricoes.len(), 4);

    // Designação under a CONSELHO DE ADMINISTRAÇÃO organ (multi-member).
    match extract.inscricoes[1]
        .detail
        .as_ref()
        .unwrap()
        .payload
        .as_ref()
        .unwrap()
    {
        InscriptionPayload::Designation(d) => {
            assert_eq!(d.orgaos[0].name, "CONSELHO DE ADMINISTRAÇÃO");
            assert_eq!(d.orgaos[0].members.len(), 2);
        }
        other => panic!("expected Designation, got {other:?}"),
    }

    let presidente = extract
        .orgaos
        .iter()
        .find(|o| o.name.contains("Henrique Vaz"))
        .expect("presidente present");
    assert_eq!(presidente.role.as_deref(), Some("Presidente"));
    assert_eq!(presidente.appointment_date.as_deref(), Some("2015-09-20"));

    let sofia = extract
        .orgaos
        .iter()
        .find(|o| o.name.contains("Sofia Raquel"))
        .expect("administradora present");
    assert_eq!(sofia.role.as_deref(), Some("Administrador"));
    assert_eq!(sofia.appointment_date.as_deref(), Some("2015-09-20"));
    assert_eq!(sofia.cessation_date.as_deref(), Some("2022-05-18"));
}

#[test]
fn parses_fundacao_fixture() {
    let extract = lookup(MockRegistryTransport::from_fixture_fundacao());

    assert_eq!(extract.nipc.as_deref(), Some("509028700"));
    assert_eq!(
        extract.firma.as_deref(),
        Some("Fundação Encosto Estratégico")
    );
    assert_eq!(extract.legal_form, Some(LegalForm::Fundacao));
    assert_eq!(extract.cae, vec![cae("94991", CaeRole::Principal)]);
    assert_eq!(extract.matricula.as_deref(), Some("F-0287/20180405"));
    assert!(
        extract
            .capital
            .as_deref()
            .unwrap()
            .contains("250.000,00 EUR")
    );

    let presidente = extract
        .orgaos
        .iter()
        .find(|o| o.name.contains("Teresa Manuela"))
        .expect("presidente present");
    assert_eq!(presidente.role.as_deref(), Some("Presidente"));
    assert_eq!(presidente.appointment_date.as_deref(), Some("2018-04-02"));

    let vogal = extract
        .orgaos
        .iter()
        .find(|o| o.name.contains("Álvaro Nuno"))
        .expect("vogal present");
    assert_eq!(vogal.role.as_deref(), Some("Vogal"));
    assert_eq!(vogal.appointment_date.as_deref(), Some("2018-04-02"));
    assert_eq!(vogal.cessation_date.as_deref(), Some("2024-01-30"));
}

#[test]
fn error_page_is_unrecognized() {
    let transport = MockRegistryTransport::empty().with_html(FIXTURE_EXPIRED);
    let code = AccessCode::parse(TEST_CODE).unwrap();
    let err = RegistryClient::new(transport)
        .lookup(&code, None)
        .expect_err("error page must not parse as a certidão");
    assert!(matches!(err, RegistryError::Unrecognized(_)));
}

#[test]
fn empty_mock_is_upstream_failure() {
    let code = AccessCode::parse(TEST_CODE).unwrap();
    let err = RegistryClient::new(MockRegistryTransport::empty())
        .lookup(&code, None)
        .expect_err("no canned document");
    assert!(matches!(err, RegistryError::Upstream(_)));
}

#[test]
fn provenance_carries_masked_code_and_digest_only() {
    let transport = MockRegistryTransport::from_fixture_spq();
    let code = AccessCode::parse(TEST_CODE).unwrap();
    let extract = RegistryClient::new(transport).lookup(&code, None).unwrap();

    let prov = &extract.provenance;
    assert_eq!(prov.access_code_masked, "****-****-7477");
    assert_eq!(prov.source_url, "mock://registry/certidao");
    assert_eq!(prov.raw_digest.len(), 64);
    assert!(prov.raw_digest.chars().all(|c| c.is_ascii_hexdigit()));

    // The digest must match a direct sha256 of the fixture bytes (parser computes it internally).
    let recomputed = parse_certidao(FIXTURE_SPQ, "****-****-7477", "u", "t")
        .unwrap()
        .provenance
        .raw_digest;
    assert_eq!(prov.raw_digest, recomputed);
}

#[test]
fn full_code_never_leaks_into_the_serialized_extract() {
    let transport = MockRegistryTransport::from_fixture_spq();
    let code = AccessCode::parse(TEST_CODE).unwrap();
    let extract = RegistryClient::new(transport).lookup(&code, None).unwrap();

    let json = serde_json::to_string(&extract).unwrap();
    assert!(!json.contains("7110-6727-7477"));
    assert!(!json.contains("711067277477"));
    assert!(json.contains("****-****-7477"));
}

#[test]
fn mock_records_only_the_masked_code() {
    let transport = MockRegistryTransport::from_fixture_spq();
    let code = AccessCode::parse(TEST_CODE).unwrap();

    // Consult twice directly through the transport, then inspect the recorded log.
    transport.fetch(&code, None).unwrap();
    transport.fetch(&code, None).unwrap();

    assert_eq!(
        transport.recorded(),
        vec!["****-****-7477".to_string(), "****-****-7477".to_string()]
    );
}

#[test]
fn constituicao_payload_serializes_with_a_type_tag() {
    // Freeze the wire shape for the API executor: the payload is internally tagged.
    let extract = lookup(MockRegistryTransport::from_fixture_constituicao());
    let json = serde_json::to_value(&extract.inscricoes[0].detail).unwrap();
    assert_eq!(json["payload"]["type"], "Constitution");
    assert_eq!(
        json["apresentacao"]["act_kinds"].as_array().unwrap().len(),
        2
    );
}
