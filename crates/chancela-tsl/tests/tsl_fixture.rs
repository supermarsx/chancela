//! Fixture-based, fully offline tests for `chancela-tsl` (no network).
//!
//! Drives the public API against the bundled sample Portuguese Trusted List
//! (`fixtures/pt-tsl-sample.xml`) and an unlisted CA certificate (`fixtures/unlisted-ca.der`).
//! See `crates/chancela-tsl/TESTING.md`.

use std::path::PathBuf;

use chancela_tsl::parse::{FOR_ESEALS, FOR_ESIGNATURES, SVCTYPE_CA_QC};
use chancela_tsl::{
    BytesTslSource, DigitalIdentity, FileTslSource, QualifiedStatus, ServiceStatus, TrustedList,
    TslClient, TslError, parse_tsl, qualified_esig_services, resolve_esig_status,
    resolve_qtst_match_details, validate_tsl_signature,
};
use time::OffsetDateTime;
use time::macros::datetime;

/// A moment inside the fixture's validity window (issued 2026-01-15, next update 2026-07-15).
const NOW: OffsetDateTime = datetime!(2026-07-06 12:00:00 UTC);
/// A moment after the fixture's `NextUpdate` — the cache should be stale here.
const AFTER_NEXT_UPDATE: OffsetDateTime = datetime!(2026-08-01 00:00:00 UTC);

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn load_list() -> TrustedList {
    let xml = std::fs::read(fixture_dir().join("pt-tsl-sample.xml")).expect("read fixture");
    parse_tsl(&xml).expect("parse fixture")
}

fn load_xml() -> Vec<u8> {
    std::fs::read(fixture_dir().join("pt-tsl-sample.xml")).expect("read fixture")
}

fn fixture_without_signature() -> Vec<u8> {
    let mut xml = String::from_utf8(load_xml()).expect("fixture is UTF-8");
    let start = xml.find("  <ds:Signature").expect("signature start");
    let end_tag = "  </ds:Signature>\n";
    let end = xml[start..].find(end_tag).expect("signature end") + start + end_tag.len();
    xml.replace_range(start..end, "");
    xml.into_bytes()
}

/// The DER of the first `X509Certificate` identity of the first service of the provider whose
/// name contains `name_substr`.
fn issuer_cert(list: &TrustedList, name_substr: &str) -> Vec<u8> {
    let provider = list
        .providers
        .iter()
        .find(|p| p.name.contains(name_substr))
        .unwrap_or_else(|| panic!("provider containing {name_substr:?} not found"));
    provider.services[0]
        .digital_identities
        .iter()
        .find_map(|id| match id {
            DigitalIdentity::Certificate(der) => Some(der.clone()),
            _ => None,
        })
        .expect("service carries an X509Certificate identity")
}

#[test]
fn parses_scheme_information() {
    let list = load_list();
    assert_eq!(list.scheme_operator_name, "National Security Authority");
    assert_eq!(
        list.scheme_name,
        "PT:Supervision/Accreditation Status List of certification services from Certification Service Providers"
    );
    assert_eq!(list.scheme_territory, "PT");
    assert_eq!(list.sequence_number, Some(52));
    assert_eq!(list.issue_date_time, Some(datetime!(2026-01-15 0:00 UTC)));
    assert_eq!(list.next_update, Some(datetime!(2026-07-15 0:00 UTC)));
    assert_eq!(list.providers.len(), 4);
}

#[test]
fn parses_provider_service_status_and_identity_report_fields() {
    let list = load_list();
    let multicert = list
        .providers
        .iter()
        .find(|p| p.name.contains("MULTICERT"))
        .expect("MULTICERT provider");
    assert_eq!(
        multicert.name,
        "MULTICERT - Electronic Certification Services SA"
    );
    assert_eq!(multicert.trade_names, vec!["MULTICERT"]);
    assert_eq!(
        multicert.information_uris,
        vec!["https://www.multicert.com/"]
    );

    let service = &multicert.services[0];
    assert_eq!(service.service_type, SVCTYPE_CA_QC);
    assert_eq!(service.name, "MULTICERT CA para Assinatura Qualificada");
    assert_eq!(
        service
            .names
            .iter()
            .filter(|name| name.value == "MULTICERT CA para Assinatura Qualificada")
            .count(),
        3,
        "duplicate/multilingual service names are retained for catalog search"
    );
    assert_eq!(service.status, ServiceStatus::Granted);
    assert_eq!(
        service.status_starting_time,
        Some(datetime!(2020-01-01 0:00 UTC))
    );
    assert_eq!(
        service.additional_service_info,
        vec![FOR_ESIGNATURES.to_owned()]
    );
    assert!(service.digital_identities.iter().any(|id| matches!(
        id,
        DigitalIdentity::Certificate(der) if der.len() > 512
    )));
    assert!(service.digital_identities.iter().any(|id| matches!(
        id,
        DigitalIdentity::SubjectName(name) if name.contains("MULTICERT CA para Assinatura Qualificada")
    )));
    assert!(service.digital_identities.iter().any(|id| matches!(
        id,
        DigitalIdentity::SubjectKeyId(ski) if ski.len() == 20
    )));

    let digitalsign = list
        .providers
        .iter()
        .find(|p| p.name.contains("DigitalSign"))
        .expect("DigitalSign provider");
    assert_eq!(digitalsign.services[0].status, ServiceStatus::Withdrawn);
    assert_eq!(digitalsign.services[0].status_starting_time, None);
    assert_eq!(
        digitalsign.services[0].status_starting_time_raw.as_deref(),
        Some("not-a-date")
    );

    let egia = list
        .providers
        .iter()
        .find(|p| p.name == "EGIA")
        .expect("EGIA provider");
    assert_eq!(
        egia.services[0].additional_service_info,
        vec![FOR_ESEALS.to_owned()]
    );

    let tsa = list
        .providers
        .iter()
        .find(|p| p.name == "Cartorio Notarial Timestamping")
        .expect("TSA provider");
    assert!(
        tsa.names
            .iter()
            .any(|name| name.value == "Cartório Âncora Carimbo do Tempo")
    );
    assert_eq!(tsa.trade_names, vec!["Âncora TSA São Tomé"]);
    assert_eq!(tsa.services.len(), 2);
    assert_eq!(
        tsa.services[0].service_supply_points,
        vec!["http://tsa.cartorio.example.test/tsa/server"]
    );
    let revoked_tsa = &tsa.services[1];
    assert!(
        revoked_tsa.name.is_empty(),
        "missing ServiceName stays empty"
    );
    assert!(matches!(
        revoked_tsa.status,
        ServiceStatus::Revoked(ref uri) if uri.ends_with("/supervisionRevoked")
    ));
    assert_eq!(revoked_tsa.status_starting_time, None);
    assert_eq!(
        revoked_tsa.status_starting_time_raw.as_deref(),
        Some("not-a-date")
    );
}

#[test]
fn granted_qtsp_is_qualified_for_esig() {
    let list = load_list();
    let cert = issuer_cert(&list, "MULTICERT");
    assert_eq!(
        resolve_esig_status(&list, &cert, NOW),
        QualifiedStatus::Granted
    );
}

#[test]
fn withdrawn_service_is_not_qualified() {
    let list = load_list();
    let cert = issuer_cert(&list, "DigitalSign");
    assert_eq!(
        resolve_esig_status(&list, &cert, NOW),
        QualifiedStatus::Withdrawn
    );
}

#[test]
fn seal_only_ca_is_not_qualified_for_esig() {
    // EGIA's CA/QC is granted, but only for e-seals — not e-signatures.
    let list = load_list();
    let cert = issuer_cert(&list, "EGIA");
    assert_eq!(
        resolve_esig_status(&list, &cert, NOW),
        QualifiedStatus::Withdrawn
    );
}

#[test]
fn unlisted_issuer_is_unknown() {
    let list = load_list();
    let cert = std::fs::read(fixture_dir().join("unlisted-ca.der")).expect("read unlisted cert");
    assert_eq!(
        resolve_esig_status(&list, &cert, NOW),
        QualifiedStatus::Unknown
    );
}

#[test]
fn garbage_issuer_bytes_are_unknown_not_an_error() {
    let list = load_list();
    assert_eq!(
        resolve_esig_status(&list, b"not-a-certificate", NOW),
        QualifiedStatus::Unknown
    );
}

#[test]
fn service_history_is_ignored() {
    // MULTICERT carries a withdrawn ServiceHistory instance with an all-zero SKI; the parser must
    // keep that history structured without mixing it into the *current* granted service.
    let list = load_list();
    let svc = &list
        .providers
        .iter()
        .find(|p| p.name.contains("MULTICERT"))
        .unwrap()
        .services[0];
    assert_eq!(svc.status, ServiceStatus::Granted);
    // Exactly one certificate identity and one (non-zero) SKI — the history entries are absent.
    let ski_count = svc
        .digital_identities
        .iter()
        .filter(|id| matches!(id, DigitalIdentity::SubjectKeyId(_)))
        .count();
    assert_eq!(ski_count, 1);
    assert!(
        svc.digital_identities
            .iter()
            .any(|id| matches!(id, DigitalIdentity::SubjectKeyId(s) if s.iter().any(|&b| b != 0)))
    );
    assert_eq!(svc.history.len(), 1);
    assert_eq!(svc.history[0].status, ServiceStatus::Withdrawn);
    assert!(
        svc.history[0]
            .digital_identities
            .iter()
            .any(|id| matches!(id, DigitalIdentity::SubjectKeyId(s) if s.iter().all(|&b| b == 0)))
    );
}

#[test]
fn discovery_lists_only_the_granted_esig_service() {
    let list = load_list();
    let services = qualified_esig_services(&list, NOW);
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].name, "MULTICERT CA para Assinatura Qualificada");
}

#[test]
fn client_caches_and_reports_staleness() {
    let source = FileTslSource::new(fixture_dir().join("pt-tsl-sample.xml"));
    let mut client = TslClient::new(source);

    // Cold cache: nothing yet.
    assert!(client.cached().is_none());

    client.ensure_fresh(NOW).expect("fetch + parse");
    let cached = client.cached().expect("cache populated");
    assert!(!cached.is_stale(NOW));
    assert!(cached.is_stale(AFTER_NEXT_UPDATE));
}

#[test]
fn client_downgrades_granted_to_unknown_when_signature_does_not_verify() {
    // Security audit t41/C2: the fixture carries a placeholder <ds:Signature> that does not
    // verify (no <ds:Reference>, no <ds:KeyInfo>, fake SignatureValue). TslClient MUST NOT
    // report Granted for an issuer on an unauthenticated list — Granted is downgraded to
    // Unknown. (resolve_esig_status, the pure function, still returns Granted — the gate lives
    // in TslClient, not in the status resolver.)
    let source = FileTslSource::new(fixture_dir().join("pt-tsl-sample.xml"));
    let mut client = TslClient::new(source);
    client.ensure_fresh(NOW).unwrap();
    let cert = issuer_cert(client.cached().unwrap().list(), "MULTICERT");

    assert_eq!(
        client.is_qualified_for_esig(&cert, NOW).unwrap(),
        QualifiedStatus::Unknown,
        "an unauthenticated list must not vouch for an issuer"
    );
    // The pure resolver still returns Granted — the cache carries the raw status for inspection.
    assert_eq!(
        resolve_esig_status(client.cached().unwrap().list(), &cert, NOW),
        QualifiedStatus::Granted
    );
    assert!(
        !client.cached().unwrap().signature_valid(),
        "fixture signature is not valid"
    );
}

#[test]
fn qtst_match_details_return_anchors_and_downgrade_when_unauthenticated() {
    let xml = br#"<TrustServiceStatusList>
      <SchemeInformation><SchemeTerritory>PT</SchemeTerritory></SchemeInformation>
      <TrustServiceProviderList>
        <TrustServiceProvider>
          <TSPInformation><TSPName><Name xml:lang="en">Unsigned TSA</Name></TSPName></TSPInformation>
          <TSPServices><TSPService><ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST</ServiceTypeIdentifier>
            <ServiceName><Name xml:lang="en">Unsigned TSA QTST</Name></ServiceName>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <ServiceDigitalIdentity><DigitalId><X509Certificate>dHNhLWNlcnQ=</X509Certificate></DigitalId></ServiceDigitalIdentity>
          </ServiceInformation></TSPService></TSPServices>
        </TrustServiceProvider>
      </TrustServiceProviderList>
    </TrustServiceStatusList>"#;
    let cert = b"tsa-cert".to_vec();
    let list = parse_tsl(xml).unwrap();
    let raw = resolve_qtst_match_details(&list, &cert, NOW);
    assert_eq!(raw.status, QualifiedStatus::Granted);
    assert_eq!(raw.trust_anchor_ders, vec![cert.clone()]);
    assert_eq!(raw.matches.len(), 1);
    assert!(raw.matches[0].granted_and_effective);

    let source = BytesTslSource::new(xml.to_vec());
    let mut client = TslClient::new(source);
    let details = client.qtst_match_details(&cert, NOW).unwrap();
    assert_eq!(details.status, QualifiedStatus::Unknown);
    assert!(details.trust_anchor_ders.is_empty());
    assert!(!details.authenticated);
    assert_eq!(details.matches.len(), 1);
}

#[test]
fn client_downgrades_granted_to_unknown_when_signature_is_missing() {
    let xml = fixture_without_signature();
    let list = parse_tsl(&xml).unwrap();
    let cert = issuer_cert(&list, "MULTICERT");
    assert_eq!(
        resolve_esig_status(&list, &cert, NOW),
        QualifiedStatus::Granted
    );

    let mut client = TslClient::new(BytesTslSource::new(xml));
    assert_eq!(
        client.is_qualified_for_esig(&cert, NOW).unwrap(),
        QualifiedStatus::Unknown,
        "an unsigned list must not vouch for an issuer"
    );
    assert!(!client.cached().unwrap().signature_valid());
}

#[test]
fn tsl_signature_validation_rejects_missing_signature_metadata() {
    let err = validate_tsl_signature(&fixture_without_signature()).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureStructure(_)),
        "got {err:?}"
    );
}

#[test]
fn tsl_signature_validation_rejects_unsupported_canonicalization_metadata() {
    let xml = br#"<TrustServiceStatusList>
      <SchemeInformation><SchemeTerritory>PT</SchemeTerritory></SchemeInformation>
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
          <ds:CanonicalizationMethod Algorithm="urn:unsupported-c14n"/>
          <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
          <ds:Reference URI="">
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
          </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>ZmFrZQ==</ds:SignatureValue>
      </ds:Signature>
    </TrustServiceStatusList>"#;
    let err = validate_tsl_signature(xml).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureUnsupportedAlgorithm(ref alg) if alg.contains("canonicalization")),
        "got {err:?}"
    );
}

#[test]
fn tsl_signature_validation_rejects_digest_mismatch_metadata() {
    let xml = br#"<TrustServiceStatusList>
      <SchemeInformation><SchemeTerritory>PT</SchemeTerritory></SchemeInformation>
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
          <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
          <ds:Reference URI="">
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
          </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>ZmFrZQ==</ds:SignatureValue>
      </ds:Signature>
    </TrustServiceStatusList>"#;
    let err = validate_tsl_signature(xml).unwrap_err();
    assert!(
        matches!(err, TslError::SignatureDigestMismatch),
        "got {err:?}"
    );
}

#[test]
fn tsl_signature_validation_rejects_incomplete_fixture_signature() {
    // The bundled fixture carries a placeholder <ds:Signature> with only a CanonicalizationMethod,
    // SignatureMethod, and a fake SignatureValue — no <ds:Reference>, no <ds:KeyInfo>. The
    // validator MUST detect this and reject it rather than silently accepting the list.
    let xml = std::fs::read(fixture_dir().join("pt-tsl-sample.xml")).unwrap();
    let err = validate_tsl_signature(&xml).unwrap_err();
    // The exact variant depends on which structural check trips first (missing Reference, missing
    // KeyInfo, etc.), but it MUST be a signature-structure/digest/verification error, never the
    // old `SignatureValidationNotImplemented`.
    assert!(
        matches!(
            err,
            TslError::SignatureStructure(_)
                | TslError::SignatureDigestMismatch
                | TslError::SignatureVerificationFailed
                | TslError::SignatureUnsupportedAlgorithm(_)
        ),
        "got {err:?}"
    );
}
