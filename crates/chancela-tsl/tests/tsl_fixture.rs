//! Fixture-based, fully offline tests for `chancela-tsl` (no network).
//!
//! Drives the public API against the bundled sample Portuguese Trusted List
//! (`fixtures/pt-tsl-sample.xml`) and an unlisted CA certificate (`fixtures/unlisted-ca.der`).
//! See `crates/chancela-tsl/TESTING.md`.

use std::path::PathBuf;

use chancela_tsl::{
    DigitalIdentity, FileTslSource, QualifiedStatus, ServiceStatus, TrustedList, TslClient,
    TslError, parse_tsl, qualified_esig_services, resolve_esig_status, validate_tsl_signature,
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
    assert_eq!(list.scheme_territory, "PT");
    assert_eq!(list.sequence_number, Some(52));
    assert_eq!(list.issue_date_time, Some(datetime!(2026-01-15 0:00 UTC)));
    assert_eq!(list.next_update, Some(datetime!(2026-07-15 0:00 UTC)));
    assert_eq!(list.providers.len(), 4);
}

#[test]
fn prefers_english_provider_name() {
    let list = load_list();
    // The MULTICERT TSP has both a pt and an en <Name>; the English one must win.
    assert!(
        list.providers
            .iter()
            .any(|p| p.name == "MULTICERT - Electronic Certification Services SA"),
        "providers: {:?}",
        list.providers.iter().map(|p| &p.name).collect::<Vec<_>>()
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
    // keep only the *current* granted status and the current SKI.
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
fn client_resolves_qualified_status_end_to_end() {
    let source = FileTslSource::new(fixture_dir().join("pt-tsl-sample.xml"));
    let mut client = TslClient::new(source);
    // Prime the cache to read the certificate straight from the parsed list.
    client.ensure_fresh(NOW).unwrap();
    let cert = issuer_cert(client.cached().unwrap().list(), "MULTICERT");

    assert_eq!(
        client.is_qualified_for_esig(&cert, NOW).unwrap(),
        QualifiedStatus::Granted
    );
}

#[test]
fn tsl_signature_validation_is_a_phase_2_stub() {
    let xml = std::fs::read(fixture_dir().join("pt-tsl-sample.xml")).unwrap();
    assert!(matches!(
        validate_tsl_signature(&xml),
        Err(TslError::SignatureValidationNotImplemented)
    ));
}
