//! Mock end-to-end SCAP flow over the public API: list providers → fetch attributes → build
//! signature evidence (attach) → verify evidence. Plus the two binding invariants: the mock can
//! **never** yield a `verified_by_scap` status, and a PROD config without credentials fails closed.
//!
//! All fixture data is fictional.

use chancela_scap::transport::mock::{FIXTURE_CITIZEN_ID, FIXTURE_CITIZEN_NAME};
use chancela_scap::{
    AmaScapConfig, CitizenRef, MockScapTransport, ScapClient, ScapCredentials, ScapEnvironment,
    ScapVerificationStatus,
};

fn mock_client() -> ScapClient<MockScapTransport> {
    ScapClient::new(AmaScapConfig::preprod(), MockScapTransport::default())
        .expect("preprod mock client")
}

#[test]
fn mock_end_to_end_list_fetch_attach_verify() {
    let client = mock_client();

    // 1. list providers
    let providers = client.list_providers().expect("list providers");
    assert_eq!(providers.len(), 2);

    // 2. fetch the fictional signer's attributes
    let citizen = CitizenRef::new(FIXTURE_CITIZEN_ID).with_full_name(FIXTURE_CITIZEN_NAME);
    let attributes = client.fetch_attributes(&citizen).expect("fetch attributes");
    assert_eq!(attributes.len(), 2);

    // 3. attach: build signature evidence for the first attribute
    let evidence = client
        .build_signature_evidence(attributes[0].clone(), &citizen)
        .expect("build evidence");

    // The mock is non-authoritative: the evidence is declared-only, with no verification metadata.
    assert_eq!(evidence.status, ScapVerificationStatus::DeclaredOnly);
    assert!(evidence.authority_reference.is_none());
    assert!(evidence.verified_at.is_none());

    // 4. verify the evidence: markers reflect declared-only, and the record is internally consistent
    let report = client.verify_evidence(&evidence).expect("verify evidence");
    assert!(!report.verified);
    assert_eq!(
        report.verification_status_marker,
        "declared_capacity_by_provider"
    );
    assert_eq!(
        report.status_scope_marker,
        "declared_capacity_evidence_only"
    );
}

#[test]
fn mock_never_yields_verified_by_scap() {
    let client = mock_client();
    let citizen = CitizenRef::new(FIXTURE_CITIZEN_ID);
    let attributes = client.fetch_attributes(&citizen).unwrap();

    // Every attribute the mock reports must produce declared-only evidence — never verified.
    for attribute in attributes {
        let evidence = client
            .build_signature_evidence(attribute, &citizen)
            .unwrap();
        assert_ne!(
            evidence.status,
            ScapVerificationStatus::VerifiedByScap,
            "mock must never yield verified_by_scap"
        );
        assert!(!evidence.is_verified());
        assert_ne!(
            evidence.status.verification_status_marker(),
            "verified_by_scap"
        );
    }
    // (The stronger guarantee is at compile time: `MockScapTransport` cannot construct the
    // `AuthoritativeGrant` witness that `VerificationDecision::Granted` — and hence a verified
    // status — requires. See `chancela_scap::transport` module docs.)
}

#[test]
fn prod_without_credentials_fails_closed() {
    let cfg = AmaScapConfig {
        environment: ScapEnvironment::Prod,
        base_url: chancela_scap::config::PROD_BASE_URL.to_owned(),
        credentials: None,
        provider_filter: None,
    };
    // Both the config validation and the client constructor must reject it.
    assert!(cfg.validate().is_err());
    let result = ScapClient::new(cfg, MockScapTransport::default());
    assert!(matches!(result, Err(chancela_scap::ScapError::Config(_))));
}

#[test]
fn prod_with_credentials_builds() {
    let cfg = AmaScapConfig::prod(ScapCredentials::new("app-fictional", "secret-fictional"));
    let client = ScapClient::new(cfg, MockScapTransport::default()).expect("prod client builds");
    assert_eq!(client.config().environment, ScapEnvironment::Prod);
}
