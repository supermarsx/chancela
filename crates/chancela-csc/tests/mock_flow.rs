//! Offline round-trip tests for the CSC v2 flow using [`MockCscTransport`] at the **client** level.
//!
//! These run with no network. Real QTSP sandbox/prod calls live behind the `network-tests`
//! feature + `#[ignore]` (see `tests/network.rs`).

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use chancela_csc::mock::{
    ERROR_INVALID_OTP, MockCscTransport, OAUTH_TOKEN_OK, credentials_info_response,
    sign_hash_response,
};
use chancela_csc::rest::{
    OID_RSA_ENCRYPTION, PATH_CREDENTIALS_AUTHORIZE, PATH_CREDENTIALS_INFO, PATH_CREDENTIALS_LIST,
    PATH_OAUTH2_TOKEN, PATH_SIGNATURES_SIGN_HASH,
};
use chancela_csc::{CscClient, CscError, SignatureAlgorithm};

use common::{CREDENTIAL_ID, OTP, RsaSigner};

/// Build a happy-path client over a mock wired with a real ephemeral cert + signature.
fn happy_client(signer: &RsaSigner, issuer: &RsaSigner) -> (CscClient<MockCscTransport>, Vec<u8>) {
    let info = credentials_info_response(
        &[signer.cert_der_b64(), issuer.cert_der_b64()],
        &[OID_RSA_ENCRYPTION],
    );
    // The signHash signature must cover the exact hash the client will send; in these client-level
    // tests we sign an arbitrary 32-byte digest and assert the client returns exactly it.
    let digest = [0x5Au8; 32];
    let sig = signer.sign_digest(&digest);
    let transport = MockCscTransport::happy_path(info, sign_hash_response(&STANDARD.encode(&sig)));
    let client = CscClient::new(transport, common::test_config(), common::test_secrets());
    (client, digest.to_vec())
}

#[test]
fn full_token_list_info_otp_authorize_sign_round_trip() {
    let signer = RsaSigner::new("Amélia Marques (QTSP teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let (client, digest) = happy_client(&signer, &issuer);
    let digest: [u8; 32] = digest.try_into().unwrap();

    // 1. oauth2/token → bearer token.
    let token = client.authenticate().unwrap();
    assert_eq!(token.as_str(), "csc-preprod-access-token-0001");

    // 2. credentials/list → the sole credential id.
    let creds = client.list_credentials(&token).unwrap();
    assert_eq!(creds, vec![CREDENTIAL_ID.to_string()]);
    assert_eq!(client.resolve_credential_id(&token).unwrap(), CREDENTIAL_ID);

    // 3. credentials/info → real cert chain (leaf + one issuer), RSA algorithm, OTP required.
    let cert = client.credential_info(&token, CREDENTIAL_ID).unwrap();
    assert_eq!(cert.leaf_der, signer.cert_der());
    assert_eq!(cert.chain_der, vec![issuer.cert_der()]);
    assert!(matches!(cert.algorithm, SignatureAlgorithm::RsaPkcs1Sha256));
    assert!(cert.otp_required);
    assert!(!cert.pin_required);

    // 4. credentials/sendOTP → dispatch (no error).
    client.send_otp(&token, CREDENTIAL_ID).unwrap();

    // 5. credentials/authorize (with OTP) → SAD.
    let sad = client
        .authorize(&token, CREDENTIAL_ID, &digest, Some(OTP), None)
        .unwrap();
    assert!(sad.as_str().contains("SAD-encosto-preprod"));

    // 6. signatures/signHash → RawSignature carrying the leaf + chain.
    let raw = client
        .sign_hash(&token, CREDENTIAL_ID, &sad, &digest, &cert)
        .unwrap();
    assert!(matches!(raw.algorithm, SignatureAlgorithm::RsaPkcs1Sha256));
    assert_eq!(raw.signature.len(), 256, "RSA-2048 signature is 256 bytes");
    assert_eq!(raw.signing_cert_der, signer.cert_der());
    assert_eq!(raw.chain_der, vec![issuer.cert_der()]);

    // Wire assertions: the token call uses Basic client auth; every other call uses Bearer; the
    // credential id + base64 hash + OTP are threaded onto the right calls.
    let t = client.transport();
    let calls = t.calls();
    assert_eq!(calls[0].path, PATH_OAUTH2_TOKEN);
    assert_eq!(calls[0].auth_kind, "basic", "token uses Basic client auth");
    assert!(calls.iter().skip(1).all(|c| c.auth_kind == "bearer"));

    let info_body = t.last_body_for(PATH_CREDENTIALS_INFO).unwrap();
    assert!(info_body.contains(CREDENTIAL_ID));
    let auth_body = t.last_body_for(PATH_CREDENTIALS_AUTHORIZE).unwrap();
    assert!(
        auth_body.contains(&STANDARD.encode(digest)),
        "hash wired to authorize"
    );
    assert!(auth_body.contains(OTP), "OTP wired to authorize");
    let sign_body = t.last_body_for(PATH_SIGNATURES_SIGN_HASH).unwrap();
    assert!(
        sign_body.contains("SAD-encosto-preprod"),
        "SAD wired to signHash"
    );
}

#[test]
fn no_client_secret_appears_in_any_request_body() {
    // The client secret is carried in the HTTP Basic Authorization header, NEVER the JSON body.
    let signer = RsaSigner::new("Amélia Marques (QTSP teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let (client, digest) = happy_client(&signer, &issuer);
    let digest: [u8; 32] = digest.try_into().unwrap();

    let token = client.authenticate().unwrap();
    let cert = client.credential_info(&token, CREDENTIAL_ID).unwrap();
    let sad = client
        .authorize(&token, CREDENTIAL_ID, &digest, Some(OTP), None)
        .unwrap();
    let _ = client.sign_hash(&token, CREDENTIAL_ID, &sad, &digest, &cert);

    for call in client.transport().calls() {
        assert!(
            !call.body.contains("csc-client-secret-test"),
            "client secret must never be in a request body (path {})",
            call.path
        );
    }
}

#[test]
fn invalid_otp_at_authorize_maps_to_service_error() {
    let signer = RsaSigner::new("Amélia Marques (QTSP teste)", 1);
    let issuer = RsaSigner::new("Encosto Estratégico Lda — EC Teste", 2);
    let info = credentials_info_response(
        &[signer.cert_der_b64(), issuer.cert_der_b64()],
        &[OID_RSA_ENCRYPTION],
    );
    let transport = MockCscTransport::happy_path(info, sign_hash_response("AA=="))
        .with_response(PATH_CREDENTIALS_AUTHORIZE, ERROR_INVALID_OTP);
    let client = CscClient::new(transport, common::test_config(), common::test_secrets());

    let token = client.authenticate().unwrap();
    let err = client
        .authorize(&token, CREDENTIAL_ID, &[0u8; 32], Some("000000"), None)
        .unwrap_err();
    match err {
        CscError::Service { error, .. } => assert_eq!(error, "invalid_otp"),
        other => panic!("expected Service error, got {other:?}"),
    }
}

#[test]
fn missing_response_is_transport_error() {
    let client = CscClient::new(
        MockCscTransport::empty(),
        common::test_config(),
        common::test_secrets(),
    );
    let err = client.authenticate().unwrap_err();
    assert!(matches!(err, CscError::Transport(_)));
}

#[test]
fn empty_credentials_list_errors_with_no_credential() {
    let transport = MockCscTransport::empty()
        .with_response(PATH_OAUTH2_TOKEN, OAUTH_TOKEN_OK)
        .with_response(PATH_CREDENTIALS_LIST, r#"{ "credentialIDs": [] }"#);
    let client = CscClient::new(transport, common::test_config(), common::test_secrets());
    let token = client.authenticate().unwrap();
    let err = client.resolve_credential_id(&token).unwrap_err();
    assert!(matches!(err, CscError::NoCredential { .. }));
}

#[test]
fn malformed_certificate_der_is_rejected() {
    let transport = MockCscTransport::empty()
        .with_response(PATH_OAUTH2_TOKEN, OAUTH_TOKEN_OK)
        .with_response(
            PATH_CREDENTIALS_INFO,
            credentials_info_response(&["bm90LWEtY2VydA==".to_string()], &[OID_RSA_ENCRYPTION]),
        );
    let client = CscClient::new(transport, common::test_config(), common::test_secrets());
    let token = client.authenticate().unwrap();
    let err = client.credential_info(&token, CREDENTIAL_ID).unwrap_err();
    assert!(matches!(err, CscError::Certificate(_)));
}

/// A user-authorization client returns its pre-obtained token without a token-endpoint call.
#[test]
fn user_authorization_uses_preobtained_token() {
    use chancela_csc::{CscAuthorization, CscSecrets};
    let mut config = common::test_config();
    config.authorization = CscAuthorization::User;
    let secrets = CscSecrets::with_access_token("user-bearer-token-xyz");
    let client = CscClient::new(MockCscTransport::empty(), config, secrets);
    let token = client.authenticate().unwrap();
    assert_eq!(token.as_str(), "user-bearer-token-xyz");
    // No call was made to the token endpoint.
    assert!(client.transport().calls().is_empty());
}
