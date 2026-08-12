//! The t50 `signing.configure` slice-guard on `PUT /v1/settings`.
//!
//! Relocating the signature-policy surface behind a dedicated verb only becomes a real *server* gate
//! if changing the signing slice of the settings document requires `signing.configure`, not merely
//! the document-wide `settings.manage`. These tests pin exactly that boundary:
//!
//! - a role holding `settings.manage` but NOT `signing.configure` (a future custom role — the
//!   grandfather migration grants the verb to every EXISTING `settings.manage` holder, so this shape
//!   only arises when an operator deliberately builds it) may still save an unrelated document, but
//!   is refused (403) the moment the signing slice changes;
//! - a holder of both (Owner) may change the signing slice.

use crate::common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, Permission, Role, RoleAssignment, RoleCatalog, RoleId, Scope};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let dir =
            std::env::temp_dir().join(format!("chancela-api-signing-gate-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self { dir }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn send(state: AppState, req: Request<Body>) -> (StatusCode, Value) {
    let response = router(state).oneshot(req).await.expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body collects");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("body is JSON")
    };
    (status, value)
}

fn with_session(mut req: Request<Body>, token: &str) -> Request<Body> {
    req.headers_mut()
        .insert("x-chancela-session", token.parse().expect("session header"));
    req
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("request builds")
}

fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

/// Seed a user assigned `role_id` and open a session, returning the session token.
async fn seed_session(state: &AppState, username: &str, role_id: RoleId) -> String {
    let uid = UserId(Uuid::new_v4());
    state.users.write().await.insert(
        uid,
        User {
            passkeys: Vec::new(),
            id: uid,
            username: username.to_owned(),
            display_name: username.to_owned(),
            email: None,
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: Some(password_hash()),
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(role_id, Scope::Global)],
            language: Default::default(),
        },
    );
    let (status, body) = send(
        state.clone(),
        json_request(
            "POST",
            "/v1/session",
            json!({ "user_id": uid.0, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "session opens: {body}");
    body["token"].as_str().expect("token").to_owned()
}

#[tokio::test]
async fn put_settings_gates_the_signing_slice_on_signing_configure() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());

    // A custom role holding settings.manage + settings.read but deliberately NOT signing.configure
    // (a future operator-authored role: grandfathering would have granted the verb to every existing
    // settings.manage holder, so only a deliberate build produces this shape).
    let settings_only_id = RoleId(Uuid::new_v4());
    let permission_set: BTreeSet<Permission> =
        [Permission::SettingsRead, Permission::SettingsManage]
            .into_iter()
            .collect();
    {
        let mut roles = state.roles.write().await;
        *roles = RoleCatalog::seeded_defaults();
        roles.insert(Role {
            id: settings_only_id,
            name: "Settings Only".to_owned(),
            permission_set,
            protected: false,
        });
    }

    let settings_only = seed_session(&state, "amelia.settings", settings_only_id).await;
    let owner = seed_session(&state, "amelia.owner", OWNER_ROLE_ID).await;

    // The current document, read back as the settings.manage holder.
    let (status, doc) = send(
        state.clone(),
        with_session(get("/v1/settings"), &settings_only),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");

    // Re-PUT the document UNCHANGED: the signing slice did not change, so settings.manage alone is
    // enough — the server-owned `providers` metadata must not spuriously trip the gate.
    let (status, body) = send(
        state.clone(),
        with_session(
            json_request("PUT", "/v1/settings", doc.clone()),
            &settings_only,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unchanged signing slice must not require signing.configure: {body}"
    );

    // Now flip a signing-policy field. The same settings.manage-only caller is refused.
    let mut changed = doc.clone();
    let prior = changed["signing"]["require_qualified_for_seal"]
        .as_bool()
        .unwrap_or(false);
    changed["signing"]["require_qualified_for_seal"] = json!(!prior);

    let (status, body) = send(
        state.clone(),
        with_session(
            json_request("PUT", "/v1/settings", changed.clone()),
            &settings_only,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "changing the signing slice without signing.configure must be refused: {body}"
    );

    // A holder of signing.configure (Owner, via Permission::ALL) may make the same change.
    let (status, body) = send(
        state.clone(),
        with_session(json_request("PUT", "/v1/settings", changed), &owner),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "owner may change signing policy: {body}"
    );
    assert_eq!(body["signing"]["require_qualified_for_seal"], json!(!prior));
}

/// A throwaway self-signed CA certificate, PEM-armoured — something that genuinely parses as X.509,
/// which is what `validate_tls_intermediates` demands and what distinguishes an acceptable entry
/// from the base64 blob the anchor fields would have taken.
///
/// Generated in-process from a fixed scalar rather than committed as a literal, so no certificate
/// blob lives in the repository at all and nobody can mistake the fixture for a real one.
fn synthetic_ca_pem() -> String {
    use base64::Engine;
    use der::Encode;
    use der::asn1::{Any, BitString, OctetString};
    use der::oid::ObjectIdentifier;
    use p256::ecdsa::signature::Signer;
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use std::str::FromStr;
    use x509_cert::certificate::{Certificate, TbsCertificate, Version};
    use x509_cert::ext::Extension;
    use x509_cert::ext::pkix::BasicConstraints;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::Validity;

    const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    const ID_CE_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

    let key = p256::ecdsa::SigningKey::from_slice(&[0x5au8; 32]).expect("valid scalar");
    let sig_alg = AlgorithmIdentifierOwned {
        oid: ECDSA_WITH_SHA256,
        parameters: None::<Any>,
    };
    let name = Name::from_str("CN=Chancela Test Intermediate").expect("name");
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[7]).expect("serial"),
        signature: sig_alg.clone(),
        issuer: name.clone(),
        validity: Validity::from_now(std::time::Duration::from_secs(365 * 24 * 3600))
            .expect("validity"),
        subject: name,
        subject_public_key_info: SubjectPublicKeyInfoOwned::from_key(*key.verifying_key())
            .expect("spki"),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![Extension {
            extn_id: ID_CE_BASIC_CONSTRAINTS,
            critical: true,
            extn_value: OctetString::new(
                BasicConstraints {
                    ca: true,
                    path_len_constraint: Some(0),
                }
                .to_der()
                .expect("basic constraints"),
            )
            .expect("extension value"),
        }]),
    };
    let tbs_der = tbs.to_der().expect("tbs der");
    let signature: p256::ecdsa::Signature = key.sign(&tbs_der);
    let der = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(signature.to_der().as_bytes()).expect("signature"),
    }
    .to_der()
    .expect("certificate der");
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
}

/// `signing.tls_intermediate_certs` over the wire: gated like every other signing field, refused at
/// save when it is not a real certificate, and — the part worth pinning at HTTP level — kept
/// entirely separate from the trust anchors it sits beside.
///
/// The last assertion is the one that would not survive a careless refactor. Both fields are
/// `Vec<String>` of PEM on the same struct, one card apart in the UI and one line apart in
/// `SigningSettings`. Writing a transport certificate into the anchor list would authenticate
/// nothing (it can never be a Trusted List's signer), so nothing would fail loudly — the deployment
/// would simply look anchored and refuse every signature.
#[tokio::test]
async fn tls_intermediates_are_signing_configuration_validated_and_not_anchors() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());

    let settings_only_id = RoleId(Uuid::new_v4());
    let permission_set: BTreeSet<Permission> =
        [Permission::SettingsRead, Permission::SettingsManage]
            .into_iter()
            .collect();
    {
        let mut roles = state.roles.write().await;
        *roles = RoleCatalog::seeded_defaults();
        roles.insert(Role {
            id: settings_only_id,
            name: "Settings Only".to_owned(),
            permission_set,
            protected: false,
        });
    }
    let settings_only = seed_session(&state, "amelia.settings", settings_only_id).await;
    let owner = seed_session(&state, "amelia.owner", OWNER_ROLE_ID).await;

    let (status, doc) = send(state.clone(), with_session(get("/v1/settings"), &owner)).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    // Absent from the wire while empty, which is the shipped state: a server that sends its full
    // certificate chain needs nothing here.
    assert!(
        doc["signing"].get("tls_intermediate_certs").is_none(),
        "an unconfigured install must not serialize the field at all: {doc}"
    );

    // A syntactically perfect PEM whose body is valid base64 and is not a certificate. The ANCHOR
    // fields accept exactly this — an anchor is only ever fingerprinted, so a non-certificate is
    // inert there. An intermediate is handed to path building, which would ignore it silently: the
    // operator would configure their fix, be told it saved, and see nothing change.
    let mut invalid = doc.clone();
    invalid["signing"]["tls_intermediate_certs"] =
        json!(["-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----"]);
    let (status, body) = send(
        state.clone(),
        with_session(json_request("PUT", "/v1/settings", invalid.clone()), &owner),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a non-certificate must be refused at save: {body}"
    );
    let message = body["error"].as_str().unwrap_or_default();
    assert!(
        message.contains("signing.tls_intermediate_certs[0]"),
        "the refusal must name the field and the index: {body}"
    );

    // Gated on signing.configure, not settings.manage — supplying a chain link is signing
    // configuration. `settings.rs`'s `signing_policy_changed` compares the whole slice, so this is
    // structural rather than a field list; asserting it here proves the structure covers this field
    // over the wire, not only in the unit test next to it.
    let mut supplied = doc.clone();
    // Synthetic and self-signed, generated here: this test asserts on plumbing, not on a chain
    // (`outbound_tls`'s handshake tests do the chain). No real certificate — least of all the real
    // intermediate this feature exists for — is ever committed to this repository.
    let intermediate = synthetic_ca_pem();
    supplied["signing"]["tls_intermediate_certs"] = json!([intermediate]);
    let (status, body) = send(
        state.clone(),
        with_session(
            json_request("PUT", "/v1/settings", supplied.clone()),
            &settings_only,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "supplying a TLS intermediate is signing configuration: {body}"
    );

    let (status, body) = send(
        state.clone(),
        with_session(json_request("PUT", "/v1/settings", supplied), &owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner may supply one: {body}");
    assert_eq!(
        body["signing"]["tls_intermediate_certs"],
        json!([intermediate]),
        "stored verbatim, never re-encoded"
    );
    // Transport trust is not list trust. Supplying a chain link must leave the deployment exactly as
    // unanchored as it was.
    assert!(
        body["signing"].get("tsl_trust_anchor_certs").is_none(),
        "a TLS intermediate must never land in the anchor list: {body}"
    );
    assert!(
        body["signing"].get("tsl_trust_anchor_sha256").is_none(),
        "a TLS intermediate must never land in the anchor fingerprints: {body}"
    );
}
