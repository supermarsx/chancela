//! The Trusted-List **read** paths resolve their trust anchors from settings ∪ environment (t61-e2).
//!
//! Before this, every read endpoint resolved the operator's *algorithm policy* from settings but
//! took its *anchors* from the environment alone, while the refresh/LOTL path and the signing-time
//! `build_trust_policy` unioned settings with the environment. An operator who provisioned an
//! anchor through the admin UI alone therefore saw the product contradict itself: the same list was
//! reported signed by the import that installed it and unsigned by every screen that displayed it,
//! with `trusted_esignature_services` counted zero.
//!
//! These tests drive the whole stack — router, session, settings document, cached `tsl.xml` — over a
//! Trusted List signed **in-process** by an ephemeral P-256 key, so the anchor pinned in settings is
//! the only thing that can make it authenticate. Nothing here reads a real certificate, fingerprint
//! or endpoint; the fixture is synthesized on every run.
//!
//! What is deliberately NOT tested here: the environment arm of the union. Setting
//! `CHANCELA_TSL_TRUST_ANCHOR[_SHA256]` is a process-global mutation and this suite runs its tests
//! concurrently. The env arm is pinned by the unit tests in `src/trust.rs`, which serialize on a
//! dedicated lock. Nothing below sets or clears an environment variable — the settings-only claim
//! holds because the synthesized signer can match no anchor a developer machine happens to carry.

use crate::common;

use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration as StdDuration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, RoleId, Scope};
use der::Encode;
use der::asn1::{BitString, ObjectIdentifier};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

const STATUS: &str = "/v1/trust/status";
const CATALOG: &str = "/v1/trust/catalog";
const TSA: &str = "/v1/trust/tsa";

const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
const EXC_C14N_10: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const SHA256_DIGEST: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

// --- Synthesized signed Trusted List ------------------------------------------------------------

/// A Trusted List signed in-process, plus the certificate an operator would pin to trust it.
struct SignedList {
    xml: Vec<u8>,
    /// SHA-256 of the signer certificate's DER, lower-case hex — the exact shape
    /// `signing.tsl_trust_anchor_sha256` takes.
    anchor_sha256: String,
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn base64_standard(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The bundled sample list with its (deliberately unverifiable) placeholder signature removed.
///
/// CRLF is normalised away first: this does byte-exact string surgery against `\n`-terminated
/// patterns, and a checkout that materialised the fixture with CRLF would otherwise miss them.
fn sample_without_signature() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../chancela-tsl/fixtures/pt-tsl-sample.xml");
    let raw = std::fs::read(path).expect("read bundled Trusted List fixture");
    let raw: Vec<u8> = if raw.contains(&b'\r') {
        raw.into_iter().filter(|&b| b != b'\r').collect()
    } else {
        raw
    };
    let mut xml = String::from_utf8(raw).expect("fixture is UTF-8");
    let start = xml.find("  <ds:Signature").expect("signature start");
    let end_tag = "  </ds:Signature>\n";
    let end = xml[start..].find(end_tag).expect("signature end") + start + end_tag.len();
    xml.replace_range(start..end, "");
    xml
}

/// Sign the sample list with a fresh P-256 key and embed the signer certificate, so the list
/// authenticates against — and only against — an anchor pinning that certificate.
fn signed_list() -> SignedList {
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use rsa::rand_core::OsRng;

    let unsigned = sample_without_signature();
    let key = SigningKey::random(&mut OsRng);
    let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).expect("p256 spki");
    let cert_der = self_signed_cert("Trusted List read-path test signer", spki);

    let digest = Sha256::digest(unsigned.as_bytes());
    let signed_info = format!(
        r#"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{EXC_C14N_10}"/><ds:SignatureMethod Algorithm="{ECDSA_SHA256}"/><ds:Reference URI=""><ds:DigestMethod Algorithm="{SHA256_DIGEST}"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>"#,
        base64_standard(&digest)
    );
    let signature: p256::ecdsa::Signature = key.sign(signed_info.as_bytes());
    let signature_element = format!(
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>{}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
        base64_standard(&signature.to_bytes()),
        base64_standard(&cert_der)
    );
    let insert_at = unsigned
        .find("</TrustServiceStatusList>")
        .expect("fixture root close");
    let xml = format!(
        "{}{}{}",
        &unsigned[..insert_at],
        signature_element,
        &unsigned[insert_at..]
    );
    SignedList {
        xml: xml.into_bytes(),
        anchor_sha256: hex_lower(&Sha256::digest(&cert_der)),
    }
}

/// A self-signed certificate carrying `spki`. The signature bytes are filler: anchoring matches on
/// the SHA-256 of the DER, and the XML-DSig verifier takes the public key from here — neither reads
/// this certificate's own signature.
fn self_signed_cert(cn: &str, spki: SubjectPublicKeyInfoOwned) -> Vec<u8> {
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::Validity;
    use x509_cert::{Certificate, TbsCertificate, Version};

    let sig_alg = AlgorithmIdentifierOwned {
        oid: OID_ECDSA_WITH_SHA256,
        parameters: None,
    };
    let name = Name::from_str(&format!("CN={cn}")).expect("name");
    let cert = Certificate {
        tbs_certificate: TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[1]).expect("serial"),
            signature: sig_alg.clone(),
            issuer: name.clone(),
            validity: Validity::from_now(StdDuration::from_secs(365 * 24 * 3600))
                .expect("validity"),
            subject: name,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        },
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&[0u8; 64]).expect("signature bits"),
    };
    cert.to_der().expect("certificate DER")
}

// --- Harness ------------------------------------------------------------------------------------

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir =
            std::env::temp_dir().join(format!("chancela-api-trust-anchors-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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

fn get(uri: &str, token: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("request builds");
    req.headers_mut()
        .insert("x-chancela-session", token.parse().expect("session header"));
    req
}

fn post(uri: &str, token: &str, body: Value) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request builds");
    req.headers_mut()
        .insert("x-chancela-session", token.parse().expect("session header"));
    req
}

async fn seed_owner_session(state: &AppState) -> String {
    {
        let mut roles = state.roles.write().await;
        *roles = RoleCatalog::seeded_defaults();
    }
    let uid = UserId(Uuid::new_v4());
    state.users.write().await.insert(
        uid,
        User {
            passkeys: Vec::new(),
            id: uid,
            username: "amelia.marques".to_owned(),
            display_name: "Amélia Marques".to_owned(),
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
            role_assignments: vec![RoleAssignment::new(RoleId(OWNER_ROLE_ID.0), Scope::Global)],
            language: Default::default(),
        },
    );
    let (status, body) = send(
        state.clone(),
        Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "user_id": uid.0, "password": TEST_PASSWORD }).to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "session opens: {body}");
    body["token"].as_str().expect("token").to_owned()
}

/// An install whose only trust configuration is what `anchor_sha256` says: the signed list is
/// already cached, and the settings document carries the pinned anchors (possibly none).
async fn install_with(dir: &TempDir, list: &SignedList, anchor_sha256: &[&str]) -> AppState {
    std::fs::write(dir.0.join("tsl.xml"), &list.xml).expect("write cached Trusted List");
    let state = AppState::with_data_dir(dir.0.clone());
    {
        let mut settings = state.settings.write().await;
        settings.signing.tsl_trust_anchor_sha256 =
            anchor_sha256.iter().map(|s| (*s).to_owned()).collect();
    }
    state
}

/// Every read path's verdict for one install, keyed by the endpoint an operator would be looking at.
struct ReadPathVerdicts {
    status: String,
    catalog: String,
    tsa: String,
    provider: String,
    service: String,
    /// `summary.trusted_esignature_services` from `/v1/trust/status` — zero whenever the list is
    /// not authenticated, which is the count an operator sees contradicted.
    trusted_esignature_services: u64,
    qualified_esignature_services: u64,
}

impl ReadPathVerdicts {
    fn all(&self) -> [&str; 5] {
        [
            &self.status,
            &self.catalog,
            &self.tsa,
            &self.provider,
            &self.service,
        ]
    }
}

async fn read_path_verdicts(state: &AppState, token: &str) -> ReadPathVerdicts {
    let (status_code, status_body) = send(state.clone(), get(STATUS, token)).await;
    assert_eq!(status_code, StatusCode::OK, "{status_body}");

    let (catalog_code, catalog_body) = send(state.clone(), get(CATALOG, token)).await;
    assert_eq!(catalog_code, StatusCode::OK, "{catalog_body}");

    let (tsa_code, tsa_body) = send(state.clone(), get(TSA, token)).await;
    assert_eq!(tsa_code, StatusCode::OK, "{tsa_body}");

    let provider = catalog_body["providers"]
        .as_array()
        .and_then(|providers| providers.first())
        .expect("the fixture list carries at least one provider");
    let provider_id = provider["id"].as_str().expect("provider id");
    let service_id = provider["services"]
        .as_array()
        .and_then(|services| services.first())
        .and_then(|service| service["id"].as_str())
        .expect("the fixture provider carries at least one service");

    let (provider_code, provider_body) = send(
        state.clone(),
        get(&format!("/v1/trust/providers/{provider_id}"), token),
    )
    .await;
    assert_eq!(provider_code, StatusCode::OK, "{provider_body}");

    let (service_code, service_body) = send(
        state.clone(),
        get(&format!("/v1/trust/services/{service_id}"), token),
    )
    .await;
    assert_eq!(service_code, StatusCode::OK, "{service_body}");

    let signature = |body: &Value, pointer: &str| -> String {
        body.pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing {pointer} in {body}"))
            .to_owned()
    };
    ReadPathVerdicts {
        status: signature(&status_body, "/validation/signature"),
        catalog: signature(&catalog_body, "/summary/validation/signature"),
        tsa: signature(&tsa_body, "/summary/tsl/signature"),
        provider: signature(&provider_body, "/summary/validation/signature"),
        service: signature(&service_body, "/summary/validation/signature"),
        trusted_esignature_services: status_body["trusted_esignature_services"]
            .as_u64()
            .expect("trusted count"),
        qualified_esignature_services: status_body["qualified_esignature_services"]
            .as_u64()
            .expect("qualified count"),
    }
}

// --- Tests --------------------------------------------------------------------------------------

/// The regression this fixes. An anchor configured **only** in the settings document — never in the
/// environment — must make every read path report the list it authenticates as validly signed.
/// Against the pre-fix code all five answered `Invalid`, because they resolved anchors from the
/// environment alone.
#[tokio::test]
async fn an_anchor_configured_only_in_settings_is_honoured_by_every_read_path() {
    let dir = TempDir::new();
    let list = signed_list();
    let state = install_with(&dir, &list, &[&list.anchor_sha256]).await;
    let token = seed_owner_session(&state).await;

    let verdicts = read_path_verdicts(&state, &token).await;

    for (endpoint, verdict) in [STATUS, CATALOG, TSA, "providers/{id}", "services/{id}"]
        .into_iter()
        .zip(verdicts.all())
    {
        assert_eq!(
            verdict, "Valid",
            "{endpoint} must honour an anchor provisioned in settings alone"
        );
    }
    assert!(
        verdicts.qualified_esignature_services > 0,
        "the fixture must carry qualified e-signature services for this claim to mean anything"
    );
    assert_eq!(
        verdicts.trusted_esignature_services, verdicts.qualified_esignature_services,
        "an authenticated list makes its qualified services trusted; a zero here is the count the \
         operator saw contradicted"
    );
}

/// Fail-closed, which the union must never weaken: no anchor in settings and none in the
/// environment authenticates nothing, on every read path, for a list that is otherwise perfectly
/// signed. The only difference from the test above is the absence of the anchor.
#[tokio::test]
async fn no_anchor_anywhere_leaves_every_read_path_fail_closed() {
    let dir = TempDir::new();
    let list = signed_list();
    let state = install_with(&dir, &list, &[]).await;
    let token = seed_owner_session(&state).await;

    let verdicts = read_path_verdicts(&state, &token).await;

    for (endpoint, verdict) in [STATUS, CATALOG, TSA, "providers/{id}", "services/{id}"]
        .into_iter()
        .zip(verdicts.all())
    {
        assert_eq!(
            verdict, "Invalid",
            "{endpoint} must trust no list when no anchor is configured anywhere"
        );
    }
    assert_eq!(
        verdicts.trusted_esignature_services, 0,
        "an unanchored list vouches for no service, however many it lists"
    );
}

/// An anchor that cannot be parsed is a misconfiguration, and a misconfigured anchor trusts
/// nothing — it must not be silently dropped (which would leave the *other* anchors deciding) nor
/// take the whole catalog down (which would hide the reason from the operator who must fix it).
#[tokio::test]
async fn an_unparseable_settings_anchor_fails_the_verdict_closed_and_says_why() {
    let dir = TempDir::new();
    let list = signed_list();
    let state = install_with(&dir, &list, &[&list.anchor_sha256, "not-a-fingerprint"]).await;
    let token = seed_owner_session(&state).await;

    let (code, body) = send(state.clone(), get(STATUS, &token)).await;
    assert_eq!(
        code,
        StatusCode::OK,
        "the catalog must stay readable so the error is visible: {body}"
    );
    assert_eq!(
        body["validation"]["signature"], "Invalid",
        "a valid anchor alongside an invalid one must not rescue the verdict: {body}"
    );
    assert!(
        body["validation"]["error"]
            .as_str()
            .is_some_and(|error| error.contains("anchor")),
        "the reported error must name the anchor configuration: {body}"
    );
}

/// The coherence property whose absence was the user-visible bug: the verdict the import path
/// records and the verdict the read paths display are the same verdict, for the same list and the
/// same settings. Run twice — once with the settings anchor, once without — so agreement is shown
/// in both directions rather than at a single point.
#[tokio::test]
async fn the_refresh_verdict_and_the_read_path_verdicts_agree() {
    for anchored in [true, false] {
        let dir = TempDir::new();
        let list = signed_list();
        let source = dir.0.join("import-source.xml");
        std::fs::write(&source, &list.xml).expect("write import source");

        let anchors: Vec<&str> = if anchored {
            vec![list.anchor_sha256.as_str()]
        } else {
            Vec::new()
        };
        let state = install_with(&dir, &list, &anchors).await;
        let token = seed_owner_session(&state).await;

        let (code, refresh) = send(
            state.clone(),
            post(
                "/v1/trust/refresh",
                &token,
                json!({ "path": source.display().to_string() }),
            ),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "refresh reports a status: {refresh}");

        let refresh_signature = refresh
            .pointer("/validation/signature")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("refresh status carries a validation verdict: {refresh}"))
            .to_owned();
        let expected = if anchored { "Valid" } else { "Invalid" };
        assert_eq!(
            refresh_signature, expected,
            "the import path must honour the settings anchor (anchored = {anchored}): {refresh}"
        );

        let verdicts = read_path_verdicts(&state, &token).await;
        for verdict in verdicts.all() {
            assert_eq!(
                verdict, refresh_signature,
                "a read path disagreed with the import that installed the list (anchored = \
                 {anchored}); this incoherence is the bug"
            );
        }
    }
}
