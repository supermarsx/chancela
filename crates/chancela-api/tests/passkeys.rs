//! t10 passkeys over the wire: both ceremonies, the step-up scoping, and the ways each must fail.
//!
//! ## Why there is a software authenticator in here
//!
//! Every interesting property of this feature is a property of *bytes an authenticator produced*.
//! "The signature verifies", "the origin is checked", "a UV-less assertion is not a wrong
//! credential", "a sign-in challenge cannot satisfy a step-up" — none of them can be exercised by
//! calling the handlers with hand-built JSON, because the handlers correctly refuse anything that
//! is not a real, signed WebAuthn response. So [`Authenticator`] below is a real (if minimal) CTAP2
//! authenticator: it holds a P-256 key, builds `authenticatorData` and `clientDataJSON` to the
//! spec's byte layout, and signs.
//!
//! That it is *ours* is what makes the negative tests meaningful. A test that only drives the happy
//! path proves the library accepts what the library produced; these drive an independent
//! implementation, and then break it one field at a time.

#[path = "common/mod.rs"]
mod common;

use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, Scope};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

const RP_ID: &str = "example.pt";
const ORIGIN: &str = "https://livros.example.pt";
const BASE_URL: &str = "https://livros.example.pt";

// =================================================================================================
// A minimal CBOR writer — only the shapes an authenticator emits
// =================================================================================================

/// The five CBOR shapes a `none`-attestation authenticator needs. Deliberately not a crate: a
/// general CBOR encoder would be more code and would let a test express bytes no authenticator ever
/// sends, which is the opposite of what a test authenticator is for.
mod cbor {
    fn head(major: u8, value: u64, out: &mut Vec<u8>) {
        let major = major << 5;
        match value {
            0..=23 => out.push(major | value as u8),
            24..=0xff => {
                out.push(major | 24);
                out.push(value as u8);
            }
            0x100..=0xffff => {
                out.push(major | 25);
                out.extend_from_slice(&(value as u16).to_be_bytes());
            }
            _ => {
                out.push(major | 26);
                out.extend_from_slice(&(value as u32).to_be_bytes());
            }
        }
    }

    pub fn uint(value: u64, out: &mut Vec<u8>) {
        head(0, value, out);
    }

    /// A negative integer, given as its absolute value minus one — COSE labels are `-1`, `-2`, `-3`
    /// and `-7`, which encode as major type 1 with `n - 1`.
    pub fn nint(abs_minus_one: u64, out: &mut Vec<u8>) {
        head(1, abs_minus_one, out);
    }

    pub fn bytes(value: &[u8], out: &mut Vec<u8>) {
        head(2, value.len() as u64, out);
        out.extend_from_slice(value);
    }

    pub fn text(value: &str, out: &mut Vec<u8>) {
        head(3, value.len() as u64, out);
        out.extend_from_slice(value.as_bytes());
    }

    pub fn map(len: u64, out: &mut Vec<u8>) {
        head(5, len, out);
    }

    pub fn bool(value: bool, out: &mut Vec<u8>) {
        out.push(if value { 0xf5 } else { 0xf4 });
    }
}

// =================================================================================================
// The software authenticator
// =================================================================================================

/// Authenticator data flag bits, per WebAuthn L3 §6.1.
mod flag {
    pub const UP: u8 = 0x01;
    pub const UV: u8 = 0x04;
    pub const BE: u8 = 0x08;
    pub const BS: u8 = 0x10;
    pub const AT: u8 = 0x40;
    pub const ED: u8 = 0x80;
}

/// A single-credential CTAP2 authenticator with a P-256 key.
struct Authenticator {
    key: SigningKey,
    credential_id: Vec<u8>,
    aaguid: [u8; 16],
    sign_count: u32,
    /// Whether it provisions an `hmac-secret` — i.e. whether the credential it mints is one a PRF
    /// wrap could ever be derived for.
    hmac_secret: bool,
    /// Backup eligibility / state, as the BE and BS flag pair.
    backup_eligible: bool,
    backed_up: bool,
}

impl Authenticator {
    fn new() -> Self {
        Authenticator {
            key: SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng),
            // 32 bytes: comfortably inside the spec's 16–1023 range, and the length a real platform
            // authenticator tends to mint.
            credential_id: (0u8..32)
                .map(|i| i.wrapping_mul(7).wrapping_add(3))
                .collect(),
            aaguid: [0x11; 16],
            sign_count: 0,
            hmac_secret: false,
            backup_eligible: true,
            backed_up: true,
        }
    }

    /// A device-bound authenticator: no backup, and a counter that actually advances.
    fn device_bound() -> Self {
        Authenticator {
            backup_eligible: false,
            backed_up: false,
            sign_count: 41,
            credential_id: (0u8..32)
                .map(|i| i.wrapping_mul(11).wrapping_add(5))
                .collect(),
            ..Authenticator::new()
        }
    }

    fn with_hmac_secret(mut self) -> Self {
        self.hmac_secret = true;
        self
    }

    /// The COSE_Key encoding of the public half: `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`.
    fn cose_public_key(&self) -> Vec<u8> {
        let point = self.key.verifying_key().to_encoded_point(false);
        let x = point.x().expect("uncompressed point has x");
        let y = point.y().expect("uncompressed point has y");
        let mut out = Vec::new();
        cbor::map(5, &mut out);
        cbor::uint(1, &mut out); // kty
        cbor::uint(2, &mut out); // EC2
        cbor::uint(3, &mut out); // alg
        cbor::nint(6, &mut out); // -7 = ES256
        cbor::nint(0, &mut out); // -1 = crv
        cbor::uint(1, &mut out); // P-256
        cbor::nint(1, &mut out); // -2 = x
        cbor::bytes(x, &mut out);
        cbor::nint(2, &mut out); // -3 = y
        cbor::bytes(y, &mut out);
        out
    }

    fn flags(&self, user_verified: bool, attested: bool) -> u8 {
        let mut flags = flag::UP;
        if user_verified {
            flags |= flag::UV;
        }
        if self.backup_eligible {
            flags |= flag::BE;
        }
        if self.backed_up {
            flags |= flag::BS;
        }
        if attested {
            flags |= flag::AT;
        }
        // ED is set only at *registration*, and only for an authenticator that provisions the
        // secret — see [`Authenticator::extension_output`] for why an assertion carries none.
        if attested && self.hmac_secret {
            flags |= flag::ED;
        }
        flags
    }

    /// The `hmac-secret` extension output.
    ///
    /// **Present at registration and absent at assertion, and that asymmetry is the point.** The
    /// server asks for `prf` at *enrolment* (so the authenticator provisions the secret, which it
    /// can only ever be asked to do then) and asks for nothing at *sign-in*, because PRF evaluation
    /// is a later lane. An authenticator returns an extension output only for an extension the RP
    /// requested, so an assertion here carries none — and if it did, the server would refuse it as
    /// unsolicited, which is the correct fail-closed behaviour and is pinned by
    /// `an_unsolicited_extension_at_sign_in_is_refused`.
    fn extension_output(&self, registration: bool) -> Vec<u8> {
        if !self.hmac_secret || !registration {
            return Vec::new();
        }
        let mut out = Vec::new();
        cbor::map(1, &mut out);
        cbor::text("hmac-secret", &mut out);
        // At creation the authenticator reports only that it created the secret. CTAP 2.2 does not
        // evaluate PRF at creation time, which is why enrolment asks for the secret rather than
        // for a value.
        cbor::bool(true, &mut out);
        out
    }

    /// The same assertion, but carrying an `hmac-secret` output the RP never asked for. Only the
    /// unsolicited-extension test uses this.
    fn assert_with_unsolicited_extension(
        &self,
        challenge: &str,
        origin: &str,
        rp_id: &str,
        user_handle: &[u8],
    ) -> Value {
        let client_data = self.client_data_json("webauthn.get", challenge, origin);
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        auth_data.push(self.flags(true, false) | flag::ED);
        auth_data.extend_from_slice(&self.sign_count.to_be_bytes());
        let mut extensions = Vec::new();
        cbor::map(1, &mut extensions);
        cbor::text("hmac-secret", &mut extensions);
        cbor::bytes(&[0u8; 64], &mut extensions);
        auth_data.extend_from_slice(&extensions);
        self.sign_assertion(client_data, auth_data, user_handle)
    }

    fn authenticator_data(&self, rp_id: &str, user_verified: bool, attested: bool) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        data.push(self.flags(user_verified, attested));
        data.extend_from_slice(&self.sign_count.to_be_bytes());
        if attested {
            data.extend_from_slice(&self.aaguid);
            data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
            data.extend_from_slice(&self.credential_id);
            data.extend_from_slice(&self.cose_public_key());
        }
        data.extend_from_slice(&self.extension_output(attested));
        data
    }

    fn client_data_json(&self, ceremony: &str, challenge: &str, origin: &str) -> Vec<u8> {
        json!({
            "type": ceremony,
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false,
        })
        .to_string()
        .into_bytes()
    }

    /// A registration response, in the WebAuthn L3 JSON shape the browser produces.
    fn register(&self, options: &Value, origin: &str, user_verified: bool) -> Value {
        let challenge = options["challenge"].as_str().expect("challenge in options");
        let rp_id = options["rp"]["id"].as_str().expect("rp.id in options");
        let client_data = self.client_data_json("webauthn.create", challenge, origin);
        let auth_data = self.authenticator_data(rp_id, user_verified, true);

        // The `none` attestation statement: an empty map. Its whole verification procedure is that
        // `attStmt` is empty, which is why the ruling's "attestation: none" removes the hardest
        // part of the registration ceremony.
        let mut attestation = Vec::new();
        cbor::map(3, &mut attestation);
        cbor::text("fmt", &mut attestation);
        cbor::text("none", &mut attestation);
        cbor::text("attStmt", &mut attestation);
        cbor::map(0, &mut attestation);
        cbor::text("authData", &mut attestation);
        cbor::bytes(&auth_data, &mut attestation);

        let mut extension_results = json!({});
        if self.hmac_secret {
            extension_results["prf"] = json!({ "enabled": true });
        }
        json!({
            "id": B64URL.encode(&self.credential_id),
            "rawId": B64URL.encode(&self.credential_id),
            "type": "public-key",
            "authenticatorAttachment": if self.backup_eligible { "platform" } else { "cross-platform" },
            "clientExtensionResults": extension_results,
            "response": {
                "clientDataJSON": B64URL.encode(&client_data),
                "attestationObject": B64URL.encode(&attestation),
                "transports": if self.backup_eligible {
                    json!(["internal", "hybrid"])
                } else {
                    json!(["usb", "nfc"])
                },
            },
        })
    }

    /// An authentication assertion. `user_handle` is what a discoverable credential returns instead
    /// of a username.
    fn assert(
        &mut self,
        options: &Value,
        origin: &str,
        rp_id: &str,
        user_handle: &[u8],
        user_verified: bool,
    ) -> Value {
        let challenge = options["challenge"].as_str().expect("challenge in options");
        self.sign_count = self.sign_count.saturating_add(1);
        self.assert_at_counter(challenge, origin, rp_id, user_handle, user_verified)
    }

    /// The same assertion without advancing the counter — for the regression case.
    fn assert_at_counter(
        &self,
        challenge: &str,
        origin: &str,
        rp_id: &str,
        user_handle: &[u8],
        user_verified: bool,
    ) -> Value {
        let client_data = self.client_data_json("webauthn.get", challenge, origin);
        let auth_data = self.authenticator_data(rp_id, user_verified, false);
        self.sign_assertion(client_data, auth_data, user_handle)
    }

    /// Sign `auth_data` and assemble the `PublicKeyCredential` JSON a browser would produce.
    fn sign_assertion(
        &self,
        client_data: Vec<u8>,
        auth_data: Vec<u8>,
        user_handle: &[u8],
    ) -> Value {
        // §7.2 step 23: the signature is over `authData ‖ SHA-256(clientDataJSON)`.
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let signature: Signature = self
            .key
            .sign_prehash(&Sha256::digest(&signed))
            .expect("prehash sign");
        json!({
            "id": B64URL.encode(&self.credential_id),
            "rawId": B64URL.encode(&self.credential_id),
            "type": "public-key",
            "authenticatorAttachment": if self.backup_eligible { "platform" } else { "cross-platform" },
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": B64URL.encode(&client_data),
                "authenticatorData": B64URL.encode(&auth_data),
                "signature": B64URL.encode(signature.to_der().as_bytes()),
                "userHandle": B64URL.encode(user_handle),
            },
        })
    }
}

// =================================================================================================
// Harness
// =================================================================================================

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        common::ensure_credential_key();
        let dir = std::env::temp_dir().join(format!("chancela-passkeys-{}", Uuid::new_v4()));
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
        .expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

fn with_session(mut req: Request<Body>, token: &str) -> Request<Body> {
    req.headers_mut()
        .insert("x-chancela-session", token.parse().expect("header"));
    req
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("req")
}

fn post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("req")
}

fn patch(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("req")
}

fn delete(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("req")
}

/// A state with one Owner, a configured public base URL, and a configured RP ID.
async fn harness(dir: &TempDir) -> (AppState, UserId, String) {
    let state = AppState::with_data_dir(&dir.0);
    let uid = UserId(Uuid::new_v4());
    state.users.write().await.insert(
        uid,
        User {
            id: uid,
            username: "amelia.marques".to_owned(),
            display_name: "Amélia Marques".to_owned(),
            email: None,
            created_at: OffsetDateTime::now_utc().format(&Rfc3339).expect("stamp"),
            active: true,
            password_hash: Some(password_hash()),
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            secret_source: Default::default(),
            recovery_hash: Some(password_hash()),
            role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
            language: Default::default(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
            passkeys: Vec::new(),
        },
    );
    {
        let mut settings = state.settings.write().await;
        settings.platform.public_base_url = Some(BASE_URL.to_owned());
        settings.auth.passkeys.rp_id = Some(RP_ID.to_owned());
    }
    let (status, session) = send(
        state.clone(),
        post(
            "/v1/session",
            json!({ "username": "amelia.marques", "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sign in: {session}");
    let token = session["token"].as_str().expect("token").to_owned();
    (state, uid, token)
}

/// Run the enrolment ceremony end to end, returning the assertion-time `(rp_id, user_handle)`.
async fn enrol(
    state: &AppState,
    uid: UserId,
    token: &str,
    authenticator: &Authenticator,
    name: &str,
) -> Vec<u8> {
    let (status, options) = send(
        state.clone(),
        with_session(
            post(&format!("/v1/users/{}/passkeys/options", uid.0), json!({})),
            token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "begin enrolment: {options}");
    let public_key = &options["public_key"];
    let handle = B64URL
        .decode(public_key["user"]["id"].as_str().expect("user.id"))
        .expect("user handle base64url");
    let credential = authenticator.register(public_key, ORIGIN, true);
    let (status, view) = send(
        state.clone(),
        with_session(
            post(
                &format!("/v1/users/{}/passkeys", uid.0),
                json!({ "credential": credential, "name": name }),
            ),
            token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "finish enrolment: {view}");
    handle
}

// =================================================================================================
// RP ID validation — refused at configuration time, before a user ever sees it
// =================================================================================================

/// **The finding of the whole feature, pinned.**
///
/// `webauthn_rp` performs neither the registrable-suffix check nor a Public Suffix List check, so a
/// mis-set RP ID passes every server-side path and then fails inside the browser with a
/// `SecurityError` this process never sees. These assertions are the only thing between an operator
/// typing a wrong value and every one of their users failing to enrol.
#[tokio::test]
async fn a_mis_set_rp_id_is_refused_at_configuration_time() {
    let dir = TempDir::new();
    let (state, _uid, token) = harness(&dir).await;

    // A value that is neither the host nor a parent of it.
    for (rp_id, why) in [
        ("example.com", "a different registrable domain"),
        ("wrong.example.pt", "a sibling subdomain"),
        ("deep.livros.example.pt", "a child of the origin's host"),
        ("Example.pt", "uppercase, which the browser never matches"),
        ("https://example.pt", "carries a scheme"),
        ("example.pt:443", "carries a port"),
        ("example.pt/path", "carries a path"),
    ] {
        let (status, body) = put_rp_id(&state, &token, rp_id).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "RP ID {rp_id:?} ({why}) must be refused: {body}"
        );
    }
}

/// **The trap a one-line "registrable parent" derivation walks straight into.**
///
/// Stripping the first label off `chancela.pt` yields `pt`, which is arithmetically a suffix of the
/// host and passes every check a suffix test can make. It is a public suffix, no browser will
/// accept it as an RP ID, and the failure is invisible server-side. Only the list knows.
#[tokio::test]
async fn a_public_suffix_is_refused_because_no_browser_would_accept_it() {
    let dir = TempDir::new();
    let (state, _uid, token) = harness(&dir).await;
    // `pt` is the value a "strip one label" derivation produces for this instance's host, so it
    // has already passed the arithmetic suffix test by the time the list sees it. That is exactly
    // the case no amount of server-side care catches without a list.
    let (status, body) = put_rp_id(&state, &token, "pt").await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the public suffix \"pt\" must be refused: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("public suffix"),
        "the refusal must name why, so an operator does not read it as a typo: {body}"
    );
}

#[tokio::test]
async fn the_host_and_its_registrable_parent_are_both_accepted() {
    let dir = TempDir::new();
    let (state, _uid, token) = harness(&dir).await;
    for good in ["livros.example.pt", "example.pt"] {
        let (status, body) = put_rp_id(&state, &token, good).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "RP ID {good:?} must be accepted: {body}"
        );
    }
}

/// Enrolment refuses by name when the instance has no configured origin — exactly as invitations
/// already refuse. Discovering this at a user's first enrolment instead would be too late.
#[tokio::test]
async fn enrolment_is_refused_when_the_rp_id_or_base_url_is_unset() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;

    state.settings.write().await.auth.passkeys.rp_id = None;
    let (status, body) = send(
        state.clone(),
        with_session(
            post(&format!("/v1/users/{}/passkeys/options", uid.0), json!({})),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "passkeys_rp_id_unset");

    {
        let mut settings = state.settings.write().await;
        settings.platform.public_base_url = None;
        settings.auth.passkeys.rp_id = None;
    }
    let (status, body) = send(
        state.clone(),
        with_session(
            post(&format!("/v1/users/{}/passkeys/options", uid.0), json!({})),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "passkeys_public_base_url_unset");
}

async fn put_rp_id(state: &AppState, token: &str, rp_id: &str) -> (StatusCode, Value) {
    let mut document = {
        let settings = state.settings.read().await;
        serde_json::to_value(&*settings).expect("settings serialise")
    };
    document["platform"]["public_base_url"] = json!(BASE_URL);
    document["auth"] = document.get("auth").cloned().unwrap_or_else(|| json!({}));
    document["auth"]["passkeys"] = json!({ "rp_id": rp_id });
    let req = Request::builder()
        .method("PUT")
        .uri("/v1/settings")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(document.to_string()))
        .expect("req");
    send(state.clone(), with_session(req, token)).await
}

// =================================================================================================
// The round trips, both ways
// =================================================================================================

#[tokio::test]
async fn a_passkey_round_trips_from_enrolment_to_sign_in() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let mut authenticator = Authenticator::new().with_hmac_secret();
    let handle = enrol(&state, uid, &token, &authenticator, "Telemóvel da Amélia").await;

    // The listing reflects what was enrolled, including the PRF capability that could only ever
    // have been asked for at creation time.
    let (status, list) = send(
        state.clone(),
        with_session(get(&format!("/v1/users/{}/passkeys", uid.0)), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["passkeys"].as_array().expect("array").len(), 1);
    assert_eq!(list["passkeys"][0]["name"], "Telemóvel da Amélia");
    assert_eq!(list["passkeys"][0]["rp_id"], RP_ID);
    assert_eq!(list["passkeys"][0]["usable"], true);
    assert_eq!(list["passkeys"][0]["backup"], "exists");
    assert_eq!(list["passkeys"][0]["prf_capable"], true);
    assert_eq!(list["rp_id"], RP_ID);
    assert_eq!(list["enrolment_available"], true);

    // Sign in with it. No identifier is sent at any point — the whole flow is discoverable.
    let (status, options) = send(
        state.clone(),
        post("/v1/session/passkey/options", json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{options}");
    assert_eq!(options["purpose"], "sign_in");
    let assertion = authenticator.assert(&options["public_key"], ORIGIN, RP_ID, &handle, true);
    let (status, session) = send(
        state.clone(),
        post("/v1/session/passkey", json!({ "credential": assertion })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "passkey sign-in: {session}");
    assert!(
        session["token"].is_string(),
        "a session was minted: {session}"
    );
    assert_eq!(session["user"]["username"], "amelia.marques");
}

/// **A user-verified assertion is already the second factor.** An account that requires 2FA and
/// holds a passkey must not be sent to a TOTP screen: the assertion was possession *and*
/// verification, and asking for a code afterwards adds a step without adding a factor.
#[tokio::test]
async fn a_user_verified_assertion_satisfies_the_second_factor() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let mut authenticator = Authenticator::new();
    let handle = enrol(&state, uid, &token, &authenticator, "Telemóvel").await;
    state
        .users
        .write()
        .await
        .get_mut(&uid)
        .expect("user")
        .two_factor_required = true;

    let (_, options) = send(
        state.clone(),
        post("/v1/session/passkey/options", json!({})),
    )
    .await;
    let assertion = authenticator.assert(&options["public_key"], ORIGIN, RP_ID, &handle, true);
    let (status, session) = send(
        state.clone(),
        post("/v1/session/passkey", json!({ "credential": assertion })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert!(
        session["two_factor_challenge"].is_null(),
        "a UV assertion must not raise a second-factor challenge: {session}"
    );
    assert!(
        session["required_action"].is_null(),
        "a passkey satisfies the enrol-a-second-factor wall: {session}"
    );
}

// =================================================================================================
// The refusals
// =================================================================================================

/// A UV-less **registration** is refused outright, and that is the library holding the line the
/// PRF-stability invariant needs: the seed a PRF output derives from depends on whether UV happened,
/// so a credential created without it could never produce a stable secret.
#[tokio::test]
async fn a_registration_without_user_verification_is_refused() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let authenticator = Authenticator::new();
    let (_, options) = send(
        state.clone(),
        with_session(
            post(&format!("/v1/users/{}/passkeys/options", uid.0), json!({})),
            &token,
        ),
    )
    .await;
    let credential = authenticator.register(&options["public_key"], ORIGIN, false);
    let (status, body) = send(
        state.clone(),
        with_session(
            post(
                &format!("/v1/users/{}/passkeys", uid.0),
                json!({ "credential": credential, "name": "Sem verificação" }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(
        state
            .users
            .read()
            .await
            .get(&uid)
            .expect("user")
            .passkeys
            .is_empty(),
        "a refused registration must store nothing"
    );
}

/// A tampered signature is refused. The bytes are otherwise a perfectly well-formed assertion from
/// a credential this instance really holds — only the signature is wrong.
#[tokio::test]
async fn a_tampered_signature_is_refused() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let mut authenticator = Authenticator::new();
    let handle = enrol(&state, uid, &token, &authenticator, "Telemóvel").await;

    let (_, options) = send(
        state.clone(),
        post("/v1/session/passkey/options", json!({})),
    )
    .await;
    let mut assertion = authenticator.assert(&options["public_key"], ORIGIN, RP_ID, &handle, true);
    let signature = assertion["response"]["signature"]
        .as_str()
        .expect("signature");
    let mut bytes = B64URL.decode(signature).expect("base64url");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    assertion["response"]["signature"] = json!(B64URL.encode(&bytes));

    let (status, body) = send(
        state.clone(),
        post("/v1/session/passkey", json!({ "credential": assertion })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["code"], "passkey_assertion_invalid");
}

/// **A sibling origin is refused, and the CORS allow-list does not widen it.** Companion origins may
/// call this API; letting one satisfy a WebAuthn origin check would discard the phishing binding
/// that is the entire point of the ceremony.
#[tokio::test]
async fn an_assertion_from_a_sibling_origin_is_refused() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let mut authenticator = Authenticator::new();
    let handle = enrol(&state, uid, &token, &authenticator, "Telemóvel").await;

    let (_, options) = send(
        state.clone(),
        post("/v1/session/passkey/options", json!({})),
    )
    .await;
    // A sibling under the same registrable parent — so the RP ID still matches, and only the origin
    // check can catch it. That is the case a naive implementation gets wrong.
    let assertion = authenticator.assert(
        &options["public_key"],
        "https://atas.example.pt",
        RP_ID,
        &handle,
        true,
    );
    let (status, body) = send(
        state.clone(),
        post("/v1/session/passkey", json!({ "credential": assertion })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a sibling origin must not sign in: {body}"
    );
}

/// **The constraint the PRF lane must respect, pinned now so it is discovered here and not there.**
///
/// The server asks for `prf` at enrolment and for nothing at sign-in, and it verifies with
/// `error_on_unsolicited_extensions` on. So an authenticator that returns an `hmac-secret` output
/// at sign-in is refused — which means **PRF at sign-in cannot be added from the browser alone**.
/// A client that sets `extensions.prf.eval` on its own produces exactly this shape, and it will
/// fail. Requesting it is the server's job (`webauthn_rp::request::auth::Extension::prf`), and that
/// is a deliberate follow-up, not an oversight.
#[tokio::test]
async fn an_unsolicited_extension_at_sign_in_is_refused() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let authenticator = Authenticator::new().with_hmac_secret();
    let handle = enrol(&state, uid, &token, &authenticator, "Telemóvel").await;

    let (_, options) = send(
        state.clone(),
        post("/v1/session/passkey/options", json!({})),
    )
    .await;
    let challenge = options["public_key"]["challenge"]
        .as_str()
        .expect("challenge");
    let assertion =
        authenticator.assert_with_unsolicited_extension(challenge, ORIGIN, RP_ID, &handle);
    let (status, body) = send(
        state.clone(),
        post("/v1/session/passkey", json!({ "credential": assertion })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an extension the server never requested must not be accepted: {body}"
    );
}

/// A challenge is spent by the attempt. The second presentation of the same assertion finds
/// nothing, and gets the identical refusal a challenge that never existed would.
#[tokio::test]
async fn a_challenge_cannot_be_replayed() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let mut authenticator = Authenticator::new();
    let handle = enrol(&state, uid, &token, &authenticator, "Telemóvel").await;

    let (_, options) = send(
        state.clone(),
        post("/v1/session/passkey/options", json!({})),
    )
    .await;
    let assertion = authenticator.assert(&options["public_key"], ORIGIN, RP_ID, &handle, true);
    let (status, _) = send(
        state.clone(),
        post(
            "/v1/session/passkey",
            json!({ "credential": assertion.clone() }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = send(
        state.clone(),
        post("/v1/session/passkey", json!({ "credential": assertion })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["code"], "passkey_ceremony_invalid");
}

/// **The replay this whole scoping exists to prevent.**
///
/// A sign-in assertion is a real, correctly-signed assertion from a real credential. Without the
/// purpose binding it would satisfy a factory reset. Here it is offered as a step-up proof for a
/// destructive operation and must be refused — and refused with the same uniform `403` a missing
/// proof gets, so nobody learns that the challenge was live but wrongly scoped.
#[tokio::test]
async fn a_sign_in_assertion_cannot_satisfy_a_step_up() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let mut authenticator = Authenticator::new();
    let handle = enrol(&state, uid, &token, &authenticator, "Telemóvel").await;

    // A genuine sign-in ceremony, completed as far as producing a signed assertion.
    let (_, options) = send(
        state.clone(),
        post("/v1/session/passkey/options", json!({})),
    )
    .await;
    assert_eq!(options["purpose"], "sign_in");
    let sign_in_assertion =
        authenticator.assert(&options["public_key"], ORIGIN, RP_ID, &handle, true);

    let (status, body) = send(
        state.clone(),
        with_session(
            post(
                "/v1/data/reset",
                json!({
                    "scope": "backend_factory",
                    "confirm_phrase": "REPOR FÁBRICA",
                    "skip_export_confirm": true,
                    "export_first": false,
                    "reauth": { "passkey": { "credential": sign_in_assertion } },
                }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a sign-in assertion replayed into a factory reset: {body}"
    );
}

/// The other half: a step-up-scoped assertion *does* satisfy the gate, so a passkey-only account is
/// not locked out of the operations its own existence made non-vacuous.
#[tokio::test]
async fn a_step_up_scoped_assertion_satisfies_the_gate() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let mut authenticator = Authenticator::new();
    let handle = enrol(&state, uid, &token, &authenticator, "Telemóvel").await;

    let (status, options) = send(
        state.clone(),
        with_session(post("/v1/reauth/passkey/options", json!({})), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{options}");
    assert_eq!(options["purpose"], "step_up");
    let assertion = authenticator.assert(&options["public_key"], ORIGIN, RP_ID, &handle, true);

    // Revocation is step-up-gated, and it is the operation this account can reach without a store.
    // A `403` here would mean the arm did not accept the proof; anything else means it did.
    let credential_id = B64URL.encode(&authenticator.credential_id);
    let (status, body) = send(
        state.clone(),
        with_session(
            delete(
                &format!("/v1/users/{}/passkeys/{credential_id}", uid.0),
                json!({ "reauth": { "passkey": { "credential": assertion } } }),
            ),
            &token,
        ),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "a step-up-scoped assertion must satisfy the gate: {body}"
    );
}

/// A step-up challenge belongs to the session that asked for it. Redeeming it proves a ceremony was
/// started, never *by whom* — so another account's assertion must not pass, even though the
/// challenge itself is live and correctly scoped.
#[tokio::test]
async fn another_users_assertion_cannot_satisfy_this_users_step_up() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let mut mine = Authenticator::new();
    let my_handle = enrol(&state, uid, &token, &mine, "Meu telemóvel").await;

    // A second account with its own credential, enrolled through its own session.
    let other_id = UserId(Uuid::new_v4());
    {
        let mut users = state.users.write().await;
        let template = users.get(&uid).cloned().expect("seed user");
        users.insert(
            other_id,
            User {
                id: other_id,
                username: "bruno.silva".to_owned(),
                display_name: "Bruno Silva".to_owned(),
                passkeys: Vec::new(),
                ..template
            },
        );
    }
    let (_, other_session) = send(
        state.clone(),
        post(
            "/v1/session",
            json!({ "username": "bruno.silva", "password": TEST_PASSWORD }),
        ),
    )
    .await;
    let other_token = other_session["token"].as_str().expect("token").to_owned();
    let mut theirs = Authenticator::device_bound();
    let their_handle = enrol(&state, other_id, &other_token, &theirs, "Chave do Bruno").await;

    // Strip my other credentials, so the *only* thing that can carry this gate is a passkey. That
    // is what makes the two halves below distinguishable: without it, a `403` would be equally
    // explained by the passkey arm never running at all.
    {
        let mut users = state.users.write().await;
        let me = users.get_mut(&uid).expect("user");
        me.password_hash = None;
        me.recovery_hash = None;
    }
    let credential_id = B64URL.encode(&mine.credential_id);
    let revoke = |assertion: Value| {
        delete(
            &format!("/v1/users/{}/passkeys/{credential_id}", uid.0),
            json!({ "reauth": { "passkey": { "credential": assertion } } }),
        )
    };

    // *My* session asks for a step-up challenge; *their* authenticator answers it. The challenge is
    // live, correctly scoped, and the assertion is genuinely signed — only the subject is wrong.
    let (_, options) = send(
        state.clone(),
        with_session(post("/v1/reauth/passkey/options", json!({})), &token),
    )
    .await;
    let theirs_assertion =
        theirs.assert(&options["public_key"], ORIGIN, RP_ID, &their_handle, true);
    let (status, body) = send(
        state.clone(),
        with_session(revoke(theirs_assertion), &token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a challenge's subject must be checked, not assumed from its redemption: {body}"
    );

    // And the control: *my* authenticator, answering an identically-scoped challenge from the same
    // session, reaches past the gate. Only the credential's owner differed.
    let (_, options) = send(
        state.clone(),
        with_session(post("/v1/reauth/passkey/options", json!({})), &token),
    )
    .await;
    let mine_assertion = mine.assert(&options["public_key"], ORIGIN, RP_ID, &my_handle, true);
    let (status, body) = send(state.clone(), with_session(revoke(mine_assertion), &token)).await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "the same gate, the same scoping, my own credential: {body}"
    );
}

// =================================================================================================
// The signature counter
// =================================================================================================

/// **A counter regression is recorded, not fatal.**
///
/// A device that legitimately reset its counter would lock its owner out if this were a gate. So
/// the assertion succeeds and an operator gets a ledger event to look at. The credential here is
/// device-bound and starts at a non-zero counter, because the check only applies when the stored
/// and returned values are both non-zero.
#[tokio::test]
async fn a_counter_regression_is_logged_and_the_assertion_still_succeeds() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let mut authenticator = Authenticator::device_bound();
    let handle = enrol(&state, uid, &token, &authenticator, "Chave de segurança").await;

    // One good assertion, so the stored counter is non-zero and moving.
    let (_, options) = send(
        state.clone(),
        post("/v1/session/passkey/options", json!({})),
    )
    .await;
    let good = authenticator.assert(&options["public_key"], ORIGIN, RP_ID, &handle, true);
    let (status, _) = send(
        state.clone(),
        post("/v1/session/passkey", json!({ "credential": good })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let stored = state.users.read().await.get(&uid).expect("user").passkeys[0].sign_count;
    assert!(
        stored > 0,
        "the fixture authenticator must have a live counter"
    );

    // Now an assertion that does not advance it. Same credential, same key, valid signature.
    let (_, options) = send(
        state.clone(),
        post("/v1/session/passkey/options", json!({})),
    )
    .await;
    let challenge = options["public_key"]["challenge"]
        .as_str()
        .expect("challenge");
    let regressed = authenticator.assert_at_counter(challenge, ORIGIN, RP_ID, &handle, true);
    let (status, body) = send(
        state.clone(),
        post("/v1/session/passkey", json!({ "credential": regressed })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a counter regression must not fail the assertion: {body}"
    );

    let ledger = state.ledger.read().await;
    assert!(
        ledger
            .events()
            .iter()
            .any(|event| event.kind == "user.passkey.counter_regression"),
        "the regression must be visible to an operator"
    );
}

/// A synced passkey returns zero forever, so the check must not apply to it at all. Otherwise every
/// iCloud Keychain and Google Password Manager credential in existence would look suspicious on
/// every single assertion.
#[tokio::test]
async fn a_constant_zero_counter_is_not_a_regression() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let authenticator = Authenticator::new(); // synced: counter stays at 0
    let handle = enrol(&state, uid, &token, &authenticator, "Telemóvel").await;

    for _ in 0..3 {
        let (_, options) = send(
            state.clone(),
            post("/v1/session/passkey/options", json!({})),
        )
        .await;
        let challenge = options["public_key"]["challenge"]
            .as_str()
            .expect("challenge");
        let assertion = authenticator.assert_at_counter(challenge, ORIGIN, RP_ID, &handle, true);
        let (status, body) = send(
            state.clone(),
            post("/v1/session/passkey", json!({ "credential": assertion })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let ledger = state.ledger.read().await;
    assert!(
        !ledger
            .events()
            .iter()
            .any(|event| event.kind == "user.passkey.counter_regression"),
        "a synced passkey's constant-zero counter is not an anomaly"
    );
}

// =================================================================================================
// Revocation and the lifecycle guard
// =================================================================================================

/// Revoking the **last** credential of an account that holds nothing else is refused by the
/// existing account-lifecycle guard — the one in `credentials.rs`, not a second one built here.
#[tokio::test]
async fn revoking_the_last_credential_of_a_passkey_only_account_is_refused() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let mut authenticator = Authenticator::new();
    let handle = enrol(&state, uid, &token, &authenticator, "Telemóvel").await;

    // Strip everything else: the account is now passkey-only, which is the shape the guard exists
    // for. The session already minted stays valid, so the revocation can still be attempted.
    {
        let mut users = state.users.write().await;
        let user = users.get_mut(&uid).expect("user");
        user.password_hash = None;
        user.recovery_hash = None;
    }

    // The passkey is now the *only* proof this account can offer, so the revocation carries one.
    // That it can is the point of shipping the proof arm and the storage together: without the arm
    // this account would be refused at the gate rather than at the guard, and its holder would be
    // locked out of every destructive operation instead of being told what the operation costs.
    let (_, options) = send(
        state.clone(),
        with_session(post("/v1/reauth/passkey/options", json!({})), &token),
    )
    .await;
    let assertion = authenticator.assert(&options["public_key"], ORIGIN, RP_ID, &handle, true);

    let credential_id = B64URL.encode(&authenticator.credential_id);
    let (status, body) = send(
        state.clone(),
        with_session(
            delete(
                &format!("/v1/users/{}/passkeys/{credential_id}", uid.0),
                json!({ "reauth": { "passkey": { "credential": assertion } } }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the step-up proof was accepted and the lifecycle guard is what refuses: {body}"
    );
    assert_eq!(body["code"], "account_would_have_no_sign_in_credential");
    assert_eq!(
        state
            .users
            .read()
            .await
            .get(&uid)
            .expect("user")
            .passkeys
            .len(),
        1,
        "a refused revocation leaves the account exactly as it was"
    );
}

/// Revoking one of several removes no *kind*, so the guard is silent and the operation proceeds.
#[tokio::test]
async fn revoking_one_of_several_passkeys_is_allowed() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let first = Authenticator::new();
    let second = Authenticator::device_bound();
    enrol(&state, uid, &token, &first, "Telemóvel").await;
    enrol(&state, uid, &token, &second, "Chave de segurança").await;

    let credential_id = B64URL.encode(&first.credential_id);
    let (status, body) = send(
        state.clone(),
        with_session(
            delete(
                &format!("/v1/users/{}/passkeys/{credential_id}", uid.0),
                json!({ "reauth": { "password": TEST_PASSWORD } }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["passkeys"].as_array().expect("array").len(), 1);
    assert_eq!(body["passkeys"][0]["name"], "Chave de segurança");
}

// =================================================================================================
// Rename
// =================================================================================================

/// Renaming is the whole reason this route exists: without it a credential can be created and
/// deleted but not relabelled, so "which one is the work laptop?" is answered by revoking it.
#[tokio::test]
async fn a_credential_can_be_relabelled_without_being_revoked() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let authenticator = Authenticator::new();
    enrol(&state, uid, &token, &authenticator, "Telemóvel").await;
    let credential_id = B64URL.encode(&authenticator.credential_id);

    let (status, body) = send(
        state.clone(),
        with_session(
            patch(
                &format!("/v1/users/{}/passkeys/{credential_id}", uid.0),
                json!({ "name": "  Portátil do escritório  " }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["name"], "Portátil do escritório",
        "trimmed, not stored raw"
    );
    assert_eq!(
        body["credential_id"], credential_id,
        "a rename must not mint a new credential"
    );

    // The credential itself is untouched — same id, and it still signs in.
    let (status, list) = send(
        state.clone(),
        with_session(get(&format!("/v1/users/{}/passkeys", uid.0)), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["passkeys"].as_array().expect("array").len(), 1);
    assert_eq!(list["passkeys"][0]["name"], "Portátil do escritório");
    assert_eq!(list["passkeys"][0]["credential_id"], credential_id);
}

/// A blank label is refused, not silently defaulted. Defaulting would show the operator a
/// credential named something they never typed, on the screen they use to tell two apart.
#[tokio::test]
async fn a_rename_to_a_blank_label_is_refused() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let authenticator = Authenticator::new();
    enrol(&state, uid, &token, &authenticator, "Telemóvel").await;
    let credential_id = B64URL.encode(&authenticator.credential_id);

    for blank in ["", "   ", "\t\n"] {
        let (status, body) = send(
            state.clone(),
            with_session(
                patch(
                    &format!("/v1/users/{}/passkeys/{credential_id}", uid.0),
                    json!({ "name": blank }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{blank:?}: {body}"
        );
        assert_eq!(body["code"], "passkey_name_empty");
    }

    let (_, list) = send(
        state.clone(),
        with_session(get(&format!("/v1/users/{}/passkeys", uid.0)), &token),
    )
    .await;
    assert_eq!(
        list["passkeys"][0]["name"], "Telemóvel",
        "a refused rename leaves the label exactly as it was"
    );
}

/// Self-only, like every other mutation on this surface. An administrator who could relabel
/// someone else's credential could make the revocation confirmation name the wrong device.
#[tokio::test]
async fn another_user_cannot_rename_this_users_credential() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let authenticator = Authenticator::new();
    enrol(&state, uid, &token, &authenticator, "Telemóvel").await;
    let credential_id = B64URL.encode(&authenticator.credential_id);

    // A second Owner — every permission the instance has, and still refused.
    let other = UserId(Uuid::new_v4());
    state.users.write().await.insert(
        other,
        User {
            id: other,
            username: "bruno.salgado".to_owned(),
            display_name: "Bruno Salgado".to_owned(),
            email: None,
            created_at: OffsetDateTime::now_utc().format(&Rfc3339).expect("stamp"),
            active: true,
            password_hash: Some(password_hash()),
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            secret_source: Default::default(),
            recovery_hash: Some(password_hash()),
            role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
            language: Default::default(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
            passkeys: Vec::new(),
        },
    );
    let (status, session) = send(
        state.clone(),
        post(
            "/v1/session",
            json!({ "username": "bruno.salgado", "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let other_token = session["token"].as_str().expect("token").to_owned();

    let (status, body) = send(
        state.clone(),
        with_session(
            patch(
                &format!("/v1/users/{}/passkeys/{credential_id}", uid.0),
                json!({ "name": "Roubada" }),
            ),
            &other_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // …and the list read they *are* allowed still shows the original label.
    let (status, list) = send(
        state.clone(),
        with_session(get(&format!("/v1/users/{}/passkeys", uid.0)), &other_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "an admin may read the list: {list}");
    assert_eq!(list["passkeys"][0]["name"], "Telemóvel");
}

/// Both labels reach the ledger. The other passkey events name a credential by its label alone, so
/// a rename recording only the new one would orphan every line written before it.
#[tokio::test]
async fn a_rename_records_both_labels_in_the_ledger() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let authenticator = Authenticator::new();
    enrol(&state, uid, &token, &authenticator, "Telemóvel").await;
    let credential_id = B64URL.encode(&authenticator.credential_id);

    let (status, _) = send(
        state.clone(),
        with_session(
            patch(
                &format!("/v1/users/{}/passkeys/{credential_id}", uid.0),
                json!({ "name": "Portátil" }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let ledger = state.ledger.read().await;
    let renamed = ledger
        .events()
        .iter()
        .find(|event| event.kind == "user.passkey.renamed")
        .expect("the rename must be recorded");
    let justification = renamed
        .justification
        .as_deref()
        .expect("a justification names the credential");
    assert!(justification.contains("Telemóvel"), "{justification}");
    assert!(justification.contains("Portátil"), "{justification}");
}

/// Both credentials of one account share **one** user handle. A per-credential handle would make
/// the same person look like a different account to each of their own authenticators.
#[tokio::test]
async fn every_credential_of_an_account_shares_one_user_handle() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    let first = Authenticator::new();
    let second = Authenticator::device_bound();
    let handle_a = enrol(&state, uid, &token, &first, "Telemóvel").await;
    let handle_b = enrol(&state, uid, &token, &second, "Chave de segurança").await;
    assert_eq!(handle_a, handle_b, "one account, one handle");
    assert_ne!(
        handle_a,
        uid.0.as_bytes().to_vec(),
        "and it is not the user id"
    );
}

// =================================================================================================
// The domain-change gate
// =================================================================================================

/// **Moving the instance destroys every enrolled passkey, permanently.** The gate says how many,
/// exactly, and makes the operator write the phrase — because the alternative to being told is
/// finding out from users.
#[tokio::test]
async fn changing_the_public_base_url_host_is_gated_by_a_typed_phrase() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    enrol(&state, uid, &token, &Authenticator::new(), "Telemóvel").await;
    enrol(
        &state,
        uid,
        &token,
        &Authenticator::device_bound(),
        "Chave de segurança",
    )
    .await;

    let (status, body) = put_base_url(&state, &token, "https://atas.example.pt", None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "passkey_domain_change_unconfirmed");
    let message = body["error"].as_str().unwrap_or_default();
    assert!(
        message.contains('2'),
        "the refusal must name the exact number of credentials that stop working: {body}"
    );
    assert!(
        message.contains("PERDER CHAVES"),
        "and the phrase the operator has to write: {body}"
    );
    assert_eq!(
        state
            .settings
            .read()
            .await
            .platform
            .resolved_public_base_url()
            .as_deref(),
        Some(BASE_URL),
        "a refused change leaves the instance where it was"
    );

    // With the phrase, it goes through. A wall, not a prohibition: an operator who genuinely needs
    // to move should not be left editing settings.json by hand with no record of being told.
    let (status, body) = put_base_url(
        &state,
        &token,
        "https://atas.example.pt",
        Some("PERDER CHAVES"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A change that keeps the host is not a domain change, so an operator adjusting a path or a port
/// is never asked for the phrase. Over-confirming is its own failure — it trains operators to type
/// through prompts exactly where the prompt matters.
#[tokio::test]
async fn a_change_that_keeps_the_host_is_not_gated() {
    let dir = TempDir::new();
    let (state, uid, token) = harness(&dir).await;
    enrol(&state, uid, &token, &Authenticator::new(), "Telemóvel").await;
    let (status, body) =
        put_base_url(&state, &token, "https://livros.example.pt/livros", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// With nothing enrolled there is nothing to lose, so the gate is silent. It counts credentials
/// rather than asking whether the feature is switched on.
#[tokio::test]
async fn the_gate_is_silent_when_no_passkey_is_enrolled() {
    let dir = TempDir::new();
    let (state, _uid, token) = harness(&dir).await;
    let (status, body) = put_base_url(&state, &token, "https://atas.example.pt", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

async fn put_base_url(
    state: &AppState,
    token: &str,
    base_url: &str,
    phrase: Option<&str>,
) -> (StatusCode, Value) {
    let mut document = {
        let settings = state.settings.read().await;
        serde_json::to_value(&*settings).expect("settings serialise")
    };
    document["platform"]["public_base_url"] = json!(base_url);
    // The RP ID must move with the host, or `validate_against` refuses first and this test would
    // be asserting the wrong refusal.
    let host = base_url
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or_default()
        .to_owned();
    document["auth"] = document.get("auth").cloned().unwrap_or_else(|| json!({}));
    document["auth"]["passkeys"] = json!({ "rp_id": host });
    let uri = match phrase {
        Some(phrase) => format!("/v1/settings?passkey_confirm_phrase={}", urlencode(phrase)),
        None => "/v1/settings".to_owned(),
    };
    let req = Request::builder()
        .method("PUT")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(document.to_string()))
        .expect("req");
    send(state.clone(), with_session(req, token)).await
}

fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

// =================================================================================================
// Storage compatibility
// =================================================================================================

/// **An old stored user row still deserialises.**
///
/// The store *skips rows it cannot parse* rather than failing the load, so a non-defaulted field on
/// `User` would not surface as an error — it would silently drop every pre-existing account from
/// the read model. This pins a row written before passkeys existed.
#[test]
fn a_user_row_written_before_passkeys_existed_still_loads() {
    let legacy = json!({
        "id": "9b1f6c00-0000-4000-8000-0000000000a1",
        "username": "amelia.marques",
        "display_name": "Amélia Marques",
        "created_at": "2026-01-04T09:00:00Z",
        "active": true,
        "password_hash": "$argon2id$v=19$m=19456,t=2,p=1$YWFhYWFhYWE$",
        "secret_source": "password",
        "role_assignments": [],
    });
    let user: User = serde_json::from_value(legacy).expect("a pre-passkeys row must still load");
    assert!(user.passkeys.is_empty());
    assert_eq!(user.username, "amelia.marques");

    // And it round-trips back out without gaining a key, so an existing `users.json` is unchanged
    // until an account actually enrols something.
    let written = serde_json::to_value(&user).expect("serialise");
    assert!(
        written.get("passkeys").is_none(),
        "an account with no passkeys must not grow the field in the file: {written}"
    );
}
