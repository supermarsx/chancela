//! t51-e3 — the Chave Móvel Digital **production test signature**, tested exclusively through its
//! refusals.
//!
//! # Why there is no happy path in this file
//!
//! Every completed call to `/v1/signature/cmd/test-signature/{initiate,confirm}` produces a real,
//! legally binding qualified electronic signature against AMA's live production service, made with
//! a real citizen's Chave Móvel Digital and a real SMS OTP. There is no rehearsal mode to test
//! against: `CCMovelSign` dispatches the OTP and `ValidateOtp` returns the signature. So this suite
//! proves the **gates** — every path that must refuse, and the one path that must refuse *hardest*
//! (an injected mock transport) — and deliberately never drives a request past the point where AMA
//! would be contacted.
//!
//! The strongest assertion here is the mock refusal. A "successful" test signature against a canned
//! SOAP fixture would tell an operator that production CMD works when nothing was contacted, which
//! is worse than any failure this endpoint can return.
//!
//! Fictional example data only: "Encosto Estratégico Lda" / "Amélia Marques" — never real names.

mod common;

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{
    AppState, CmdCredentialFields, CmdEnvSetting, CredentialFieldSet, CredentialMode, router,
};
use chancela_cmd::{CmdError, ScmdTransport};
use common::TEST_PASSWORD;
use serde_json::{Value, json};
use tokio::sync::RwLock as AsyncRwLock;
use tower::ServiceExt;
use zeroize::Zeroizing;

/// The typed phrase t56 minted for `ConfirmationAction::CmdTestSignature`. A fixed, non-localised
/// pt-PT token by decision — asserting it here pins the contract the UI must reproduce exactly.
const CONFIRM_PHRASE: &str = "ASSINAR TESTE";

const INITIATE_URI: &str = "/v1/signature/cmd/test-signature/initiate";
const CONFIRM_URI: &str = "/v1/signature/cmd/test-signature/confirm";

const PHONE: &str = "+351 912345678";
const PIN: &str = "271828";

const CMD_ENV_KEYS: [&str; 5] = [
    "CHANCELA_CMD_ENV",
    "CHANCELA_CMD_APPLICATION_ID",
    "CHANCELA_CMD_HTTP_BASIC_USERNAME",
    "CHANCELA_CMD_HTTP_BASIC_PASSWORD",
    "CHANCELA_CMD_AMA_CERT_PEM",
];

/// A parseable AMA field-encryption certificate, so a "complete" production entry can be assembled
/// in a test without ever being used to contact anything.
const AMA_CERT_PEM: &str = include_str!("../../chancela-cmd/fixtures/ama_encryption_cert.pem");

/// Serializes the process-global `CHANCELA_CMD_*` / `CHANCELA_CREDENTIAL_*` env vars, exactly as
/// `cmd_signing.rs` does: every test here drives the same `resolve_cmd_candidates` walk, which
/// reads those vars whenever nothing is stored.
static ENV_LOCK: AsyncRwLock<()> = AsyncRwLock::const_new(());

// --- harness -----------------------------------------------------------------------------------

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "chancela-cmd-test-signature-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct EnvRestore(Vec<(&'static str, Option<String>)>);
impl EnvRestore {
    fn capture_and_remove(keys: &[&'static str]) -> Self {
        Self(
            keys.iter()
                .map(|key| {
                    let value = std::env::var(key).ok();
                    unsafe {
                        std::env::remove_var(key);
                    }
                    (*key, value)
                })
                .collect(),
        )
    }
}
impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (key, value) in &self.0 {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

/// A transport that would answer nothing. It exists only to prove that *having* an injected
/// transport at all is refused — no request in this suite may ever reach it, and any call it
/// receives is a test failure by construction.
struct NeverCalledTransport;
impl ScmdTransport for NeverCalledTransport {
    fn call(&self, _action: &str, _body: &str) -> Result<String, CmdError> {
        panic!(
            "the CMD production test signature reached an injected transport; the mock refusal is broken"
        );
    }
}

fn set_provider_credential_test_key() {
    unsafe {
        std::env::set_var(
            "CHANCELA_CREDENTIAL_KEY",
            "cmd-test-signature-provider-credential-test-key",
        );
        std::env::remove_var("CHANCELA_CREDENTIAL_KEY_FILE");
        std::env::remove_var("CHANCELA_CREDENTIAL_STRICT");
    }
}

/// A persistent state with **no** CMD ApplicationId in settings, so the environment fallback yields
/// nothing and the "not configured" refusal is reachable.
async fn state_at(dir: &std::path::Path) -> AppState {
    let state = AppState::with_data_dir(dir);
    {
        let mut settings = state.settings.write().await;
        settings.signing.tsa_url = None;
        settings.signing.tsa_providers.clear();
    }
    state
}

async fn set_prod(state: &AppState) {
    state.settings.write().await.signing.cmd.env = CmdEnvSetting::Prod;
}

fn zeroizing(value: &str) -> Zeroizing<String> {
    Zeroizing::new(value.to_owned())
}

fn seed_stored_cmd(state: &AppState, fields: CmdCredentialFields) {
    state
        .provider_credentials
        .put(CredentialMode::Cmd, "", fields.into_set_pairs(), &[])
        .expect("seed stored CMD credentials");
}

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

fn json_req(method: &str, uri: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("x-chancela-session", token);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

/// A fully-formed initiate body: valid phone, valid PIN shape, and a **complete** T3 proof
/// (step-up password + the exact typed phrase). Every test that wants to exercise a gate *after*
/// the confirmation gate starts from this.
fn initiate_body() -> Value {
    json!({
        "phone": PHONE,
        "pin": PIN,
        "confirmation": {
            "reauth": { "password": TEST_PASSWORD },
            "confirm_phrase": CONFIRM_PHRASE,
        },
    })
}

async fn bootstrap(state: &AppState) -> String {
    let (status, user) = send(
        state,
        json_req(
            "POST",
            "/v1/users",
            None,
            json!({
                "username": "amelia.marques",
                "display_name": "Amélia Marques",
                "password": TEST_PASSWORD,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create first user: {user}");
    let uid = user["id"].as_str().expect("user id").to_owned();
    let (status, session) = send(
        state,
        json_req(
            "POST",
            "/v1/session",
            None,
            json!({ "user_id": uid, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "open session: {session}");
    session["token"].as_str().expect("token").to_owned()
}

fn error_of(body: &Value) -> String {
    body["error"].as_str().unwrap_or_default().to_owned()
}

// --- the mock must be unreachable ---------------------------------------------------------------

/// **The load-bearing test.** An instance with an injected SCMD transport must refuse the
/// production test signature outright rather than run it against canned responses.
///
/// A green "production CMD works" derived from a mock is the single worst outcome this endpoint
/// can produce — it would tell an operator their AMA integration is live when nothing was
/// contacted. The transport used here panics on any call, so the test fails loudly if the refusal
/// ever stops working, rather than quietly passing on a fabricated success.
///
/// The refusal is checked on **both** phases: confirm is where the signature actually comes into
/// existence, so it carries its own copy of every gate rather than trusting initiate's.
#[tokio::test]
async fn an_injected_transport_is_refused_and_never_reported_as_a_production_test() {
    let _guard = ENV_LOCK.write().await;
    let _env = EnvRestore::capture_and_remove(&CMD_ENV_KEYS);
    set_provider_credential_test_key();
    let dir = TempDir::new();
    let mut state = state_at(&dir.0).await;
    state.cmd_transport = Some(Arc::new(NeverCalledTransport));
    set_prod(&state).await;
    // A complete, valid production credential: the ONLY thing standing between this request and a
    // real signature attempt is the injected-transport refusal.
    seed_stored_cmd(
        &state,
        CmdCredentialFields {
            application_id: Some(zeroizing("CHANCELA-PROD-0001")),
            http_basic_username: Some(zeroizing("ama-user")),
            http_basic_password: Some(zeroizing("ama-password")),
            ama_cert_pem: Some(zeroizing(AMA_CERT_PEM)),
        },
    );
    let token = bootstrap(&state).await;

    let (status, body) = send(
        &state,
        json_req("POST", INITIATE_URI, Some(&token), initiate_body()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "an injected transport must refuse, never simulate: {body}"
    );
    assert!(
        error_of(&body).contains("simulado"),
        "the refusal says plainly that a simulated transport is not a production test: {body}"
    );
    assert!(
        state.pending_cmd_test_signatures.read().await.is_empty(),
        "a refused test must leave no pending session"
    );

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            CONFIRM_URI,
            Some(&token),
            json!({
                "session_id": "any",
                "otp": "314159",
                "confirmation": {
                    "reauth": { "password": TEST_PASSWORD },
                    "confirm_phrase": CONFIRM_PHRASE,
                },
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "confirm carries the same refusal, not just initiate: {body}"
    );
    assert_no_retained_signature(&dir.0);
}

/// The structural half of the same proof, read off the source rather than the behaviour.
///
/// The behavioural test above proves the guard fires. This proves there is **nothing for it to
/// guard against**: the module contains no reference to a mock transport, reads
/// `state.cmd_transport` only to refuse, and builds `HttpScmdTransport` unconditionally. A future
/// edit that reintroduces an injected-transport branch fails here even if it keeps the guard.
#[test]
fn the_module_has_no_branch_that_could_select_a_mock_transport() {
    let src = module_code();

    assert!(
        !src.contains("MockScmdTransport"),
        "the CMD test-signature module must never name a mock transport"
    );
    assert!(
        src.contains("HttpScmdTransport::from_config"),
        "the module must build the real HTTP transport"
    );
    // Exactly the two SCMD drivers construct a transport, and both construct the real one.
    assert_eq!(
        src.matches("HttpScmdTransport::from_config").count(),
        2,
        "initiate and confirm each build the real transport, and nothing else builds one"
    );
    // `cmd_transport` may be mentioned only by the refusal guard and the prose that explains it.
    // The one *code* read is `state.cmd_transport.is_some()`.
    assert_eq!(
        src.matches("state.cmd_transport").count(),
        1,
        "the only read of the injected-transport seam is the refusal"
    );
    assert!(
        src.contains("state.cmd_transport.is_some()"),
        "and that read is the refusal guard"
    );
}

/// The result of a production test signature can never be mistaken for a signature on an
/// instrument, because it is never written where one would be looked for.
///
/// `require_real_signatures` reads `instrument_signatures_for_subject`. This module writes to a
/// dedicated retention directory and appends its own ledger events; it never touches the
/// instrument-signature writer, has no `subject`, and has no `slot_id`. Asserting that at the
/// source level is the honest form of "a test signature does not advance any termo's open gate" —
/// the behavioural form would require producing a real qualified signature.
#[test]
fn a_test_signature_is_never_written_where_an_instrument_signature_is_read() {
    let src = module_code();
    for forbidden in [
        "upsert_signed_termo_slot_signature",
        "upsert_signed_instrument_slot_signature",
        "instrument_signatures_for_subject",
        "upsert_signed_document",
        "signed_documents",
        "slot_id",
    ] {
        assert!(
            !src.contains(forbidden),
            "the CMD test signature must not reach {forbidden}: a test signature that could \
             satisfy an instrument's signing requirement would be an evidentiary failure"
        );
    }
}

// --- the confirmation gate ----------------------------------------------------------------------

/// T3 is enforced at the API, not only in a dialog. Both halves are required: the step-up proof and
/// the exact typed phrase.
///
/// **Every refusal here must be 403, never 401.** A credential-proof 401 signs the operator out;
/// that regression was fixed once and must not come back.
#[tokio::test]
async fn the_typed_phrase_gate_refuses_with_403_and_never_signs_the_operator_out() {
    let _guard = ENV_LOCK.write().await;
    let _env = EnvRestore::capture_and_remove(&CMD_ENV_KEYS);
    set_provider_credential_test_key();
    let dir = TempDir::new();
    let state = state_at(&dir.0).await;
    set_prod(&state).await;
    let token = bootstrap(&state).await;

    let cases: [(&str, Value); 4] = [
        ("no proof at all", json!({ "phone": PHONE, "pin": PIN })),
        (
            "step-up only, no phrase",
            json!({
                "phone": PHONE, "pin": PIN,
                "confirmation": { "reauth": { "password": TEST_PASSWORD } },
            }),
        ),
        (
            "the wrong phrase",
            json!({
                "phone": PHONE, "pin": PIN,
                "confirmation": {
                    "reauth": { "password": TEST_PASSWORD },
                    "confirm_phrase": "assinar teste",
                },
            }),
        ),
        (
            "the right phrase but no step-up",
            json!({
                "phone": PHONE, "pin": PIN,
                "confirmation": { "confirm_phrase": CONFIRM_PHRASE },
            }),
        ),
    ];

    for (label, body) in cases {
        let (status, response) =
            send(&state, json_req("POST", INITIATE_URI, Some(&token), body)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{label}: the confirmation gate must refuse with 403: {response}"
        );
        assert_ne!(
            status,
            StatusCode::UNAUTHORIZED,
            "{label}: a confirmation failure must never be a 401 — that signs the operator out"
        );
    }

    assert!(
        state.pending_cmd_test_signatures.read().await.is_empty(),
        "no refused request may leave a pending session"
    );
    assert_no_retained_signature(&dir.0);
}

/// RBAC stays the primary who-may gate, and the confirmation proof does not substitute for it.
#[tokio::test]
async fn the_endpoint_requires_a_session_and_the_signing_permissions() {
    let _guard = ENV_LOCK.write().await;
    let _env = EnvRestore::capture_and_remove(&CMD_ENV_KEYS);
    set_provider_credential_test_key();
    let dir = TempDir::new();
    let state = state_at(&dir.0).await;
    set_prod(&state).await;

    // No session at all — even with a perfectly formed confirmation proof.
    for uri in [INITIATE_URI, CONFIRM_URI] {
        let (status, body) = send(&state, json_req("POST", uri, None, initiate_body())).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{uri} must require a session: {body}"
        );
    }
    let (status, body) = send(
        &state,
        json_req(
            "GET",
            "/v1/signature/cmd/test-signature/00000000-0000-0000-0000-000000000000/document",
            None,
            Value::Null,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the retained-document route must require a session: {body}"
    );
}

// --- fail closed --------------------------------------------------------------------------------

/// Preprod is refused. There is no fallback: the operator asked whether **production** works, and
/// answering with preprod would answer a different question while still costing a real signature.
#[tokio::test]
async fn a_preprod_deployment_is_refused_and_never_falls_back() {
    let _guard = ENV_LOCK.write().await;
    let _env = EnvRestore::capture_and_remove(&CMD_ENV_KEYS);
    set_provider_credential_test_key();
    let dir = TempDir::new();
    let state = state_at(&dir.0).await;
    // Deliberately left at the default, which is preprod.
    seed_stored_cmd(
        &state,
        CmdCredentialFields {
            application_id: Some(zeroizing("CHANCELA-PREPROD-0001")),
            ..Default::default()
        },
    );
    let token = bootstrap(&state).await;

    let (status, body) = send(
        &state,
        json_req("POST", INITIATE_URI, Some(&token), initiate_body()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "preprod must refuse, not silently run: {body}"
    );
    let message = error_of(&body);
    assert!(
        message.contains("pré-produção") && message.contains("produção"),
        "the refusal names the environment and what to change: {body}"
    );
    assert_no_retained_signature(&dir.0);
}

/// **t113, the reported bug.** Deployment default preprod, entry says prod.
///
/// Network-free by construction: it refuses before AMA is contacted, so the assertion is about
/// WHICH refusal — i.e. which environment was resolved — not about signing.
#[tokio::test]
async fn an_entry_marked_prod_is_honoured_on_a_preprod_deployment_and_still_needs_the_cert() {
    let _guard = ENV_LOCK.write().await;
    let _env = EnvRestore::capture_and_remove(&CMD_ENV_KEYS);
    set_provider_credential_test_key();
    let dir = TempDir::new();
    let state = state_at(&dir.0).await;
    let token = bootstrap(&state).await;

    // (1) DEPLOYMENT DEFAULT PREPROD, ENTRY SAYS PROD — the reported bug.
    //
    // The entry deliberately omits `ama_cert_pem`. If the selector were ignored the entry would
    // resolve preprod, where the certificate is optional, and the run would be turned away by the
    // ENVIRONMENT refusal. Being turned away for the MISSING CERTIFICATE instead is what proves
    // the selector was honoured — and simultaneously proves production still demands it.
    let (status, created) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/provider-credentials/cmd/_/entries",
            Some(&token),
            json!({
                "label": "CMD produção",
                "selectors": { "env": "prod" },
                "set": {
                    "application_id": "CHANCELA-PROD-0001",
                    "http_basic_username": "ama-user",
                    "http_basic_password": "ama-password",
                },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");

    let (status, body) = send(
        &state,
        json_req("POST", INITIATE_URI, Some(&token), initiate_body()),
    )
    .await;
    assert_ne!(
        body["code"], "cmd_test_environment_preprod",
        "the entry selected production, so the environment must no longer be the refusal: {body}"
    );
    assert!(
        error_of(&body).contains("ama_cert_pem"),
        "production still demands the AMA field-encryption certificate: {status} {body}"
    );
    assert_no_retained_signature(&dir.0);
}

/// **t113, the other direction.** A complete production-grade credential that its own selector
/// marks preprod is refused, on a deployment whose default is production.
///
/// Its own state, because the failover walk assembles every enabled entry and one unusable entry
/// would mask what this is asserting.
#[tokio::test]
async fn an_entry_marked_preprod_is_refused_even_on_a_production_deployment() {
    let _guard = ENV_LOCK.write().await;
    let _env = EnvRestore::capture_and_remove(&CMD_ENV_KEYS);
    set_provider_credential_test_key();
    let dir = TempDir::new();
    let state = state_at(&dir.0).await;
    set_prod(&state).await;
    let token = bootstrap(&state).await;

    // Making the selector authoritative must not become a way to fire a real signature against a
    // credential the operator marked as non-production.
    let (status, created) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/provider-credentials/cmd/_/entries",
            Some(&token),
            json!({
                "label": "CMD pré-produção",
                "selectors": { "env": "preprod" },
                "set": {
                    "application_id": "CHANCELA-PREPROD-0002",
                    "http_basic_username": "ama-user",
                    "http_basic_password": "ama-password",
                    "ama_cert_pem": AMA_CERT_PEM,
                },
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let preprod_entry = created["entry"]["entry_id"]
        .as_str()
        .expect("entry id")
        .to_owned();

    let mut body = initiate_body();
    body["entry_id"] = json!(preprod_entry);
    let (status, response) = send(&state, json_req("POST", INITIATE_URI, Some(&token), body)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a preprod-marked entry must refuse even on a prod deployment: {response}"
    );
    assert_eq!(
        response["code"], "cmd_test_environment_preprod",
        "{response}"
    );
    assert!(
        state.pending_cmd_test_signatures.read().await.is_empty(),
        "a refused environment must not create a pending session"
    );
    assert_no_retained_signature(&dir.0);
}

/// No credentials at all: refuse, and name the **admin-panel** fields an operator can go and fill —
/// not the environment variables they never set.
#[tokio::test]
async fn absent_credentials_refuse_and_name_the_admin_panel_fields() {
    let _guard = ENV_LOCK.write().await;
    let _env = EnvRestore::capture_and_remove(&CMD_ENV_KEYS);
    set_provider_credential_test_key();
    let dir = TempDir::new();
    let state = state_at(&dir.0).await;
    set_prod(&state).await;
    let token = bootstrap(&state).await;

    let (status, body) = send(
        &state,
        json_req("POST", INITIATE_URI, Some(&token), initiate_body()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "an unconfigured provider must refuse: {body}"
    );
    let message = error_of(&body);
    for field in [
        "application_id",
        "http_basic_username",
        "http_basic_password",
        "ama_cert_pem",
    ] {
        assert!(
            message.contains(field),
            "the refusal names the admin-panel field {field}: {body}"
        );
    }
    assert!(
        !message.contains("CHANCELA_CMD_"),
        "an operator who filled a form must not be told about environment variables: {body}"
    );
    assert_no_retained_signature(&dir.0);
}

/// A **partial** stored entry fails closed through the signing path's own assembler, naming the
/// exact field that is missing — and never mixes the stored record with the environment.
#[tokio::test]
async fn an_incomplete_stored_entry_fails_closed_naming_the_missing_field() {
    let _guard = ENV_LOCK.write().await;
    let _env = EnvRestore::capture_and_remove(&CMD_ENV_KEYS);
    set_provider_credential_test_key();
    let dir = TempDir::new();
    let state = state_at(&dir.0).await;
    set_prod(&state).await;
    seed_stored_cmd(
        &state,
        CmdCredentialFields {
            application_id: Some(zeroizing("CHANCELA-PROD-0001")),
            ..Default::default()
        },
    );
    let token = bootstrap(&state).await;

    let (status, body) = send(
        &state,
        json_req("POST", INITIATE_URI, Some(&token), initiate_body()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a partial production entry must fail closed: {body}"
    );
    let message = error_of(&body);
    assert!(
        message.contains("ama_cert_pem"),
        "the refusal names the missing production certificate field: {body}"
    );
    assert!(
        state.pending_cmd_test_signatures.read().await.is_empty(),
        "an incomplete credential must not create a pending session"
    );
    assert_no_retained_signature(&dir.0);
}

/// Entry pinning: naming an entry that does not exist (or has been disabled) is a refusal, never a
/// quiet failover to a different credential. A test that silently tested another credential would
/// have answered the wrong question — with a real signature.
#[tokio::test]
async fn a_pinned_entry_that_is_gone_refuses_rather_than_failing_over() {
    let _guard = ENV_LOCK.write().await;
    let _env = EnvRestore::capture_and_remove(&CMD_ENV_KEYS);
    set_provider_credential_test_key();
    let dir = TempDir::new();
    let state = state_at(&dir.0).await;
    set_prod(&state).await;
    seed_stored_cmd(
        &state,
        CmdCredentialFields {
            application_id: Some(zeroizing("CHANCELA-PROD-0001")),
            http_basic_username: Some(zeroizing("ama-user")),
            http_basic_password: Some(zeroizing("ama-password")),
            ama_cert_pem: Some(zeroizing(AMA_CERT_PEM)),
        },
    );
    let token = bootstrap(&state).await;

    let mut body = initiate_body();
    body["entry_id"] = json!("nao-existe");
    let (status, response) = send(&state, json_req("POST", INITIATE_URI, Some(&token), body)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a pinned entry that is gone must refuse: {response}"
    );
    assert!(
        error_of(&response).contains("não recorre a outra credencial"),
        "the refusal says plainly that no other credential was tried: {response}"
    );
    assert!(
        state.pending_cmd_test_signatures.read().await.is_empty(),
        "a refused pin must not create a pending session"
    );
    assert_no_retained_signature(&dir.0);
}

/// A server that keeps nothing on disk refuses **before** signing. Producing a real qualified
/// signature that could not be retained would leave the citizen's signature with no record of why
/// it exists — worse than not producing one.
#[tokio::test]
async fn a_server_that_cannot_retain_refuses_before_signing() {
    let _guard = ENV_LOCK.write().await;
    let _env = EnvRestore::capture_and_remove(&CMD_ENV_KEYS);
    set_provider_credential_test_key();
    let dir = TempDir::new();
    // An instance that keeps nothing on disk. Built from a data directory so the seeded RBAC
    // catalog is present (the point under test is retention, not authorization) and then stripped
    // of its persistence path, which is exactly what `AppState::data_dir` reads.
    let mut state = state_at(&dir.0).await;
    state.persist_path = None;
    set_prod(&state).await;
    let token = bootstrap(&state).await;

    let (status, body) = send(
        &state,
        json_req("POST", INITIATE_URI, Some(&token), initiate_body()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "an instance with nowhere to retain must refuse: {body}"
    );
    assert!(
        error_of(&body).contains("conservada"),
        "the refusal explains that the signature could not be kept: {body}"
    );
    assert!(
        state.pending_cmd_test_signatures.read().await.is_empty(),
        "a refused test must leave no pending session"
    );
}

/// A malformed phone is rejected before anything is resolved or contacted.
#[tokio::test]
async fn a_malformed_phone_is_rejected_before_the_provider_is_resolved() {
    let _guard = ENV_LOCK.write().await;
    let _env = EnvRestore::capture_and_remove(&CMD_ENV_KEYS);
    set_provider_credential_test_key();
    let dir = TempDir::new();
    let state = state_at(&dir.0).await;
    set_prod(&state).await;
    let token = bootstrap(&state).await;

    let mut body = initiate_body();
    body["phone"] = json!("912345678");
    let (status, response) = send(&state, json_req("POST", INITIATE_URI, Some(&token), body)).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a malformed phone is client-actionable: {response}"
    );
    assert_no_retained_signature(&dir.0);
}

/// An unknown test id is a 404, and the id is parsed as a UUID before it can reach the filesystem.
#[tokio::test]
async fn the_retained_document_route_rejects_unknown_and_malformed_ids() {
    let _guard = ENV_LOCK.read().await;
    set_provider_credential_test_key();
    let dir = TempDir::new();
    let state = state_at(&dir.0).await;
    let token = bootstrap(&state).await;

    for id in [
        "00000000-0000-0000-0000-000000000000",
        "..%2f..%2fsettings",
        "not-a-uuid",
    ] {
        let (status, body) = send(
            &state,
            json_req(
                "GET",
                &format!("/v1/signature/cmd/test-signature/{id}/document"),
                Some(&token),
                Value::Null,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{id} must not resolve to a document: {body}"
        );
    }
}

/// A wrong PIN is a **distinct, legible** outcome, not a generic failure.
///
/// The flow cannot reach AMA in a test, but the contract it relies on to make a PIN rejection legible
/// is public and network-free. A wrong signing PIN makes `SCMDSign` (`CCMovelSign`) return a
/// non-success status, which is `CmdError::ServiceStatus`. The signing layer flattens that error to
/// its `Display` string (`SigningError::Provider(e.to_string())`), and `chancela-api` recovers the
/// stable code back from that string — so a PIN rejection reaches the operator as
/// `cmd_service_rejected`, the code whose translated copy names the mobile number and the signing
/// PIN. This pins that it stays SEPARATE from a transport error, a configuration error and an
/// OTP-stage rejection, which an operator asking "is the PIN actually working?" must be able to tell
/// apart. The happy half of that same question — a PIN that *was* accepted — is the initiate
/// response's `pin_accepted` value, covered by the module's own unit tests.
#[test]
fn a_scmd_sign_pin_rejection_is_a_distinct_stable_code_separate_from_the_other_failure_classes() {
    use chancela_cmd::error::{
        CMD_CONFIGURATION_INVALID, CMD_OTP_REJECTED, CMD_SERVICE_REJECTED, CMD_TRANSPORT_FAILED,
    };

    // A wrong PIN: SCMDSign refuses to start the signature.
    let pin_rejected = CmdError::ServiceStatus {
        code: "401".to_owned(),
        message: "PIN invalido".to_owned(),
    };
    // The typed code and the one recovered from the flattened `Display` agree — and the recovered
    // one is what the operator actually sees, because the flow surfaces the provider error by its
    // `Display`, its typed variant long gone by the time the API classifies it.
    assert_eq!(pin_rejected.stable_code(), CMD_SERVICE_REJECTED);
    assert_eq!(
        CmdError::stable_code_from_display(&pin_rejected.to_string()),
        CMD_SERVICE_REJECTED,
        "a PIN rejection must classify as cmd_service_rejected via the exact path the flow uses"
    );

    // The neighbouring failure classes an operator must not confuse it with, each its own code.
    let otp = CmdError::OtpRejected {
        code: "402".to_owned(),
        message: "OTP invalido".to_owned(),
    };
    let transport = CmdError::Transport("connection refused".to_owned());
    let config = CmdError::Config("missing application id".to_owned());
    assert_eq!(otp.stable_code(), CMD_OTP_REJECTED);
    assert_eq!(transport.stable_code(), CMD_TRANSPORT_FAILED);
    assert_eq!(config.stable_code(), CMD_CONFIGURATION_INVALID);
    for other in [
        CMD_OTP_REJECTED,
        CMD_TRANSPORT_FAILED,
        CMD_CONFIGURATION_INVALID,
    ] {
        assert_ne!(
            CMD_SERVICE_REJECTED, other,
            "a PIN rejection must not collapse into {other}"
        );
    }
}

/// The CMD test-signature module's source with every comment line removed.
///
/// The structural assertions below are about what the module can *do*, so they must read code and
/// not prose — the module's own documentation necessarily names `MockScmdTransport` and
/// `instrument_signatures` in order to explain why it never touches them, and a naive substring
/// search would flag exactly the sentences that make the guarantee legible.
fn module_code() -> String {
    include_str!("../src/cmd_test_signature.rs")
        .replace("\r\n", "\n")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Nothing in this suite may leave a signed artifact behind. If one appears, a test drove a request
/// further than it was supposed to go.
fn assert_no_retained_signature(dir: &std::path::Path) {
    let retention = dir.join("cmd-test-signatures");
    if !retention.exists() {
        return;
    }
    let pdfs: Vec<_> = std::fs::read_dir(&retention)
        .expect("read the retention directory")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "pdf"))
        .collect();
    assert!(
        pdfs.is_empty(),
        "a refusal path produced a retained signature at {retention:?} — a test reached AMA"
    );
}
