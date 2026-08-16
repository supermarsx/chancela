//! The degraded read-only gate: it must be able to LIFT, and its refusal must name the cause it
//! actually has.
//!
//! Two defects, both in the gate rather than in the detection feeding it.
//!
//! The gate was one-way. `refresh_act_fixity` raised it on an altered sealed act and nothing ever
//! lowered it, so an instance whose acts had been repaired out of band stayed read-only until the
//! process was restarted — with `GET /v1/ledger/integrity` cheerfully reporting a healthy chain and
//! healthy acts above a `degraded: true` it had no way to retract.
//!
//! And the refusal was a single fixed string naming the integrity *chain* and telling the operator
//! to re-anchor. On a fixity failure that is wrong twice: the chain verifies (that is the entire
//! reason the fixity pass exists), and re-anchoring a verifying chain returns `409 "a cadeia já
//! verifica"`. The one remedy the refusal named could not run in the one situation it created.
//!
//! The refusals are asserted through the machine-readable `integrity` code, never the pt-PT
//! sentence: the cause is the contract, the wording is copy.

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, router};
use serde_json::{Value, json};
use tower::ServiceExt;

const TEST_PASSWORD: &str = "Teste-Forte7!X";

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-degraded-cause-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).expect("temp dir created");
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body collects");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "{status} body is not JSON ({error}): {}",
                String::from_utf8_lossy(&bytes)
            )
        })
    };
    (status, value)
}

fn get_req(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-chancela-session", token)
        .body(Body::empty())
        .expect("request builds")
}

/// An ordinary mutation — the thing the gate exists to refuse.
fn create_entity(token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/entities")
        .header("content-type", "application/json")
        .header("x-chancela-session", token)
        .body(Body::from(
            json!({ "name": "Encosto Estratégico Lda", "nipc": "503004642", "seat": "Lisboa",
                    "kind": "SociedadePorQuotas" })
            .to_string(),
        ))
        .expect("request builds")
}

async fn bootstrap_owner(state: &AppState) -> String {
    let (status, user) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/users")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "username": "amelia.marques",
                    "display_name": "Amélia Marques",
                    "password": TEST_PASSWORD,
                })
                .to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "bootstrap owner: {user}");
    let id = user["id"].as_str().expect("owner id").to_owned();
    let (status, session) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "user_id": id, "password": TEST_PASSWORD }).to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "open session: {session}");
    session["token"].as_str().expect("token").to_owned()
}

/// An affirmatively-broken fixity verdict, built without naming a variant of the fixity enum: this
/// is a test of the GATE, and it should not go red when the detection it consumes gains a case.
fn broken_fixity() -> chancela_core::ActFixityReport {
    chancela_core::ActFixityReport {
        healthy: false,
        sealed_checked: 1,
        broken: 1,
        ..chancela_core::ActFixityReport::default()
    }
}

#[tokio::test]
async fn a_verifying_record_lifts_the_read_only_gate_again() {
    // The one-way gate. Detection could put the instance into read-only mode and nothing but a
    // restart could take it out — so an operator who repaired the data out of band was left with a
    // permanently read-only instance whose own integrity page said everything verified.
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.0.clone());
    let owner = bootstrap_owner(&state).await;
    *state.degraded.write().await = true;

    let (status, refusal) = send(&state, create_entity(&owner)).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the gate is down to begin with: {refusal}"
    );

    // The operator asks whether the record is intact. It is — and the answer is now allowed to
    // retract the gate rather than only ever raise it.
    let (status, integrity) = send(&state, get_req("/v1/ledger/integrity", &owner)).await;
    assert_eq!(status, StatusCode::OK, "{integrity}");
    assert_eq!(integrity["healthy"], true, "{integrity}");
    assert_eq!(integrity["act_fixity"]["healthy"], true, "{integrity}");
    assert_eq!(
        integrity["degraded"], false,
        "a verifying chain over verifying acts must not still report read-only: {integrity}"
    );
    assert!(
        !*state.degraded.read().await,
        "the gate must actually be lifted, not merely reported lifted"
    );

    let (status, created) = send(&state, create_entity(&owner)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "writes must resume once the record verifies: {created}"
    );
}

#[tokio::test]
async fn a_fixity_failure_refuses_with_its_own_cause_not_the_chains() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.0.clone());
    let owner = bootstrap_owner(&state).await;
    *state.act_fixity.write().await = broken_fixity();
    *state.degraded.write().await = true;

    let (status, refusal) = send(&state, create_entity(&owner)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
    assert_eq!(refusal["read_only"], true, "{refusal}");
    assert_eq!(
        refusal["integrity"], "act_fixity_broken",
        "the refusal must name the sealed-act fixity failure: {refusal}"
    );
    assert_ne!(
        refusal["integrity"], "broken",
        "claiming a broken chain sends the operator to re-anchor, which refuses with 409 because \
         the chain verifies — the dead end this distinction exists to close: {refusal}"
    );
}

#[tokio::test]
async fn a_broken_chain_keeps_the_chain_refusal_it_always_had() {
    // The fallback arm, unchanged: a broken chain still says so, and re-anchoring genuinely is its
    // remedy. The new arms are additions, not a rewrite of the refusal every operator knows.
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.0.clone());
    let owner = bootstrap_owner(&state).await;
    *state.degraded.write().await = true;

    let (status, refusal) = send(&state, create_entity(&owner)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
    assert_eq!(refusal["read_only"], true, "{refusal}");
    assert_eq!(refusal["integrity"], "broken", "{refusal}");
}

/// The other half of making the gate two-way, run once per sticky cause.
///
/// `degraded` is one bool, and only two of its causes (the chain, the sealed acts) are measurable
/// at runtime. Making those two lift the gate is only safe if the causes that are NOT measurable
/// survive the recomputation — otherwise asking the integrity endpoint a question hands back write
/// access over state the instance already knows it could not load or verify.
///
/// Each cause is a separate flag with a separate resolver, and this covers both: a shared flag
/// would let one repair clear the other's alarm, which is the same laundering one level down.
async fn a_sticky_cause_survives_a_healthy_recomputation(
    raise: fn(&AppState) -> &tokio::sync::RwLock<bool>,
) {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.0.clone());
    let owner = bootstrap_owner(&state).await;
    *raise(&state).write().await = true;
    *state.degraded.write().await = true;

    let (status, integrity) = send(&state, get_req("/v1/ledger/integrity", &owner)).await;
    assert_eq!(status, StatusCode::OK, "{integrity}");
    assert_eq!(
        integrity["healthy"], true,
        "the chain itself is fine: {integrity}"
    );
    assert_eq!(integrity["act_fixity"]["healthy"], true, "{integrity}");
    assert_eq!(
        integrity["degraded"], true,
        "the cause the recomputation cannot see must keep the gate down: {integrity}"
    );

    let (status, refusal) = send(&state, create_entity(&owner)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refusal}");
    assert_eq!(
        refusal["integrity"], "durable_state_unverified",
        "and the refusal must not blame the chain either: {refusal}"
    );
}

#[tokio::test]
async fn a_read_model_that_failed_to_load_survives_a_healthy_recomputation() {
    a_sticky_cause_survives_a_healthy_recomputation(|state| &state.degraded_read_model).await;
}

#[tokio::test]
async fn a_promotion_handoff_that_could_not_verify_survives_a_healthy_recomputation() {
    // Sharper than the read-model case: the chain this node serves from is precisely NOT the durable
    // chain the promotion refused to adopt, so "the chain verifies" is not evidence about it at all.
    a_sticky_cause_survives_a_healthy_recomputation(|state| &state.degraded_promotion_handoff)
        .await;
}
