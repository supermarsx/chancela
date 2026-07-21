//! t88 — the audit (attestation) key is generated **at account creation**.
//!
//! The key is a P-256 scalar wrapped under a KEK derived from the user's password, so it can only
//! ever be created by someone holding that password in plaintext. Creation is the one moment an
//! administrator legitimately holds it. These tests pin what that buys and what it costs:
//!
//!  1. a created account has a usable key immediately — not a promise to generate one later;
//!  2. the key is genuinely bound to the initial password (it unlocks at sign-in, and attests);
//!  3. changing the password re-wraps the SAME key rather than orphaning or silently dropping it;
//!  4. the `user.created` event is digested over the `UserView` — which records **that** a key
//!     exists — and not over the full `User`, which carries the argon2 verifier and the wrapped
//!     blob (KEK salt, nonce, ciphertext).
//!
//! On (4): `Ledger::append` hashes the payload into `payload_digest` and drops the bytes, so this
//! was never a disclosure — the payload is unreadable either way. It is asserted because the
//! preimage should describe the audited fact, and because the handler is the one user endpoint
//! that fed the whole struct in; a refactor is more likely to restore that than to invent it.

mod common;

use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

use common::TEST_PASSWORD;

/// A private data directory for one test (removed on the way out).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("chancela-t88-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("test data dir");
        TempDir(dir)
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
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, value)
}

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn post_as(uri: &str, body: Value, token: &str) -> Request<Body> {
    let mut req = post_json(uri, body);
    req.headers_mut()
        .insert("x-chancela-session", token.parse().expect("header"));
    req
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("request builds")
}

/// The ledger feed and the attestation verify endpoint both require a session (`ledger.read`).
fn get_as(uri: &str, token: &str) -> Request<Body> {
    let mut req = get(uri);
    req.headers_mut()
        .insert("x-chancela-session", token.parse().expect("header"));
    req
}

/// Bootstrap an Owner and return `(user_id, session_token)`.
async fn bootstrap_owner(state: &AppState) -> (String, String) {
    let (status, created) = send(
        state.clone(),
        post_json(
            "/api/v1/users",
            json!({ "username": "amelia.marques", "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "owner bootstraps: {created}");
    let user_id = created["id"].as_str().expect("id").to_owned();

    let (status, session) = send(
        state.clone(),
        post_json(
            "/api/v1/session",
            json!({ "user_id": user_id, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner signs in: {session}");
    let token = session["token"].as_str().expect("token").to_owned();
    (user_id, token)
}

#[tokio::test]
async fn a_created_account_already_has_an_audit_key() {
    let dir = TempDir::new("has-key");
    let state = AppState::with_data_dir(&dir.0);
    let (owner_id, owner) = bootstrap_owner(&state).await;

    // The bootstrap create takes the same path, so the very first user has one too — an instance
    // whose Owner has no key could never attest its own founding events.
    let (status, view) = send(
        state.clone(),
        post_as(
            "/api/v1/users",
            json!({ "username": "bruno.dias", "password": TEST_PASSWORD }),
            &owner,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "user created: {view}");
    assert_eq!(
        view["has_attestation_key"],
        json!(true),
        "created with a key: {view}"
    );
    let fingerprint = view["attestation_key_fingerprint"]
        .as_str()
        .expect("fingerprint published")
        .to_owned();
    assert_eq!(fingerprint.len(), 32, "32-hex fingerprint: {fingerprint}");

    let users = state.users.read().await;
    let owner_key = users
        .get(&chancela_api::UserId(owner_id.parse().expect("owner uuid")))
        .expect("owner stored")
        .attestation_key
        .as_ref();
    assert!(owner_key.is_some(), "the bootstrap user has a key too");

    // Two accounts created with the SAME password must not share a keypair: the scalar is random
    // and only its wrapping is password-derived.
    assert_ne!(
        owner_key.expect("owner key").fingerprint,
        fingerprint,
        "each account gets its own keypair"
    );
}

#[tokio::test]
async fn the_key_is_usable_at_first_sign_in_with_no_further_action() {
    let dir = TempDir::new("usable");
    let state = AppState::with_data_dir(&dir.0);
    let (_, owner) = bootstrap_owner(&state).await;

    let (status, view) = send(
        state.clone(),
        post_as(
            "/api/v1/users",
            json!({ "username": "bruno.dias", "password": TEST_PASSWORD }),
            &owner,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "user created: {view}");
    let user_id = view["id"].as_str().expect("id").to_owned();
    let stored = state
        .users
        .read()
        .await
        .get(&chancela_api::UserId(user_id.parse().expect("uuid")))
        .expect("stored")
        .attestation_key
        .clone()
        .expect("key at rest");

    // The proof the key is bound to the password the ADMIN chose: signing in with that password
    // unwraps the scalar. If the wrapping secret were anything else, this errors rather than 200.
    let (status, session) = send(
        state.clone(),
        post_json(
            "/api/v1/session",
            json!({ "user_id": user_id, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "new user signs in: {session}");

    stored
        .unlock(TEST_PASSWORD)
        .expect("unlocks under the password the admin chose");
    assert!(
        stored.unlock("a-different-password").is_err(),
        "it does not unwrap under any other password"
    );
}

#[tokio::test]
async fn changing_the_password_rewraps_the_same_key_rather_than_dropping_it() {
    let dir = TempDir::new("rewrap");
    let state = AppState::with_data_dir(&dir.0);
    let (_, owner) = bootstrap_owner(&state).await;

    let (status, view) = send(
        state.clone(),
        post_as(
            "/api/v1/users",
            json!({ "username": "bruno.dias", "password": TEST_PASSWORD }),
            &owner,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "user created: {view}");
    let user_id = view["id"].as_str().expect("id").to_owned();
    let original = view["attestation_key_fingerprint"]
        .as_str()
        .expect("fingerprint")
        .to_owned();

    // The user changes the admin-chosen password — the action the UI tells them to take.
    let new_password = "Cascata-Prudente-71";
    let (status, session) = send(
        state.clone(),
        post_json(
            "/api/v1/session",
            json!({ "user_id": user_id, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "signs in: {session}");
    let token = session["token"].as_str().expect("token").to_owned();

    let (status, updated) = send(
        state.clone(),
        post_as(
            &format!("/api/v1/users/{user_id}/secret"),
            json!({ "password": new_password, "current_password": TEST_PASSWORD }),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "password changed: {updated}");

    // The key SURVIVES, with the same identity — past attestations stay verifiable — but it is now
    // wrapped under a secret the creating administrator never held.
    assert_eq!(
        updated["has_attestation_key"],
        json!(true),
        "key not dropped: {updated}"
    );
    assert_eq!(
        updated["attestation_key_fingerprint"],
        json!(original),
        "same keypair, re-wrapped: {updated}"
    );

    let stored = state
        .users
        .read()
        .await
        .get(&chancela_api::UserId(user_id.parse().expect("uuid")))
        .expect("stored")
        .attestation_key
        .clone()
        .expect("key still present");
    assert!(
        stored.unlock(new_password).is_ok(),
        "unwraps under the new password"
    );
    assert!(
        stored.unlock(TEST_PASSWORD).is_err(),
        "the initial password no longer opens it"
    );
}

#[tokio::test]
async fn the_creation_event_records_that_a_key_exists_and_no_material_that_wraps_it() {
    let dir = TempDir::new("ledger");
    let state = AppState::with_data_dir(&dir.0);
    let (_, owner) = bootstrap_owner(&state).await;

    let (status, view) = send(
        state.clone(),
        post_as(
            "/api/v1/users",
            json!({ "username": "bruno.dias", "password": TEST_PASSWORD }),
            &owner,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "user created: {view}");

    let ledger = state.ledger.read().await;
    let created = ledger
        .events()
        .iter()
        .filter(|e| e.kind == "user.created")
        .next_back()
        .expect("a user.created event")
        .clone();
    drop(ledger);

    // `Event` keeps only `payload_digest` — `Ledger::append` hashes the bytes and drops them — so
    // the payload cannot be read back and asserted on directly. What CAN be pinned is which
    // serialization the digest was taken over, and that is exactly the regression worth catching:
    // reverting to `serde_json::to_vec(&user)` would put the argon2 verifier and the wrapped key
    // blob (KEK salt, nonce, ciphertext) back into the hash preimage.
    let stored = state
        .users
        .read()
        .await
        .get(&chancela_api::UserId(
            view["id"].as_str().expect("id").parse().expect("uuid"),
        ))
        .expect("stored")
        .clone();
    let full_user_digest: [u8; 32] =
        Sha256::digest(serde_json::to_vec(&stored).expect("User serializes")).into();
    assert_ne!(
        created.payload_digest, full_user_digest,
        "the create event must not be digested over the full `User`"
    );

    // (No positive digest equality here: rebuilding the exact preimage would mean re-serializing a
    // `serde_json::Value`, whose key order is not the struct's declaration order, so the comparison
    // would pin JSON formatting rather than content.)
    assert_eq!(
        view["has_attestation_key"],
        json!(true),
        "and that view records that creation produced a key: {view}"
    );

    // The justification is a fixed string, so nothing about the credential reaches the one event
    // field that IS persisted verbatim.
    let justification = created.justification.clone().unwrap_or_default();
    assert_eq!(justification, "user created");
    assert!(!justification.contains(TEST_PASSWORD));
}

/// **Rotation must NOT destroy the account's attestation history.** Reported by t89-edituser from
/// a static read of `ledger.rs:245-254`, then executed here — this test asserted the defect until
/// t92 fixed it, and now asserts the fix in the same round trip.
///
/// The defect: the verifying public key was looked up by fingerprint across users' *current* keys
/// only, and `User.attestation_key` is a single `Option` that regenerate replaces. A rotation
/// therefore stranded every signature the previous key had produced — correct signatures, intact
/// chain hashes, and an `invalid` verdict.
///
/// The fix (t92): the superseded key's **public half** is retained on the user
/// (`User::retire_attestation_key`) and the lookup searches current *and* retired keys. The secret
/// scalar still goes away with the blob, so a retired key verifies the past and can never sign
/// again. Retention starts at the change: an attestation whose key was rotated before it shipped
/// is genuinely unverifiable and still reports so.
#[tokio::test]
async fn rotating_the_key_keeps_attestations_the_old_key_signed_verifiable() {
    let dir = TempDir::new("rotate");
    let state = AppState::with_data_dir(&dir.0);
    let (owner_id, owner) = bootstrap_owner(&state).await;

    // A mutation signed under the key the account was created with.
    let (status, entity) = send(
        state.clone(),
        post_as(
            "/api/v1/entities",
            json!({
                "name": "Encosto Estratégico Lda",
                "nipc": "503004642",
                "seat": "Lisboa",
                "kind": "SociedadeAnonima",
            }),
            &owner,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "entity created: {entity}");

    let (_, events) = send(state.clone(), get_as("/api/v1/ledger/events", &owner)).await;
    let created = events
        .as_array()
        .expect("events")
        .iter()
        .find(|e| e["kind"] == "entity.created")
        .expect("entity.created present")
        .clone();
    assert!(
        !created["attestation"].is_null(),
        "the event was attested by the creation-time key: {created}"
    );
    let seq = created["seq"].as_u64().expect("seq");

    // Valid before the rotation.
    let (status, before) = send(
        state.clone(),
        get_as(&format!("/api/v1/ledger/attestations/{seq}"), &owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        before["valid"],
        json!(true),
        "valid before rotate: {before}"
    );

    // Rotate. Same password, self-service — nothing exceptional, exactly what the edit screen's
    // "Rodar chave" does.
    let (status, rotated) = send(
        state.clone(),
        post_as(
            &format!("/api/v1/users/{owner_id}/attestation-key"),
            json!({ "current_password": TEST_PASSWORD }),
            &owner,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "key rotated: {rotated}");
    assert_ne!(
        rotated["attestation_key_fingerprint"], before["attestation"]["fingerprint"],
        "rotation mints a new keypair"
    );

    // The chain is untouched, the signature is still correct — and the key that verifies it is
    // still reachable, because rotation retired its public half instead of discarding it.
    let (status, after) = send(
        state.clone(),
        get_as(&format!("/api/v1/ledger/attestations/{seq}"), &owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        after["valid"],
        json!(true),
        "a correctly-signed attestation survives the rotation: {after}"
    );
    assert!(after["reason"].is_null(), "and no reason is given: {after}");
    assert_eq!(
        after["attestation"]["fingerprint"], before["attestation"]["fingerprint"],
        "still attributed to the key that actually signed it, not the new one: {after}"
    );
}

/// A chain of rotations, not just one: every key an account has ever used must keep verifying what
/// it signed. One retained key could be an accident of ordering; three cannot.
#[tokio::test]
async fn every_key_in_a_rotation_chain_still_verifies_what_it_signed() {
    let dir = TempDir::new("chain");
    let state = AppState::with_data_dir(&dir.0);
    let (owner_id, owner) = bootstrap_owner(&state).await;

    // Three generations of key, each signing one entity before it is superseded.
    let nipcs = ["503004642", "500000000", "501442600"];
    let mut signed: Vec<(u64, String)> = Vec::new(); // (seq, fingerprint that signed it)
    let mut owner = owner;

    for (i, nipc) in nipcs.iter().enumerate() {
        let (status, entity) = send(
            state.clone(),
            post_as(
                "/api/v1/entities",
                json!({
                    "name": format!("Encosto Estratégico {} Lda", i + 1),
                    "nipc": nipc,
                    "seat": "Lisboa",
                    "kind": "SociedadeAnonima",
                }),
                &owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "entity {i} created: {entity}");

        let (_, events) = send(state.clone(), get_as("/api/v1/ledger/events", &owner)).await;
        let created = events
            .as_array()
            .expect("events")
            .iter()
            .filter(|e| e["kind"] == "entity.created")
            .next_back()
            .expect("entity.created present")
            .clone();
        signed.push((
            created["seq"].as_u64().expect("seq"),
            created["attestation"]["fingerprint"]
                .as_str()
                .expect("fingerprint")
                .to_owned(),
        ));

        // Rotate after each of the first two; the third stays current.
        if i + 1 < nipcs.len() {
            let (status, rotated) = send(
                state.clone(),
                post_as(
                    &format!("/api/v1/users/{owner_id}/attestation-key"),
                    json!({ "current_password": TEST_PASSWORD }),
                    &owner,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "rotation {i} succeeds: {rotated}");

            // A session unlocks the signing key AT SIGN-IN and keeps it in memory, so the existing
            // token would go on signing with the key that was just retired. Sign in again to pick
            // up the new one — otherwise this test would rotate three times and still produce
            // three attestations from one key.
            let (status, session) = send(
                state.clone(),
                post_json(
                    "/api/v1/session",
                    json!({ "user_id": owner_id, "password": TEST_PASSWORD }),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "re-signs in: {session}");
            owner = session["token"].as_str().expect("token").to_owned();
        }
    }

    // Three DISTINCT keys signed the three events.
    let fingerprints: std::collections::HashSet<&str> =
        signed.iter().map(|(_, f)| f.as_str()).collect();
    assert_eq!(
        fingerprints.len(),
        3,
        "three generations of key: {signed:?}"
    );

    // All three attestations verify — the two retired keys and the current one alike.
    for (seq, fingerprint) in &signed {
        let (status, v) = send(
            state.clone(),
            get_as(&format!("/api/v1/ledger/attestations/{seq}"), &owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            v["valid"],
            json!(true),
            "seq {seq}, signed by {fingerprint}, still verifies: {v}"
        );
        assert_eq!(v["attestation"]["fingerprint"], json!(fingerprint));
    }
}

/// Retention keeps the public half and **nothing else**. Asserted against the stored shape and the
/// bytes actually written to `users.json`, not against the type's documentation: the whole safety
/// argument for retaining keys forever is that there is no secret in what is retained.
#[tokio::test]
async fn retiring_a_key_retains_no_secret_material() {
    let dir = TempDir::new("no-secrets");
    let state = AppState::with_data_dir(&dir.0);
    let (owner_id, owner) = bootstrap_owner(&state).await;

    let uid = chancela_api::UserId(owner_id.parse().expect("owner uuid"));
    let superseded = state
        .users
        .read()
        .await
        .get(&uid)
        .expect("owner stored")
        .attestation_key
        .clone()
        .expect("owner has a key");

    let (status, rotated) = send(
        state.clone(),
        post_as(
            &format!("/api/v1/users/{owner_id}/attestation-key"),
            json!({ "current_password": TEST_PASSWORD }),
            &owner,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "key rotated: {rotated}");

    let retired = state
        .users
        .read()
        .await
        .get(&uid)
        .expect("owner stored")
        .retired_attestation_keys
        .clone();
    assert_eq!(retired.len(), 1, "exactly the outgoing key: {retired:?}");
    let entry = &retired[0];
    assert_eq!(entry.fingerprint, superseded.fingerprint);
    assert_eq!(entry.public_key_sec1, superseded.public_key_sec1);

    // Serialize the retained entry and assert the three fields that WRAP THE SCALAR are absent.
    // A future field added to the retired type would have to be justified against this.
    let json = serde_json::to_value(entry).expect("retired key serializes");
    let mut keys = json
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["fingerprint", "public_key_sec1", "retired_at"],
        "the retained shape is exactly the public half plus a timestamp: {json}"
    );

    // And the same at rest: the superseded blob's wrapping material is nowhere in `users.json`.
    // (The CURRENT key's own salt/nonce/ciphertext are still there, as they must be — these three
    // values belong to the key that was just retired.)
    let on_disk = std::fs::read_to_string(dir.0.join("users.json")).expect("users.json");
    for secret in [
        &superseded.kdf_salt,
        &superseded.nonce,
        &superseded.ciphertext,
    ] {
        assert!(
            !on_disk.contains(secret.as_str()),
            "no wrapping material from the superseded key survives on disk"
        );
    }
    assert!(
        on_disk.contains(&superseded.public_key_sec1),
        "but its public half does — that is the point"
    );
}

/// **Retiring a key does not stop a session that already holds it** (found by t88 while reviewing
/// t92's retention work). Pinned because the behaviour is surprising and, since retention, no
/// longer self-announcing.
///
/// `create_session` unlocks the scalar at sign-in and keeps it for the life of the token
/// (`session.rs:790`), and nothing in `users.rs` touches the session layer — so removing the key
/// at rest leaves an existing session signing with it. Before retention such a signature failed to
/// verify ("signing key not found"), which at least made the window visible; now the fingerprint
/// is retained and the verdict is `valid`. The signature genuinely was produced by that key, so
/// `valid` is not wrong — but it means the only remaining evidence of the window is this test.
///
/// This asserts the CURRENT behaviour. It is not an endorsement: closing the gap means resolving
/// the key per request, as `roles::effective_permissions_for` already does for authority. If that
/// changes, this test should flip to assert no attestation is produced at all.
#[tokio::test]
async fn a_live_session_keeps_signing_with_a_retired_key() {
    let dir = TempDir::new("live-session");
    let state = AppState::with_data_dir(&dir.0);
    let (owner_id, owner) = bootstrap_owner(&state).await;

    // Remove the key at rest, using the session that is holding the unlocked copy.
    let removal = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/users/{owner_id}/attestation-key"))
        .header("content-type", "application/json")
        .header("x-chancela-session", &owner)
        .body(Body::from(
            json!({ "current_password": TEST_PASSWORD }).to_string(),
        ))
        .expect("request builds");
    let (status, view) = send(state.clone(), removal).await;
    assert_eq!(status, StatusCode::OK, "key removed: {view}");
    assert_eq!(view["has_attestation_key"], json!(false));

    // That SAME session now makes a mutation.
    let (status, entity) = send(
        state.clone(),
        post_as(
            "/api/v1/entities",
            json!({
                "name": "Encosto Estratégico Lda",
                "nipc": "503004642",
                "seat": "Lisboa",
                "kind": "SociedadeAnonima",
            }),
            &owner,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "entity created: {entity}");

    let (_, events) = send(state.clone(), get_as("/api/v1/ledger/events", &owner)).await;
    let created = events
        .as_array()
        .expect("events")
        .iter()
        .filter(|e| e["kind"] == "entity.created")
        .next_back()
        .expect("entity.created present")
        .clone();

    // The event IS attested — the removal did not reach the session's in-memory key.
    assert!(
        !created["attestation"].is_null(),
        "a removed key still signs from a live session: {created}"
    );
    let seq = created["seq"].as_u64().expect("seq");

    // And because the public half is retained, that post-removal signature verifies.
    let (status, verdict) = send(
        state.clone(),
        get_as(&format!("/api/v1/ledger/attestations/{seq}"), &owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        verdict["valid"],
        json!(true),
        "post-removal signature verifies against the retained fingerprint: {verdict}"
    );

    // The user holds no key at rest — the signing capability lives only in the open session.
    let stored = state
        .users
        .read()
        .await
        .get(&chancela_api::UserId(owner_id.parse().expect("owner uuid")))
        .expect("owner stored")
        .clone();
    assert!(stored.attestation_key.is_none());
    assert_eq!(stored.retired_attestation_keys.len(), 1);
}
