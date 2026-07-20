//! Journey: users → session → actor attribution, and persistence across a restart.
//!
//! Proves the composed session layer: a mutation chain carrying `X-Chancela-Session` attributes
//! every ledger event to the user's `username`; the same operation WITHOUT the header is refused
//! (`401` — under the t41 hardening every mutation endpoint requires a valid session, so an
//! unauthenticated write is rejected, not downgraded to the system `"api"` actor); and across a
//! restart of the same data dir, `users.json` persists and the durable ledger (t30) reloads intact,
//! while in-memory sessions reset (the pre-restart token no longer resolves).

mod common;

use common::*;
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn users_session_actor_and_persistence_across_restart() {
    let mut h = ServerHarness::start().await;

    // A user profile, fetchable by id. RBAC (t64-E3): reading a profile is `user.read`, so sign in
    // first (the bootstrap first user is Owner\@Global; open_session records the auto-auth token).
    let user_id = create_user(&h, "amelia.marques", "Amélia Marques").await;
    let token = open_session(&h, &user_id).await;
    let (status, got) = h.get_json(&format!("/v1/users/{user_id}")).await;
    assert_eq!(status, 200);
    assert_eq!(got["username"], "amelia.marques");
    assert!(
        got.get("password_hash").is_none(),
        "reserved field never on the wire"
    );

    // A session resolves the user behind the header; without it the current user is null.
    let (status, sess) = h.get_json_auth("/v1/session", &token).await;
    assert_eq!(status, 200);
    assert_eq!(sess["user"]["username"], "amelia.marques");
    let (status, anon) = h.get_json_noauth("/v1/session").await;
    assert_eq!(status, 200);
    assert_eq!(anon["user"], Value::Null);

    // A full mutation chain WITH the session → every ledger event is attributed to "amelia.marques".
    let (status, entity) = h
        .post_json_auth(
            "/v1/entities",
            json!({
                "name": "Encosto Estratégico, S.A.",
                "nipc": "503004642",
                "seat": "Lisboa",
                "kind": "SociedadeAnonima",
            }),
            &token,
        )
        .await;
    assert_eq!(status, 201);
    let entity_id = entity["id"].as_str().expect("entity id").to_owned();

    let (status, book) = h
        .post_json_auth(
            "/v1/books",
            json!({
                "entity_id": entity_id,
                "kind": "AssembleiaGeral",
                "purpose": "livro de atas da assembleia geral",
                "opening_date": "2026-01-15",
                "required_signatories": ["Administrador"],
            }),
            &token,
        )
        .await;
    assert_eq!(status, 201);
    let book_id = book["id"].as_str().expect("book id").to_owned();

    let act_id = draft_act(&h, &book_id, "Ata da AG anual", Some(&token)).await;
    fill_act_contents(&h, &act_id, &token).await;
    advance_to_signing(&h, &act_id, Some(&token)).await;
    let (status, sealed) = h
        // The fully-filled CSC ata (mesa set via the wire, t31) has no findings — no ack needed.
        .post_json_auth(
            &format!("/v1/acts/{act_id}/seal"),
            manual_signature_seal_body("Arquivo E2E / Actor ata"),
            &token,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(sealed["ata_number"], 1);

    // Every mutation carrying the session is attributed to the user. (The `user.created` event
    // predates the session — the user was not logged in when creating their own profile — so it is
    // the system actor "api"; every entity/book/act event after login is the username.)
    let (_, events) = h.get_json("/v1/ledger/events").await;
    let chain: Vec<(String, String)> = events
        .as_array()
        .expect("events")
        .iter()
        .map(|e| {
            (
                e["kind"].as_str().unwrap_or_default().to_owned(),
                e["actor"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    for (kind, actor) in &chain {
        if kind == "user.created" {
            continue;
        }
        assert_eq!(
            actor, "amelia.marques",
            "{kind} attributed to the session user; chain={chain:?}"
        );
    }
    assert!(
        chain.iter().any(|(k, _)| k == "act.sealed"),
        "the chain reached the seal: {chain:?}"
    );

    // The same operation WITHOUT a session header is now REFUSED (t41: every mutation requires a
    // valid session). It is not downgraded to the system "api" actor — it is a 401, and nothing is
    // appended to the chain.
    let (status, refused) = h
        .post_json(
            "/v1/acts",
            json!({ "book_id": book_id, "title": "Ata sem sessão", "channel": "Physical" }),
        )
        .await;
    assert_eq!(
        status, 401,
        "an unauthenticated mutation is refused: {refused}"
    );
    let (_, events) = h.get_json("/v1/ledger/events").await;
    let api_drafts = events
        .as_array()
        .expect("events")
        .iter()
        .filter(|e| e["kind"] == "act.drafted" && e["actor"] == "api")
        .count();
    assert_eq!(
        api_drafts, 0,
        "no act.drafted is attributed to \"api\" — the unauthenticated write was rejected"
    );

    // Capture the durable ledger length before restarting: with the t30 store, the whole
    // hash chain survives a restart (it no longer resets).
    let (_, before) = h.get_json("/v1/ledger/verify").await;
    let length_before = before["length"].clone();
    assert_ne!(
        length_before,
        json!(0),
        "the chain has events before restart"
    );

    // Restart over the same data dir: users.json persists; the old token no longer resolves
    // (sessions are in-memory); and the durable ledger reloads intact.
    h.restart().await;

    // The old token is dead (in-memory sessions reset), and `GET /v1/users` is auth-gated (t41), so
    // re-open a session for the persisted user to read the list back.
    let fresh_token = open_session(&h, &user_id).await;
    let (status, list) = h.get_json_auth("/v1/users", &fresh_token).await;
    assert_eq!(status, 200);
    assert!(
        list.as_array()
            .expect("users list")
            .iter()
            .any(|u| u["username"] == "amelia.marques"),
        "users.json persisted across restart"
    );

    // The pre-restart bearer still resolves: sessions live in the shared session authority, and a
    // restarted node reconstructs IDENTITY from it (deliberately without the unlocked signing key —
    // that requires signing in on this process again). It must reconstruct the *same* identity.
    let (status, sess) = h.get_json_auth("/v1/session", &token).await;
    assert_eq!(status, 200);
    assert_eq!(
        sess["user"]["username"], "amelia.marques",
        "the restarted node reconstructs the caller's identity, not somebody else's: {sess}"
    );

    // Reconstruction is not leniency: a bearer that was never issued still resolves to nothing.
    let (status, forged) = h
        .get_json_auth("/v1/session", "not-a-token-that-was-ever-issued")
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        forged["user"],
        Value::Null,
        "an unissued bearer never resolves to a session: {forged}"
    );

    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(
        verify["valid"], true,
        "the durable chain still verifies after restart"
    );
    assert_eq!(
        verify["length"], length_before,
        "the durable ledger (t30) survived the restart intact"
    );
}
