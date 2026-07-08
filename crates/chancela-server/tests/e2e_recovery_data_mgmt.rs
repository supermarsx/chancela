//! Journey (t54 acceptance): chain-integrity recovery + data-management over the real server.
//!
//! Two composed-system journeys the layer-isolated tests can't exercise.
//!
//! **Degraded gate then re-anchor repair.** Build a domain, tamper a stored event byte on disk, and
//! restart. The server boots into DEGRADED read-only mode: `/health` reports `integrity:"broken"`
//! and `degraded:true`, `GET /v1/ledger/integrity` pinpoints the break, an ordinary mutation is
//! blocked with `503`, but reads and the recovery plane stay open. A `POST
//! /v1/ledger/recovery/reanchor` (last-resort) requires step-up re-auth (a session alone is `403`),
//! then repairs the chain, lifts the gate, and mutations flow again — with the re-anchor permanently
//! disclosed.
//!
//! **Destructive data-management with step-up re-auth.** A `backend_domain` wipe requires a
//! type-to-confirm phrase AND step-up re-auth (a session alone is refused with `403`); on success
//! the domain is cleared but the append-only ledger is preserved with a chained `data.wiped`.

mod common;

use common::*;
use serde_json::json;

/// Seed an entity → book → sealed ata #1, returning `(entity_id, book_id)`.
async fn seed_domain(h: &ServerHarness, token: &str) -> (String, String) {
    let entity_id = create_entity(
        h,
        "Encosto Estratégico, S.A.",
        "503004642",
        "Lisboa",
        "SociedadeAnonima",
        token,
    )
    .await;
    let book_id = open_book(h, &entity_id, token).await;
    let act_id = draft_act(h, &book_id, "Ata da Assembleia Geral Anual", Some(token)).await;
    fill_act_contents(h, &act_id, token).await;
    advance_to_signing(h, &act_id, Some(token)).await;
    let (status, _) = h
        .post_json_auth(&format!("/v1/acts/{act_id}/seal"), json!({}), token)
        .await;
    assert_eq!(status, 200, "seal ata #1");
    (entity_id, book_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn a_broken_chain_gates_mutations_then_reanchor_repairs_and_reopens() {
    let mut h = ServerHarness::start().await;
    // A signed-in operator WITH a password, set now (while healthy): the last-resort re-anchor now
    // requires step-up re-auth, and once the instance boots degraded a domain mutation like setting a
    // secret is 503-gated — so the credential must exist before the restart. The user (and its
    // password) persist across the restart in the durable roster.
    let user_id = create_user(&h, "e2e.operator", "E2E Operator").await;
    let token = open_session(&h, &user_id).await;
    let (status, _) = h
        .post_json_auth(
            &format!("/v1/users/{user_id}/secret"),
            json!({ "password": "Reancorar-Cadeia5!" }),
            &token,
        )
        .await;
    assert_eq!(status, 200, "set operator password");
    let (entity_id, _book_id) = seed_domain(&h, &token).await;

    // Healthy baseline: the integrity report is clean and not degraded.
    let (status, report) = h.get_json("/v1/ledger/integrity").await;
    assert_eq!(status, 200);
    assert_eq!(report["healthy"], true);
    assert_eq!(report["degraded"], false);

    // --- Tamper a stored event byte on disk, then restart into the degraded state ---------------
    h.stop();
    let db_path = h.data_dir.join(chancela_store::DB_FILE);
    {
        let conn = rusqlite::Connection::open(&db_path).expect("open store db");
        let mut digest: Vec<u8> = conn
            .query_row("SELECT payload_digest FROM events WHERE seq = 1", [], |r| {
                r.get(0)
            })
            .expect("read event digest");
        digest[0] ^= 0xff;
        let rows = conn
            .execute(
                "UPDATE events SET payload_digest = ?1 WHERE seq = 1",
                rusqlite::params![digest],
            )
            .expect("tamper event row");
        assert_eq!(rows, 1);
    }
    h.start_again().await;

    // Re-authenticate BEFORE the gated reads below: the in-memory session dropped on restart, and the
    // operator holds a password so the harness' passwordless auto-reopen cannot sign in — do it
    // explicitly WITH the password (the session endpoint stays open even while degraded). RBAC
    // (t64-E3): the integrity report and entity reads below are permission-gated (`ledger.read` /
    // `entity.read`), so the operator must be signed in.
    let user_id = create_user_or_signin(&h).await;
    let (status, s) = h
        .post_json(
            "/v1/session",
            json!({ "user_id": user_id, "password": "Reancorar-Cadeia5!" }),
        )
        .await;
    assert_eq!(status, 200, "re-open session with password: {s}");
    let token = s["token"].as_str().expect("session token").to_owned();
    h.set_default_token(&token);

    // /health + the integrity report both report the broken, degraded chain.
    let (_, health) = h.get_json("/health").await;
    assert_eq!(health["persistent"], true);
    assert_eq!(health["integrity"], "broken");
    assert_eq!(health["degraded"], true);
    let (status, report) = h.get_json("/v1/ledger/integrity").await;
    assert_eq!(status, 200);
    assert_eq!(report["healthy"], false);
    assert_eq!(report["degraded"], true);
    assert!(
        report["global"]["first_break"].is_object(),
        "the integrity report pinpoints the break: {report}"
    );

    // An ordinary mutation is blocked with 503 + the honest read-only body.
    let (status, body) = h
        .post_json_auth(
            "/v1/entities",
            json!({ "name": "Nova, S.A.", "nipc": "500000000", "seat": "Porto", "kind": "SociedadeAnonima" }),
            &token,
        )
        .await;
    assert_eq!(status, 503, "mutation gated while degraded: {body}");
    assert_eq!(body["read_only"], true);
    assert_eq!(body["integrity"], "broken");

    // Reads stay fully served (the operator can inspect).
    let (status, entity) = h.get_json(&format!("/v1/entities/{entity_id}")).await;
    assert_eq!(status, 200, "reads open while degraded: {entity}");

    // Re-anchor now requires step-up re-auth (like the destructive wipes): a session alone is 403.
    let (status, _) = h
        .post_json_auth(
            "/v1/ledger/recovery/reanchor",
            json!({ "reason": "cópia de segurança indisponível — re-ancoragem autorizada" }),
            &token,
        )
        .await;
    assert_eq!(status, 403, "reanchor with a session alone is refused");

    // Re-anchor (last-resort recovery) with valid step-up repairs the chain and is permanently
    // disclosed.
    let (status, resp) = h
        .post_json_auth(
            "/v1/ledger/recovery/reanchor",
            json!({
                "reason": "cópia de segurança indisponível — re-ancoragem autorizada",
                "reauth": { "password": "Reancorar-Cadeia5!" }
            }),
            &token,
        )
        .await;
    assert_eq!(status, 200, "reanchor repairs the chain: {resp}");
    assert_eq!(resp["integrity"]["healthy"], true);
    assert_eq!(resp["integrity"]["degraded"], false);
    assert!(resp["record"]["reason"].is_string());

    // The gate is lifted: /health is ok again and a mutation now flows.
    let (_, health) = h.get_json("/health").await;
    assert_eq!(health["integrity"], "ok");
    assert_eq!(health["degraded"], false);
    let (status, created) = h
        .post_json_auth(
            "/v1/entities",
            json!({ "name": "Nova, S.A.", "nipc": "500000000", "seat": "Porto", "kind": "SociedadeAnonima" }),
            &token,
        )
        .await;
    assert_eq!(status, 201, "mutations flow after repair: {created}");

    // The re-anchor is permanently disclosed on the integrity report.
    let (_, report) = h.get_json("/v1/ledger/integrity").await;
    assert!(
        !report["reanchored_segments"]
            .as_array()
            .expect("segments")
            .is_empty(),
        "the re-anchor is permanently disclosed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn a_passwordless_owner_recovers_a_degraded_instance_without_step_up() {
    // t69 lockout fix over the real server: the first user (Owner\@Global) is PASSWORDLESS and holds
    // no recovery phrase. When the chain breaks and the instance boots degraded, this operator can
    // still re-anchor with a SESSION ALONE (no step-up proof) — a passwordless user's self session IS
    // the strongest proof they can offer. Without the fix, a passwordless-only instance whose chain
    // breaks could never be recovered by anyone.
    let mut h = ServerHarness::start().await;
    let user_id = create_user(&h, "amelia.marques", "Amélia Marques").await; // first user = Owner
    let token = open_session(&h, &user_id).await; // passwordless session
    let (entity_id, _book_id) = seed_domain(&h, &token).await;

    // --- Tamper a stored event byte on disk, then restart into the degraded state ------------------
    h.stop();
    let db_path = h.data_dir.join(chancela_store::DB_FILE);
    {
        let conn = rusqlite::Connection::open(&db_path).expect("open store db");
        let mut digest: Vec<u8> = conn
            .query_row("SELECT payload_digest FROM events WHERE seq = 1", [], |r| {
                r.get(0)
            })
            .expect("read event digest");
        digest[0] ^= 0xff;
        let rows = conn
            .execute(
                "UPDATE events SET payload_digest = ?1 WHERE seq = 1",
                rusqlite::params![digest],
            )
            .expect("tamper event row");
        assert_eq!(rows, 1);
    }
    h.start_again().await;

    // Re-open a PASSWORDLESS session (the in-memory session dropped on restart; the user holds no
    // password, so a plain passwordless sign-in works — and the session endpoint stays open while
    // degraded).
    let user_id = create_user_or_signin(&h).await;
    let token = open_session(&h, &user_id).await;

    // The instance booted degraded and pinpoints the break.
    let (_, health) = h.get_json("/health").await;
    assert_eq!(health["integrity"], "broken");
    assert_eq!(health["degraded"], true);
    let (status, report) = h.get_json("/v1/ledger/integrity").await;
    assert_eq!(status, 200);
    assert_eq!(report["healthy"], false);
    assert!(
        report["global"]["first_break"].is_object(),
        "the integrity report pinpoints the break: {report}"
    );

    // An ordinary mutation is still 503-gated (the passwordless carve-out relaxes step-up, never the
    // degraded read-only gate).
    let (status, body) = h
        .post_json_auth(
            "/v1/entities",
            json!({ "name": "Nova, S.A.", "nipc": "500000000", "seat": "Porto", "kind": "SociedadeAnonima" }),
            &token,
        )
        .await;
    assert_eq!(status, 503, "mutation gated while degraded: {body}");

    // t69: re-anchor with a SESSION ALONE (no reauth) → 200. The passwordless Owner is NOT 403'd for
    // lacking a credential they never set; recovery proceeds and is permanently disclosed.
    let (status, resp) = h
        .post_json_auth(
            "/v1/ledger/recovery/reanchor",
            json!({ "reason": "instância só com utilizadores sem palavra-passe — recuperação autorizada" }),
            &token,
        )
        .await;
    assert_eq!(
        status, 200,
        "passwordless Owner re-anchors without step-up: {resp}"
    );
    assert_eq!(resp["integrity"]["healthy"], true);
    assert_eq!(resp["integrity"]["degraded"], false);

    // The gate is lifted: mutations flow again.
    let (status, created) = h
        .post_json_auth(
            "/v1/entities",
            json!({ "name": "Nova, S.A.", "nipc": "500000000", "seat": "Porto", "kind": "SociedadeAnonima" }),
            &token,
        )
        .await;
    assert_eq!(status, 201, "mutations flow after repair: {created}");
    let _ = entity_id;

    // The re-anchor is permanently disclosed on the integrity report (recovery discloses, never erases).
    let (_, report) = h.get_json("/v1/ledger/integrity").await;
    assert!(
        !report["reanchored_segments"]
            .as_array()
            .expect("segments")
            .is_empty(),
        "the re-anchor is permanently disclosed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn backend_domain_wipe_requires_step_up_reauth_and_preserves_the_ledger() {
    let h = ServerHarness::start().await;

    // A signed-in operator WITH a password (self-service first-secret is free), for step-up re-auth.
    let user_id = create_user(&h, "amelia.marques", "Amélia Marques").await;
    let token = open_session(&h, &user_id).await;
    let (status, _) = h
        .post_json_auth(
            &format!("/v1/users/{user_id}/secret"),
            json!({ "password": "Limpar-Dados6!X" }),
            &token,
        )
        .await;
    assert_eq!(status, 200, "set first password");

    let (entity_id, _book_id) = seed_domain(&h, &token).await;
    let (_, verify_before) = h.get_json("/v1/ledger/verify").await;
    let len_before = verify_before["length"].as_u64().expect("len");

    // A session alone (no re-auth) is refused with 403 — the double-confirm + step-up is mandatory.
    let (status, _) = h
        .post_json_auth(
            "/v1/data/reset",
            json!({ "scope": "backend_domain", "confirm_phrase": "LIMPAR DADOS", "export_first": true }),
            &token,
        )
        .await;
    assert_eq!(status, 403, "session alone is not enough");

    // Confirm phrase + step-up re-auth → the domain wipe proceeds (ledger preserved).
    let (status, resp) = h
        .post_json_auth(
            "/v1/data/reset",
            json!({
                "scope": "backend_domain",
                "confirm_phrase": "LIMPAR DADOS",
                "export_first": true,
                "reauth": { "password": "Limpar-Dados6!X" }
            }),
            &token,
        )
        .await;
    assert_eq!(status, 200, "domain wipe: {resp}");
    assert!(
        resp["export_archive"].is_string(),
        "export-first archive retained"
    );

    // Domain data cleared; the append-only ledger PRESERVED and grew a chained data.wiped.
    let (status, gone) = h.get_json(&format!("/v1/entities/{entity_id}")).await;
    assert_eq!(status, 404, "domain cleared: {gone}");
    let (_, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(verify["valid"], true, "ledger still verifies");
    assert!(
        verify["length"].as_u64().expect("len") > len_before,
        "ledger preserved and grew (data.wiped)"
    );
    let kinds = ledger_kinds(&h).await;
    assert!(
        kinds.iter().any(|k| k == "data.wiped"),
        "a data.wiped event was chained: {kinds:?}"
    );
}

/// Create a fresh operator (post-restart, when the in-memory session is gone) or, if the first-run
/// bootstrap is no longer available, sign in as an existing roster user. Returns a user id ready to
/// open a session with.
async fn create_user_or_signin(h: &ServerHarness) -> String {
    let (status, roster) = h.get_json("/v1/session/roster").await;
    assert_eq!(status, 200);
    if let Some(first) = roster["users"].as_array().and_then(|u| u.first()) {
        return first["id"].as_str().expect("roster user id").to_owned();
    }
    create_user(h, "recovery.operator", "Recovery Operator").await
}
