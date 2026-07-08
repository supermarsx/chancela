//! Journey: selected live responses shape-match the canonical `contracts/*.json` fixtures.
//!
//! Folds the "server contract" check into the E2E harness (keeping it off `chancela-api`): a rich
//! composed state is built over the real binary, then each live wire response is asserted against its
//! fixture with [`assert_shape`] (recursive key-set + JSON-type over real bytes). Drift in any handler
//! or DTO — a renamed, added, removed, or retyped field — fails here; the peer web suite (t15-e3)
//! asserts the same fixtures parse on the client, so drift breaks whichever side moved.

mod common;

use common::*;
use serde_json::json;

const CODE: &str = "1234-5678-9012";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn live_responses_match_the_canonical_contracts() {
    let registry = spawn_registry_fixture(CERTIDAO_HTML).await;
    let h =
        ServerHarness::start_with(HarnessOptions::default().with_registry(registry.url.clone()))
            .await;

    // A user + session (user.json, session.json).
    let user_id = create_user(&h, "amelia.marques", "Amélia Marques").await;
    let token = open_session(&h, &user_id).await;
    let (status, user) = h.get_json(&format!("/v1/users/{user_id}")).await;
    assert_eq!(status, 200);
    assert_shape("user", &user, &contract("user.json"));

    let (status, session) = h.get_json_auth("/v1/session", &token).await;
    assert_eq!(status, 200);
    assert_shape("session", &session, &contract("session.json"));

    // An entity (entity.json).
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
    assert_shape("entity", &entity, &contract("entity.json"));
    let entity_id = entity["id"].as_str().expect("entity id").to_owned();

    // A book (book.json).
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
    assert_shape("book", &book, &contract("book.json"));
    let book_id = book["id"].as_str().expect("book id").to_owned();

    // A sealed ata (act.sealed.json).
    let act_id = draft_act(&h, &book_id, "Ata da Assembleia Geral Anual", Some(&token)).await;
    fill_act_contents(&h, &act_id, &token).await;
    advance_to_signing(&h, &act_id, Some(&token)).await;
    let (status, _) = h
        // The fully-filled CSC ata (mesa set via the wire, t31) has no findings — no ack needed.
        .post_json_auth(&format!("/v1/acts/{act_id}/seal"), json!({}), &token)
        .await;
    assert_eq!(status, 200);
    let (status, act) = h.get_json(&format!("/v1/acts/{act_id}")).await;
    assert_eq!(status, 200);
    assert_shape("act.sealed", &act, &contract("act.sealed.json"));

    // Settings (settings.json).
    let (status, _) = h
        .put_json_auth(
            "/v1/settings",
            json!({
                "schema_version": 1,
                "organization": { "name": "Encosto Estratégico, S.A.", "default_actor": "amelia.marques" },
                "documents": { "locale": "pt-PT", "numbering_scheme_default": "Sequential" },
                "signing": {
                    "preferred_family": "CartaoCidadao",
                    "tsa_url": "https://tsa.example.pt/tsr",
                    "tsl_url": "https://tsl.example.pt/tsl.xml",
                    "require_qualified_for_seal": false
                },
                "appearance": { "theme": "system", "leather_texture": true, "texture_intensity": 60 }
            }),
            &token,
        )
        .await;
    assert_eq!(status, 200);
    let (status, settings) = h.get_json("/v1/settings").await;
    assert_eq!(status, 200);
    assert_shape("settings", &settings, &contract("settings.json"));

    // A stored registry extract (registry.extract.json).
    let (status, _) = h
        .post_json_auth(
            &format!("/v1/entities/{entity_id}/registry/import"),
            json!({ "code": CODE, "overwrite": true }),
            &token,
        )
        .await;
    assert_eq!(status, 200);
    let (status, extract) = h
        .get_json_auth(&format!("/v1/entities/{entity_id}/registry"), &token)
        .await;
    assert_eq!(status, 200);
    assert_shape(
        "registry.extract",
        &extract,
        &contract("registry.extract.json"),
    );

    // CAE single-code entry + catalog metadata (cae.entry.json, cae.catalog.json).
    let (status, cae_entry) = h.get_json("/v1/cae/68110").await;
    assert_eq!(status, 200);
    assert_shape("cae.entry", &cae_entry, &contract("cae.entry.json"));

    let (status, cae_catalog) = h.get_json("/v1/cae").await;
    assert_eq!(status, 200);
    assert_shape("cae.catalog", &cae_catalog, &contract("cae.catalog.json"));

    // The law archive manifest merged with store state (law.manifest.json). Nothing is fetched in
    // this journey, so the live entries report `stored: false` with null store fields — the
    // matcher's nullable-field permissiveness checks the populated fixture types against them.
    let (status, law) = h.get_json("/v1/law").await;
    assert_eq!(status, 200);
    assert_shape("law.manifest", &law, &contract("law.manifest.json"));

    // The ledger feed + dashboard (ledger.events.json, dashboard.json).
    let (status, events) = h.get_json("/v1/ledger/events").await;
    assert_eq!(status, 200);
    assert_shape("ledger.events", &events, &contract("ledger.events.json"));

    let (status, dashboard) = h.get_json("/v1/dashboard").await;
    assert_eq!(status, 200);
    assert_shape("dashboard", &dashboard, &contract("dashboard.json"));

    // A hot backup manifest (backup.manifest.json). The e2e server is data-dir-backed, so the
    // durable store snapshots and the manifest returns 200 (t30 §3.2).
    let (status, manifest) = h.post_json_auth("/v1/backup", json!({}), &token).await;
    assert_eq!(status, 200, "backup: {manifest}");
    assert_shape(
        "backup.manifest",
        &manifest,
        &contract("backup.manifest.json"),
    );
}
