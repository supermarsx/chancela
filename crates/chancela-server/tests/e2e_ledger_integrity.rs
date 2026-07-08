//! Journey: audit-ledger integrity and the security-invariant sweeps over full wire dumps.
//!
//! Compose a rich state (user + session, a registry import, a sealed ata, a settings change), then
//! assert `GET /v1/ledger/verify` stays valid throughout and sweep the entire ledger/users/settings
//! wire output for two invariants that must hold everywhere: the full código de acesso never appears
//! (only its masked form), and no `password` material is ever serialized.

mod common;

use common::*;
use serde_json::json;

const CODE: &str = "1234-5678-9012";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn ledger_integrity_and_secret_sweeps() {
    let registry = spawn_registry_fixture(CERTIDAO_HTML).await;
    let h =
        ServerHarness::start_with(HarnessOptions::default().with_registry(registry.url.clone()))
            .await;

    // Empty ledger verifies.
    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(verify["valid"], true);
    assert_eq!(verify["length"], 0);

    // A user + session so mutations are attributed to a real person.
    let user_id = create_user(&h, "amelia.marques", "Amélia Marques").await;
    let token = open_session(&h, &user_id).await;

    // A registry import (masked-code ledger event) and a full seal lifecycle.
    let (status, report) = h
        .post_json_auth(
            "/v1/entities/import-from-registry",
            json!({ "code": CODE }),
            &token,
        )
        .await;
    assert_eq!(status, 201, "import: {report}");
    let entity_id = report["entity"]["id"].as_str().expect("id").to_owned();

    let book_id = open_book(&h, &entity_id, &token).await;
    let act_id = draft_act(&h, &book_id, "Ata da AG", Some(&token)).await;
    fill_act_contents(&h, &act_id, &token).await;
    advance_to_signing(&h, &act_id, Some(&token)).await;
    let (status, _) = h
        // The fully-filled CSC ata (mesa set via the wire, t31) has no findings — no ack needed.
        .post_json_auth(&format!("/v1/acts/{act_id}/seal"), json!({}), &token)
        .await;
    assert_eq!(status, 200);

    // A settings change (its own auditable event).
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
                "appearance": { "theme": "dark", "leather_texture": true, "texture_intensity": 42 }
            }),
            &token,
        )
        .await;
    assert_eq!(status, 200);

    // The chain is valid, non-trivial, and every event resolves.
    let (status, verify) = h.get_json("/v1/ledger/verify").await;
    assert_eq!(status, 200);
    assert_eq!(verify["valid"], true);
    assert!(verify["length"].as_u64().expect("length") >= 9);

    // Sweep every wire dump that could carry a secret.
    let (_, events) = h.get_json("/v1/ledger/events").await;
    let (_, users) = h.get_json_auth("/v1/users", &token).await;
    let (_, settings) = h.get_json("/v1/settings").await;
    let (_, provenance) = h
        .get_json_auth(&format!("/v1/entities/{entity_id}/registry"), &token)
        .await;

    for (label, dump) in [
        ("ledger", events.to_string()),
        ("users", users.to_string()),
        ("settings", settings.to_string()),
        ("provenance", provenance.to_string()),
    ] {
        assert!(!dump.contains(CODE), "{label}: grouped access code leaked");
        assert!(
            !dump.contains("123456789012"),
            "{label}: bare access code leaked"
        );
        assert!(
            !dump.to_lowercase().contains("password"),
            "{label}: password material on the wire"
        );
    }

    // Positive control: the masked form IS present where the extract's provenance is shown.
    assert_eq!(
        provenance["provenance"]["access_code_masked"],
        "****-****-9012"
    );
}
