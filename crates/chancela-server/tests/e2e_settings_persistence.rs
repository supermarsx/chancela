//! Journey: settings round-trip, validation, and persistence across a restart.
//!
//! `GET` returns defaults; a whole-document `PUT` round-trips and is reflected by the next `GET`;
//! out-of-range / bad-enum / bad-URL values are refused with `422`; and a restart over the same data
//! dir loads the persisted `settings.json`.

mod common;

use common::*;
use serde_json::{Value, json};

fn sample_settings() -> Value {
    json!({
        "schema_version": 1,
        "organization": { "name": "Encosto Estratégico, S.A.", "default_actor": "amelia.marques" },
        "documents": { "locale": "en-US", "numbering_scheme_default": "LooseLeaf" },
        "catalog": {
            "cae_update_url": "https://catalog.example.pt/cae.json",
            "cae_sources": [],
            "cae_official_source": false
        },
        "signing": {
            "preferred_family": "ChaveMovelDigital",
            "tsa_url": "https://tsa.example.pt/tsr",
            "tsl_url": "https://tsl.example.pt/tsl.xml",
            "require_qualified_for_seal": true
        },
        "appearance": { "theme": "dark", "leather_texture": false, "texture_intensity": 25, "button_texture": false },
        "onboarding": { "completed": false, "completed_at": null }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn settings_round_trip_validation_and_persistence() {
    let mut h = ServerHarness::start().await;

    // Defaults before any PUT.
    let (status, defaults) = h.get_json("/v1/settings").await;
    assert_eq!(status, 200);
    assert_eq!(defaults["documents"]["locale"], "pt-PT");
    assert_eq!(defaults["appearance"]["theme"], "system");
    assert_eq!(defaults["appearance"]["texture_intensity"], 60);

    // A full PUT round-trips and is reflected by the next GET.
    let (status, stored) = h.put_json("/v1/settings", sample_settings()).await;
    assert_eq!(status, 200);
    assert_eq!(stored, sample_settings());
    let (status, got) = h.get_json("/v1/settings").await;
    assert_eq!(status, 200);
    assert_eq!(got, sample_settings());

    // The change is auditable.
    let (_, events) = h.get_json("/v1/ledger/events").await;
    assert!(
        events
            .as_array()
            .expect("events")
            .iter()
            .any(|e| e["kind"] == "settings.updated"),
        "a settings.updated event was appended"
    );

    // Validation: out-of-range intensity, a bad locale, and a non-http URL each 422.
    let cases: [fn(&mut Value); 3] = [
        |s| s["appearance"]["texture_intensity"] = json!(150),
        // `fr-FR` is now a supported locale; use a tag outside the 14-locale set.
        |s| s["documents"]["locale"] = json!("zz-ZZ"),
        |s| s["signing"]["tsa_url"] = json!("ftp://tsa.example.pt"),
    ];
    for mutate in cases {
        let mut bad = sample_settings();
        mutate(&mut bad);
        let (status, body) = h.put_json("/v1/settings", bad).await;
        assert_eq!(status, 422, "invalid settings must 422: {body}");
        assert!(body["error"].is_string());
    }

    // The persisted file survives a restart; the rejected PUTs never overwrote the stored document.
    assert!(
        h.data_dir.join("settings.json").is_file(),
        "settings.json persisted to disk"
    );
    h.restart().await;
    let (status, got) = h.get_json("/v1/settings").await;
    assert_eq!(status, 200);
    assert_eq!(
        got,
        sample_settings(),
        "persisted settings loaded after restart"
    );
}
