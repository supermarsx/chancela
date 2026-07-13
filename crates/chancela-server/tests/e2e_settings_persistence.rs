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
            "cae_official_source": false,
            "preferred_official_source": "Ine"
        },
        "signing": {
            "preferred_family": "ChaveMovelDigital",
            "tsa_url": "https://tsa.example.pt/tsr",
            "tsl_url": "https://tsl.example.pt/tsl.xml",
            "tsl_sources": [
                {
                    "id": "pt-gns",
                    "name": "Portugal GNS Trusted List",
                    "enabled": true,
                    "url": "https://www.gns.gov.pt/media/TSLPT.xml",
                    "path": null,
                    "country": "PT",
                    "scheme": "eidas",
                    "digest": null,
                    "timeout_seconds": 30,
                    "max_bytes": 26214400,
                    "refresh": {
                        "enabled": false,
                        "cadence": {
                            "kind": "daily",
                            "hour_utc": 3
                        }
                    }
                },
                {
                    "id": "eu-lotl",
                    "name": "EU List of Trusted Lists",
                    "enabled": false,
                    "url": "https://ec.europa.eu/tools/lotl/eu-lotl.xml",
                    "path": null,
                    "country": "EU",
                    "scheme": "lotl",
                    "digest": null,
                    "timeout_seconds": 30,
                    "max_bytes": 26214400,
                    "refresh": {
                        "enabled": false,
                        "cadence": {
                            "kind": "daily",
                            "hour_utc": 2
                        }
                    }
                }
            ],
            "tsa_providers": [
                {
                    "id": "pt-cc",
                    "name": "Portugal Cartao de Cidadao TSA",
                    "enabled": true,
                    "url": "http://ts.cartaodecidadao.pt/tsa/server",
                    "path": null,
                    "default": true,
                    "policy": null,
                    "digest": "sha256",
                    "timeout_seconds": 30,
                    "max_bytes": 1048576
                }
            ],
            "require_qualified_for_seal": true,
            "cmd": {
                "env": "preprod",
                "application_id": null,
                "ama_cert_configured": false
            },
            "providers": [
                {
                    "id": "cmd",
                    "mode": "CMD",
                    "label": "Chave Móvel Digital (CMD/SCMD)",
                    "configured": false,
                    "production_blocked": true,
                    "local_only": false,
                    "note": "Missing AMA ApplicationId/certificate; defaults to pre-production."
                },
                {
                    "id": "cc",
                    "mode": "CC",
                    "label": "Cartão de Cidadão",
                    "configured": false,
                    "production_blocked": false,
                    "local_only": true,
                    "note": "Requires a co-located desktop process and card reader; no PIN is stored."
                },
                {
                    "id": "csc_qtsp",
                    "mode": "CSC_QTSP",
                    "label": "CSC/QTSP remote provider",
                    "configured": false,
                    "production_blocked": true,
                    "local_only": false,
                    "note": "No CSC/QTSP provider is configured in protected storage or environment."
                },
                {
                    "id": "soft_pkcs12",
                    "mode": "LOCAL_PKCS12",
                    "label": "Local soft certificate (PKCS#12/PFX)",
                    "configured": false,
                    "production_blocked": true,
                    "local_only": true,
                    "note": "Local-only test/operator material; private key and passphrase are never captured in settings."
                }
            ]
        },
        "workflow": {
            "reminders": {
                "enabled": true,
                "dashboard_limit": 7,
                "due_soon_days": 30,
                "attendance_lookahead_days": 21,
                "sources": {
                    "profile_calendar": true,
                    "act_follow_ups": false,
                    "attendance_hygiene": true
                }
            }
        },
        "appearance": { "theme": "dark", "leather_texture": false, "texture_intensity": 25, "button_texture": false },
        "platform": {
            "logging": {
                "global": "info",
                "app": "info",
                "api": "info",
                "mcp": "info",
                "service_overrides": {}
            },
            "api_server": {
                "enabled": true,
                "desired_state": "running",
                "last_action": null
            },
            "mcp_stdio_server": {
                "enabled": false,
                "desired_state": "stopped",
                "last_action": null
            },
            "audit": []
        },
        "ui": {
            "registered_entity_columns": ["Name", "Nipc", "Type", "LastActivity", "Actions"]
        },
        "ai": { "enabled": false },
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
    let token = bootstrap_session(&h).await;

    // Defaults before any PUT.
    let (status, defaults) = h.get_json("/v1/settings").await;
    assert_eq!(status, 200);
    assert_eq!(defaults["documents"]["locale"], "pt-PT");
    assert_eq!(defaults["appearance"]["theme"], "system");
    assert_eq!(defaults["appearance"]["texture_intensity"], 60);
    assert_eq!(
        defaults["workflow"]["reminders"],
        json!({
            "enabled": true,
            "dashboard_limit": 5,
            "due_soon_days": 45,
            "attendance_lookahead_days": 45,
            "sources": {
                "profile_calendar": true,
                "act_follow_ups": true,
                "attendance_hygiene": true
            }
        })
    );

    // A full PUT round-trips and is reflected by the next GET.
    let (status, stored) = h
        .put_json_auth("/v1/settings", sample_settings(), &token)
        .await;
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

    // Validation: out-of-range intensity/reminder policy, a bad locale, and a non-http URL each 422.
    let cases: [fn(&mut Value); 4] = [
        |s| s["appearance"]["texture_intensity"] = json!(150),
        |s| s["workflow"]["reminders"]["dashboard_limit"] = json!(51),
        // `fr-FR` is now a supported locale; use a tag outside the 14-locale set.
        |s| s["documents"]["locale"] = json!("zz-ZZ"),
        |s| s["signing"]["tsa_url"] = json!("ftp://tsa.example.pt"),
    ];
    for mutate in cases {
        let mut bad = sample_settings();
        mutate(&mut bad);
        let (status, body) = h.put_json_auth("/v1/settings", bad, &token).await;
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
