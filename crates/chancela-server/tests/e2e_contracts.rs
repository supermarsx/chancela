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

    // Password policy (session.password-policy.json). This is an unauthenticated onboarding
    // contract, and the rule list is ordered/stable because the web checklist switches on the codes.
    let (status, policy) = h.get_json_noauth("/v1/session/password-policy").await;
    assert_eq!(status, 200);
    let expected_policy = contract("session.password-policy.json");
    let live_codes = policy["rules"]
        .as_array()
        .expect("password policy rules")
        .iter()
        .map(|r| r["code"].as_str().expect("password policy rule code"))
        .collect::<Vec<_>>();
    let expected_codes = expected_policy["rules"]
        .as_array()
        .expect("contract password policy rules")
        .iter()
        .map(|r| {
            r["code"]
                .as_str()
                .expect("contract password policy rule code")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        live_codes, expected_codes,
        "password policy rule codes/order drifted"
    );
    assert_eq!(
        policy, expected_policy,
        "password policy response drifted from session.password-policy.json"
    );

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
    let tenant_id = entity["tenant_id"]
        .as_str()
        .expect("entity tenant id")
        .to_owned();

    // The top-level tenant collection (tenant.json): create a tenant through the collection endpoint
    // and shape-match the wire response. (wp27-e1: the `/v1/tenants` collection, distinct from the
    // pre-existing `/v1/tenants/{tenant_id}/...` sub-resources.)
    let (status, tenant) = h
        .post_json_auth(
            "/v1/tenants",
            json!({ "name": "Encosto Estratégico Holding" }),
            &token,
        )
        .await;
    assert_eq!(status, 201, "create tenant: {tenant}");
    assert_shape("tenant", &tenant, &contract("tenant.json"));

    // Companion device pairing (pairing.json): the operator mints a short-lived code, the phone
    // exchanges it (unauthenticated) for a companion session + device, and the enrolled device is
    // then listed. (wp27-e4: the pairing/device-enrollment protocol atop the durable session
    // machinery — the code is single-use, the session is identity-only, the device is reload-safe.)
    let (status, minted) = h
        .post_json_auth(
            "/v1/pairing/codes",
            json!({ "label": "Telemóvel da Amélia" }),
            &token,
        )
        .await;
    assert_eq!(status, 200, "mint pairing code: {minted}");
    let pairing_code = minted["code"].as_str().expect("pairing code").to_owned();
    // The phone exchanges the code with NO session (it has none yet) and receives its own token.
    let (status, exchanged) = h
        .post_json(
            "/v1/pairing/exchange",
            json!({ "code": pairing_code.clone() }),
        )
        .await;
    assert_eq!(status, 200, "exchange pairing code: {exchanged}");
    let companion_token = exchanged["token"]
        .as_str()
        .expect("companion token")
        .to_owned();
    assert!(
        !exchanged["device_id"]
            .as_str()
            .expect("device id")
            .is_empty(),
        "exchange returns an enrolled device id"
    );
    assert_eq!(exchanged["user"]["username"], "amelia.marques");
    // The single-use code cannot be exchanged a second time.
    let (status, reused) = h
        .post_json("/v1/pairing/exchange", json!({ "code": pairing_code }))
        .await;
    assert_eq!(status, 401, "a pairing code is single-use: {reused}");
    // The companion token authenticates as the operator's user.
    let (status, companion_session) = h.get_json_auth("/v1/session", &companion_token).await;
    assert_eq!(status, 200);
    assert_eq!(companion_session["user"]["username"], "amelia.marques");
    // The operator sees the enrolled device (pairing.json shape).
    let (status, devices) = h.get_json_auth("/v1/pairing/devices", &token).await;
    assert_eq!(status, 200, "list pairing devices: {devices}");
    assert_shape("pairing", &devices, &contract("pairing.json"));

    // Tenant-local company group + its first named, versioned shared-template library.
    let groups_path = format!("/v1/tenants/{tenant_id}/groups");
    let (status, group) = h
        .post_json_auth(
            &groups_path,
            json!({
                "name": "Grupo Encosto",
                "description": "Empresas do Grupo Encosto"
            }),
            &token,
        )
        .await;
    assert_eq!(status, 201, "create group: {group}");
    assert_shape("group", &group, &contract("group.json"));
    let group_id = group["id"].as_str().expect("group id").to_owned();
    let (status, grouped_entity) = h
        .put_json_auth(
            &format!("{groups_path}/{group_id}/entities/{entity_id}"),
            json!({}),
            &token,
        )
        .await;
    assert_eq!(status, 200, "assign entity to group: {grouped_entity}");
    assert_eq!(grouped_entity["group_id"], group_id);

    let libraries_path = format!("{groups_path}/{group_id}/template-libraries");
    let (status, library) = h
        .post_json_auth(
            &libraries_path,
            json!({
                "name": "Atas comuns",
                "description": "Modelos partilhados entre as empresas do grupo",
                "template_ids": ["csc-ata-ag/v1"]
            }),
            &token,
        )
        .await;
    assert_eq!(status, 201, "create group template library: {library}");
    assert_shape(
        "group.template-library",
        &library,
        &contract("group.template-library.json"),
    );

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
        .post_json_auth(
            &format!("/v1/acts/{act_id}/seal"),
            manual_signature_seal_body("Arquivo E2E / Contract ata"),
            &token,
        )
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

    // TSL trust catalog (tsl.catalog.json): offline deterministic parse of cached/bundled TSL XML.
    let (status, tsl_catalog) = h.get_json("/v1/trust/catalog").await;
    assert_eq!(status, 200);
    assert_shape("tsl.catalog", &tsl_catalog, &contract("tsl.catalog.json"));

    // TSA diagnostics/catalog (tsa.status.json): configured URL + offline RFC 3161 fixture probe.
    let (status, tsa_catalog) = h.get_json("/v1/trust/tsa").await;
    assert_eq!(status, 200);
    assert_shape("tsa.status", &tsa_catalog, &contract("tsa.status.json"));

    // The law archive manifest merged with store state (law.manifest.json). Nothing is fetched in
    // this journey, so the live entries report `stored: false` with null store fields — the
    // matcher's nullable-field permissiveness checks the populated fixture types against them.
    let (status, law) = h.get_json("/v1/law").await;
    assert_eq!(status, 200);
    assert_shape("law.manifest", &law, &contract("law.manifest.json"));

    // Template catalog (templates.json): merged shape includes built-in provenance/editability
    // fields; this journey has no user-authored rows yet, so the live first element is a built-in.
    let (status, templates) = h.get_json_auth("/v1/templates", &token).await;
    assert_eq!(status, 200);
    assert_shape("templates", &templates, &contract("templates.json"));
    assert!(
        templates
            .as_array()
            .expect("templates array")
            .iter()
            .any(|template| template["source"] == "builtin" && template["editable"] == false),
        "template catalog exposes built-in provenance/editability: {templates}"
    );

    // User-authored template lifecycle (template.summary.json, template.import-verdict.json,
    // template.export.json). One authored spec drives all three wire shapes: creating it returns
    // the `TemplateSummary`; re-importing the same id as a dry-run hits the uniqueness preflight and
    // returns the populated `{ok:false, error:{code,field,message}}` conflict verdict (no persist);
    // exporting it returns the canonical spec JSON (lossless re-import). The id carries a `/`, so the
    // export path percent-encodes it.
    let authored_template = json!({
        "id": "user-encosto-ata/v1",
        "family": "CommercialCompany",
        "stage": "Ata",
        "channels": ["Physical"],
        "signature_policy": "QualifiedPreferred",
        "rule_pack_id": "csc-art63/v2",
        "locale": "pt-PT",
        "blocks": [
            { "kind": "Heading", "level": 1, "template": "Ata n.º {{ ata_number }}" },
            {
                "kind": "Paragraph",
                "template": "Reunida a assembleia em {{ meeting_date | long_date }}."
            }
        ]
    });

    let (status, template_summary) = h
        .post_json_auth("/v1/templates", authored_template.clone(), &token)
        .await;
    assert_eq!(status, 201, "create user template: {template_summary}");
    assert_shape(
        "template.summary",
        &template_summary,
        &contract("template.summary.json"),
    );

    // Re-importing the same id as a dry-run: the uniqueness preflight rejects it with a populated
    // conflict verdict (200, `ok:false`), without persisting anything.
    let (status, import_verdict) = h
        .post_json_auth(
            "/v1/templates/import?dry_run=true",
            authored_template,
            &token,
        )
        .await;
    assert_eq!(status, 200, "template import dry-run: {import_verdict}");
    assert_eq!(
        import_verdict["ok"], false,
        "dry-run of an already-persisted id conflicts: {import_verdict}"
    );
    assert_shape(
        "template.import-verdict",
        &import_verdict,
        &contract("template.import-verdict.json"),
    );

    // Exporting the authored template returns its canonical spec JSON.
    let (status, template_export) = h
        .get_json_auth("/v1/templates/user-encosto-ata%2Fv1/export", &token)
        .await;
    assert_eq!(status, 200, "export user template: {template_export}");
    assert_shape(
        "template.export",
        &template_export,
        &contract("template.export.json"),
    );

    // The ledger feed + dashboard (ledger.events.json, dashboard.json).
    let (status, events) = h.get_json("/v1/ledger/events").await;
    assert_eq!(status, 200);
    assert_shape("ledger.events", &events, &contract("ledger.events.json"));

    let (status, dashboard) = h.get_json("/v1/dashboard").await;
    assert_eq!(status, 200);
    assert_shape("dashboard", &dashboard, &contract("dashboard.json"));

    let (status, group_dashboard) = h
        .get_json(&format!("{groups_path}/{group_id}/dashboard"))
        .await;
    assert_eq!(status, 200, "group dashboard: {group_dashboard}");
    assert_shape(
        "group.dashboard",
        &group_dashboard,
        &contract("group.dashboard.json"),
    );

    // A hot backup manifest (backup.manifest.json). The e2e server is data-dir-backed, so the
    // durable store snapshots and the manifest returns 200 (t30 §3.2).
    let (status, manifest) = h.post_json_auth("/v1/backup", json!({}), &token).await;
    assert_eq!(status, 200, "backup: {manifest}");
    assert_shape(
        "backup.manifest",
        &manifest,
        &contract("backup.manifest.json"),
    );

    // Local sync/handoff preflight report (sync.handoff-preflight.json). This composes only local
    // evidence from the durable state, untrusted backup candidates, and recovery receipts; it does
    // not perform sync or touch providers/connectors.
    let (status, handoff) = h.get_json_auth("/v1/sync/handoff-preflight", &token).await;
    assert_eq!(status, 200, "sync handoff preflight: {handoff}");
    assert_shape(
        "sync.handoff-preflight",
        &handoff,
        &contract("sync.handoff-preflight.json"),
    );
}
