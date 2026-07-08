//! Journey: CAE lookup / search / catalog metadata / refresh-supersede / cache-across-restart.
//!
//! The embedded both-revision catalog is queried (single-code lookup with hierarchy, a revision pin,
//! accent-folded search, no-search metadata with the official structural counts), then a refresh
//! against the child's **real** CAE source (`CHANCELA_CAE_URL` → a fixture serving a superseding
//! dataset) swaps the live catalog, writes the cache, and is a no-op on repeat; a restart with no URL
//! loads the catalog from that cache (`origin: Cache`).
//!
//! Determinism note: the harness seeds a stale-content-but-fresh-mtime `cae-catalog.json` before the
//! first spawn. Its fresh mtime makes the startup background refresh a no-op (so it cannot race the
//! manual refresh), while its old `generated_at` keeps the embedded catalog active until the manual
//! refresh runs.

mod common;

use common::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn cae_lookup_search_refresh_and_cache_across_restart() {
    let cae = spawn_cae_fixture(SUPERSEDING_CAE_DATASET).await;
    let mut h = ServerHarness::start_with(
        HarnessOptions::default()
            .with_cae(cae.url.clone())
            .with_seed_cae_cache(STALE_CAE_CACHE),
    )
    .await;

    // A session so the CAE refresh + settings mutations are authorized (t41). The user id is kept
    // so a fresh session can be opened after the restart (in-memory sessions do not survive it).
    let user_id = create_user(&h, "e2e.operator", "E2E Operator").await;
    let token = open_session(&h, &user_id).await;

    // Single-code lookup resolves designation + level + revision + full hierarchy.
    let (status, entry) = h.get_json("/v1/cae/68110").await;
    assert_eq!(status, 200);
    assert_eq!(entry["designation"], "Compra e venda de bens imobiliários.");
    assert_eq!(entry["level"], "Subclasse");
    assert_eq!(entry["revision"], "Rev4");
    let hierarchy = entry["hierarchy"].as_array().expect("hierarchy");
    assert_eq!(hierarchy.len(), 5, "secção→…→subclasse");
    assert_eq!(hierarchy[0]["level"], "Seccao");
    assert_eq!(hierarchy[4]["code"], "68110");

    // A revision pin: 68100 exists only in Rev.3.
    let (status, _) = h.get_json("/v1/cae/68100?revision=Rev4").await;
    assert_eq!(status, 404);
    let (status, rev3) = h.get_json("/v1/cae/68100?revision=Rev3").await;
    assert_eq!(status, 200);
    assert_eq!(rev3["revision"], "Rev3");

    // Accent-folded search returns matching nodes without hierarchy.
    let (status, hits) = h.get_json("/v1/cae?search=imobili&limit=5").await;
    assert_eq!(status, 200);
    let arr = hits.as_array().expect("hits");
    assert!(!arr.is_empty() && arr.len() <= 5);
    assert!(
        arr[0].get("hierarchy").is_none(),
        "list form omits hierarchy"
    );

    // No-search metadata: still the embedded catalog, with the official structural counts.
    let (status, meta) = h.get_json("/v1/cae").await;
    assert_eq!(status, 200);
    assert_eq!(meta["origin"], "Embedded");
    assert_eq!(meta["counts"]["rev4"]["seccao"], 22);
    assert_eq!(meta["counts"]["rev4"]["subclasse"], 915);
    assert_eq!(meta["counts"]["rev3"]["seccao"], 21);
    assert_eq!(meta["counts"]["rev3"]["subclasse"], 850);
    assert_eq!(meta["digest"].as_str().expect("digest").len(), 64);

    // Refresh against the fixture supersedes: the live catalog swaps to the tiny dataset, the cache
    // is written, and a cae.updated event is appended.
    let (status, refresh) = h.post_json_auth("/v1/cae/refresh", json!({}), &token).await;
    assert_eq!(status, 200, "refresh: {refresh}");
    assert_eq!(refresh["updated"], true);
    assert_eq!(refresh["metadata"]["origin"], "Cache");
    assert!(
        h.data_dir.join("cae-catalog.json").is_file(),
        "the cache file was written"
    );

    let (status, a) = h.get_json("/v1/cae/A").await;
    assert_eq!(status, 200);
    assert_eq!(a["designation"], "Secção de teste");

    let (_, events) = h.get_json("/v1/ledger/events").await;
    let updated = events
        .as_array()
        .expect("events")
        .iter()
        .find(|e| e["kind"] == "cae.updated")
        .expect("cae.updated event present");
    assert_eq!(updated["scope"], "cae");

    // A repeat refresh of the same dataset is a no-op.
    let (status, refresh) = h.post_json_auth("/v1/cae/refresh", json!({}), &token).await;
    assert_eq!(status, 200);
    assert_eq!(refresh["updated"], false);

    // Restart with NO CHANCELA_CAE_URL: the catalog is loaded from the written cache.
    h.clear_cae_url();
    h.restart().await;

    // The in-memory session did not survive the restart; re-open one for the persisted user.
    let token = open_session(&h, &user_id).await;
    let (status, meta) = h.get_json("/v1/cae").await;
    assert_eq!(status, 200);
    assert_eq!(
        meta["origin"], "Cache",
        "catalog loaded from cache after restart"
    );
    let (status, a) = h.get_json("/v1/cae/A").await;
    assert_eq!(status, 200);
    assert_eq!(a["designation"], "Secção de teste");

    // --- The update URL is settings-configurable, not env-only ---
    // This restarted child has NO CHANCELA_CAE_URL. A *plain* no-config refresh now runs the built-in
    // official Diário da República default chain (the "no URL ⇒ obtain from the official gov
    // artifacts" behaviour), so it is no longer a 422 — that path is covered hermetically at the api
    // layer (a live DR fetch is out of scope here). The friendly, settings-aware 422 remains only when
    // a default is impossible: a `?source` pin that matches nothing configured (e.g. `?source=mirror`
    // with no mirrors). That is the case exercised here (the user's original hit was an opaque 500).
    let (status, body) = h
        .post_json_auth("/v1/cae/refresh?source=mirror", json!({}), &token)
        .await;
    assert_eq!(status, 422, "pinned source with nothing configured: {body}");
    assert!(
        body["error"]
            .as_str()
            .expect("error string")
            .contains("Configurações"),
        "the error points the operator at Configurações: {body}"
    );

    // Configure the update URL in settings (not the environment); the refresh now finds the fixture
    // again by settings, proving settings-over-env resolution. It is a no-op against the cached data.
    let (_, mut settings) = h.get_json("/v1/settings").await;
    settings["catalog"]["cae_update_url"] = json!(cae.url.clone());
    let (status, _) = h.put_json_auth("/v1/settings", settings, &token).await;
    assert_eq!(status, 200);
    let (status, refresh) = h.post_json_auth("/v1/cae/refresh", json!({}), &token).await;
    assert_eq!(
        status, 200,
        "settings-configured URL drives the refresh: {refresh}"
    );
    assert_eq!(refresh["updated"], false, "same dataset ⇒ no-op: {refresh}");
}
