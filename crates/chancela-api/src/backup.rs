//! Hot-backup endpoint (contract §3.2, t30 §D6): `POST /v1/backup`.
//!
//! Snapshots the durable store with `VACUUM INTO` (transactionally consistent, no downtime),
//! bundles it with the JSON sidecars (`settings.json`, `users.json`, `cae-catalog.json`, `laws/`)
//! and a `manifest.json` into a single zip under `<data_dir>/backups/`, and returns the manifest.
//! In-memory mode (no durable store) → `422`, mirroring the no-data-dir precedents. The backup is
//! itself recorded in the chain via a `backup.created` event (which is then persisted too, so the
//! chain records its own backups).

use axum::Json;
use axum::extract::State;
use chancela_store::{BackupManifest, StoreError};
use serde_json::json;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::error::ApiError;

/// The `422` body when a backup is requested without on-disk persistence (frozen §3.2).
const NOT_PERSISTENT_MSG: &str = "backup requires on-disk persistence; set CHANCELA_DATA_DIR";

/// `POST /v1/backup` — take a hot backup and return its [`BackupManifest`] (contract §3.2).
pub async fn create_backup(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<BackupManifest>, ApiError> {
    // In-memory mode: nothing durable to snapshot → 422 (mirrors `law.rs`'s no-data-dir 422).
    let Some(store) = state.store.clone() else {
        return Err(ApiError::Unprocessable(NOT_PERSISTENT_MSG.to_owned()));
    };
    let data_dir = state.data_dir().ok_or_else(|| {
        ApiError::Internal("durable store without a resolvable data directory".to_owned())
    })?;

    // The sidecars bundled alongside the SQLite snapshot (plan §D6). A missing path is skipped by
    // the store's archiver, so an absent cache/laws dir is fine.
    let sidecars = vec![
        data_dir.join(crate::settings::SETTINGS_FILE),
        data_dir.join(crate::users::USERS_FILE),
        data_dir.join(chancela_cae::CACHE_FILE),
        data_dir.join(crate::law::LAWS_DIR),
    ];

    // VACUUM INTO + zip are synchronous and can be non-trivial; run them off the async runtime.
    let manifest = tokio::task::spawn_blocking(move || store.backup(&data_dir, &sidecars))
        .await
        .map_err(|e| ApiError::Internal(format!("backup task failed to join: {e}")))?
        .map_err(map_backup_error)?;

    // Record the backup in the chain, and persist that event (the chain records its own backups).
    let actor = actor.resolve("api");
    let payload = serde_json::to_vec(&json!({
        "path": manifest.path,
        "bytes": manifest.bytes,
        "ledger_length": manifest.ledger_length,
        "ledger_verified": manifest.ledger_verified,
    }))?;
    {
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &actor,
            "backup",
            "backup.created",
            Some("backup created"),
            &payload,
        );
        state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
    }

    Ok(Json(manifest))
}

/// Map a store backup failure to its HTTP status: a not-persistent store is a `422` with the frozen
/// message; anything else is an internal `500`.
fn map_backup_error(e: StoreError) -> ApiError {
    match e {
        StoreError::NotPersistent => ApiError::Unprocessable(NOT_PERSISTENT_MSG.to_owned()),
        other => ApiError::Internal(format!("backup failed: {other}")),
    }
}
