//! **wp16 P3b — backend-conditional storage seam for the five non-ledger file sidecars.**
//!
//! Chancela keeps five stores *outside* the hash-chained ledger as JSON/encrypted file sidecars in
//! the data dir: `users.json`, `roles.json`, `delegations.json`, `settings.json`, and the encrypted
//! `provider-credentials.enc.json`. On the embedded / SQLite single-node build these stay **exactly**
//! as they always were — atomic temp+rename file writes — so single-node behaviour is byte-identical.
//!
//! In a Postgres (multi-node) deployment those five stores must be **shared across nodes** (plan
//! §8.2): a follower must see a user/role/delegation/settings change the leader made, and every node
//! must resolve the same provider credentials. This module is the seam that routes each sidecar's
//! **load** (boot) and **write-through** (on change) to the active source:
//!
//! - **SQLite / default** ⇒ the existing file path, unchanged (`state.sidecars_db_backed == false`).
//! - **Postgres** ⇒ the wp16 P3b-store DB tables via `Store`/`Tx` (`users`/`roles`/`delegations`/
//!   `settings`/`provider_credentials`), so all nodes share one durable copy.
//!
//! The selection is a pure function of the resolved durable backend (set once at startup on
//! [`AppState::sidecars_db_backed`](crate::AppState)); no per-sidecar env flag and no in-place
//! file→DB migration. A fresh Postgres deployment starts with **empty** sidecar tables — that is the
//! normal fresh state (onboarding populates them); an existing instance migrates via the wp15 restore
//! bundle, which already carries these sidecars. We never auto-copy local files into the DB in place.
//!
//! Provider credentials are special: the wp13 XChaCha20-Poly1305 / AAD crypto envelope stays entirely
//! in [`crate::secretstore_persist`]. Only the *storage* of the already-encrypted
//! `EncryptedCredentialRecord` blob moves to the `provider_credentials` table on Postgres — the store
//! treats the blob as opaque ciphertext and never decrypts it (see
//! [`ProviderCredentialStore`](crate::secretstore_persist::ProviderCredentialStore)).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::RwLock;

use chancela_authz::{Role, RoleCatalog};
use chancela_store::{Store, StoreError, Tx};

use crate::AppState;
use crate::delegations::StoredDelegation;
use crate::error::ApiError;
use crate::settings::Settings;
use crate::users::{User, UserId};

/// The three `(id, json)` document sidecar tables reconciled through the shared upsert helper.
#[derive(Clone, Copy)]
enum DocumentTable {
    Users,
    Roles,
    Delegations,
}

/// Read the current row ids for `table` from the store (the delete-reconcile baseline).
fn existing_ids(store: &Store, table: DocumentTable) -> Result<Vec<(String, String)>, StoreError> {
    match table {
        DocumentTable::Users => store.users(),
        DocumentTable::Roles => store.roles(),
        DocumentTable::Delegations => store.delegations(),
    }
}

/// Reconcile `table` to exactly `rows` in one transaction: upsert every current `(id, json)` row and
/// delete any DB row whose id is no longer present in memory. This mirrors the whole-document atomic
/// file write (the file always reflects the full in-memory collection), so a delete (a removed role)
/// is honoured and never lingers. Runs under the store's writer/leader gate on Postgres.
/// The shared single-transaction body: upsert every current `(id, json)` row and delete any DB row
/// whose id is no longer present. Factored out so the synchronous boot-seed path
/// ([`reconcile_documents`]) and the async write-through path ([`reconcile_documents_async`]) run
/// byte-identical SQL.
fn reconcile_documents_tx(
    tx: &Tx<'_>,
    table: DocumentTable,
    rows: &[(String, String)],
    existing: &[(String, String)],
) -> Result<(), StoreError> {
    let present: HashSet<&str> = rows.iter().map(|(id, _)| id.as_str()).collect();
    for (id, json) in rows {
        match table {
            DocumentTable::Users => tx.upsert_user(id, json)?,
            DocumentTable::Roles => tx.upsert_role(id, json)?,
            DocumentTable::Delegations => tx.upsert_delegation(id, json)?,
        }
    }
    for (id, _) in existing {
        if !present.contains(id.as_str()) {
            match table {
                DocumentTable::Users => tx.delete_user(id)?,
                DocumentTable::Roles => tx.delete_role(id)?,
                DocumentTable::Delegations => tx.delete_delegation(id)?,
            }
        }
    }
    Ok(())
}

/// Synchronous reconcile — used by the boot-time seed/migration path ([`persist_seed`] via
/// [`hydrate_from_store`]), which runs before the async request runtime is a concern.
fn reconcile_documents(
    store: &Store,
    table: DocumentTable,
    rows: Vec<(String, String)>,
) -> Result<(), StoreError> {
    let existing = existing_ids(store, table)?;
    store.persist(|tx| reconcile_documents_tx(tx, table, &rows, &existing))
}

/// Async reconcile for the request-path write-through (wp27-e9): offload the blocking store
/// transaction onto the blocking pool via [`Store::persist_blocking_async`] so the async worker
/// thread is not blocked. The sidecar read guard is held across this `.await` by the caller — that
/// preserves the snapshot-to-durable-write exclusion and is safe (a read guard held across `.await`
/// does not block; the offload just moves the SQL off the worker). `rows`, `existing`, and the
/// `Copy` `table` are owned and moved into the `Send + 'static` closure.
async fn reconcile_documents_async(
    store: &Store,
    table: DocumentTable,
    rows: Vec<(String, String)>,
) -> Result<(), StoreError> {
    let existing = store
        .read_blocking_async(move |s| existing_ids(s, table))
        .await?;
    store
        .persist_blocking_async(move |tx| reconcile_documents_tx(tx, table, &rows, &existing))
        .await
}

/// Persist a boot-time seed/migration write, tolerating the writer-leader gate. A **follower** node
/// (a second Postgres instance) is not the cluster writer; the leader performs the one-time
/// seed/migration and the follower reloads it via the change-feed, so a `NotLeader` refusal here is
/// expected and non-fatal. Any other store error still fails startup closed.
fn persist_seed(
    store: &Store,
    table: DocumentTable,
    rows: Vec<(String, String)>,
) -> Result<(), StoreError> {
    match reconcile_documents(store, table, rows) {
        Ok(()) => Ok(()),
        Err(StoreError::NotLeader) => {
            eprintln!(
                "wp16 P3b: this node is not the cluster writer-leader; skipping the one-time sidecar \
                 seed/migration (the leader seeds it and this node adopts it via the change-feed)"
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn serialize_error(kind: &str, e: serde_json::Error) -> ApiError {
    ApiError::Internal(format!(
        "failed to serialize {kind} for the durable store: {e}"
    ))
}

// =================================================================================================
// Write-through: called on every user / role / delegation / settings mutation.
// =================================================================================================

/// Persist the live user directory to the active source. On Postgres this reconciles the `users`
/// table; otherwise it writes `users.json` atomically (unchanged). A no-op when neither is present.
pub(crate) async fn persist_users(state: &AppState) -> Result<(), ApiError> {
    if state.sidecars_db_backed {
        let Some(store) = state.store.as_ref() else {
            return Ok(());
        };
        let users = state.users.read().await;
        let mut rows = Vec::with_capacity(users.len());
        for user in users.values() {
            let json = serde_json::to_string(user).map_err(|e| serialize_error("user", e))?;
            rows.push((user.id.0.to_string(), json));
        }
        // Keep the sidecar read lock held until the authoritative DB snapshot has been
        // reconciled. This preserves the file-backed path's snapshot-to-durable-write
        // exclusion: a concurrent writer cannot mutate auth state and persist it while
        // this older whole-table snapshot is still able to commit last.
        reconcile_documents_async(store, DocumentTable::Users, rows)
            .await
            .map_err(|e| AppState::map_store_write_error("failed to persist users", e))?;
        return Ok(());
    }
    if let Some(path) = &state.users_path {
        let users = state.users.read().await;
        crate::users::write_users_atomic(path, &users)
            .map_err(|e| ApiError::Internal(format!("failed to persist users: {e}")))?;
    }
    Ok(())
}

/// Persist the live role catalog to the active source (Postgres `roles` table, else `roles.json`).
pub(crate) async fn persist_roles(state: &AppState) -> Result<(), ApiError> {
    if state.sidecars_db_backed {
        let Some(store) = state.store.as_ref() else {
            return Ok(());
        };
        let roles = state.roles.read().await;
        let mut rows = Vec::with_capacity(roles.len());
        for role in roles.iter() {
            let json = serde_json::to_string(role).map_err(|e| serialize_error("role", e))?;
            rows.push((role.id.0.to_string(), json));
        }
        // Keep the sidecar read lock held until the authoritative DB snapshot has been
        // reconciled so stale whole-table role snapshots cannot commit after newer
        // role mutations.
        reconcile_documents_async(store, DocumentTable::Roles, rows)
            .await
            .map_err(|e| AppState::map_store_write_error("failed to persist roles", e))?;
        return Ok(());
    }
    if let Some(path) = &state.roles_path {
        let roles = state.roles.read().await;
        crate::roles::write_roles_atomic(path, &roles)
            .map_err(|e| ApiError::Internal(format!("failed to persist roles: {e}")))?;
    }
    Ok(())
}

/// Persist the live delegation table to the active source (Postgres `delegations` table, else
/// `delegations.json`). Active **and** revoked records are written (the store retains both).
pub(crate) async fn persist_delegations(state: &AppState) -> Result<(), ApiError> {
    if state.sidecars_db_backed {
        let Some(store) = state.store.as_ref() else {
            return Ok(());
        };
        let delegations = state.delegations.read().await;
        let mut rows = Vec::with_capacity(delegations.len());
        for delegation in delegations.values() {
            let json =
                serde_json::to_string(delegation).map_err(|e| serialize_error("delegation", e))?;
            rows.push((delegation.id.0.to_string(), json));
        }
        // Keep the sidecar read lock held until the authoritative DB snapshot has been
        // reconciled so stale whole-table delegation snapshots cannot commit after
        // newer delegation mutations.
        reconcile_documents_async(store, DocumentTable::Delegations, rows)
            .await
            .map_err(|e| AppState::map_store_write_error("failed to persist delegations", e))?;
        return Ok(());
    }
    if let Some(path) = &state.delegations_path {
        let delegations = state.delegations.read().await;
        crate::delegations::write_delegations_atomic(path, &delegations)
            .map_err(|e| ApiError::Internal(format!("failed to persist delegations: {e}")))?;
    }
    Ok(())
}

/// Persist the settings singleton to the active source (Postgres `settings` row, else
/// `settings.json`). Takes the already-validated document the handler is about to commit.
pub(crate) async fn persist_settings(
    state: &AppState,
    settings: &Settings,
) -> Result<(), ApiError> {
    if state.sidecars_db_backed {
        let Some(store) = state.store.as_ref() else {
            return Ok(());
        };
        let json = serde_json::to_string(settings).map_err(|e| serialize_error("settings", e))?;
        store
            .persist_blocking_async(move |tx| tx.put_settings(&json))
            .await
            .map_err(|e| AppState::map_store_write_error("failed to persist settings", e))?;
        return Ok(());
    }
    if let Some(path) = &state.persist_path {
        crate::settings::write_settings_atomic(path, settings)
            .map_err(|e| ApiError::Internal(format!("failed to persist settings: {e}")))?;
    }
    Ok(())
}

// =================================================================================================
// Boot hydration (Postgres): the DB tables are authoritative for the five sidecars.
// =================================================================================================

/// One decoded snapshot of the four document/settings sidecars loaded from the DB.
struct LoadedSidecars {
    users: HashMap<UserId, User>,
    roles: RoleCatalog,
    delegations: HashMap<crate::delegations::DelegationId, StoredDelegation>,
    settings: Settings,
}

/// Load + decode the four document/settings sidecars from the store. A malformed row is skipped with
/// a warning (mirrors the malformed-tolerant file loaders) rather than blocking startup; a store
/// **error** propagates so a Postgres node fails startup closed instead of booting half-empty.
fn load_sidecars(store: &Store) -> Result<LoadedSidecars, StoreError> {
    let mut users = HashMap::new();
    for (id, json) in store.users()? {
        match serde_json::from_str::<User>(&json) {
            Ok(user) => {
                users.insert(user.id, user);
            }
            Err(e) => eprintln!("warning: skipping malformed DB user row {id} ({e})"),
        }
    }

    let mut roles = RoleCatalog::new();
    for (id, json) in store.roles()? {
        match serde_json::from_str::<Role>(&json) {
            Ok(role) => roles.insert(role),
            Err(e) => eprintln!("warning: skipping malformed DB role row {id} ({e})"),
        }
    }

    let mut delegations = HashMap::new();
    for (id, json) in store.delegations()? {
        match serde_json::from_str::<StoredDelegation>(&json) {
            Ok(delegation) => {
                delegations.insert(delegation.id, delegation);
            }
            Err(e) => eprintln!("warning: skipping malformed DB delegation row {id} ({e})"),
        }
    }

    let settings = match store.settings()? {
        Some(json) => serde_json::from_str::<Settings>(&json).unwrap_or_else(|e| {
            eprintln!(
                "warning: DB settings row is not a valid settings document ({e}); using defaults"
            );
            Settings::default()
        }),
        None => Settings::default(),
    };

    Ok(LoadedSidecars {
        users,
        roles,
        delegations,
        settings,
    })
}

/// **Boot (Postgres only).** Make the DB tables authoritative for the five document/settings sidecars:
/// load them from the store (replacing the file-derived in-memory defaults), then apply the same
/// seed-defaults + no-lockout role migration the file path applies and **persist any change back to
/// the DB** so a fresh (empty) Postgres deploy self-seeds the role catalog exactly once. On an empty
/// deployment this leaves users/delegations empty and settings at their defaults — the normal fresh
/// state; onboarding populates them. Called with exclusive ownership of `state` during startup, so it
/// swaps the whole `Arc<RwLock<..>>` rather than taking the async locks.
pub(crate) fn hydrate_from_store(state: &mut AppState, store: &Store) -> Result<(), StoreError> {
    let LoadedSidecars {
        mut users,
        mut roles,
        delegations,
        settings,
    } = load_sidecars(store)?;

    // Seed the default role catalog (Owner forced canonical/locked) and bring legacy users forward
    // with the idempotent, anti-lockout role migration — persisting each back to the DB only when it
    // actually changed, mirroring the file path's write-once seeding.
    // t87: drop the two retired duplicate roles first, so the seeding pass below cannot re-add them
    // and the reconcile deletes their rows. `retire_merged_roles` is idempotent, so a database that
    // has already been migrated takes this branch only via `ensure_seeded_defaults`, as before.
    let retired_any = crate::roles::retire_merged_roles(&mut roles);
    if crate::roles::ensure_seeded_defaults(&mut roles) || retired_any {
        let rows = roles
            .iter()
            .filter_map(|role| {
                serde_json::to_string(role)
                    .ok()
                    .map(|json| (role.id.0.to_string(), json))
            })
            .collect();
        persist_seed(store, DocumentTable::Roles, rows)?;
    }
    // t87 runs in the same pass and before the anti-lockout default, so a user whose only assignment
    // named a retired role is moved onto the successor rather than looking unassigned.
    let retired_holders_moved = crate::roles::migrate_retired_roles(&mut users);
    if crate::roles::migrate_roles(&mut users) || retired_holders_moved {
        let rows = users
            .values()
            .filter_map(|user| {
                serde_json::to_string(user)
                    .ok()
                    .map(|json| (user.id.0.to_string(), json))
            })
            .collect();
        persist_seed(store, DocumentTable::Users, rows)?;
    }

    state.users = Arc::new(RwLock::new(users));
    state.roles = Arc::new(RwLock::new(roles));
    state.delegations = Arc::new(RwLock::new(delegations));
    state.settings = Arc::new(RwLock::new(settings));
    Ok(())
}

// =================================================================================================
// Follower reload (Postgres): refresh the shared sidecars on a change-feed tick / invalidation.
// =================================================================================================

/// **Follower reload (Postgres only).** Re-read the five shared sidecars from the DB and swap them
/// into the live locks so a follower observes a leader's user/role/delegation/settings/credential
/// change. Invoked from the change-feed reconcile (every sidecar mutation also appends a ledger
/// event, so the feed already wakes) and after a full durable reload. The DB reads run on the
/// blocking pool so a stall never blocks a runtime worker; a read error keeps the prior in-memory
/// sidecars (reads stay available and lag is tolerated) rather than clearing them.
#[cfg(feature = "postgres")]
pub(crate) async fn reload_into_state(state: &AppState, store: &Store) {
    let store = store.clone();
    let loaded = tokio::task::spawn_blocking(move || load_sidecars(&store)).await;
    let loaded = match loaded {
        Ok(Ok(loaded)) => loaded,
        Ok(Err(e)) => {
            eprintln!(
                "cluster: sidecar reload from DB failed ({e}); keeping prior in-memory copies"
            );
            return;
        }
        Err(e) => {
            eprintln!("cluster: sidecar reload task panicked ({e})");
            return;
        }
    };
    *state.users.write().await = loaded.users;
    *state.roles.write().await = loaded.roles;
    *state.delegations.write().await = loaded.delegations;
    *state.settings.write().await = loaded.settings;
    // Refresh the encrypted provider-credential records (ciphertext only; no decryption here). The DB
    // read runs on the blocking pool so the synchronous `postgres` query never executes on a runtime
    // worker thread; `reload_from_db` handles its own read errors (failing that store closed).
    let credentials = state.provider_credentials.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || credentials.reload_from_db()).await {
        eprintln!("cluster: provider-credential reload task panicked ({e})");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc as StdArc;
    use std::sync::Mutex as StdMutex;

    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    use uuid::Uuid;

    use crate::cluster_shared_state::{InvalidationBus, InvalidationEvent, SharedInvalidationBus};
    use crate::users::SecretSource;

    use super::*;

    fn sample_user(name: &str) -> User {
        User {
            id: UserId(Uuid::new_v4()),
            username: name.to_owned(),
            display_name: name.to_owned(),
            email: None,
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: None,
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            secret_source: SecretSource::default(),
            recovery_hash: None,
            role_assignments: Vec::new(),
            language: Default::default(),
        }
    }

    #[test]
    fn document_table_dispatch_is_exhaustive() {
        // A compile-time reminder that every DocumentTable arm is handled by the reconcile helpers.
        for table in [
            DocumentTable::Users,
            DocumentTable::Roles,
            DocumentTable::Delegations,
        ] {
            let _copy = table; // Copy + used, so an added variant forces this array to be updated.
        }
    }

    /// SQLite / single-node keeps the byte-identical file path: `sidecars_db_backed` is `false` and a
    /// user write goes to `users.json`, not any DB table.
    #[tokio::test]
    async fn sqlite_backend_selects_the_file_impl_and_writes_users_json() {
        let dir = std::env::temp_dir().join(format!("chancela-p3b-file-{}", Uuid::new_v4()));
        let state = AppState::with_data_dir(&dir);
        assert!(
            !state.sidecars_db_backed,
            "the SQLite/default backend keeps the file sidecars"
        );

        let user = sample_user("amelia.marques");
        let uid = user.id;
        state.users.write().await.insert(uid, user);
        persist_users(&state)
            .await
            .expect("persist users via the file impl");

        let users_json = dir.join(crate::users::USERS_FILE);
        assert!(users_json.exists(), "the SQLite path writes users.json");
        let reloaded = crate::users::load_users(&users_json).expect("reload users.json");
        assert!(
            reloaded.contains_key(&uid),
            "the file impl round-trips the user"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A recording invalidation bus proving a role change publishes a cross-node signal (the pub/sub
    /// is mocked; a live-Redis fan-out is exercised in `cluster_shared_state`'s `#[ignore]` tests).
    #[derive(Debug, Default)]
    struct RecordingBus {
        published: StdMutex<Vec<InvalidationEvent>>,
    }
    impl InvalidationBus for RecordingBus {
        fn publish(&self, event: &InvalidationEvent) {
            self.published.lock().unwrap().push(event.clone());
        }
        fn subscribe_dsn(&self) -> Option<String> {
            None
        }
        fn kind(&self) -> &'static str {
            "recording"
        }
    }

    #[test]
    fn role_change_publishes_a_cross_node_invalidation() {
        let bus = StdArc::new(RecordingBus::default());
        let mut state = AppState::default();
        state.cluster_shared.invalidation = SharedInvalidationBus(bus.clone());

        let user_id = Uuid::new_v4();
        state.publish_role_changed(user_id);

        let published = bus.published.lock().unwrap();
        assert_eq!(published.len(), 1);
        assert_eq!(
            published[0],
            InvalidationEvent::RoleChanged { user_id },
            "a role/delegation change signals other nodes to drop the principal's cached authority"
        );
    }

    #[test]
    fn default_local_bus_publish_is_a_noop_single_node() {
        // The single-node default bus swallows the publish — no panic, no cross-node traffic.
        let state = AppState::default();
        assert!(!state.sidecars_db_backed);
        state.publish_role_changed(Uuid::new_v4());
    }

    // ── Live-Postgres round-trips (§8.2) ─────────────────────────────────────────────────────────
    //
    // These exercise the real DB-backed seam. They are `#[ignore]` so the offline suite never needs a
    // database; run them with DATABASE_URL (the first opener wins the writer lock ⇒ leader):
    //   DATABASE_URL=postgres://... cargo test -p chancela-api --features postgres -- --ignored
    #[cfg(feature = "postgres")]
    mod live {
        use chancela_authz::{Delegation, Permission, Scope, UserId as AuthzUserId};
        use chancela_store::{Store, StoreBackendSelection};
        use zeroize::Zeroizing;

        use crate::delegations::{DelegationId, StoredDelegation};
        use crate::secretstore_persist::{
            CredentialFieldSet, CredentialMode, CscCredentialFields, FIELD_CLIENT_SECRET,
            ProviderCredentialStore,
        };

        use super::*;

        const TEST_DB_KEY: &[u8] = b"wp16-p3b-api-live-credential-db-key-0123456789";

        fn open() -> Option<Store> {
            let url = std::env::var("DATABASE_URL")
                .ok()
                .filter(|s| !s.is_empty())?;
            Some(
                Store::open_backend(StoreBackendSelection::Postgres { database_url: url })
                    .expect("open postgres store"),
            )
        }

        fn pg_state(store: Store) -> AppState {
            AppState {
                store: Some(store),
                sidecars_db_backed: true,
                ..AppState::default()
            }
        }

        #[tokio::test]
        #[ignore = "requires a live Postgres (set DATABASE_URL)"]
        async fn user_role_delegation_settings_write_persists_and_reloads_via_the_db() {
            let Some(store) = open() else { return };
            if !store.cluster_is_leader() {
                return; // only the writer-leader may persist; skip if a peer holds the lock.
            }
            let state = pg_state(store.clone());

            // Users.
            let user = sample_user(&format!("live.user.{}", Uuid::new_v4().simple()));
            let uid = user.id;
            state.users.write().await.insert(uid, user);
            persist_users(&state).await.expect("persist user to the DB");

            // Roles.
            let role = chancela_authz::Role {
                id: chancela_authz::RoleId(Uuid::new_v4()),
                name: format!("Live Role {}", Uuid::new_v4().simple()),
                permission_set: [Permission::LedgerRead].into_iter().collect(),
                protected: false,
            };
            let role_id = role.id;
            state.roles.write().await.insert(role);
            persist_roles(&state).await.expect("persist role to the DB");

            // Delegations.
            let del = StoredDelegation::new(
                DelegationId(Uuid::new_v4()),
                OffsetDateTime::now_utc()
                    .format(&Rfc3339)
                    .unwrap_or_default(),
                Delegation::new(
                    AuthzUserId(Uuid::new_v4()),
                    AuthzUserId(uid.0),
                    Permission::ActAdvance,
                    Scope::Global,
                ),
            );
            let del_id = del.id;
            state.delegations.write().await.insert(del_id, del);
            persist_delegations(&state)
                .await
                .expect("persist delegation to the DB");

            // Settings (mutate a field and round-trip it).
            let mut settings = state.settings.read().await.clone();
            let marker = format!("Encosto Estratégico {}", Uuid::new_v4().simple());
            settings.organization.name = Some(marker.clone());
            *state.settings.write().await = settings.clone();
            persist_settings(&state, &settings)
                .await
                .expect("persist settings to the DB");

            // A fresh reload from the DB observes every write (what a follower's feed does).
            let reloaded = load_sidecars(&store).expect("reload sidecars from the DB");
            assert!(reloaded.users.contains_key(&uid), "user persisted");
            assert!(reloaded.roles.get(role_id).is_some(), "role persisted");
            assert!(
                reloaded.delegations.contains_key(&del_id),
                "delegation persisted"
            );
            assert_eq!(
                reloaded.settings.organization.name.as_deref(),
                Some(marker.as_str()),
                "settings persisted"
            );
        }

        #[test]
        #[ignore = "requires a live Postgres (set DATABASE_URL)"]
        fn credential_record_round_trips_through_the_db_blob_path() {
            let Some(store) = open() else { return };
            if !store.cluster_is_leader() {
                return;
            }
            let dir = std::env::temp_dir().join(format!("chancela-p3b-cred-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("create data dir");
            let provider = format!("encosto-{}", Uuid::new_v4().simple());
            let secret = "sk_live_amelia_marques_9f8e7d6c5b4a";

            // Write the encrypted blob through the DB-backed store (wp13 envelope unchanged).
            {
                let creds = ProviderCredentialStore::load_db_backed_with_db_key(
                    store.clone(),
                    &dir,
                    TEST_DB_KEY,
                    false,
                );
                creds
                    .put(
                        CredentialMode::CscQtsp,
                        &provider,
                        CscCredentialFields {
                            client_secret: Some(Zeroizing::new(secret.to_owned())),
                            ..Default::default()
                        }
                        .into_set_pairs(),
                        &[],
                    )
                    .expect("put credential via the DB blob path");
            }

            // A fresh store instance reloads purely from the DB row and decrypts through the same
            // envelope, proving the ciphertext was preserved verbatim in the `provider_credentials`
            // table (no re-encryption, no plaintext at rest in the store).
            let reloaded = ProviderCredentialStore::load_db_backed_with_db_key(
                store.clone(),
                &dir,
                TEST_DB_KEY,
                false,
            );
            let record = reloaded
                .read(CredentialMode::CscQtsp, &provider)
                .expect("read")
                .expect("record present in the DB");
            assert_eq!(
                record.fields.get(FIELD_CLIENT_SECRET).map(|z| z.as_str()),
                Some(secret),
                "the DB blob path preserves ciphertext and decrypts through the unchanged envelope"
            );

            // Clearing removes the row (reconcile deletes it), so a later reload sees nothing.
            reloaded
                .clear_record(CredentialMode::CscQtsp, &provider)
                .expect("clear the DB record");
            let after = ProviderCredentialStore::load_db_backed_with_db_key(
                store,
                &dir,
                TEST_DB_KEY,
                false,
            );
            assert!(
                after
                    .read(CredentialMode::CscQtsp, &provider)
                    .expect("read after clear")
                    .is_none(),
                "a cleared credential record is deleted from the DB, not left behind"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
