//! Per-user, **non-ledger** UI preferences (t37): configurable table columns for the entities,
//! books and templates tables, persisted server-side so a choice follows the operator across
//! devices.
//!
//! ## Why this is its own sidecar, and deliberately not the ledger
//!
//! The obvious home for a per-user setting is the user record — but a [`UserView`](crate::users)
//! is a **ledger payload**: it is the digest input for every `user.created` / `user.updated`
//! event. Putting churny column toggles there would move the digest of all future user events and
//! emit a `user.updated` ledger event on every show/hide of a column, polluting the audit trail
//! with UI noise. So this store is a plain per-user sidecar — **not** in the ledger, **not** in
//! [`UserView`](crate::users), **not** in the settings contract — carrying zero digest movement.
//!
//! ## Shape and persistence
//!
//! The document is a map `user_id → `[`UserPreferences`], with its own [`schema_version`]. It is
//! read at startup and rewritten atomically (temp file + rename) on every successful `PUT`,
//! mirroring [`crate::settings`] / [`crate::notifications`]. Without a data directory it lives
//! purely in memory and resets on restart, like the rest of the scaffold state.
//!
//! ## Endpoints (self-scoped)
//!
//! `GET`/`PUT /v1/me/preferences` act **only** on the acting session's own row — the session
//! subject is the key, there is no admin-edits-others path, and no new RBAC verb (self-service,
//! like the language write on a user's own account). An API key is not an interactive user and is
//! refused. A user with no stored row reads back defaults; `PUT` is a whole-document replace of the
//! caller's [`UserPreferences`].
//!
//! ## Contract-agnostic on purpose
//!
//! The server stores column ids as opaque, bounded strings and validates only their *shape*
//! (count, length, charset, no duplicates). It deliberately does **not** know the entity/book/
//! template column enums: the effective visible set — personal override → org default → product
//! default — is resolved on the web side against the real column lists. Keeping the server ignorant
//! of the column vocabulary means adding or renaming a column never touches this file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::error::ApiError;
use crate::users::UserId;

/// The file name holding the per-user preferences document inside the data directory.
pub const USER_PREFERENCES_FILE: &str = "user_preferences.json";

/// The current schema version of the preferences document. Bumped only on a breaking shape change;
/// an older/newer stored document still loads (unknown fields ignored, missing fields defaulted).
pub const USER_PREFERENCES_SCHEMA_VERSION: u32 = 1;

/// The three tables whose columns are configurable. Purely defensive: it bounds how large a single
/// user's row can grow (the whole document is one user's three arrays at most).
const MAX_COLUMNS_PER_TABLE: usize = 64;
/// A column identifier is a short PascalCase enum name (e.g. `LastActivity`). This caps a malformed
/// or hostile id well above any real one.
const MAX_COLUMN_ID_BYTES: usize = 64;

// --- The document -------------------------------------------------------------------------------

/// The whole per-user preferences document: a map from user id (as its canonical UUID string) to
/// that user's [`UserPreferences`], plus a schema discriminator.
///
/// Keyed by the UUID *string* rather than by [`UserId`] so the JSON is a plain, deterministic
/// object (`{"<uuid>": …}`) with no reliance on newtype map-key serde, and so a write is byte-stable
/// for clean diffs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserPreferencesStore {
    /// Schema version discriminator (always [`USER_PREFERENCES_SCHEMA_VERSION`] when written here).
    pub schema_version: u32,
    /// Per-user rows, keyed by the user id's canonical UUID string.
    pub users: BTreeMap<String, UserPreferences>,
}

impl Default for UserPreferencesStore {
    fn default() -> Self {
        UserPreferencesStore {
            schema_version: USER_PREFERENCES_SCHEMA_VERSION,
            users: BTreeMap::new(),
        }
    }
}

impl UserPreferencesStore {
    /// The caller's stored preferences, or defaults when they have no row.
    fn get(&self, user_id: UserId) -> UserPreferences {
        self.users
            .get(&user_id.to_string())
            .cloned()
            .unwrap_or_default()
    }

    /// Replace the caller's row. An all-default value removes the row entirely rather than storing an
    /// empty object, so "reset to defaults" leaves no trace and the file shrinks back.
    fn set(&mut self, user_id: UserId, prefs: UserPreferences) {
        self.schema_version = USER_PREFERENCES_SCHEMA_VERSION;
        if prefs == UserPreferences::default() {
            self.users.remove(&user_id.to_string());
        } else {
            self.users.insert(user_id.to_string(), prefs);
        }
    }

    /// Drop any row whose columns do not survive sanitisation, so a hand-edited or older file can
    /// never round-trip garbage back onto the wire.
    fn sanitized(mut self) -> Self {
        self.schema_version = USER_PREFERENCES_SCHEMA_VERSION;
        self.users = self
            .users
            .into_iter()
            .filter_map(|(key, prefs)| {
                // Keep only well-formed UUID keys and their sanitised, non-empty preferences.
                Uuid::parse_str(&key).ok()?;
                let cleaned = prefs.sanitized();
                (cleaned != UserPreferences::default()).then_some((key, cleaned))
            })
            .collect();
        self
    }
}

/// One user's UI preferences. Additive: a future preference is a new serde-defaulted field, so an
/// older stored row keeps loading.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserPreferences {
    /// Per-table visible-column choices.
    pub table_columns: TableColumnPreferences,
}

impl UserPreferences {
    /// Validate the whole document for a `PUT` — every present table must be well-formed, or the
    /// request is refused (`422`) rather than silently trimmed.
    fn validate(&self) -> Result<(), ApiError> {
        self.table_columns.validate()
    }

    /// A defensively cleaned copy: each present table's ids trimmed, bad ids dropped, duplicates
    /// collapsed, count capped, and an emptied table folded back to "no override" (`None`).
    fn sanitized(&self) -> Self {
        UserPreferences {
            table_columns: self.table_columns.sanitized(),
        }
    }
}

/// The visible-column choice per configurable table.
///
/// Each field is an **ordered set of column ids**. `None` means "no personal override for this
/// table" — the web then falls back to the org default (entities) or the product default (books,
/// templates). This is why the fields are `Option`: it lets a user personalise one table without
/// implying anything about the others. `PUT` replaces the whole object, so sending `null` (or
/// omitting a field) clears that table's override.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TableColumnPreferences {
    /// The registered-entities table (`EntitiesPage`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entities: Option<Vec<String>>,
    /// The books/livros table (`BooksTable`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub books: Option<Vec<String>>,
    /// The templates/minutas catalog table (`TemplatesCatalogPage`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub templates: Option<Vec<String>>,
}

impl TableColumnPreferences {
    /// The three (table name, value) pairs, so validation and sanitisation iterate rather than
    /// repeat themselves three times.
    fn tables(&self) -> [(&'static str, &Option<Vec<String>>); 3] {
        [
            ("entities", &self.entities),
            ("books", &self.books),
            ("templates", &self.templates),
        ]
    }

    fn validate(&self) -> Result<(), ApiError> {
        for (name, columns) in self.tables() {
            if let Some(columns) = columns {
                validate_columns(name, columns)?;
            }
        }
        Ok(())
    }

    fn sanitized(&self) -> Self {
        TableColumnPreferences {
            entities: sanitize_columns(self.entities.as_deref()),
            books: sanitize_columns(self.books.as_deref()),
            templates: sanitize_columns(self.templates.as_deref()),
        }
    }
}

/// Whether a column id is a well-formed opaque identifier: non-empty, bounded, ASCII-alphanumeric.
/// The server does not check it against any column enum (see the module note) — only its shape.
fn is_valid_column_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_COLUMN_ID_BYTES
        && id.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Strict validation for a `PUT`: reject an over-long list, a malformed id, or a duplicate rather
/// than repair it silently — the caller learns exactly what it sent that was wrong.
fn validate_columns(table: &str, columns: &[String]) -> Result<(), ApiError> {
    if columns.len() > MAX_COLUMNS_PER_TABLE {
        return Err(ApiError::Unprocessable(format!(
            "table_columns.{table} accepts at most {MAX_COLUMNS_PER_TABLE} columns, got {}",
            columns.len()
        )));
    }
    let mut seen = std::collections::BTreeSet::new();
    for id in columns {
        if !is_valid_column_id(id) {
            return Err(ApiError::Unprocessable(format!(
                "table_columns.{table} contains an invalid column id {id:?}: a column id must be \
                 1..={MAX_COLUMN_ID_BYTES} ASCII-alphanumeric characters"
            )));
        }
        if !seen.insert(id.as_str()) {
            return Err(ApiError::Unprocessable(format!(
                "table_columns.{table} contains the duplicate column id {id:?}"
            )));
        }
    }
    Ok(())
}

/// Lenient cleanup for a value read from disk: keep the valid, order-preserving, duplicate-free ids
/// up to the cap; fold an empty result back to `None` (no override). Never errors — a corrupt file
/// must not stop the server from starting.
fn sanitize_columns(columns: Option<&[String]>) -> Option<Vec<String>> {
    let columns = columns?;
    let mut seen = std::collections::BTreeSet::new();
    let cleaned: Vec<String> = columns
        .iter()
        .filter(|id| is_valid_column_id(id))
        .filter(|id| seen.insert(id.to_string()))
        .take(MAX_COLUMNS_PER_TABLE)
        .cloned()
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

// --- Persistence --------------------------------------------------------------------------------

/// Read `user_preferences.json` from `path`, returning `None` if it is absent or unreadable, and
/// falling back to defaults (with a warning) if it is present but malformed. A corrupt file must
/// never stop the server from starting. Loaded rows are sanitised so garbage cannot round-trip.
pub(crate) fn load_user_preferences(path: &Path) -> Option<UserPreferencesStore> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<UserPreferencesStore>(&bytes) {
        Ok(store) => Some(store.sanitized()),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid user preferences document ({e}); using defaults",
                path.display()
            );
            None
        }
    }
}

/// Atomically write `store` to `path`: serialize to a uniquely-named temp file in the same
/// directory, then rename it over the destination (an atomic replace on both Windows and Unix). The
/// parent directory is created if missing. Mirrors [`crate::settings::write_settings_atomic`].
pub(crate) fn write_user_preferences_atomic(
    path: &Path,
    store: &UserPreferencesStore,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(store).map_err(std::io::Error::other)?;
    let tmp = tmp_path(path);
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Persist the in-memory store to its sidecar, when the state is file-backed. A no-op in memory.
pub(crate) async fn persist_user_preferences(state: &AppState) -> Result<(), ApiError> {
    if let Some(path) = &state.user_preferences_path {
        let store = state.user_preferences.read().await;
        write_user_preferences_atomic(path, &store)
            .map_err(|e| ApiError::Internal(format!("failed to persist user preferences: {e}")))?;
    }
    Ok(())
}

/// A sibling temp path for the atomic write, made unique so two concurrent `PUT`s never race on the
/// same temp file before their renames.
fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| USER_PREFERENCES_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

// --- Handlers -----------------------------------------------------------------------------------

/// Resolve the acting session to its own [`UserId`] — the self-scope key.
///
/// An API key is refused (`403`): it authenticates a machine principal, not an interactive user, so
/// it has no personal preferences to read or write. The [`CurrentActor`] extractor has already
/// rejected an absent/expired/invalid session with `401`, so reaching here means a live session
/// whose user must still resolve in the directory.
async fn resolve_self(state: &AppState, actor: &CurrentActor) -> Result<UserId, ApiError> {
    let Some(username) = actor.session_username() else {
        return Err(ApiError::Forbidden(
            "uma chave API não abre uma sessão interativa com preferências pessoais".to_owned(),
        ));
    };
    state
        .users
        .read()
        .await
        .values()
        .find(|u| u.username == username)
        .map(|u| u.id)
        .ok_or_else(|| ApiError::Unauthorized("sessão inválida".to_owned()))
}

/// `GET /v1/me/preferences` — the acting user's own UI preferences (defaults if they have no row).
pub async fn get_me_preferences(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<UserPreferences>, ApiError> {
    let user_id = resolve_self(&state, &actor).await?;
    let prefs = state.user_preferences.read().await.get(user_id);
    Ok(Json(prefs))
}

/// `PUT /v1/me/preferences` — replace the acting user's own UI preferences.
///
/// The body is a whole [`UserPreferences`] document; it is parsed by hand so a malformed body
/// renders through [`ApiError`] as the standard `{"error": …}` shape, then validated (per-table
/// count/shape/duplicates). On success the caller's row is replaced (an all-default value removes
/// it), the sidecar is persisted, and the stored value is echoed back. **No ledger event is
/// appended** — that is the entire point of this store.
pub async fn put_me_preferences(
    State(state): State<AppState>,
    actor: CurrentActor,
    body: Bytes,
) -> Result<Json<UserPreferences>, ApiError> {
    let user_id = resolve_self(&state, &actor).await?;
    let incoming: UserPreferences = serde_json::from_slice(&body)
        .map_err(|e| ApiError::Unprocessable(format!("invalid preferences document: {e}")))?;
    incoming.validate()?;
    // Validation already proved the ids well-formed and duplicate-free; sanitise only folds an
    // explicitly-empty table (`[]`) back to "no override" so it stores identically to omitting it.
    let stored = incoming.sanitized();
    state
        .user_preferences
        .write()
        .await
        .set(user_id, stored.clone());
    persist_user_preferences(&state).await?;
    Ok(Json(stored))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use uuid::Uuid;

    use super::*;
    use crate::users::{User, UserId};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("chancela-user-prefs-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn prefs(entities: Option<&[&str]>, books: Option<&[&str]>) -> UserPreferences {
        let to_vec = |v: Option<&[&str]>| v.map(|c| c.iter().map(|s| s.to_string()).collect());
        UserPreferences {
            table_columns: TableColumnPreferences {
                entities: to_vec(entities),
                books: to_vec(books),
                templates: None,
            },
        }
    }

    async fn seed_user(state: &AppState, username: &str) -> UserId {
        let uid = UserId(Uuid::new_v4());
        state.users.write().await.insert(
            uid,
            User {
                id: uid,
                username: username.to_owned(),
                display_name: "Amélia Marques".to_owned(),
                email: None,
                created_at: "2026-01-01T00:00:00Z".to_owned(),
                active: true,
                password_hash: None,
                attestation_key: None,
                retired_attestation_keys: Vec::new(),
                totp: None,
                two_factor_required: false,
                force_password_change: false,
                secret_source: Default::default(),
                recovery_hash: None,
                role_assignments: Vec::new(),
                language: Default::default(),
            },
        );
        uid
    }

    #[test]
    fn write_load_round_trips_a_users_columns() {
        let dir = TempDir::new();
        let path = dir.0.join(USER_PREFERENCES_FILE);
        let mut store = UserPreferencesStore::default();
        let uid = UserId(Uuid::new_v4());
        store.set(
            uid,
            prefs(Some(&["Name", "Nipc", "Actions"]), Some(&["Kind", "State"])),
        );

        write_user_preferences_atomic(&path, &store).expect("write");
        let loaded = load_user_preferences(&path).expect("load");

        assert_eq!(loaded, store);
        assert_eq!(
            loaded.get(uid).table_columns.entities.as_deref(),
            Some(["Name".to_owned(), "Nipc".to_owned(), "Actions".to_owned()].as_slice())
        );
        // A user with no row reads back defaults, not an error.
        assert_eq!(
            loaded.get(UserId(Uuid::new_v4())),
            UserPreferences::default()
        );
    }

    #[test]
    fn setting_defaults_removes_the_row() {
        let mut store = UserPreferencesStore::default();
        let uid = UserId(Uuid::new_v4());
        store.set(uid, prefs(Some(&["Name"]), None));
        assert!(store.users.contains_key(&uid.to_string()));

        store.set(uid, UserPreferences::default());
        assert!(
            !store.users.contains_key(&uid.to_string()),
            "resetting to defaults must leave no row behind"
        );
    }

    #[test]
    fn validation_rejects_bad_ids_duplicates_and_overflow() {
        // A non-alphanumeric id.
        assert!(prefs(Some(&["Na me"]), None).validate().is_err());
        assert!(prefs(Some(&["drop;table"]), None).validate().is_err());
        // A duplicate within a table.
        assert!(prefs(Some(&["Name", "Name"]), None).validate().is_err());
        // Too many columns.
        let many: Vec<&str> = std::iter::repeat("A")
            .take(MAX_COLUMNS_PER_TABLE + 1)
            .collect();
        // (all identical would trip the duplicate check first, so make them distinct)
        let distinct: Vec<String> = (0..=MAX_COLUMNS_PER_TABLE)
            .map(|i| format!("Col{i}"))
            .collect();
        let over = UserPreferences {
            table_columns: TableColumnPreferences {
                entities: Some(distinct),
                books: None,
                templates: None,
            },
        };
        assert!(over.validate().is_err());
        let _ = many;
        // A well-formed set passes.
        assert!(
            prefs(Some(&["Name", "Nipc", "Actions"]), Some(&["Kind"]))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn sanitize_drops_garbage_and_folds_empty_to_none() {
        // A hand-edited file with a bad id and a duplicate: the bad id is dropped, the dupe collapsed.
        let raw = UserPreferences {
            table_columns: TableColumnPreferences {
                entities: Some(vec![
                    "Name".to_owned(),
                    "bad id".to_owned(),
                    "Name".to_owned(),
                    "Nipc".to_owned(),
                ]),
                books: Some(vec![]),
                templates: None,
            },
        };
        let clean = raw.sanitized();
        assert_eq!(
            clean.table_columns.entities.as_deref(),
            Some(["Name".to_owned(), "Nipc".to_owned()].as_slice())
        );
        // An explicitly-empty table folds back to "no override".
        assert_eq!(clean.table_columns.books, None);
    }

    #[test]
    fn store_sanitize_drops_non_uuid_keys_and_empty_rows() {
        let mut store = UserPreferencesStore::default();
        store
            .users
            .insert("not-a-uuid".to_owned(), prefs(Some(&["Name"]), None));
        let empty_key = Uuid::new_v4().to_string();
        store
            .users
            .insert(empty_key.clone(), UserPreferences::default());
        let good_key = Uuid::new_v4().to_string();
        store
            .users
            .insert(good_key.clone(), prefs(Some(&["Name"]), None));

        let clean = store.sanitized();
        assert!(!clean.users.contains_key("not-a-uuid"));
        assert!(!clean.users.contains_key(&empty_key));
        assert!(clean.users.contains_key(&good_key));
    }

    #[tokio::test]
    async fn put_then_get_round_trips_for_the_acting_user() {
        let state = AppState::default();
        let uid = seed_user(&state, "amelia.marques").await;
        let actor = CurrentActor::from_session_username(Some("amelia.marques".to_owned()));

        let body = serde_json::to_vec(&prefs(Some(&["Name", "Nipc"]), Some(&["Kind"]))).unwrap();
        let stored = put_me_preferences(State(state.clone()), actor.clone(), body.into())
            .await
            .expect("put succeeds")
            .0;
        assert_eq!(
            stored.table_columns.entities.as_deref(),
            Some(["Name".to_owned(), "Nipc".to_owned()].as_slice())
        );

        let got = get_me_preferences(State(state.clone()), actor)
            .await
            .expect("get")
            .0;
        assert_eq!(got, stored);
        // Stored under exactly the acting user's id.
        assert!(
            state
                .user_preferences
                .read()
                .await
                .users
                .contains_key(&uid.to_string())
        );
    }

    #[tokio::test]
    async fn one_user_cannot_see_or_clobber_anothers_row() {
        let state = AppState::default();
        seed_user(&state, "amelia.marques").await;
        seed_user(&state, "bruno.costa").await;
        let amelia = CurrentActor::from_session_username(Some("amelia.marques".to_owned()));
        let bruno = CurrentActor::from_session_username(Some("bruno.costa".to_owned()));

        let amelia_body = serde_json::to_vec(&prefs(Some(&["Name"]), None)).unwrap();
        let _ = put_me_preferences(State(state.clone()), amelia.clone(), amelia_body.into())
            .await
            .expect("amelia put");
        let bruno_body = serde_json::to_vec(&prefs(Some(&["Type"]), None)).unwrap();
        let _ = put_me_preferences(State(state.clone()), bruno.clone(), bruno_body.into())
            .await
            .expect("bruno put");

        // Each reads only their own choice.
        let amelia_got = get_me_preferences(State(state.clone()), amelia)
            .await
            .unwrap()
            .0;
        let bruno_got = get_me_preferences(State(state.clone()), bruno)
            .await
            .unwrap()
            .0;
        assert_eq!(
            amelia_got.table_columns.entities.as_deref(),
            Some(["Name".to_owned()].as_slice())
        );
        assert_eq!(
            bruno_got.table_columns.entities.as_deref(),
            Some(["Type".to_owned()].as_slice())
        );
    }

    #[tokio::test]
    async fn an_api_key_has_no_personal_preferences() {
        let state = AppState::default();
        // A default CurrentActor has no session username (stands in for an API-key principal here).
        let actor = CurrentActor::default();
        let err = get_me_preferences(State(state.clone()), actor.clone())
            .await
            .expect_err("api key is refused");
        assert!(matches!(err, ApiError::Forbidden(_)));
        let body = serde_json::to_vec(&prefs(Some(&["Name"]), None)).unwrap();
        let err = put_me_preferences(State(state), actor, body.into())
            .await
            .expect_err("api key is refused");
        assert!(matches!(err, ApiError::Forbidden(_)));
    }

    #[tokio::test]
    async fn put_persists_to_the_sidecar_when_file_backed() {
        let dir = TempDir::new();
        let path = dir.0.join(USER_PREFERENCES_FILE);
        let state = AppState {
            user_preferences_path: Some(std::sync::Arc::new(path.clone())),
            ..AppState::default()
        };
        seed_user(&state, "amelia.marques").await;
        let actor = CurrentActor::from_session_username(Some("amelia.marques".to_owned()));
        let body = serde_json::to_vec(&prefs(Some(&["Name", "Actions"]), None)).unwrap();
        let _ = put_me_preferences(State(state.clone()), actor, body.into())
            .await
            .expect("put");

        // The file exists and reloads to the same content.
        let reloaded = load_user_preferences(&path).expect("reload");
        assert_eq!(reloaded, *state.user_preferences.read().await);
    }
}
