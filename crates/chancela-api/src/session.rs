//! Session endpoints (contract §2.8, extended by plan t29 §4.2/§4.4/§4.5): mint, inspect, and
//! drop an opaque actor token, requiring the per-user password verifier.
//!
//! A session maps an opaque token to a [`SessionEntry`] — the user, plus (when the user signed in
//! with a password and holds an attestation key) the **decrypted signing key** held in memory for
//! the life of the session. The UI mints one with `POST /v1/session {username, password}` (or the
//! back-compat `{user_id, password}` when it already holds the id), sends
//! the returned token as the `X-Chancela-Session` header on every subsequent request, and the
//! [`CurrentActor`](crate::actor::CurrentActor) /
//! [`CurrentAttestor`](crate::actor::CurrentAttestor) extractors resolve it.
//!
//! **Security (t41):** sessions carry a 24h [`expires_at`](SessionEntry::expires_at) and the
//! [`CurrentActor`](crate::actor::CurrentActor) extractor rejects expired/missing tokens with
//! `401`. Sign-in failures (unknown user, inactive user, wrong password) return
//! `401 "credenciais inválidas"`; a legacy user with no password verifier returns a state-specific
//! rejection and never mints a session. The backoff speed-bump holds its write lock across the
//! argon2 verify so concurrent requests cannot all read "no backoff" and then each spend ~100 ms in
//! argon2.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::AppState;
use crate::actor::{SESSION_HEADER, SESSION_TTL_SECS, resolve_session_actor};
use crate::apikeys::read_bearer_api_key;
use crate::attestation::{hash_secret_with_seed, verify_secret_with_seed};
use crate::cluster_shared_state;
use crate::error::ApiError;
use crate::users::{User, UserId, UserView};

/// A live session: the user it authenticates, plus the optional in-memory attestation signing key
/// unlocked at sign-in (plan t29 §4.4) and the expiry timestamp (t41 M3).
pub struct SessionEntry {
    pub user_id: UserId,
    pub unlocked_key: Option<SigningKey>,
    pub expires_at: OffsetDateTime,
}

/// Digest-only session registry used by durable, single-node data-dir deployments.
///
/// The plaintext bearer token and optional unlocked attestation key remain process-local. The file
/// contains only a SHA-256 token digest, principal id, exact issue time, and idle expiry, which is
/// enough to re-authenticate a presented token after a clean or unclean API restart without turning
/// the registry itself into a bearer-token database.
pub(crate) const SESSIONS_FILE: &str = "sessions.json";
const SESSION_REGISTRY_SCHEMA_VERSION: u32 = 1;
const MAX_DURABLE_SESSIONS: usize = 10_000;
const MAX_SESSION_REGISTRY_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableSessionRecord {
    token_sha256: String,
    pub(crate) user_id: Uuid,
    pub(crate) issued_at_unix: i64,
    pub(crate) expires_at_unix: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableSessionDocument {
    schema_version: u32,
    sessions: Vec<DurableSessionRecord>,
}

#[derive(Debug)]
struct DurableSessionRegistryInner {
    path: Option<PathBuf>,
    records: RwLock<HashMap<String, DurableSessionRecord>>,
}

/// Cloneable handle to the durable session registry. [`Default`] is explicitly ephemeral.
#[derive(Clone, Debug)]
pub struct DurableSessionRegistry(Arc<DurableSessionRegistryInner>);

impl Default for DurableSessionRegistry {
    fn default() -> Self {
        Self(Arc::new(DurableSessionRegistryInner {
            path: None,
            records: RwLock::new(HashMap::new()),
        }))
    }
}

impl DurableSessionRegistry {
    pub(crate) fn load(path: PathBuf) -> Self {
        let records = load_durable_sessions(&path).unwrap_or_else(|error| {
            eprintln!(
                "warning: {} is not a valid durable session registry ({error}); all persisted sessions are invalidated",
                path.display()
            );
            HashMap::new()
        });
        Self(Arc::new(DurableSessionRegistryInner {
            path: Some(path),
            records: RwLock::new(records),
        }))
    }

    pub(crate) fn is_durable(&self) -> bool {
        self.0.path.is_some()
    }

    pub(crate) async fn insert(
        &self,
        token: &str,
        user_id: Uuid,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<(), ApiError> {
        let digest = session_token_digest(token);
        let record = DurableSessionRecord {
            token_sha256: digest.clone(),
            user_id,
            issued_at_unix: issued_at.unix_timestamp(),
            expires_at_unix: expires_at.unix_timestamp(),
        };
        let mut records = self.0.records.write().await;
        let mut next = records.clone();
        next.retain(|_, existing| issued_at.unix_timestamp() < existing.expires_at_unix);
        if next.len() >= MAX_DURABLE_SESSIONS && !next.contains_key(&digest) {
            return Err(ApiError::Unavailable(
                "limite de sessões duráveis atingido; termine uma sessão e tente novamente"
                    .to_owned(),
            ));
        }
        next.insert(digest, record);
        self.persist(&next)?;
        *records = next;
        Ok(())
    }

    /// Resolve a token digest and atomically persist its new sliding idle expiry.
    pub(crate) async fn resolve_and_slide(
        &self,
        token: &str,
        now: OffsetDateTime,
        new_expires_at: OffsetDateTime,
    ) -> Result<Option<DurableSessionRecord>, ApiError> {
        let digest = session_token_digest(token);
        let mut records = self.0.records.write().await;
        let Some(mut record) = records.get(&digest).cloned() else {
            return Ok(None);
        };
        let mut next = records.clone();
        if now.unix_timestamp() >= record.expires_at_unix {
            next.remove(&digest);
            self.persist(&next)?;
            *records = next;
            return Ok(None);
        }
        record.expires_at_unix = new_expires_at.unix_timestamp();
        next.insert(digest, record.clone());
        self.persist(&next)?;
        *records = next;
        Ok(Some(record))
    }

    /// Slide a record only when it belongs to this registry. This keeps manually injected test/e2e
    /// sessions working while every session minted through the production handler is write-through.
    pub(crate) async fn slide_if_present(
        &self,
        token: &str,
        now: OffsetDateTime,
        new_expires_at: OffsetDateTime,
    ) -> Result<Option<DurableSessionRecord>, ApiError> {
        if !self.is_durable() {
            return Ok(None);
        }
        self.resolve_and_slide(token, now, new_expires_at).await
    }

    pub(crate) async fn revoke(&self, token: &str) -> Result<(), ApiError> {
        if !self.is_durable() {
            return Ok(());
        }
        let digest = session_token_digest(token);
        let mut records = self.0.records.write().await;
        if !records.contains_key(&digest) {
            return Ok(());
        }
        let mut next = records.clone();
        next.remove(&digest);
        self.persist(&next)?;
        *records = next;
        Ok(())
    }

    /// Revoke a durable session by its **token digest** rather than the plaintext bearer (wp27-e4
    /// companion device revoke). The companion-device registry persists only the SHA-256 digest of a
    /// device's session token, so revoking a device can kill its durable session without the registry
    /// ever holding the plaintext token. A no-op for a non-durable registry or an unknown digest.
    pub(crate) async fn revoke_by_digest(&self, digest: &str) -> Result<(), ApiError> {
        if !self.is_durable() {
            return Ok(());
        }
        let mut records = self.0.records.write().await;
        if !records.contains_key(digest) {
            return Ok(());
        }
        let mut next = records.clone();
        next.remove(digest);
        self.persist(&next)?;
        *records = next;
        Ok(())
    }

    pub(crate) async fn clear(&self) -> Result<(), ApiError> {
        if !self.is_durable() {
            return Ok(());
        }
        let mut records = self.0.records.write().await;
        let next = HashMap::new();
        self.persist(&next)?;
        *records = next;
        Ok(())
    }

    fn persist(&self, records: &HashMap<String, DurableSessionRecord>) -> Result<(), ApiError> {
        let Some(path) = &self.0.path else {
            return Ok(());
        };
        write_durable_sessions_atomic(path, records).map_err(|error| {
            ApiError::Internal(format!(
                "failed to persist durable session registry {}: {error}",
                path.display()
            ))
        })
    }
}

pub(crate) fn session_token_digest(token: &str) -> String {
    crate::hex::hex(&<[u8; 32]>::from(Sha256::digest(token.as_bytes())))
}

fn load_durable_sessions(path: &Path) -> Result<HashMap<String, DurableSessionRecord>, String> {
    recover_interrupted_session_replace(path).map_err(|error| error.to_string())?;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => return Err(error.to_string()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("registry path is not a regular file".to_owned());
    }
    if metadata.len() > MAX_SESSION_REGISTRY_BYTES {
        return Err(format!(
            "registry exceeds {MAX_SESSION_REGISTRY_BYTES} bytes"
        ));
    }
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let document: DurableSessionDocument =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if document.schema_version != SESSION_REGISTRY_SCHEMA_VERSION {
        return Err(format!(
            "unsupported schema version {}",
            document.schema_version
        ));
    }
    if document.sessions.len() > MAX_DURABLE_SESSIONS {
        return Err(format!(
            "registry contains more than {MAX_DURABLE_SESSIONS} sessions"
        ));
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut seen = HashSet::with_capacity(document.sessions.len());
    let mut records = HashMap::with_capacity(document.sessions.len());
    for record in document.sessions {
        if !is_lower_hex_digest(&record.token_sha256)
            || record.issued_at_unix > record.expires_at_unix
            || OffsetDateTime::from_unix_timestamp(record.issued_at_unix).is_err()
            || OffsetDateTime::from_unix_timestamp(record.expires_at_unix).is_err()
        {
            return Err("registry contains an invalid session record".to_owned());
        }
        if !seen.insert(record.token_sha256.clone()) {
            return Err("registry contains a duplicate token digest".to_owned());
        }
        if now < record.expires_at_unix {
            records.insert(record.token_sha256.clone(), record);
        }
    }
    Ok(records)
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn write_durable_sessions_atomic(
    path: &Path,
    records: &HashMap<String, DurableSessionRecord>,
) -> std::io::Result<()> {
    recover_interrupted_session_replace(path)?;
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(std::io::Error::other(
            "refusing to replace a symlinked session registry",
        ));
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut sessions: Vec<DurableSessionRecord> = records.values().cloned().collect();
    sessions.sort_by(|a, b| {
        a.issued_at_unix
            .cmp(&b.issued_at_unix)
            .then(a.token_sha256.cmp(&b.token_sha256))
    });
    let document = DurableSessionDocument {
        schema_version: SESSION_REGISTRY_SCHEMA_VERSION,
        sessions,
    };
    let json = serde_json::to_vec_pretty(&document).map_err(std::io::Error::other)?;
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| SESSIONS_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    let tmp = path.with_file_name(name);
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(&json)?;
        file.sync_all()?;

        #[cfg(not(windows))]
        {
            std::fs::rename(&tmp, path)?;
        }

        // Windows cannot rename over an existing destination. Preserve the previous complete
        // document as a rollback file until the replacement has been published, mirroring the ZK
        // index writer's crash-recovery protocol.
        #[cfg(windows)]
        {
            let backup = session_registry_backup_path(path);
            if backup.exists() {
                std::fs::remove_file(&backup)?;
            }
            if path.exists() {
                std::fs::rename(path, &backup)?;
            }
            if let Err(error) = std::fs::rename(&tmp, path) {
                let _ = if backup.exists() {
                    std::fs::rename(&backup, path)
                } else {
                    Ok(())
                };
                return Err(error);
            }
            if backup.exists() {
                std::fs::remove_file(backup)?;
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            if let Some(parent) = path.parent() {
                std::fs::File::open(parent)?.sync_all()?;
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(windows)]
fn session_registry_backup_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| SESSIONS_FILE.into());
    name.push(".replace-backup");
    path.with_file_name(name)
}

/// Complete or roll back an interrupted Windows replace. On other platforms no backup protocol is
/// needed because rename-over-existing is atomic.
fn recover_interrupted_session_replace(path: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let backup = session_registry_backup_path(path);
        match (path.exists(), backup.exists()) {
            (false, true) => std::fs::rename(backup, path)?,
            (true, true) => std::fs::remove_file(backup)?,
            _ => {}
        }
    }
    #[cfg(not(windows))]
    let _ = path;
    Ok(())
}

/// Per-user sign-in backoff state (plan t29 §4.5).
pub struct Backoff {
    pub fails: u32,
    pub next_allowed_at: OffsetDateTime,
}

/// The backoff delay (seconds) after `fails` consecutive failures: `[1,2,4,8,16,32,64]`, capped
/// at 30 s (t41 M1 — leading zeros dropped so even the first failure buys a second). Shared with the
/// cross-user secret/reset backoff (t52) so both speed-bumps escalate identically.
pub(crate) fn backoff_secs(fails: u32) -> i64 {
    const TABLE: [i64; 7] = [1, 2, 4, 8, 16, 32, 64];
    let idx = (fails as usize).saturating_sub(1).min(TABLE.len() - 1);
    TABLE[idx].min(30)
}

/// `POST /v1/session` body. The user is addressed by **either** `username` (the identifier an
/// operator types; preferred, and the only form a signed-out client can know) **or** `user_id`
/// (kept for back-compat: the onboarding wizard and the signed-in account switcher already hold the
/// id, as do the server test harnesses). `username` wins when both are sent.
///
/// Neither field is required by serde: a body carrying no identifier at all is rejected by
/// [`create_session`] with the same opaque `401` as a bad credential, so nothing about the request
/// shape can be probed either.
#[derive(Deserialize)]
pub struct CreateSession {
    #[serde(default)]
    pub user_id: Option<Uuid>,
    #[serde(default)]
    pub username: Option<String>,
    pub password: String,
}

#[derive(Serialize)]
pub struct SessionCreated {
    pub token: String,
    pub user: UserView,
}

#[derive(Serialize)]
pub struct SessionView {
    pub user: Option<UserView>,
    /// The signed-in user's effective `(permission, scope)` grants, embedded for the web's first
    /// paint so it can gate its UI without a second round-trip (t64-E3 / E5). Empty when signed out.
    /// The authoritative, fuller shape is `GET /v1/session/permissions`.
    pub permissions: Vec<PermissionGrantView>,
}

/// A [`chancela_authz::Scope`] rendered for the web (t64-E3, FROZEN for E5). A tagged union so the
/// client can switch on `kind` and read the id: `{"kind":"global"}` / `{"kind":"entity","id":..}` /
/// `{"kind":"book","id":..}`.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScopeView {
    Global,
    Tenant { id: String },
    Entity { id: String },
    Book { id: String },
    Act { id: String },
    Folder { id: String },
    TemplateLibrary { id: String },
    Archive { id: String },
    Integration { id: String },
    Repository { id: String },
}

impl From<chancela_authz::Scope> for ScopeView {
    fn from(s: chancela_authz::Scope) -> Self {
        match s {
            chancela_authz::Scope::Global => ScopeView::Global,
            chancela_authz::Scope::Tenant(t) => ScopeView::Tenant {
                id: t.0.to_string(),
            },
            chancela_authz::Scope::Entity(e) => ScopeView::Entity {
                id: e.0.to_string(),
            },
            chancela_authz::Scope::Book(b) => ScopeView::Book {
                id: b.0.to_string(),
            },
            chancela_authz::Scope::Act(a) => ScopeView::Act {
                id: a.0.to_string(),
            },
            chancela_authz::Scope::Folder(folder) => ScopeView::Folder {
                id: folder.0.to_string(),
            },
            chancela_authz::Scope::TemplateLibrary(library) => ScopeView::TemplateLibrary {
                id: library.0.to_string(),
            },
            chancela_authz::Scope::Archive(archive) => ScopeView::Archive {
                id: archive.0.to_string(),
            },
            chancela_authz::Scope::Integration(integration) => ScopeView::Integration {
                id: integration.0.to_string(),
            },
            chancela_authz::Scope::Repository(repository) => ScopeView::Repository {
                id: repository.0.to_string(),
            },
        }
    }
}

/// One effective grant: a permission verb, the scope it is held at, and whether it arrived via a
/// role assignment or a delegation (t64-E3, FROZEN for E5).
#[derive(Serialize)]
pub struct PermissionGrantView {
    /// The dotted permission id, e.g. `"entity.read"`.
    pub permission: String,
    pub scope: ScopeView,
    /// `"role"` or `"delegation"`.
    pub source: &'static str,
}

/// One role assignment the user holds: the role id and the scope it is held at (t64-E3, FROZEN).
#[derive(Serialize)]
pub struct RoleAssignmentView {
    pub role_id: String,
    pub scope: ScopeView,
}

/// Response of `GET /v1/session/permissions` (t64-E3, FROZEN for E5's web permissions context): the
/// current principal's identity, the role assignments they hold (with scopes), and the flattened
/// effective `(permission, scope)` grants (role ∪ delegation, each tagged by `source`).
#[derive(Serialize)]
pub struct PermissionsView {
    pub user_id: String,
    pub username: String,
    pub role_assignments: Vec<RoleAssignmentView>,
    pub permissions: Vec<PermissionGrantView>,
}

/// Flatten a [`ScopedPermissionSet`](chancela_authz::ScopedPermissionSet) into the wire grants,
/// tagging each with whether it is a role grant or a delegated grant.
pub(crate) fn grant_views(eff: &chancela_authz::ScopedPermissionSet) -> Vec<PermissionGrantView> {
    let mut out: Vec<PermissionGrantView> = eff
        .role_grants()
        .map(|(p, s)| PermissionGrantView {
            permission: p.as_str().to_owned(),
            scope: ScopeView::from(s),
            source: "role",
        })
        .chain(eff.delegated_grants().map(|(p, s)| PermissionGrantView {
            permission: p.as_str().to_owned(),
            scope: ScopeView::from(s),
            source: "delegation",
        }))
        .collect();
    // Deterministic order for stable responses / snapshot tests.
    out.sort_by(|a, b| a.permission.cmp(&b.permission).then(a.source.cmp(b.source)));
    out
}

/// Response of `GET /v1/session/roster` — **one boolean and nothing else** (t33-e2).
///
/// This used to carry a `users: [{ id, username, display_name, has_secret }]` array. That was user
/// enumeration by design: any anonymous caller could `curl` the complete list of valid accounts for
/// credential stuffing and targeted phishing, and `has_secret` additionally told them which of those
/// accounts had a password set. Nothing about *who* exists is answered without a session any more —
/// the signed-in `GET /v1/users` is the only user directory.
#[derive(Serialize)]
pub struct SessionRoster {
    /// `true` when no user exists at all — the first-run bootstrap create is available and the UI
    /// should show the onboarding wizard instead of a sign-in form.
    pub onboarding_required: bool,
}

/// `GET /v1/session/roster` — the **unauthenticated** first-run probe (t45, narrowed by t33-e2).
///
/// A signed-out client needs exactly one thing without a session: does this instance have any user
/// yet, i.e. should it show onboarding or a sign-in form? That is the whole response. It does not
/// enumerate users, so signing in is by typed identifier (`POST /v1/session {username, password}`),
/// not by picking off a served list.
///
/// `onboarding_required` is intentionally still answered anonymously — the bootstrap create it gates
/// is itself unauthenticated on a fresh instance, and `create_user` fails closed via
/// [`is_uninitialised_instance`](crate::users) regardless of what this endpoint reports.
pub async fn session_roster(State(state): State<AppState>) -> Json<SessionRoster> {
    let users = state.users.read().await;
    Json(SessionRoster {
        onboarding_required: users.is_empty(),
    })
}

/// How many throttle buckets an *unknown* sign-in identifier is folded into.
const UNKNOWN_IDENTIFIER_BUCKETS: u64 = 4096;

/// Fixed high half of the synthetic [`UserId`] used for unknown identifiers. Real user ids are
/// `Uuid::new_v4()`, so the odds any of the 4096 synthetic ids equals a real one are negligible —
/// and a collision would only share a *throttle bucket*, never authenticate anything.
const UNKNOWN_IDENTIFIER_TAG: [u8; 8] = [0x9e, 0x3d, 0x7a, 0x11, 0x4c, 0x82, 0x05, 0xd6];

/// A stable synthetic [`UserId`] standing in for an identifier that matched no active user.
///
/// The failed-sign-in speed-bump ([`Backoff`]) and the cluster-wide counter are both keyed by user
/// id, so an unknown identifier needs *a* key or it would face no throttle at all — and "unlimited
/// fast attempts" vs "throttled after one failure" is exactly the oracle username sign-in exists to
/// remove. Identifiers are folded into a fixed number of buckets rather than keyed 1:1 so spraying
/// arbitrary names cannot grow the backoff map without bound (a trivial memory exhaustion);
/// collisions only ever make the throttle stricter, never looser.
fn unknown_identifier_key(identifier: &str) -> UserId {
    let digest = Sha256::digest(identifier.to_ascii_lowercase().as_bytes());
    let bucket = u64::from_be_bytes(digest[..8].try_into().expect("sha256 is 32 bytes"))
        % UNKNOWN_IDENTIFIER_BUCKETS;
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&UNKNOWN_IDENTIFIER_TAG);
    bytes[8..].copy_from_slice(&bucket.to_be_bytes());
    UserId(Uuid::from_bytes(bytes))
}

/// A verifier no submitted password can ever match, so the unknown-identifier path spends the *same*
/// argon2 work a wrong password spends against a real account.
///
/// Returning early for an unknown user while a wrong password costs ~100 ms of argon2 is itself a
/// user-enumeration oracle — an attacker times the response instead of reading it. So the unknown
/// path runs the identical [`verify_secret_with_seed`] call against this. It is a legacy PHC hash of
/// a per-process random secret: `verify_legacy_phc` and the hardened verifier both run
/// `Argon2id/V0x13/Params::default()`, so the work matches, and the secret is never known to anyone.
/// Computed once per process — hashing it per request would make the unknown path *slower* than the
/// real one and simply invert the oracle.
fn dummy_verifier() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| {
        crate::attestation::hash_secret(&Uuid::new_v4().to_string())
            .unwrap_or_else(|_| String::from("$argon2id$v=19$m=19456,t=2,p=1$YWFhYWFhYWE$"))
    })
}

/// The stored verifier for a resolved user, or the state-specific refusal for a legacy account that
/// has none. Only reachable when the caller already addressed the user by **id** — see
/// [`create_session`].
fn stored_verifier_for(user: &User) -> Result<String, ApiError> {
    let Some(stored) = user.password_hash.clone() else {
        return Err(ApiError::Conflict(
            "palavra-passe não configurada para este utilizador".to_owned(),
        ));
    };
    Ok(stored)
}

/// `POST /v1/session` — mint a token for a user addressed by `username` (preferred) or `user_id`
/// (back-compat). **t41 H1 / t33-e2:** unknown identifier, inactive user, and wrong password all
/// return a uniform `401 "credenciais inválidas"` — same status, same body, same wording, and the
/// same argon2 work so the *timing* does not distinguish them either. While in backoff → `429`.
pub async fn create_session(
    State(state): State<AppState>,
    Json(req): Json<CreateSession>,
) -> Result<Json<SessionCreated>, ApiError> {
    // Resolve the identifier server-side. `username` is matched case-insensitively, consistently
    // with the uniqueness rule `create_user` enforces (`users.rs`), and only against **active**
    // users — an inactive user can never mint a session, and must be indistinguishable from one that
    // does not exist.
    let resolved: Option<User> = {
        let users = state.users.read().await;
        match (&req.username, req.user_id) {
            (Some(name), _) => users
                .values()
                .find(|u| u.active && u.username.eq_ignore_ascii_case(name))
                .cloned(),
            (None, Some(id)) => match users.get(&UserId(id)).cloned() {
                Some(u) if u.active => Some(u),
                _ => None,
            },
            // No identifier at all. Not an enumeration signal (it says nothing about who exists),
            // but it takes the same opaque failure so there is only one shape to reason about.
            (None, None) => None,
        }
    };

    // Throttle key: the real user id when we resolved one, otherwise a synthetic bucket for the
    // identifier so an unknown name is speed-bumped exactly like a known one.
    let uid = match &resolved {
        Some(u) => u.id,
        None => {
            let identifier = req
                .username
                .clone()
                .or_else(|| req.user_id.map(|id| id.to_string()))
                .unwrap_or_default();
            unknown_identifier_key(&identifier)
        }
    };

    // The verifier to check the submitted password against: the user's own, or the constant-work
    // dummy. The legacy "user exists but has no verifier" 409 is only honest when the caller
    // addressed the user by **id** — an id is unguessable, so whoever holds one already knows the
    // account exists. Reached by `username` it would re-create precisely the `has_secret` leak this
    // task removed from the roster, so there it degrades to the uniform 401 via the dummy.
    let stored = match (&resolved, &req.username) {
        (Some(u), None) => stored_verifier_for(u)?,
        (Some(u), Some(_)) => u
            .password_hash
            .clone()
            .unwrap_or_else(|| dummy_verifier().to_owned()),
        (None, _) => return Err(ApiError::Unauthorized("credenciais inválidas".to_owned())),
    };
    // wp16 P3a — GLOBAL sign-in throttle (cluster-wide when Redis is configured; a no-op single-node,
    // so the per-user backoff below stays the sole authority and behaviour is byte-identical). This
    // prevents an attacker getting N× the attempts by spraying failures across N nodes. FAIL-CLOSED:
    // if the shared counter is unreachable it reports `Unavailable`, which does NOT block here — the
    // per-node backoff is kept as the floor rather than resetting to unlimited.
    let signin_limit_key = format!("signin:{uid}");
    if cluster_shared_state::global_limit_blocks(
        &state.cluster_shared.signin_limiter.peek(&signin_limit_key),
        cluster_shared_state::GLOBAL_SIGNIN_FAILURE_CAP,
    ) {
        return Err(ApiError::TooManyRequests(
            "demasiadas tentativas — tente novamente mais tarde".to_owned(),
        ));
    }
    let now = OffsetDateTime::now_utc();
    let seed = state.verifier_seed.read().await.clone();
    let mut backoff = state.signin_backoff.write().await;
    let entry = backoff.entry(uid).or_insert(Backoff {
        fails: 0,
        next_allowed_at: now,
    });
    if now < entry.next_allowed_at {
        let ms = (entry.next_allowed_at - now).whole_milliseconds();
        let remaining = ((ms + 999) / 1000).max(1);
        return Err(ApiError::TooManyRequests(format!(
            "demasiadas tentativas — tente novamente em {remaining} s"
        )));
    }
    let verification = verify_secret_with_seed(&req.password, &stored, &seed);
    if !verification.verified {
        entry.fails += 1;
        entry.next_allowed_at = now + Duration::seconds(backoff_secs(entry.fails));
        drop(backoff);
        // Record the failure against the GLOBAL counter too (a 15-minute window). Best-effort /
        // fail-closed: an unreachable shared counter simply is not incremented; the per-node backoff
        // above already advanced, so the throttle never loosens.
        state
            .cluster_shared
            .signin_limiter
            .record_failure(&signin_limit_key, std::time::Duration::from_secs(15 * 60));
        return Err(ApiError::Unauthorized("credenciais inválidas".to_owned()));
    }
    drop(backoff);
    // The password proved out, so `stored` was a real account's verifier — the dummy is a hash of a
    // per-process random secret and can never verify. Belt and braces: if it somehow did, fall
    // through to the same opaque 401 rather than minting anything.
    let Some(mut user) = resolved else {
        return Err(ApiError::Unauthorized("credenciais inválidas".to_owned()));
    };
    state.signin_backoff.write().await.remove(&uid);
    // A successful sign-in clears the global counter too (cluster-wide reset).
    state.cluster_shared.signin_limiter.clear(&signin_limit_key);
    if verification.needs_upgrade {
        let upgraded = hash_secret_with_seed(&req.password, &seed)?;
        if let Some(updated) =
            upgrade_password_hash_after_signin(&state, uid, &stored, upgraded).await?
        {
            user = updated;
        }
    };
    let unlocked_key = match &user.attestation_key {
        Some(blob) => Some(blob.unlock(&req.password)?),
        None => None,
    };

    let token = mint_session(&state, uid, unlocked_key).await?;

    Ok(Json(SessionCreated {
        token,
        user: UserView::from(&user),
    }))
}

/// Mint a fresh opaque session token for `uid` and register it across **every** session layer — the
/// durable digest registry (single-node), the shared cluster authority (HA), the in-memory live map,
/// and the issued-at map — exactly as the successful password path in [`create_session`] does.
///
/// `unlocked_key` is the in-memory attestation signing key held for the life of the session: `Some`
/// only on the interactive password path (the key is unlocked from the password). Companion/pairing
/// sessions ([`crate::pairing`]) pass `None`, matching a follower/restarted node — the phone gets an
/// identity-only session and never an unlocked signing key it never authenticated for.
///
/// Fails closed (`503`) when the shared authority cannot **prove** the write, rolling the durable
/// record back first so a token is never returned that would vanish after a failover. This is the
/// single minting code path; the password verifier stays entirely in [`create_session`] and is not
/// weakened — pairing is additive.
pub(crate) async fn mint_session(
    state: &AppState,
    uid: UserId,
    unlocked_key: Option<SigningKey>,
) -> Result<String, ApiError> {
    let token = Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc();
    let expires_at = now + Duration::seconds(SESSION_TTL_SECS);
    if state.durable_sessions.is_durable() {
        state
            .durable_sessions
            .insert(&token, uid.0, now, expires_at)
            .await?;
    }
    // Redis is the authority in HA. Do not return a node-local token if the shared write could not
    // be proven; otherwise a token could work on the minting node but disappear after failover.
    match state.cluster_shared.sessions.put(
        &token,
        uid.0,
        now.unix_timestamp(),
        std::time::Duration::from_secs(SESSION_TTL_SECS.max(0) as u64),
    ) {
        cluster_shared_state::SessionMutation::NotShared
        | cluster_shared_state::SessionMutation::Stored => {}
        cluster_shared_state::SessionMutation::Unavailable => {
            let _ = state.durable_sessions.revoke(&token).await;
            return Err(ApiError::Unavailable(
                "serviço de sessões partilhadas indisponível; tente novamente".to_owned(),
            ));
        }
    }
    state.sessions.write().await.insert(
        token.clone(),
        SessionEntry {
            user_id: uid,
            unlocked_key,
            expires_at,
        },
    );
    state
        .session_issued_at
        .write()
        .await
        .insert(token.clone(), now);
    Ok(token)
}

async fn upgrade_password_hash_after_signin(
    state: &AppState,
    uid: UserId,
    old_hash: &str,
    new_hash: String,
) -> Result<Option<User>, ApiError> {
    let mut users = state.users.write().await;
    let changed = match users.get_mut(&uid) {
        Some(current) if current.password_hash.as_deref() == Some(old_hash) => {
            current.password_hash = Some(new_hash);
            true
        }
        _ => false,
    };
    if !changed {
        return Ok(None);
    }
    if let Some(path) = &state.users_path {
        crate::users::write_users_atomic(path, &users)
            .map_err(|e| ApiError::Internal(format!("failed to persist users: {e}")))?;
    }
    Ok(users.get(&uid).cloned())
}

/// `GET /v1/session` — the user behind the `X-Chancela-Session` header, or `{ "user": null }`.
/// Does NOT use the fallible `CurrentActor` extractor (returns null, not 401, when no session).
pub async fn get_session(
    State(state): State<AppState>,
    parts: axum::http::HeaderMap,
) -> Result<Json<SessionView>, ApiError> {
    if read_bearer_api_key(&parts)?.is_some() {
        return Err(ApiError::Forbidden(
            "chave API não abre uma sessão interativa".to_owned(),
        ));
    }

    let resolved: Option<(UserView, UserId)> = match parts
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        Some(token) => match resolve_session_actor(&state, token).await {
            Ok(Some(username)) => {
                let users = state.users.read().await;
                users
                    .values()
                    .find(|u| u.username == username)
                    .map(|u| (UserView::from(u), u.id))
            }
            _ => None,
        },
        None => None,
    };

    let (user, permissions) = match resolved {
        Some((view, uid)) => {
            let eff =
                crate::roles::effective_permissions_for(&state, uid, OffsetDateTime::now_utc())
                    .await;
            (Some(view), grant_views(&eff))
        }
        None => (None, Vec::new()),
    };
    Ok(Json(SessionView { user, permissions }))
}

/// `GET /v1/session/permissions` — the current principal's role assignments (with scopes) and
/// flattened effective `(permission, scope)` grants (t64-E3, FROZEN for the web permissions context
/// in E5). Requires a valid session (`401` without one, via [`CurrentActor`]); `403` if the session
/// no longer names an active user. Never a specific permission — introspecting one's own authority
/// is always allowed.
pub async fn session_permissions(
    State(state): State<AppState>,
    actor: crate::actor::CurrentActor,
) -> Result<Json<PermissionsView>, ApiError> {
    let now = OffsetDateTime::now_utc();
    let (uid, eff) = crate::roles::effective_permissions_for_actor(&state, &actor, now).await?;

    let (username, role_assignments) = {
        let users = state.users.read().await;
        match users.get(&uid) {
            Some(u) => (
                u.username.clone(),
                u.role_assignments
                    .iter()
                    .map(|a| RoleAssignmentView {
                        role_id: a.role_id.0.to_string(),
                        scope: ScopeView::from(a.scope),
                    })
                    .collect(),
            ),
            // The resolve step already proved the user active; a race that removed them → empty.
            None => (String::new(), Vec::new()),
        }
    };

    Ok(Json(PermissionsView {
        user_id: uid.0.to_string(),
        username,
        role_assignments,
        permissions: grant_views(&eff),
    }))
}

/// `GET /v1/session/password-policy` — the active password strength ruleset (t68).
///
/// **Unauthenticated by design** (classified `Exempt`, like `/v1/session/roster`): the first-run
/// onboarding surface must render the requirement checklist while the operator is still setting up,
/// and the rules are public knowledge the web mirrors exactly. Returns the same parameters the server
/// enforces on every password-setting path (see [`crate::password_policy`]), so a client checklist can
/// never drift from server enforcement. Carries `allow_weak_passwords` (currently a constant default
/// = `false`); the settings-document toggle that will drive it is deferred to the coordinated web
/// slice to avoid drifting the settings contract.
pub async fn password_policy() -> Json<crate::password_policy::PasswordPolicyView> {
    Json(crate::password_policy::policy_view())
}

/// `DELETE /v1/session` — drop the presented token (idempotent; always `204`).
pub async fn delete_session(
    State(state): State<AppState>,
    parts: axum::http::HeaderMap,
) -> Result<StatusCode, ApiError> {
    if read_bearer_api_key(&parts)?.is_some() {
        return Err(ApiError::Forbidden(
            "chave API não abre uma sessão interativa".to_owned(),
        ));
    }

    if let Some(token) = parts
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        state.sessions.write().await.remove(token);
        state.session_issued_at.write().await.remove(token);
        state.durable_sessions.revoke(token).await?;
        // wp16 P3a — revoke cluster-wide and publish only the digest so the bearer token never enters
        // Redis pub/sub. A shared-store failure is reported as 503 after the local copy is cleared.
        let shared_revoke = state.cluster_shared.sessions.revoke(token);
        state.cluster_shared.invalidation.publish(
            &cluster_shared_state::InvalidationEvent::SessionRevoked {
                token_sha256: session_token_digest(token),
            },
        );
        if shared_revoke == cluster_shared_state::SessionMutation::Unavailable {
            return Err(ApiError::Unavailable(
                "não foi possível confirmar o fim da sessão partilhada; tente novamente".to_owned(),
            ));
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod durable_tests {
    use axum::body::{Body, to_bytes};
    use axum::http::header::CONTENT_TYPE;
    use axum::http::{Method, Request, StatusCode};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("chancela-durable-sessions-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("create temp data dir");
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    async fn json_response(response: axum::response::Response) -> (StatusCode, Value) {
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read response body");
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("JSON response")
        };
        (status, value)
    }

    fn json_request(method: Method, uri: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    #[tokio::test]
    async fn registry_supports_repeated_windows_replacement_revoke_and_corrupt_recovery() {
        let temp = TempDir::new();
        let path = temp.path.join(SESSIONS_FILE);
        let registry = DurableSessionRegistry::load(path.clone());
        let token = "plaintext-bearer-must-never-be-written";
        let uid = Uuid::new_v4();
        let issued_at = OffsetDateTime::now_utc();

        registry
            .insert(token, uid, issued_at, issued_at + Duration::hours(1))
            .await
            .unwrap();
        for minutes in [2, 3, 4] {
            let record = registry
                .resolve_and_slide(token, issued_at, issued_at + Duration::minutes(minutes))
                .await
                .unwrap()
                .expect("record survives repeated replacements");
            assert_eq!(record.issued_at_unix, issued_at.unix_timestamp());
        }
        let persisted = std::fs::read_to_string(&path).unwrap();
        assert!(
            !persisted.contains(token),
            "plaintext token must never persist"
        );
        assert!(persisted.contains(&session_token_digest(token)));

        #[cfg(windows)]
        {
            let backup = session_registry_backup_path(&path);
            std::fs::rename(&path, &backup).unwrap();
            let after_interrupted_replace = DurableSessionRegistry::load(path.clone());
            assert!(
                after_interrupted_replace
                    .resolve_and_slide(token, issued_at, issued_at + Duration::minutes(5))
                    .await
                    .unwrap()
                    .is_some(),
                "a missing destination with a complete backup rolls back on startup"
            );
        }

        registry.revoke(token).await.unwrap();
        drop(registry);
        let reloaded = DurableSessionRegistry::load(path.clone());
        assert!(
            reloaded
                .resolve_and_slide(token, issued_at, issued_at + Duration::hours(1))
                .await
                .unwrap()
                .is_none()
        );

        // A malformed registry invalidates every old session, but the next successful login can
        // replace it; corruption never makes the durable mode permanently unwritable.
        std::fs::write(&path, b"{ definitely not valid json").unwrap();
        let recovered = DurableSessionRegistry::load(path.clone());
        recovered
            .insert("new-token", uid, issued_at, issued_at + Duration::hours(1))
            .await
            .unwrap();
        let document: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(document["schema_version"], SESSION_REGISTRY_SCHEMA_VERSION);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
                0
            );
        }
    }

    #[tokio::test]
    async fn authenticated_session_survives_restart_and_revocation_survives_another_restart() {
        let temp = TempDir::new();
        let state = crate::AppState::with_data_dir(temp.path.clone());
        let (status, user) = json_response(
            crate::router(state.clone())
                .oneshot(json_request(
                    Method::POST,
                    "/v1/users",
                    json!({
                        "username": "mobile.operator",
                        "password": "Cavalo-Certo9!"
                    }),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, session) = json_response(
            crate::router(state)
                .oneshot(json_request(
                    Method::POST,
                    "/v1/session",
                    json!({
                        "user_id": user["id"],
                        "password": "Cavalo-Certo9!"
                    }),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let token = session["token"].as_str().unwrap().to_owned();
        assert!(
            !std::fs::read_to_string(temp.path.join(SESSIONS_FILE))
                .unwrap()
                .contains(&token)
        );

        let restarted = crate::AppState::with_data_dir(temp.path.clone());
        let request = Request::builder()
            .uri("/v1/session")
            .header(SESSION_HEADER, &token)
            .body(Body::empty())
            .unwrap();
        let (status, view) = json_response(
            crate::router(restarted.clone())
                .oneshot(request)
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["user"]["username"], "mobile.operator");

        let logout = Request::builder()
            .method(Method::DELETE)
            .uri("/v1/session")
            .header(SESSION_HEADER, &token)
            .body(Body::empty())
            .unwrap();
        let response = crate::router(restarted).oneshot(logout).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let restarted_again = crate::AppState::with_data_dir(temp.path.clone());
        let request = Request::builder()
            .uri("/v1/session")
            .header(SESSION_HEADER, &token)
            .body(Body::empty())
            .unwrap();
        let (_, signed_out) = json_response(
            crate::router(restarted_again)
                .oneshot(request)
                .await
                .unwrap(),
        )
        .await;
        assert!(signed_out["user"].is_null());
    }
}
