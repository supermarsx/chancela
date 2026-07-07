//! Named user profiles + actor attribution (contract §2.8).
//!
//! Chancela is a local-first, single-operator / small-office app on loopback. The goal here is
//! **attribution**, not authentication or access control (DAT-10): identify *who* performed each
//! mutation so the audit ledger names a real person instead of the fixed `"api"` fallback. A
//! [`User`] is a profile (username + display name); a session (see [`crate::session`]) maps an
//! opaque token to a user, and the [`CurrentActor`](crate::actor::CurrentActor) extractor resolves
//! that token to the ledger actor.
//!
//! Passwords are an explicit **phase-2 seam**: [`User`] carries a reserved `password_hash` field
//! (always `None` in v1, present so `users.json` is forward-compatible) that a future login
//! endpoint would verify with argon2. There is no transport boundary to protect on loopback, so
//! adding auth now would be security theatre.
//!
//! ## Persistence
//!
//! When [`AppState`](crate::AppState) is file-backed, `users.json` in the data directory is read at
//! startup and rewritten atomically (temp file + rename, mirroring `settings.json`) on every
//! create/update. Without a data directory the profiles live in memory and reset on restart.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::attestation::{self, AttestationKeyBlob, MAX_SECRET_LEN, MIN_SECRET_LEN, verify_secret};
use crate::error::ApiError;

/// The file name holding the user profiles inside the data directory.
pub const USERS_FILE: &str = "users.json";

/// Stable identifier for a user profile. A newtype over [`Uuid`] so it cannot be confused with an
/// entity/book/act id. `Copy` so it can be looked up out of the session map cheaply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub Uuid);

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A persisted user profile.
///
/// `username` is the stable, unique (case-insensitive) slug recorded as the ledger `actor`;
/// `display_name` is the human label surfaced in the UI. `password_hash` (an argon2id PHC string)
/// and `attestation_key` (a wrapped P-256 key) are the optional-password/PKI-attestation seams
/// (plan t29): both default absent, are **never** put on the wire (see [`UserView`]), and — like
/// the access code — are swept out of every wire dump by the e2e integrity tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub username: String,
    pub display_name: String,
    pub created_at: String,
    pub active: bool,
    /// argon2id PHC hash of the optional sign-in secret (plan t29 §4.2). `None` = passwordless.
    /// Absent from `users.json` while unset (`serde(default)` so an older file still loads).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    /// The optional per-user attestation key (plan t29 §4.3): the public key in the clear plus the
    /// secret scalar wrapped under a KEK derived from the sign-in secret. A key requires a secret,
    /// so this is `None` whenever `password_hash` is `None`. Never on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_key: Option<crate::attestation::AttestationKeyBlob>,
}

/// Wire view of a [`User`]. Deliberately omits `password_hash` and the wrapped `attestation_key`
/// — no secret material ever reaches the wire (plan t29 §4.0). Instead it surfaces the presence
/// booleans and the (public) key fingerprint the UI needs.
#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: String,
    pub active: bool,
    /// Whether a sign-in secret is set (gates `POST /v1/session`).
    pub has_secret: bool,
    /// Whether an attestation key exists for this user.
    pub has_attestation_key: bool,
    /// The attestation key's 32-hex fingerprint, present iff a key exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_key_fingerprint: Option<String>,
}

impl From<&User> for UserView {
    fn from(u: &User) -> Self {
        UserView {
            id: u.id.to_string(),
            username: u.username.clone(),
            display_name: u.display_name.clone(),
            created_at: u.created_at.clone(),
            active: u.active,
            has_secret: u.password_hash.is_some(),
            has_attestation_key: u.attestation_key.is_some(),
            attestation_key_fingerprint: u.attestation_key.as_ref().map(|k| k.fingerprint.clone()),
        }
    }
}

// --- Request bodies -----------------------------------------------------------------------

/// Body of `POST /v1/users`.
#[derive(Deserialize)]
pub struct CreateUser {
    pub username: String,
    /// Human label; defaults to `username` when absent or blank.
    pub display_name: Option<String>,
}

/// Body of `PATCH /v1/users/{id}` — rename and/or (de)activate. Never deletes: attribution
/// history must stay intact.
#[derive(Deserialize)]
pub struct PatchUser {
    pub display_name: Option<String>,
    pub active: Option<bool>,
}

/// Body of `POST /v1/users/{id}/secret` — set or change the sign-in secret (plan t29 §4.2).
///
/// `password`/`current_password` carry the actual secret and appear only on this **write**
/// endpoint (not swept) — the handler never echoes them back (plan §4.0). `current_password` is
/// required only when changing an already-set secret.
#[derive(Deserialize)]
pub struct SetSecret {
    pub password: String,
    #[serde(default)]
    pub current_password: Option<String>,
}

/// Body of the secret-removal / attestation-key endpoints — carries the current sign-in secret
/// for verification (plan t29 §4.2/§4.3).
#[derive(Deserialize)]
pub struct CurrentSecret {
    #[serde(default)]
    pub current_password: Option<String>,
}

// --- Validation ---------------------------------------------------------------------------

/// Validate a username: a non-empty lowercase slug of `[a-z0-9._-]`. Returns the normalized
/// (trimmed) value, or `422` describing the violation.
fn validate_username(raw: &str) -> Result<String, ApiError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(ApiError::Unprocessable(
            "username must not be empty".to_owned(),
        ));
    }
    if name.len() > 64 {
        return Err(ApiError::Unprocessable(
            "username must be at most 64 characters".to_owned(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        return Err(ApiError::Unprocessable(
            "username must be a lowercase slug of a-z, 0-9, '.', '_' or '-'".to_owned(),
        ));
    }
    Ok(name.to_owned())
}

// --- Persistence --------------------------------------------------------------------------

/// Read `users.json` from `path` into the id→user map, returning `None` when it is absent or
/// unreadable and falling back to empty (with a warning) if present but malformed. A corrupt file
/// must never stop the server from starting.
pub(crate) fn load_users(path: &Path) -> Option<HashMap<UserId, User>> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<User>>(&bytes) {
        Ok(list) => Some(list.into_iter().map(|u| (u.id, u)).collect()),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid users document ({e}); ignoring it",
                path.display()
            );
            None
        }
    }
}

/// Atomically write the users to `path` as a JSON array, ordered by `created_at` for a stable
/// file: serialize to a uniquely-named temp file in the same directory, then rename it over the
/// destination (an atomic replace on both Windows and Unix).
fn write_users_atomic(path: &Path, users: &HashMap<UserId, User>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut list: Vec<&User> = users.values().collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    let json = serde_json::to_vec_pretty(&list).map_err(std::io::Error::other)?;
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

/// A unique sibling temp path for the atomic write.
fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| USERS_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

/// Persist the current users map if the state is file-backed; a write failure surfaces as `500`.
async fn persist(state: &AppState) -> Result<(), ApiError> {
    if let Some(path) = &state.users_path {
        let users = state.users.read().await;
        write_users_atomic(path, &users)
            .map_err(|e| ApiError::Internal(format!("failed to persist users: {e}")))?;
    }
    Ok(())
}

// --- Handlers -----------------------------------------------------------------------------

/// `POST /v1/users` — create a profile. Validates the username (`422`), rejects a duplicate
/// (case-insensitive, `409`), persists `users.json`, and appends a `user.created` event.
pub async fn create_user(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateUser>,
) -> Result<(StatusCode, Json<UserView>), ApiError> {
    let username = validate_username(&req.username)?;
    let display_name = req
        .display_name
        .map(|d| d.trim().to_owned())
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| username.clone());

    let user = {
        let mut users = state.users.write().await;
        // Uniqueness is case-insensitive on the username.
        if users
            .values()
            .any(|u| u.username.eq_ignore_ascii_case(&username))
        {
            return Err(ApiError::Conflict(format!(
                "a user named {username:?} already exists"
            )));
        }
        let user = User {
            id: UserId(Uuid::new_v4()),
            username,
            display_name,
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: None,
            attestation_key: None,
        };
        users.insert(user.id, user.clone());
        user
    };

    persist(&state).await?;

    let payload = serde_json::to_vec(&user)?;
    let actor = actor.resolve("api");
    {
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &actor,
            "user",
            "user.created",
            Some("user created"),
            &payload,
        );
        // Persist the audit event; the profile itself is durable via `users.json`.
        state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
        state.attest_latest(&attestor, &ledger).await;
    }

    Ok((StatusCode::CREATED, Json(UserView::from(&user))))
}

// --- Secret / attestation-key validation + shared recording -------------------------------

/// Validate a proposed sign-in secret: length over composition (plan §4.2, `422` on violation).
fn validate_secret(secret: &str) -> Result<(), ApiError> {
    let len = secret.chars().count();
    if len < MIN_SECRET_LEN {
        return Err(ApiError::Unprocessable(format!(
            "sign-in secret must be at least {MIN_SECRET_LEN} characters"
        )));
    }
    if len > MAX_SECRET_LEN {
        return Err(ApiError::Unprocessable(format!(
            "sign-in secret must be at most {MAX_SECRET_LEN} characters"
        )));
    }
    Ok(())
}

/// Verify a supplied current secret against the user's stored hash. `401` when a secret is set
/// and the supplied one is missing or wrong; `Ok` when the user has no secret (nothing to check).
/// The message never echoes the submitted value.
fn verify_current(user: &User, provided: Option<&str>) -> Result<(), ApiError> {
    match &user.password_hash {
        Some(phc) => {
            if provided.map(|p| verify_secret(p, phc)).unwrap_or(false) {
                Ok(())
            } else {
                Err(ApiError::Unauthorized(
                    "palavra-passe atual incorreta".to_owned(),
                ))
            }
        }
        None => Ok(()),
    }
}

/// Persist `users.json`, append the `user.updated` audit event (with a redacted digest — the
/// [`UserView`], never the secret material), and attest it if the request holds an unlocked key.
/// Mirrors the create/patch recording path (event-only site: durability of the profile is via
/// `users.json`).
async fn record_user_update(
    state: &AppState,
    user: &User,
    justification: &str,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
) -> Result<(), ApiError> {
    persist(state).await?;
    // Digest the redacted wire view, so no secret/key material feeds even the (one-way) digest.
    let payload = serde_json::to_vec(&UserView::from(user))?;
    let actor = actor.resolve("api");
    let mut ledger = state.ledger.write().await;
    ledger.append(
        &actor,
        "user",
        "user.updated",
        Some(justification),
        &payload,
    );
    state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

/// `POST /v1/users/{id}/secret` — set or change the sign-in secret (plan t29 §4.2).
///
/// No secret yet → `current_password` not required. Secret already set → `current_password`
/// required and argon2-verified (`401` on missing/wrong), and any attestation key is **re-wrapped**
/// under the new secret. Length-validated (`422`). Appends `user.updated`.
pub async fn set_secret(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<SetSecret>,
) -> Result<Json<UserView>, ApiError> {
    validate_secret(&req.password)?;
    let user = {
        let mut users = state.users.write().await;
        let user = users.get_mut(&UserId(id)).ok_or(ApiError::NotFound)?;
        let changing = user.password_hash.is_some();
        if changing {
            // Changing an existing secret: verify the current one, then re-wrap the key (if any)
            // under the new secret so it stays recoverable.
            verify_current(user, req.current_password.as_deref())?;
            let old = req.current_password.as_deref().unwrap_or_default();
            let rewrapped = match &user.attestation_key {
                Some(blob) => Some(blob.rewrap(old, &req.password)?),
                None => None,
            };
            if let Some(r) = rewrapped {
                user.attestation_key = Some(r);
            }
        }
        user.password_hash = Some(attestation::hash_secret(&req.password)?);
        user.clone()
    };
    record_user_update(&state, &user, "sign-in secret set", &actor, &attestor).await?;
    Ok(Json(UserView::from(&user)))
}

/// `DELETE /v1/users/{id}/secret` — remove the sign-in secret (plan t29 §4.2).
///
/// Verifies `current_password` (`401` on wrong), clears the secret, and **cascades**: the
/// attestation key (whose KEK is the secret) is also removed, since it would otherwise be
/// unrecoverable. Idempotent when no secret is set. Appends `user.updated`.
pub async fn remove_secret(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CurrentSecret>,
) -> Result<Json<UserView>, ApiError> {
    let user = {
        let mut users = state.users.write().await;
        let user = users.get_mut(&UserId(id)).ok_or(ApiError::NotFound)?;
        if user.password_hash.is_none() {
            // Nothing to remove — idempotent, no event.
            return Ok(Json(UserView::from(&*user)));
        }
        verify_current(user, req.current_password.as_deref())?;
        user.password_hash = None;
        user.attestation_key = None;
        user.clone()
    };
    record_user_update(
        &state,
        &user,
        "sign-in secret removed (attestation key cascaded)",
        &actor,
        &attestor,
    )
    .await?;
    Ok(Json(UserView::from(&user)))
}

/// `POST /v1/users/{id}/attestation-key` — generate or rotate the attestation key (plan t29 §4.3).
///
/// Requires a set secret (`409` if none); verifies `current_password` (`401`); generates a fresh
/// P-256 keypair wrapped under the secret. Regenerating replaces the key (older attestations still
/// verify — each embeds its own public key/fingerprint). Appends `user.updated`.
pub async fn generate_attestation_key(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CurrentSecret>,
) -> Result<Json<UserView>, ApiError> {
    let user = {
        let mut users = state.users.write().await;
        let user = users.get_mut(&UserId(id)).ok_or(ApiError::NotFound)?;
        if user.password_hash.is_none() {
            return Err(ApiError::Conflict(
                "set a sign-in secret before generating an attestation key".to_owned(),
            ));
        }
        verify_current(user, req.current_password.as_deref())?;
        let secret = req.current_password.as_deref().unwrap_or_default();
        user.attestation_key = Some(AttestationKeyBlob::generate(secret)?);
        user.clone()
    };
    record_user_update(
        &state,
        &user,
        "attestation key generated",
        &actor,
        &attestor,
    )
    .await?;
    Ok(Json(UserView::from(&user)))
}

/// `DELETE /v1/users/{id}/attestation-key` — remove the attestation key (plan t29 §4.3).
///
/// Verifies `current_password` (`401`), clears the key. Idempotent when no key exists. Appends
/// `user.updated`.
pub async fn remove_attestation_key(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CurrentSecret>,
) -> Result<Json<UserView>, ApiError> {
    let user = {
        let mut users = state.users.write().await;
        let user = users.get_mut(&UserId(id)).ok_or(ApiError::NotFound)?;
        if user.attestation_key.is_none() {
            return Ok(Json(UserView::from(&*user)));
        }
        verify_current(user, req.current_password.as_deref())?;
        user.attestation_key = None;
        user.clone()
    };
    record_user_update(&state, &user, "attestation key removed", &actor, &attestor).await?;
    Ok(Json(UserView::from(&user)))
}

/// `GET /v1/users` — every profile, ordered by creation time.
pub async fn list_users(State(state): State<AppState>) -> Json<Vec<UserView>> {
    let users = state.users.read().await;
    let mut list: Vec<&User> = users.values().collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    Json(list.into_iter().map(UserView::from).collect())
}

/// `GET /v1/users/{id}` — one profile, or `404`.
pub async fn get_user(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<Json<UserView>, ApiError> {
    let users = state.users.read().await;
    users
        .get(&UserId(id))
        .map(|u| Json(UserView::from(u)))
        .ok_or(ApiError::NotFound)
}

/// `PATCH /v1/users/{id}` — rename and/or (de)activate a profile. Appends `user.updated`.
pub async fn patch_user(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchUser>,
) -> Result<Json<UserView>, ApiError> {
    let user = {
        let mut users = state.users.write().await;
        let user = users.get_mut(&UserId(id)).ok_or(ApiError::NotFound)?;
        if let Some(display_name) = req.display_name {
            let trimmed = display_name.trim();
            if !trimmed.is_empty() {
                user.display_name = trimmed.to_owned();
            }
        }
        if let Some(active) = req.active {
            user.active = active;
        }
        user.clone()
    };

    persist(&state).await?;

    let payload = serde_json::to_vec(&user)?;
    let actor = actor.resolve("api");
    {
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &actor,
            "user",
            "user.updated",
            Some("user updated"),
            &payload,
        );
        // Persist the audit event; the profile itself is durable via `users.json`.
        state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
        state.attest_latest(&attestor, &ledger).await;
    }

    Ok(Json(UserView::from(&user)))
}
