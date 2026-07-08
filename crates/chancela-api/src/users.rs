//! Named user profiles + actor attribution (contract §2.8).
//!
//! Chancela is a local-first, single-operator / small-office app on loopback. User profiles serve
//! two purposes: **attribution** (DAT-10 — identify *who* performed each mutation so the audit
//! ledger names a real person instead of the fixed `"api"` fallback) and, since t41,
//! **access control** — every domain mutation requires a valid session, and users may hold an
//! optional argon2id sign-in secret (t29). This is no longer a passwordless, authorization-free
//! surface: an operator signs in before doing any work.
//!
//! **Security (t41):** all user-mutation endpoints require a valid session via the fallible
//! [`CurrentActor`] extractor. `create_user` is the one exception: it allows a **bootstrap** call
//! (no users exist yet → first-run setup) without a session, then requires auth for every
//! subsequent create.
//!
//! **Argon2 outside the lock (t41 H2):** secret/attestation-key handlers clone the user under a
//! brief read lock, release it, run the argon2 verify and key rewrap/generation outside any lock,
//! then re-acquire a write lock only to commit the validated change.

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
use crate::actor::{CurrentActor, CurrentAttestor, resolve_session_actor};
use crate::attestation::{self, AttestationKeyBlob, MAX_SECRET_LEN, MIN_SECRET_LEN, verify_secret};
use crate::error::ApiError;

pub const USERS_FILE: &str = "users.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub Uuid);

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub username: String,
    pub display_name: String,
    pub created_at: String,
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_key: Option<crate::attestation::AttestationKeyBlob>,
}

#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: String,
    pub active: bool,
    pub has_secret: bool,
    pub has_attestation_key: bool,
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

#[derive(Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub display_name: Option<String>,
}

#[derive(Deserialize)]
pub struct PatchUser {
    pub display_name: Option<String>,
    pub active: Option<bool>,
}

#[derive(Deserialize)]
pub struct SetSecret {
    pub password: String,
    #[serde(default)]
    pub current_password: Option<String>,
}

#[derive(Deserialize)]
pub struct CurrentSecret {
    #[serde(default)]
    pub current_password: Option<String>,
}

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

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| USERS_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

async fn persist(state: &AppState) -> Result<(), ApiError> {
    if let Some(path) = &state.users_path {
        let users = state.users.read().await;
        write_users_atomic(path, &users)
            .map_err(|e| ApiError::Internal(format!("failed to persist users: {e}")))?;
    }
    Ok(())
}

/// `POST /v1/users` — create a profile. **Bootstrap (t41):** when no users exist yet, callable
/// WITHOUT a session. Once at least one user exists, a valid session is required.
pub async fn create_user(
    State(state): State<AppState>,
    parts: axum::http::HeaderMap,
    attestor: CurrentAttestor,
    Json(req): Json<CreateUser>,
) -> Result<(StatusCode, Json<UserView>), ApiError> {
    let username = validate_username(&req.username)?;
    let display_name = req
        .display_name
        .map(|d| d.trim().to_owned())
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| username.clone());

    let session_username = {
        let user_count = state.users.read().await.len();
        if user_count == 0 {
            None
        } else {
            let token = parts
                .get(crate::actor::SESSION_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|t| !t.is_empty());
            match token {
                Some(t) => resolve_session_actor(&state, t).await?,
                None => return Err(ApiError::Unauthorized("sessão requerida".to_owned())),
            }
        }
    };
    let request_actor = session_username.unwrap_or_else(|| "api".to_owned());

    let user = {
        let mut users = state.users.write().await;
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
    {
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &request_actor,
            "user",
            "user.created",
            Some("user created"),
            &payload,
        );
        state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
        state.attest_latest(&attestor, &ledger).await;
    }

    Ok((StatusCode::CREATED, Json(UserView::from(&user))))
}

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

async fn record_user_update(
    state: &AppState,
    user: &User,
    justification: &str,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
) -> Result<(), ApiError> {
    persist(state).await?;
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

/// `POST /v1/users/{id}/secret` — set or change the sign-in secret. **t41 H2:** argon2 verify
/// and key rewrap run OUTSIDE the write lock.
pub async fn set_secret(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<SetSecret>,
) -> Result<Json<UserView>, ApiError> {
    validate_secret(&req.password)?;
    let uid = UserId(id);

    let snapshot = {
        let users = state.users.read().await;
        users.get(&uid).cloned().ok_or(ApiError::NotFound)?
    };

    let changing = snapshot.password_hash.is_some();
    if changing {
        verify_current(&snapshot, req.current_password.as_deref())?;
    }
    let new_hash = attestation::hash_secret(&req.password)?;
    let rewrapped = if changing {
        let old = req.current_password.as_deref().unwrap_or_default();
        match &snapshot.attestation_key {
            Some(blob) => Some(blob.rewrap(old, &req.password)?),
            None => None,
        }
    } else {
        None
    };

    let user = {
        let mut users = state.users.write().await;
        let user = users.get_mut(&uid).ok_or(ApiError::NotFound)?;
        if let Some(r) = rewrapped {
            user.attestation_key = Some(r);
        }
        user.password_hash = Some(new_hash);
        user.clone()
    };
    record_user_update(&state, &user, "sign-in secret set", &actor, &attestor).await?;
    Ok(Json(UserView::from(&user)))
}

/// `DELETE /v1/users/{id}/secret` — remove the sign-in secret. **t41 H2:** argon2 outside lock.
pub async fn remove_secret(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CurrentSecret>,
) -> Result<Json<UserView>, ApiError> {
    let uid = UserId(id);

    let snapshot = {
        let users = state.users.read().await;
        users.get(&uid).cloned().ok_or(ApiError::NotFound)?
    };

    if snapshot.password_hash.is_none() {
        return Ok(Json(UserView::from(&snapshot)));
    }

    verify_current(&snapshot, req.current_password.as_deref())?;

    let user = {
        let mut users = state.users.write().await;
        let user = users.get_mut(&uid).ok_or(ApiError::NotFound)?;
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

/// `POST /v1/users/{id}/attestation-key` — generate or rotate the attestation key. **t41 H2.**
pub async fn generate_attestation_key(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CurrentSecret>,
) -> Result<Json<UserView>, ApiError> {
    let uid = UserId(id);

    let snapshot = {
        let users = state.users.read().await;
        users.get(&uid).cloned().ok_or(ApiError::NotFound)?
    };

    if snapshot.password_hash.is_none() {
        return Err(ApiError::Conflict(
            "set a sign-in secret before generating an attestation key".to_owned(),
        ));
    }

    verify_current(&snapshot, req.current_password.as_deref())?;
    let secret = req.current_password.as_deref().unwrap_or_default();
    let new_key = AttestationKeyBlob::generate(secret)?;

    let user = {
        let mut users = state.users.write().await;
        let user = users.get_mut(&uid).ok_or(ApiError::NotFound)?;
        user.attestation_key = Some(new_key);
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

/// `DELETE /v1/users/{id}/attestation-key` — remove the attestation key. **t41 H2.**
pub async fn remove_attestation_key(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CurrentSecret>,
) -> Result<Json<UserView>, ApiError> {
    let uid = UserId(id);

    let snapshot = {
        let users = state.users.read().await;
        users.get(&uid).cloned().ok_or(ApiError::NotFound)?
    };

    if snapshot.attestation_key.is_none() {
        return Ok(Json(UserView::from(&snapshot)));
    }

    verify_current(&snapshot, req.current_password.as_deref())?;

    let user = {
        let mut users = state.users.write().await;
        let user = users.get_mut(&uid).ok_or(ApiError::NotFound)?;
        user.attestation_key = None;
        user.clone()
    };
    record_user_update(&state, &user, "attestation key removed", &actor, &attestor).await?;
    Ok(Json(UserView::from(&user)))
}

/// `GET /v1/users` — every profile. Requires a valid session (t41 C1).
pub async fn list_users(
    State(state): State<AppState>,
    _actor: CurrentActor,
) -> Json<Vec<UserView>> {
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
///
/// **Last-active-user guard:** deactivating (`active:false`) the only remaining active user is
/// refused with `409`. With no active user left, no session can ever be minted again
/// (`create_session` rejects inactive users) and the bootstrap-create only fires at *zero* users,
/// so the instance would be permanently bricked for mutations.
///
/// The `user.updated` payload is a [`UserView`] (via [`record_user_update`]), never the full
/// [`User`] — no argon2 hash or wrapped attestation key is fed into the audit event, matching
/// every other user handler.
pub async fn patch_user(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchUser>,
) -> Result<Json<UserView>, ApiError> {
    let user = {
        let mut users = state.users.write().await;
        // Last-active-user guard: reject deactivating the final active user (checked under the
        // write lock so two concurrent deactivations can't both pass).
        if req.active == Some(false) {
            let target = users.get(&UserId(id)).ok_or(ApiError::NotFound)?;
            if target.active && users.values().filter(|u| u.active).count() <= 1 {
                return Err(ApiError::Conflict(
                    "não pode desativar o último utilizador ativo".to_owned(),
                ));
            }
        }
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

    record_user_update(&state, &user, "user updated", &actor, &attestor).await?;
    Ok(Json(UserView::from(&user)))
}
