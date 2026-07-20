//! API-key registry, persistence, management endpoints, and bearer-principal resolution for
//! integration/MCP clients.
//!
//! Secret handling: the plaintext key is returned only from `POST /v1/api-keys` and
//! `POST /v1/api-keys/{id}/rotate`; the persisted `apikeys.json`, list responses, and audit events
//! contain only the non-secret prefix and hash-backed [`chancela_apikey::ApiKey`] record.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use chancela_apikey::{
    ApiKey, ApiKeyGrant, ApiKeyId, KeySpec, NewApiKey, RateLimit, RateLimitOutcome, RateLimitState,
    RequestPrincipal, extract_prefix,
};
use chancela_authz::{Permission, RoleId, Scope, UserId as AuthzUserId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{authorizer, forbidden, scope_relations};
use crate::error::ApiError;
use crate::roles::{ScopeInput, effective_permissions_for};
use crate::session::ScopeView;
use crate::users::UserId;

pub const API_KEYS_FILE: &str = "apikeys.json";

/// API-key registry, keyed by the key's non-secret display prefix (`chk_<prefix>`).
pub type ApiKeyRegistry = HashMap<String, ApiKey>;

/// In-memory token-bucket state per key id. Not persisted; restart resets buckets to full.
pub type ApiKeyRateLimitBuckets = HashMap<ApiKeyId, RateLimitState>;

const INVALID_API_KEY: &str = "chave API inválida";

pub(crate) fn load_api_keys(path: &Path) -> Option<ApiKeyRegistry> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<ApiKey>>(&bytes) {
        Ok(list) => Some(list.into_iter().map(|k| (k.prefix.clone(), k)).collect()),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid API-key document ({e}); ignoring it",
                path.display()
            );
            None
        }
    }
}

pub(crate) fn write_api_keys_atomic(path: &Path, keys: &ApiKeyRegistry) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut list: Vec<&ApiKey> = keys.values().collect();
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

async fn persist_api_keys(state: &AppState) -> Result<(), ApiError> {
    if let Some(path) = &state.api_keys_path {
        let keys = state.api_keys.read().await;
        write_api_keys_atomic(path, &keys)
            .map_err(|e| ApiError::Internal(format!("failed to persist API keys: {e}")))?;
    }
    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| API_KEYS_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

/// Read an `Authorization: Bearer <api-key>` credential from request headers.
///
/// Non-Bearer authorization schemes are ignored so session authentication remains unchanged. A
/// malformed Bearer header is a credential failure, not an absent session.
pub(crate) fn read_bearer_api_key(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    let Some(raw) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    else {
        return Ok(None);
    };

    let mut parts = raw.splitn(2, char::is_whitespace);
    let scheme = parts.next().unwrap_or_default();
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Ok(None);
    }

    let Some(token) = parts.next().map(str::trim).filter(|t| !t.is_empty()) else {
        return Err(ApiError::Unauthorized(INVALID_API_KEY.to_owned()));
    };
    if token.chars().any(char::is_whitespace) {
        return Err(ApiError::Unauthorized(INVALID_API_KEY.to_owned()));
    }
    Ok(Some(token))
}

/// Resolve a presented bearer key into a `chancela-apikey` principal, attenuated by the creator's
/// current live authority and the complete current resource-parent graph.
pub(crate) async fn resolve_bearer_principal(
    state: &AppState,
    presented: &str,
) -> Result<RequestPrincipal, ApiError> {
    let prefix = extract_prefix(presented)
        .ok_or_else(|| ApiError::Unauthorized(INVALID_API_KEY.to_owned()))?;

    let key = {
        let keys = state.api_keys.read().await;
        keys.get(prefix)
            .filter(|key| key.verify(presented))
            .cloned()
            .ok_or_else(|| ApiError::Unauthorized(INVALID_API_KEY.to_owned()))?
    };

    let now = OffsetDateTime::now_utc();
    if !key.is_active(now) {
        return Err(ApiError::Unauthorized(INVALID_API_KEY.to_owned()));
    }
    enforce_rate_limit(state, &key, now).await?;

    let creator_effective = effective_permissions_for(state, UserId(key.created_by.0), now).await;
    let roles = state.roles.read().await.clone();
    let relations = scope_relations(state).await;

    Ok(chancela_apikey::resolve(
        &key,
        &creator_effective,
        &roles,
        now,
        &relations,
    ))
}

async fn enforce_rate_limit(
    state: &AppState,
    key: &ApiKey,
    now: OffsetDateTime,
) -> Result<(), ApiError> {
    let policy = key.rate_limit.unwrap_or_default();
    let mut buckets = state.api_key_rate_limits.write().await;
    let bucket = buckets
        .entry(key.id)
        .or_insert_with(|| policy.initial_state(now));

    match policy.check(bucket, now) {
        RateLimitOutcome::Allowed => Ok(()),
        RateLimitOutcome::Limited { retry_after } => {
            let ms = retry_after.whole_milliseconds();
            let remaining = ((ms + 999) / 1000).max(1);
            Err(ApiError::TooManyRequests(format!(
                "limite de pedidos da chave API excedido — tente novamente em {remaining} s"
            )))
        }
    }
}

// =================================================================================================
// API-key management endpoints. These are interactive-session-only: API-key principals may use
// ordinary permission-gated business routes, but they cannot administer keys.
// =================================================================================================

#[derive(Deserialize)]
pub struct CreateApiKey {
    pub name: String,
    pub grant: ApiKeyGrantInput,
    /// RFC 3339 expiry; absent means until revoked.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Per-key override. Absent uses [`RateLimit::default`] at request time.
    #[serde(default)]
    pub rate_limit: Option<RateLimit>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ApiKeyGrantInput {
    Role {
        role_id: Uuid,
        scope: ScopeInput,
    },
    Permissions {
        #[serde(default)]
        permissions: Vec<Permission>,
        scope: ScopeInput,
    },
}

impl ApiKeyGrantInput {
    fn into_grant(self) -> ApiKeyGrant {
        match self {
            ApiKeyGrantInput::Role { role_id, scope } => {
                ApiKeyGrant::role(RoleId(role_id), scope.into())
            }
            ApiKeyGrantInput::Permissions { permissions, scope } => {
                ApiKeyGrant::perms(permissions, scope.into())
            }
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ApiKeyGrantView {
    Role {
        role_id: String,
        scope: ScopeView,
    },
    Permissions {
        permissions: Vec<String>,
        scope: ScopeView,
    },
}

impl ApiKeyGrantView {
    fn from_grant(grant: &ApiKeyGrant) -> Self {
        match grant {
            ApiKeyGrant::Role { role_id, scope } => ApiKeyGrantView::Role {
                role_id: role_id.0.to_string(),
                scope: ScopeView::from(*scope),
            },
            ApiKeyGrant::Perms { permissions, scope } => ApiKeyGrantView::Permissions {
                permissions: permissions.iter().map(|p| p.as_str().to_owned()).collect(),
                scope: ScopeView::from(*scope),
            },
        }
    }
}

#[derive(Serialize)]
pub struct ApiKeyView {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub grant: ApiKeyGrantView,
    pub created_by: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub revoked: bool,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
}

impl ApiKeyView {
    fn from_key(key: &ApiKey, now: OffsetDateTime) -> Self {
        ApiKeyView {
            id: key.id.0.to_string(),
            name: key.name.clone(),
            prefix: key.prefix.clone(),
            grant: ApiKeyGrantView::from_grant(&key.principal_grant),
            created_by: key.created_by.0.to_string(),
            created_at: format_ts(key.created_at),
            expires_at: key.expires_at.map(format_ts),
            revoked: key.revoked,
            active: key.is_active(now),
            rate_limit: key.rate_limit,
        }
    }
}

#[derive(Serialize)]
pub struct ApiKeyCreated {
    /// The full `chk_...` secret. Returned once, never persisted or included in audit events.
    pub secret: String,
    #[serde(flatten)]
    pub key: ApiKeyView,
}

/// `GET /v1/api-keys` — list non-secret API-key metadata. Requires an interactive
/// `user.manage` holder; API-key principals are refused as non-interactive.
pub async fn list_api_keys(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<ApiKeyView>>, ApiError> {
    require_interactive_api_key_admin(&state, &actor).await?;

    let now = OffsetDateTime::now_utc();
    let keys = state.api_keys.read().await;
    let mut list: Vec<ApiKeyView> = keys
        .values()
        .map(|k| ApiKeyView::from_key(k, now))
        .collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    Ok(Json(list))
}

/// `POST /v1/api-keys` — mint a shown-once API key and persist only its hash-backed record.
pub async fn create_api_key(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateApiKey>,
) -> Result<(StatusCode, Json<ApiKeyCreated>), ApiError> {
    let creator = require_interactive_api_key_admin(&state, &actor).await?;
    let name = validate_key_name(&req.name)?;
    let expires_at = parse_optional_rfc3339(req.expires_at.as_deref(), "expires_at")?;
    let grant = req.grant.into_grant();

    let now = OffsetDateTime::now_utc();
    let creator_effective = effective_permissions_for(&state, creator, now).await;
    let roles = state.roles.read().await.clone();
    let relations = scope_relations(&state).await;

    let NewApiKey { plaintext, api_key } = ApiKey::issue(
        &creator_effective,
        &roles,
        &relations,
        KeySpec {
            name,
            principal_grant: grant,
            created_by: AuthzUserId(creator.0),
            created_at: now,
            expires_at,
            rate_limit: req.rate_limit,
        },
    )
    .map_err(issue_error)?;

    state
        .api_keys
        .write()
        .await
        .insert(api_key.prefix.clone(), api_key.clone());
    persist_api_keys(&state).await?;

    let view = ApiKeyView::from_key(&api_key, now);
    record_api_key_event(
        &state,
        &view,
        "api_key.created",
        "API key created",
        &actor,
        &attestor,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(ApiKeyCreated {
            secret: plaintext,
            key: view,
        }),
    ))
}

/// `DELETE /v1/api-keys/{id}` — revoke a key. Idempotent for already-revoked keys.
pub async fn revoke_api_key(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<ApiKeyView>, ApiError> {
    require_interactive_api_key_admin(&state, &actor).await?;
    let key_id = ApiKeyId(id);

    let existing = state
        .api_keys
        .read()
        .await
        .values()
        .find(|k| k.id == key_id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    if existing.revoked {
        return Ok(Json(ApiKeyView::from_key(
            &existing,
            OffsetDateTime::now_utc(),
        )));
    }

    let updated = {
        let mut keys = state.api_keys.write().await;
        let key = keys
            .values_mut()
            .find(|k| k.id == key_id)
            .ok_or(ApiError::NotFound)?;
        key.revoked = true;
        key.clone()
    };
    state.api_key_rate_limits.write().await.remove(&updated.id);
    persist_api_keys(&state).await?;

    let view = ApiKeyView::from_key(&updated, OffsetDateTime::now_utc());
    record_api_key_event(
        &state,
        &view,
        "api_key.revoked",
        "API key revoked",
        &actor,
        &attestor,
    )
    .await?;
    Ok(Json(view))
}

/// `POST /v1/api-keys/{id}/rotate` — replace the credential material for an active key.
///
/// Rotation keeps the key's stable id, label, creator, grant, expiry, and rate-limit policy, but
/// swaps in a fresh display prefix + hash and returns the plaintext once. The old prefix mapping is
/// removed before persistence, so the old bearer secret fails closed immediately.
pub async fn rotate_api_key(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<ApiKeyCreated>, ApiError> {
    require_interactive_api_key_admin(&state, &actor).await?;
    let key_id = ApiKeyId(id);

    let existing = state
        .api_keys
        .read()
        .await
        .values()
        .find(|k| k.id == key_id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    if existing.revoked {
        return Err(ApiError::Conflict(
            "cannot rotate a revoked API key".to_owned(),
        ));
    }

    let now = OffsetDateTime::now_utc();
    let creator_effective =
        effective_permissions_for(&state, UserId(existing.created_by.0), now).await;
    let roles = state.roles.read().await.clone();
    let relations = scope_relations(&state).await;

    let NewApiKey {
        plaintext,
        api_key: mut replacement,
    } = ApiKey::issue(
        &creator_effective,
        &roles,
        &relations,
        KeySpec {
            name: existing.name.clone(),
            principal_grant: existing.principal_grant.clone(),
            created_by: existing.created_by,
            created_at: existing.created_at,
            expires_at: existing.expires_at,
            rate_limit: existing.rate_limit,
        },
    )
    .map_err(issue_error)?;
    replacement.id = existing.id;

    let updated = {
        let mut keys = state.api_keys.write().await;
        let current = keys
            .get(&existing.prefix)
            .filter(|k| k.id == key_id)
            .ok_or_else(|| ApiError::Conflict("API key changed; retry rotation".to_owned()))?;
        if current.revoked {
            return Err(ApiError::Conflict(
                "cannot rotate a revoked API key".to_owned(),
            ));
        }
        if current.key_hash != existing.key_hash {
            return Err(ApiError::Conflict(
                "API key changed; retry rotation".to_owned(),
            ));
        }
        keys.remove(&existing.prefix);
        keys.insert(replacement.prefix.clone(), replacement.clone());
        replacement
    };
    state.api_key_rate_limits.write().await.remove(&updated.id);
    persist_api_keys(&state).await?;

    let view = ApiKeyView::from_key(&updated, OffsetDateTime::now_utc());
    record_api_key_event(
        &state,
        &view,
        "api_key.rotated",
        "API key rotated",
        &actor,
        &attestor,
    )
    .await?;
    Ok(Json(ApiKeyCreated {
        secret: plaintext,
        key: view,
    }))
}

async fn require_interactive_api_key_admin(
    state: &AppState,
    actor: &CurrentActor,
) -> Result<UserId, ApiError> {
    let authz = authorizer(state, actor).await?;
    authz.require(Permission::UserManage, Scope::Global)?;
    authz.principal()
}

async fn record_api_key_event(
    state: &AppState,
    view: &ApiKeyView,
    kind: &str,
    justification: &str,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
) -> Result<(), ApiError> {
    let bytes = serde_json::to_vec(view)?;
    let actor_name = actor.resolve("api");
    let mut ledger = state.ledger.write().await;
    ledger.append(&actor_name, "api-key", kind, Some(justification), &bytes);
    state
        .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
        .await?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

fn validate_key_name(raw: &str) -> Result<String, ApiError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(ApiError::Unprocessable(
            "API key name must not be empty".to_owned(),
        ));
    }
    if name.len() > 128 {
        return Err(ApiError::Unprocessable(
            "API key name must be at most 128 characters".to_owned(),
        ));
    }
    Ok(name.to_owned())
}

fn parse_optional_rfc3339(
    value: Option<&str>,
    field: &'static str,
) -> Result<Option<OffsetDateTime>, ApiError> {
    value
        .map(|s| {
            OffsetDateTime::parse(s, &Rfc3339).map_err(|_| {
                ApiError::Unprocessable(format!("{field} must be an RFC 3339 timestamp"))
            })
        })
        .transpose()
}

fn format_ts(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339).unwrap_or_default()
}

fn issue_error(err: chancela_apikey::IssueError) -> ApiError {
    match err {
        chancela_apikey::IssueError::EmptyGrant => ApiError::Unprocessable(err.to_string()),
        chancela_apikey::IssueError::GrantContainsMeta
        | chancela_apikey::IssueError::GrantExceedsCreator => forbidden(),
    }
}
