//! `GET`/`PUT /v1/platform/env` — the server-declared environment-override surface.
//!
//! This handler is the security-critical enforcement layer of t14 ("make all the api server env
//! vars overridable ... as they should"). It joins the authoritative registry
//! ([`crate::env_overrides::REGISTRY`]) with the value the **live** process resolved and the
//! persisted override file, then enforces — on write — exactly the invariants the classification
//! promises:
//!
//! * **RBAC.** `GET` requires `SettingsRead@Global`; `PUT` requires `SettingsManage@Global`.
//! * **Only Tier A / Tier C-editable keys may be written.** A secret (Tier B), a derived/read-only
//!   var (Tier D), a typed-slice-excluded var (the egress ceiling, the ZK root), or an unknown name
//!   is rejected with `422`. **Secrets are never writable in v1** and are never echoed on `GET`
//!   (only a `configured` flag).
//! * **Per-var validation.** Every proposed value passes the registry validator before it can reach
//!   the override file, so a malformed value can never be `set_var`-ed at the next start.
//! * **Narrow-only ceilings.** A `narrow_only` var may only be *tightened* — an override that widens
//!   it beyond the deployment value is refused. (The one such var, `CHANCELA_CONNECTOR_ALLOWED_HOSTS`,
//!   is additionally typed-slice-excluded, so it is refused outright; the check is a defence-in-depth
//!   backstop for any future editable ceiling.)
//! * **Acknowledgement gate.** Any *changed* Tier-C boundary var must be named in the request's
//!   `acknowledge[]`, mirroring the `email.allow_insecure` mould, or the whole `PUT` is `422`.
//! * **Audit.** A successful change appends the `server.env.overridden` ledger event recording
//!   **which keys changed — never their values.**
//!
//! The override file is written under `CHANCELA_DATA_DIR`; the startup application of it (the
//! `unsafe` `set_var` stage) is t14-e2's job. Until e2 lands, a stored override simply shows up as
//! `restart_pending` on `GET` — which is the honest state: it takes effect on the next restart.

use std::collections::{BTreeMap, BTreeSet};

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use chancela_authz::{Permission, Scope};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::require_permission;
use crate::env_overrides::{
    self, ENV_OVERRIDDEN_EVENT, EnvOverrides, EnvVarSource, EnvVarSpec, EnvVarValidator,
    EnvVarValidatorView, OVERRIDES_FILE, ServerEnvResponse, ServerEnvUpdateRequest,
    ServerEnvVarView,
};
use crate::error::ApiError;

/// `GET /v1/platform/env` — the registry joined with live state. RBAC `SettingsRead@Global`.
///
/// Secrets are masked: their values are `null` and only [`ServerEnvVarView::configured`] signals
/// whether the live process has one. Derived / typed-slice-excluded vars are shown read-only.
pub async fn get_server_env(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<ServerEnvResponse>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsRead, Scope::Global).await?;
    Ok(Json(build_response(&state)?))
}

/// `PUT /v1/platform/env` — replace the non-secret override map. RBAC `SettingsManage@Global`.
///
/// The body is the **complete** desired override set (keys absent from it are cleared) plus the
/// boundary acknowledgements. Enforcement order is: reject non-writable keys → validate → narrow-only
/// → acknowledgement gate → persist → audit. Nothing is written until every check passes.
pub async fn put_server_env(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Bytes,
) -> Result<Json<ServerEnvResponse>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsManage, Scope::Global).await?;

    let request: ServerEnvUpdateRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::Unprocessable(format!("invalid request body: {e}")))?;

    // The override file lives under the data dir; without persistence there is nowhere durable to
    // store it (and the whole point is that a restart re-reads it). Refuse cleanly, like the ZK root.
    let data_dir = state.data_dir().ok_or_else(|| {
        ApiError::Unprocessable(
            "server environment overrides require CHANCELA_DATA_DIR persistence".to_owned(),
        )
    })?;
    let previous = env_overrides::load(&data_dir)
        .map_err(|e| ApiError::Internal(format!("failed to read the existing overrides: {e}")))?;

    // 1. Validate every proposed key/value against the registry. Build the desired set as we go so a
    //    single malformed entry rejects the whole request before anything is written.
    let mut desired: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in &request.overrides {
        let spec = classify_writable(name)?;
        spec.validator
            .validate(value)
            .map_err(|reason| ApiError::Unprocessable(format!("`{name}`: {reason}")))?;
        enforce_narrow_only(spec, value)?;
        desired.insert(name.clone(), value.clone());
    }

    // 2. Acknowledgement gate: any Tier-C boundary var whose override *changed* (added, removed, or
    //    modified) must be named in `acknowledge[]`. This is the server-side backstop; the web drives
    //    the toggle off `acknowledgement_required` in the GET view.
    let acknowledged: BTreeSet<&str> = request.acknowledge.iter().map(String::as_str).collect();
    for spec in env_overrides::registry() {
        if !spec.boundary || !spec.is_editable() {
            continue;
        }
        let before = previous.overrides.get(spec.name);
        let after = desired.get(spec.name);
        if before != after && !acknowledged.contains(spec.name) {
            return Err(ApiError::Unprocessable(format!(
                "`{}` is a security boundary; changing it requires explicit acknowledgement (list \
                 it in `acknowledge`)",
                spec.name
            )));
        }
    }

    // 3. The change set, computed from names only — this is what the ledger records. No values.
    let change = OverrideChange::between(&previous.overrides, &desired);

    // 4. Persist the override file (atomic temp + rename) before acknowledging success.
    let overrides = EnvOverrides {
        overrides: desired,
    };
    env_overrides::save(&data_dir, &overrides)
        .map_err(|e| ApiError::Internal(format!("failed to persist the overrides: {e}")))?;

    // 5. Audit — only when something actually changed, and only the *keys*.
    if change.is_change() {
        let actor = actor.resolve("api");
        let summary = change.summary();
        let diff = serde_json::to_vec(&change.audit_payload(&request.acknowledge))?;
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &actor,
            "platform",
            ENV_OVERRIDDEN_EVENT,
            Some(&summary),
            &diff,
        );
        state
            .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
            .await?;
        state.attest_latest(&attestor, &ledger).await;
    }

    Ok(Json(build_response(&state)?))
}

// -------------------------------------------------------------------------------------------------
// Enforcement helpers (free functions, unit-tested in isolation)
// -------------------------------------------------------------------------------------------------

/// Resolve `name` to a spec the panel is allowed to write, or an operator-facing `422`.
///
/// Rejects, with a message naming *why*: an unknown var, a secret (Tier B — never writable in v1), a
/// typed-slice-excluded var (the egress ceiling / ZK root — one precedence rule per var), and any
/// derived / read-only var (Tier D).
fn classify_writable(name: &str) -> Result<&'static EnvVarSpec, ApiError> {
    let spec = env_overrides::find(name).ok_or_else(|| {
        ApiError::Unprocessable(format!(
            "`{name}` is not a known server environment variable"
        ))
    })?;
    if spec.secret {
        return Err(ApiError::Unprocessable(format!(
            "`{name}` holds (or points at) a secret and is never writable from this panel"
        )));
    }
    if let Some(reason) = spec.excluded_typed_slice {
        return Err(ApiError::Unprocessable(format!(
            "`{name}` is managed by a typed settings slice and cannot be overridden here: {reason}"
        )));
    }
    if !spec.is_editable() {
        return Err(ApiError::Unprocessable(format!(
            "`{name}` is a derived / read-only value and cannot be overridden"
        )));
    }
    Ok(spec)
}

/// Enforce a narrow-only ceiling: an override may only *tighten* it, never widen it past the value
/// the deployment set in the ambient environment. Applies to host-list ceilings (the egress
/// allow-list shape); other kinds have no widening semantics and pass through.
///
/// The one narrow-only registry var is also typed-slice-excluded (so [`classify_writable`] refuses
/// it first); this is the defence-in-depth backstop that keeps the invariant true for any future
/// editable ceiling, and it is what the unit test exercises directly.
fn enforce_narrow_only(spec: &EnvVarSpec, value: &str) -> Result<(), ApiError> {
    if !spec.narrow_only || !matches!(spec.validator, EnvVarValidator::HostList) {
        return Ok(());
    }
    // No deployment ceiling in the ambient env ⇒ there is nothing to widen past.
    let Ok(ceiling) = std::env::var(spec.name) else {
        return Ok(());
    };
    let widening = ceiling_widening(value, &ceiling);
    if !widening.is_empty() {
        return Err(ApiError::Unprocessable(format!(
            "`{}` is a narrow-only ceiling; an override may only tighten it. These entries widen it \
             beyond the deployment value: {}",
            spec.name,
            widening.join(", ")
        )));
    }
    Ok(())
}

/// The host-list entries in `candidate` that lie *outside* `ceiling` — i.e. the ways `candidate`
/// would widen the ceiling. Empty ⇒ `candidate` is a subset (a tightening or an equal set). Pure and
/// env-free so it is unit-testable without touching the process environment.
fn ceiling_widening(candidate: &str, ceiling: &str) -> Vec<String> {
    let ceiling_hosts = host_set(ceiling);
    host_set(candidate)
        .into_iter()
        .filter(|host| !ceiling_hosts.contains(host))
        .collect()
}

/// Normalize a comma-separated host list to a set for subset comparison (trimmed, lowercased,
/// empties dropped).
fn host_set(list: &str) -> BTreeSet<String> {
    list.split(',')
        .map(|host| host.trim().to_ascii_lowercase())
        .filter(|host| !host.is_empty())
        .collect()
}

/// The by-name diff between the previously stored overrides and the desired set. Carries **no**
/// values — it is what the audit event records.
#[derive(Debug, Default, PartialEq, Eq)]
struct OverrideChange {
    added: Vec<String>,
    removed: Vec<String>,
    modified: Vec<String>,
}

impl OverrideChange {
    fn between(previous: &BTreeMap<String, String>, desired: &BTreeMap<String, String>) -> Self {
        let mut change = OverrideChange::default();
        for (name, value) in desired {
            match previous.get(name) {
                None => change.added.push(name.clone()),
                Some(before) if before != value => change.modified.push(name.clone()),
                Some(_) => {}
            }
        }
        for name in previous.keys() {
            if !desired.contains_key(name) {
                change.removed.push(name.clone());
            }
        }
        change
    }

    fn is_change(&self) -> bool {
        !(self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty())
    }

    fn summary(&self) -> String {
        format!(
            "server environment overrides updated: {} added, {} removed, {} changed",
            self.added.len(),
            self.removed.len(),
            self.modified.len()
        )
    }

    /// The ledger payload — key names and the acknowledgements, never any value.
    fn audit_payload<'a>(&'a self, acknowledged: &'a [String]) -> AuditPayload<'a> {
        AuditPayload {
            added: &self.added,
            removed: &self.removed,
            modified: &self.modified,
            acknowledged,
        }
    }
}

/// The `server.env.overridden` ledger payload. **Keys only**, never values (the whole reason a
/// dedicated event exists rather than dumping the override file).
#[derive(Debug, Serialize)]
struct AuditPayload<'a> {
    added: &'a [String],
    removed: &'a [String],
    modified: &'a [String],
    acknowledged: &'a [String],
}

// -------------------------------------------------------------------------------------------------
// View construction
// -------------------------------------------------------------------------------------------------

/// Build the full `GET` response: every registry var joined with live state, plus the expanded
/// per-provider secret families (always masked).
fn build_response(state: &AppState) -> Result<ServerEnvResponse, ApiError> {
    let data_dir = state.data_dir();
    let overrides = match &data_dir {
        Some(dir) => env_overrides::load(dir)
            .map_err(|e| ApiError::Internal(format!("failed to read the overrides: {e}")))?,
        None => EnvOverrides::default(),
    };
    let overrides_path = match &data_dir {
        Some(dir) => env_overrides::overrides_path(dir).display().to_string(),
        None => format!("(in-memory; {OVERRIDES_FILE} is not persisted)"),
    };

    let mut vars = Vec::new();
    let mut restart_pending = false;
    for spec in env_overrides::registry() {
        let view = build_view(spec, &overrides);
        restart_pending |= view.restart_pending;
        vars.push(view);
    }
    // Dynamic per-provider secret families (CSC providers, connector secret refs). Always Tier B /
    // display-only, never written, so they only enrich the view.
    vars.extend(expand_dynamic_secret_families(&overrides));

    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());

    Ok(ServerEnvResponse {
        vars,
        restart_pending,
        overrides_path,
        generated_at,
    })
}

/// One registry var as a view row: the declared classification joined with the live-resolved value.
/// **Secrets are masked here** — no value is ever placed on a secret row.
fn build_view(spec: &EnvVarSpec, overrides: &EnvOverrides) -> ServerEnvVarView {
    let process_value = std::env::var(spec.name).ok();
    let configured = process_value.is_some();

    // A secret is never echoed: only `configured` (env present) leaks, and even a corrupted override
    // file carrying a secret key is masked here because we build the value fields from the spec's
    // secret flag, not from what happens to be in the map.
    let (effective_value, override_value, default_value, restart_pending) = if spec.secret {
        (None, None, None, false)
    } else {
        let stored = overrides.overrides.get(spec.name).cloned();
        let restart_pending = stored
            .as_deref()
            .is_some_and(|ov| Some(ov) != process_value.as_deref());
        (
            process_value.clone(),
            stored,
            spec.default_value.map(str::to_owned),
            restart_pending,
        )
    };

    let source = if override_value
        .as_deref()
        .is_some_and(|ov| Some(ov) == process_value.as_deref())
    {
        EnvVarSource::Override
    } else if configured {
        EnvVarSource::Env
    } else {
        EnvVarSource::Default
    };

    ServerEnvVarView {
        name: spec.name.to_owned(),
        group: spec.group,
        tier: spec.tier,
        editable: spec.is_editable(),
        secret: spec.secret,
        boundary: spec.boundary,
        narrow_only: spec.narrow_only,
        acknowledgement_required: spec.acknowledgement_required,
        excluded_typed_slice: spec.excluded_typed_slice.map(str::to_owned),
        source,
        configured,
        effective_value,
        override_value,
        default_value,
        restart_pending,
        validator: spec.validator_view(),
    }
}

/// Expand the dynamic secret families ([`env_overrides::DYNAMIC_SECRET_FAMILIES`]) into concrete
/// masked rows for the configured providers / connector refs found in the live environment. These
/// are display-only: they are not registry rows, so a `PUT` naming one is rejected as unknown.
fn expand_dynamic_secret_families(overrides: &EnvOverrides) -> Vec<ServerEnvVarView> {
    let mut rows = Vec::new();
    let mut emitted: BTreeSet<String> = BTreeSet::new();

    // CSC per-provider secrets, keyed off the configured provider list (override wins over ambient).
    let providers = overrides
        .overrides
        .get("CHANCELA_CSC_PROVIDERS")
        .cloned()
        .or_else(|| std::env::var("CHANCELA_CSC_PROVIDERS").ok())
        .unwrap_or_default();
    for provider in providers.split(',') {
        let token = provider.trim().to_ascii_uppercase();
        if token.is_empty() {
            continue;
        }
        for suffix in ["CLIENT_ID", "CLIENT_SECRET", "ACCESS_TOKEN"] {
            let name = format!("CHANCELA_CSC_{token}_{suffix}");
            if emitted.insert(name.clone()) {
                rows.push(masked_secret_row(name, env_overrides::EnvVarGroup::Csc));
            }
        }
    }

    // Connector secret refs: any ambient `CHANCELA_CONNECTOR_SECRET_*` the deployment set.
    for (key, _value) in std::env::vars() {
        if key.starts_with("CHANCELA_CONNECTOR_SECRET_") && emitted.insert(key.clone()) {
            rows.push(masked_secret_row(key, env_overrides::EnvVarGroup::Connectors));
        }
    }

    rows
}

/// A masked Tier-B row for a dynamically-discovered secret: `configured` reflects whether the live
/// process has it, and no value is ever carried.
fn masked_secret_row(name: String, group: env_overrides::EnvVarGroup) -> ServerEnvVarView {
    let configured = std::env::var(&name).is_ok();
    ServerEnvVarView {
        name,
        group,
        tier: env_overrides::EnvVarTier::B,
        editable: false,
        secret: true,
        boundary: false,
        narrow_only: false,
        acknowledgement_required: false,
        excluded_typed_slice: None,
        source: if configured {
            EnvVarSource::Env
        } else {
            EnvVarSource::Default
        },
        configured,
        effective_value: None,
        override_value: None,
        default_value: None,
        restart_pending: false,
        validator: EnvVarValidatorView {
            kind: EnvVarValidator::FreeText.kind(),
            allowed: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::SESSION_TTL_SECS;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use chancela_authz::{
        OWNER_ROLE_ID, READER_ROLE_ID, REVIEWER_ROLE_ID, RoleAssignment, RoleCatalog, RoleId,
    };
    use serde_json::{Value, json};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use time::format_description::well_known::Rfc3339;
    use tower::ServiceExt;
    use uuid::Uuid;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        dir: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let seq = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir()
                .join(format!("chancela-env-handler-{}-{seq}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self { dir }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    async fn seed_token(state: &AppState, role: RoleId) -> String {
        use crate::users::{User, UserId};
        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
        }
        let uid = UserId(Uuid::new_v4());
        let user = User {
            id: uid,
            username: format!("amelia.marques.{}", Uuid::new_v4()),
            display_name: "Amélia Marques".to_owned(),
            email: None,
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: Some(crate::attestation::hash_secret("Teste-Forte7!X").unwrap()),
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(role, Scope::Global)],
            language: Default::default(),
        };
        state.users.write().await.insert(uid, user);
        let token = Uuid::new_v4().to_string();
        let now = OffsetDateTime::now_utc();
        state.sessions.write().await.insert(
            token.clone(),
            crate::session::SessionEntry {
                user_id: uid,
                unlocked_key: None,
                expires_at: now + time::Duration::seconds(SESSION_TTL_SECS),
            },
        );
        token
    }

    async fn send(state: AppState, req: Request<Body>, token: Option<&str>) -> (StatusCode, Value) {
        let req = match token {
            Some(t) => {
                let mut r = req;
                r.headers_mut()
                    .insert("x-chancela-session", t.parse().unwrap());
                r
            }
            None => req,
        };
        let response = crate::router(state)
            .oneshot(req)
            .await
            .expect("router responds");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("body is JSON")
        };
        (status, value)
    }

    fn get_req(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request builds")
    }

    fn put_req(uri: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method("PUT")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request builds")
    }

    fn var<'a>(body: &'a Value, name: &str) -> &'a Value {
        body["vars"]
            .as_array()
            .expect("vars is an array")
            .iter()
            .find(|v| v["name"] == name)
            .unwrap_or_else(|| panic!("`{name}` missing from the env view"))
    }

    // --- GET: RBAC + masking ---------------------------------------------------------------------

    #[tokio::test]
    async fn get_requires_a_session() {
        let state = AppState::default();
        let (status, _) = send(state, get_req("/v1/platform/env"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_allows_settings_read_and_masks_secrets() {
        let state = AppState::default();
        let token = seed_token(&state, READER_ROLE_ID).await; // SettingsRead, not SettingsManage
        let (status, body) = send(state, get_req("/v1/platform/env"), Some(&token)).await;
        assert_eq!(status, StatusCode::OK, "reader may read: {body}");

        // A Tier-B secret is masked: no value fields, only the classification and `configured`.
        let db_key = var(&body, "CHANCELA_DB_KEY");
        assert_eq!(db_key["tier"], "B");
        assert_eq!(db_key["secret"], true);
        assert_eq!(db_key["editable"], false);
        assert!(db_key["effective_value"].is_null(), "secret value must be null");
        assert!(db_key["override_value"].is_null());
        assert!(db_key["default_value"].is_null());

        // A Tier-A var is editable and shown with its default.
        let log = var(&body, "CHANCELA_LOG");
        assert_eq!(log["tier"], "A");
        assert_eq!(log["editable"], true);
        assert_eq!(log["default_value"], "info");
    }

    // --- PUT: RBAC -------------------------------------------------------------------------------

    #[tokio::test]
    async fn put_requires_settings_manage() {
        let state = AppState::default();
        // Reader has SettingsRead but NOT SettingsManage.
        let token = seed_token(&state, READER_ROLE_ID).await;
        let body = json!({ "overrides": { "CHANCELA_LOG": "debug" }, "acknowledge": [] });
        let (status, _) = send(state, put_req("/v1/platform/env", body), Some(&token)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "reader must not write");
    }

    #[tokio::test]
    async fn put_with_no_settings_permission_at_all_is_forbidden() {
        let state = AppState::default();
        let token = seed_token(&state, REVIEWER_ROLE_ID).await; // no settings perms
        let body = json!({ "overrides": { "CHANCELA_LOG": "debug" }, "acknowledge": [] });
        let (status, _) = send(state, put_req("/v1/platform/env", body), Some(&token)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // --- PUT: reject non-writable keys -----------------------------------------------------------

    #[tokio::test]
    async fn put_rejects_writing_a_secret() {
        let temp = TempDir::new();
        let state = AppState::with_data_dir(temp.dir.clone());
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let body = json!({ "overrides": { "CHANCELA_DB_KEY": "hunter2" }, "acknowledge": [] });
        let (status, err) = send(state, put_req("/v1/platform/env", body), Some(&token)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let msg = err["error"].as_str().or_else(|| err["message"].as_str()).unwrap_or_default();
        assert!(msg.contains("secret"), "refusal must say why: {err}");
        // Nothing was written.
        let stored = env_overrides::load(&temp.dir).expect("load");
        assert!(stored.overrides.is_empty(), "a rejected PUT must persist nothing");
    }

    #[tokio::test]
    async fn put_rejects_a_derived_var() {
        let temp = TempDir::new();
        let state = AppState::with_data_dir(temp.dir.clone());
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let body = json!({ "overrides": { "CHANCELA_DB_BACKEND": "postgres" }, "acknowledge": [] });
        let (status, _) = send(state, put_req("/v1/platform/env", body), Some(&token)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn put_rejects_the_typed_slice_ceiling() {
        // The egress allow-list ceiling is narrow-only AND typed-slice-excluded: refused outright,
        // which is how "never loosen the ceiling" manifests through this endpoint.
        let temp = TempDir::new();
        let state = AppState::with_data_dir(temp.dir.clone());
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let body = json!({
            "overrides": { "CHANCELA_CONNECTOR_ALLOWED_HOSTS": "evil.example" },
            "acknowledge": ["CHANCELA_CONNECTOR_ALLOWED_HOSTS"],
        });
        let (status, err) = send(state, put_req("/v1/platform/env", body), Some(&token)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let msg = err["error"].as_str().or_else(|| err["message"].as_str()).unwrap_or_default();
        assert!(msg.contains("typed settings slice"), "refusal must name the slice: {err}");
    }

    #[tokio::test]
    async fn put_rejects_an_unknown_var() {
        let temp = TempDir::new();
        let state = AppState::with_data_dir(temp.dir.clone());
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let body = json!({ "overrides": { "CHANCELA_NOT_A_REAL_VAR": "x" }, "acknowledge": [] });
        let (status, _) = send(state, put_req("/v1/platform/env", body), Some(&token)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn put_rejects_an_invalid_value() {
        let temp = TempDir::new();
        let state = AppState::with_data_dir(temp.dir.clone());
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        // CHANCELA_HSTS_MAX_AGE is an Unsigned; a non-numeric value must be rejected by the validator.
        let body = json!({ "overrides": { "CHANCELA_HSTS_MAX_AGE": "forever" }, "acknowledge": [] });
        let (status, _) = send(state, put_req("/v1/platform/env", body), Some(&token)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // --- PUT: acknowledgement gate ---------------------------------------------------------------

    #[tokio::test]
    async fn put_changing_a_boundary_without_ack_is_422() {
        let temp = TempDir::new();
        let state = AppState::with_data_dir(temp.dir.clone());
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        // CHANCELA_RATE_LIMIT_TRUST_FORWARDED_FOR is a Tier-C boundary; changing it needs an ack.
        let body = json!({
            "overrides": { "CHANCELA_RATE_LIMIT_TRUST_FORWARDED_FOR": "true" },
            "acknowledge": [],
        });
        let (status, err) = send(state, put_req("/v1/platform/env", body), Some(&token)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let msg = err["error"].as_str().or_else(|| err["message"].as_str()).unwrap_or_default();
        assert!(msg.contains("acknowledge"), "refusal must name the gate: {err}");
        let stored = env_overrides::load(&temp.dir).expect("load");
        assert!(stored.overrides.is_empty(), "the ungated boundary change must not persist");
    }

    #[tokio::test]
    async fn put_changing_a_boundary_with_ack_succeeds_and_audits_keys_only() {
        let temp = TempDir::new();
        let state = AppState::with_data_dir(temp.dir.clone());
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let ledger_before = state.ledger.read().await.len();

        let body = json!({
            "overrides": { "CHANCELA_RATE_LIMIT_TRUST_FORWARDED_FOR": "true" },
            "acknowledge": ["CHANCELA_RATE_LIMIT_TRUST_FORWARDED_FOR"],
        });
        let (status, view) = send(state.clone(), put_req("/v1/platform/env", body), Some(&token)).await;
        assert_eq!(status, StatusCode::OK, "acknowledged boundary change saves: {view}");

        // The override is persisted and reflected as restart_pending (the process has not applied it).
        let stored = env_overrides::load(&temp.dir).expect("load");
        assert_eq!(
            stored.overrides.get("CHANCELA_RATE_LIMIT_TRUST_FORWARDED_FOR"),
            Some(&"true".to_owned())
        );
        let row = var(&view, "CHANCELA_RATE_LIMIT_TRUST_FORWARDED_FOR");
        assert_eq!(row["override_value"], "true");
        assert_eq!(row["restart_pending"], true);
        assert_eq!(view["restart_pending"], true);

        // Exactly one ledger event of the dedicated kind was appended. (The ledger retains only the
        // payload *digest*, not the bytes — the keys-only guarantee of the payload itself is proven
        // by `override_change_is_keys_only_and_detects_each_kind`.)
        let ledger = state.ledger.read().await;
        assert_eq!(ledger.len(), ledger_before + 1, "one audit event appended");
        let event = ledger.events().last().expect("event");
        assert_eq!(event.kind, ENV_OVERRIDDEN_EVENT);
    }

    #[tokio::test]
    async fn put_a_tier_a_var_needs_no_ack() {
        let temp = TempDir::new();
        let state = AppState::with_data_dir(temp.dir.clone());
        let token = seed_token(&state, OWNER_ROLE_ID).await;
        let body = json!({ "overrides": { "CHANCELA_LOG": "debug" }, "acknowledge": [] });
        let (status, view) = send(state, put_req("/v1/platform/env", body), Some(&token)).await;
        assert_eq!(status, StatusCode::OK, "Tier A saves without ack: {view}");
        let stored = env_overrides::load(&temp.dir).expect("load");
        assert_eq!(stored.overrides.get("CHANCELA_LOG"), Some(&"debug".to_owned()));
    }

    // --- Enforcement helpers, exercised directly -------------------------------------------------

    #[test]
    fn narrow_only_ceiling_allows_tightening_and_refuses_widening() {
        let ceiling = "a.example,b.example";
        // Narrowing (a subset) or an equal set widens nothing.
        assert!(ceiling_widening("a.example", ceiling).is_empty());
        assert!(ceiling_widening("a.example,b.example", ceiling).is_empty());
        // Case / whitespace do not matter.
        assert!(ceiling_widening("  A.Example ", ceiling).is_empty());
        // Adding a host outside the ceiling is a widening — and that is what gets refused.
        assert_eq!(
            ceiling_widening("a.example,c.example", ceiling),
            vec!["c.example".to_owned()]
        );
    }

    #[test]
    fn classify_writable_names_the_reason() {
        assert!(classify_writable("CHANCELA_LOG").is_ok());
        assert!(matches!(
            classify_writable("CHANCELA_DB_KEY"),
            Err(ApiError::Unprocessable(_))
        ));
        assert!(matches!(
            classify_writable("CHANCELA_DB_BACKEND"),
            Err(ApiError::Unprocessable(_))
        ));
        assert!(matches!(
            classify_writable("CHANCELA_CONNECTOR_ALLOWED_HOSTS"),
            Err(ApiError::Unprocessable(_))
        ));
        assert!(matches!(
            classify_writable("NOPE"),
            Err(ApiError::Unprocessable(_))
        ));
    }

    #[test]
    fn override_change_is_keys_only_and_detects_each_kind() {
        let previous = BTreeMap::from([
            ("A".to_owned(), "1".to_owned()),
            ("B".to_owned(), "keep".to_owned()),
            ("C".to_owned(), "drop".to_owned()),
        ]);
        let desired = BTreeMap::from([
            ("A".to_owned(), "2".to_owned()), // modified
            ("B".to_owned(), "keep".to_owned()), // unchanged
            ("D".to_owned(), "new".to_owned()), // added
                                              // C removed
        ]);
        let change = OverrideChange::between(&previous, &desired);
        assert_eq!(change.added, vec!["D".to_owned()]);
        assert_eq!(change.removed, vec!["C".to_owned()]);
        assert_eq!(change.modified, vec!["A".to_owned()]);
        assert!(change.is_change());

        let payload = serde_json::to_string(&change.audit_payload(&["A".to_owned()])).unwrap();
        assert!(!payload.contains('1') && !payload.contains('2'), "no values in the payload: {payload}");
    }

    #[test]
    fn build_view_masks_a_secret_even_if_the_file_holds_one() {
        // Defence in depth: even a hand-corrupted override file carrying a secret key is masked.
        let overrides = EnvOverrides {
            overrides: BTreeMap::from([("CHANCELA_DB_KEY".to_owned(), "leaked".to_owned())]),
        };
        let spec = env_overrides::find("CHANCELA_DB_KEY").expect("secret spec");
        let view = build_view(spec, &overrides);
        assert!(view.secret);
        assert!(view.effective_value.is_none());
        assert!(view.override_value.is_none(), "a secret is never echoed, even from the file");
        assert!(view.default_value.is_none());
    }
}
