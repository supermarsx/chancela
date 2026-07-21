//! Top-level tenant collection CRUD (wp26/wp27 tenancy P4).
//!
//! Tenants are the isolation boundary **above** entities (`Platform → Tenant → Company/Entity → Book
//! → Act`). The per-tenant SUB-resource surface (`/v1/tenants/{tenant_id}/groups|repositories|
//! connector-targets|repository-policy`) already existed; this module adds the MISSING top-level
//! collection: create a tenant, list the tenants the caller may see, and read one by id. Persistence
//! reuses the store's `upsert_tenant` path (the same one the boot default-seed uses).
//!
//! ## Isolation
//!
//! A tenant is not itself an aggregate that carries a `tenant_id`; isolation is enforced centrally
//! through the `Scope::Tenant` authz level fed by the entity→tenant relation. [`list_tenants`]
//! therefore filters **per row** through the resolved [`Authorizer`](crate::authz::Authorizer)
//! exactly as `list_entities` does: a Global reader sees every tenant, a tenant-scoped reader sees
//! only its own, and no caller enumerates tenants outside its scope. [`get_tenant`] authorizes at the
//! addressed tenant's scope, so an unknown tenant is a non-enumerating result (a Global holder
//! proceeds to the honest `404`; a scoped non-member gets `403`).
//!
//! ## Authorization (dedicated `Tenant*` catalog — wp27-e2)
//!
//! The tenant directory is its **own** authority axis, above the entity level: these handlers gate on
//! the dedicated [`Permission::TenantCreate`]/[`Permission::TenantRead`] verbs (not the entity verbs).
//! `POST /v1/tenants` requires `tenant.create` at `Scope::Global` — minting a tenant is a
//! platform-level provisioning act with no pre-existing scope to narrow to — while the reads authorize
//! `tenant.read` at `Scope::Tenant`, so a tenant-scoped holder sees only its own tenant and a Global
//! holder sees the whole directory. The verbs are seeded to Owner, Platform Administrator and (read +
//! admin, not create) Tenant Administrator; see `chancela_authz::role`.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chancela_authz::{Permission, Scope};
use chancela_core::{Tenant, TenantId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{authorizer, require_permission, scope_of_tenant};
use crate::{ApiError, AppState};

/// Upper bound on a tenant display name (mirrors the group name cap).
const MAX_NAME_CHARS: usize = 200;

/// Wire shape for a tenant: the durable [`Tenant`] (`id` + `name`) plus a computed `entity_count`
/// (how many entities currently belong to it), mirroring the `member_count` convenience on the group
/// view. The count is a directory-level read; it never widens the caller's authorization.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct TenantView {
    #[serde(flatten)]
    tenant: Tenant,
    entity_count: usize,
}

/// Request body for `POST /v1/tenants`.
#[derive(Debug, Deserialize)]
pub(crate) struct CreateTenantBody {
    name: String,
}

/// The canonical `tenant:{id}` audit scope, so `tenant.created` joins its tenant chain (the ledger
/// derives [`ChainId::Tenant`](chancela_ledger::ChainId::Tenant) from the `tenant:` segment).
fn tenant_scope(tenant_id: TenantId) -> String {
    format!("tenant:{tenant_id}")
}

fn normalized_name(value: String) -> Result<String, ApiError> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(ApiError::Unprocessable("name must not be empty".to_owned()));
    }
    if value.chars().count() > MAX_NAME_CHARS {
        return Err(ApiError::Unprocessable(format!(
            "name exceeds {MAX_NAME_CHARS} characters"
        )));
    }
    Ok(value)
}

async fn tenant_view(state: &AppState, tenant: &Tenant) -> TenantView {
    let entity_count = state
        .entities
        .read()
        .await
        .values()
        .filter(|entity| entity.tenant_id == tenant.id)
        .count();
    TenantView {
        tenant: tenant.clone(),
        entity_count,
    }
}

/// `POST /v1/tenants` — create a tenant, record a `tenant.created` ledger event on its `tenant:{id}`
/// scope, durably persist it via the same `upsert_tenant` path the boot seed uses, and return it with
/// `201`.
pub(crate) async fn create_tenant(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<CreateTenantBody>,
) -> Result<(StatusCode, Json<TenantView>), ApiError> {
    // AUTHZ: minting a NEW tenant is a platform-level operation — there is no existing tenant to
    // scope to — so it is gated on the dedicated `tenant.create` verb at Global.
    require_permission(&state, &actor, Permission::TenantCreate, Scope::Global).await?;

    let tenant = Tenant::new(normalized_name(body.name)?);
    let payload = serde_json::to_vec(&tenant)?;
    let actor_name = actor.resolve("api");
    let scope = tenant_scope(tenant.id);
    let id = tenant.id.to_string();
    let json = serde_json::to_string(&tenant)?;

    // tenants → ledger (tenants is off the deadlock chain; we always take it before the ledger, never
    // the reverse). The durable write commits the event + the tenant row atomically; a store failure
    // rolls the append back so the in-memory directory below is never mutated on a failed write.
    let mut tenants = state.tenants.write().await;
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor_name,
        &scope,
        "tenant.created",
        None,
        &payload,
    )?;
    state
        .persist_write_through(&mut ledger, 1, move |tx| tx.upsert_tenant(&id, &json))
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    tenants.insert(tenant.id, tenant.clone());
    drop(ledger);
    drop(tenants);
    Ok((
        StatusCode::CREATED,
        Json(tenant_view(&state, &tenant).await),
    ))
}

/// `GET /v1/tenants` — list the tenants the caller may read. Per-row tenant filter (mirrors
/// `list_entities`): a Global reader sees all, a tenant-scoped reader sees only its own; a caller with
/// no read authority gets an empty list, never a status that reveals what exists.
pub(crate) async fn list_tenants(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<TenantView>>, ApiError> {
    let authz = authorizer(&state, &actor).await?;
    let mut tenants = state
        .tenants
        .read()
        .await
        .values()
        .filter(|tenant| authz.permits(Permission::TenantRead, scope_of_tenant(tenant.id)))
        .cloned()
        .collect::<Vec<_>>();
    tenants.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    let mut views = Vec::with_capacity(tenants.len());
    for tenant in &tenants {
        views.push(tenant_view(&state, tenant).await);
    }
    Ok(Json(views))
}

/// `GET /v1/tenants/{tenant_id}` — read one tenant, or `404`. Authorizes `tenant.read` at the
/// addressed tenant's scope, so an unknown tenant is non-enumerating.
pub(crate) async fn get_tenant(
    State(state): State<AppState>,
    Path(tenant): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<TenantView>, ApiError> {
    let tenant_id = TenantId(tenant);
    require_permission(
        &state,
        &actor,
        Permission::TenantRead,
        scope_of_tenant(tenant_id),
    )
    .await?;
    let tenant = state
        .tenants
        .read()
        .await
        .get(&tenant_id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    Ok(Json(tenant_view(&state, &tenant).await))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Method, Request};
    use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, RoleId};
    use serde_json::{Value, json};
    use time::OffsetDateTime;
    use tower::ServiceExt;

    async fn send_raw(state: AppState, request: Request<Body>) -> (StatusCode, Value) {
        let response = crate::router(state)
            .oneshot(request)
            .await
            .expect("router responds");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("response body is JSON")
        };
        (status, body)
    }

    fn request(method: Method, uri: &str, body: Option<Value>, token: &str) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-chancela-session", token);
        let body = match body {
            Some(value) => {
                builder = builder.header("content-type", "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        builder.body(body).expect("request builds")
    }

    async fn token_for_role_at(
        state: &AppState,
        username: &str,
        role_id: RoleId,
        scope: Scope,
    ) -> String {
        use crate::users::{User, UserId};
        use time::format_description::well_known::Rfc3339;

        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
        }
        let user_id = UserId(Uuid::new_v4());
        state.users.write().await.insert(
            user_id,
            User {
                id: user_id,
                username: username.to_owned(),
                display_name: username.to_owned(),
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
                role_assignments: vec![RoleAssignment::new(role_id, scope)],
                language: Default::default(),
            },
        );
        let token = Uuid::new_v4().to_string();
        state.sessions.write().await.insert(
            token.clone(),
            crate::session::SessionEntry {
                user_id,
                unlocked_key: None,
                expires_at: OffsetDateTime::now_utc()
                    + time::Duration::seconds(crate::actor::SESSION_TTL_SECS),
            },
        );
        token
    }

    /// Seed the singleton default tenant into an `AppState::default()` (which starts with an empty
    /// tenant directory, unlike the store-backed boot path).
    async fn install_default_tenant(state: &AppState) {
        let default = Tenant::default_tenant();
        state.tenants.write().await.insert(default.id, default);
    }

    #[tokio::test]
    async fn create_list_get_tenants_round_trip_through_the_collection() {
        let state = AppState::default();
        install_default_tenant(&state).await;
        let owner = token_for_role_at(&state, "amelia.marques", OWNER_ROLE_ID, Scope::Global).await;

        // Create.
        let (status, created) = send_raw(
            state.clone(),
            request(
                Method::POST,
                "/v1/tenants",
                Some(json!({"name": "  Encosto Estratégico Holding  "})),
                &owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["name"], "Encosto Estratégico Holding");
        assert_eq!(created["entity_count"], 0);
        let created_id = created["id"].as_str().expect("tenant id").to_owned();

        // A blank name is rejected.
        let (status, _) = send_raw(
            state.clone(),
            request(
                Method::POST,
                "/v1/tenants",
                Some(json!({"name": "   "})),
                &owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Get the created tenant back.
        let (status, got) = send_raw(
            state.clone(),
            request(
                Method::GET,
                &format!("/v1/tenants/{created_id}"),
                None,
                &owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{got}");
        assert_eq!(got["id"], created_id);

        // An unknown tenant is a 404 for a Global reader (non-enumerating; a scoped non-member would
        // instead get 403 before reaching this branch — see the isolation test).
        let (status, _) = send_raw(
            state.clone(),
            request(
                Method::GET,
                &format!("/v1/tenants/{}", Uuid::new_v4()),
                None,
                &owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // List shows the default tenant + the newly created one.
        let (status, list) =
            send_raw(state, request(Method::GET, "/v1/tenants", None, &owner)).await;
        assert_eq!(status, StatusCode::OK, "{list}");
        let ids: Vec<&str> = list
            .as_array()
            .expect("list is an array")
            .iter()
            .map(|row| row["id"].as_str().expect("row id"))
            .collect();
        assert!(ids.contains(&created_id.as_str()));
        assert!(ids.contains(&chancela_core::DEFAULT_TENANT_ID.to_string().as_str()));
    }

    /// **Anti-leak (acceptance gate).** A tenant-B-scoped owner creates an entity **through the
    /// endpoint**; it must carry tenant B's id (NOT `DEFAULT_TENANT_ID`) and be invisible to a
    /// tenant-A-scoped user in both the tenant list and the entity list. The tenant-B owner must also
    /// be refused (`403`) when it tries to create an entity in tenant A.
    #[tokio::test]
    async fn second_tenants_created_entity_carries_its_own_tenant_and_is_cross_tenant_invisible() {
        let state = AppState::default();
        install_default_tenant(&state).await;
        let global_owner =
            token_for_role_at(&state, "global.owner", OWNER_ROLE_ID, Scope::Global).await;

        // Two real tenants A and B, created through the collection endpoint.
        let (status, tenant_a) = send_raw(
            state.clone(),
            request(
                Method::POST,
                "/v1/tenants",
                Some(json!({"name": "Encosto Estratégico A, Lda"})),
                &global_owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{tenant_a}");
        let tenant_a_id = tenant_a["id"].as_str().expect("tenant a id").to_owned();
        let (status, tenant_b) = send_raw(
            state.clone(),
            request(
                Method::POST,
                "/v1/tenants",
                Some(json!({"name": "Encosto Estratégico B, Lda"})),
                &global_owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{tenant_b}");
        let tenant_b_id = tenant_b["id"].as_str().expect("tenant b id").to_owned();

        // Owners rooted at exactly one tenant each.
        let scope_a = scope_of_tenant(TenantId(Uuid::parse_str(&tenant_a_id).unwrap()));
        let scope_b = scope_of_tenant(TenantId(Uuid::parse_str(&tenant_b_id).unwrap()));
        let owner_a = token_for_role_at(&state, "owner.a", OWNER_ROLE_ID, scope_a).await;
        let owner_b = token_for_role_at(&state, "owner.b", OWNER_ROLE_ID, scope_b).await;

        // Owner B creates an entity IN tenant B via POST /v1/entities.
        let (status, entity_b) = send_raw(
            state.clone(),
            request(
                Method::POST,
                "/v1/entities",
                Some(json!({
                    "name": "Empresa B, Lda",
                    "nipc": "B-0001",
                    "seat": "Porto",
                    "kind": "SociedadePorQuotas",
                    "allow_invalid_nipc": true,
                    "tenant_id": tenant_b_id,
                })),
                &owner_b,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{entity_b}");
        // The created entity carries tenant B's id — NOT the default tenant.
        assert_eq!(entity_b["tenant_id"], tenant_b_id);
        assert_ne!(
            entity_b["tenant_id"],
            chancela_core::DEFAULT_TENANT_ID.to_string(),
            "a second tenant's entity must not be stamped with the default tenant"
        );
        let entity_b_id = entity_b["id"].as_str().expect("entity b id").to_owned();

        // Owner B cannot create an entity in tenant A (cross-tenant write guard → 403, non-enumerating).
        let (status, _) = send_raw(
            state.clone(),
            request(
                Method::POST,
                "/v1/entities",
                Some(json!({
                    "name": "Intruso, Lda",
                    "nipc": "X-0001",
                    "seat": "Braga",
                    "kind": "SociedadePorQuotas",
                    "allow_invalid_nipc": true,
                    "tenant_id": tenant_a_id,
                })),
                &owner_b,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Owner A's entity list never shows tenant B's entity.
        let (status, list_a) = send_raw(
            state.clone(),
            request(Method::GET, "/v1/entities", None, &owner_a),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{list_a}");
        assert!(
            !list_a.to_string().contains(&entity_b_id),
            "tenant B's entity leaked into tenant A's list: {list_a}"
        );

        // Owner A reading tenant B's entity directly is a non-enumerating 403.
        let (status, _) = send_raw(
            state.clone(),
            request(
                Method::GET,
                &format!("/v1/entities/{entity_b_id}"),
                None,
                &owner_a,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Owner A's tenant list shows only tenant A (never B).
        let (status, tlist_a) = send_raw(
            state.clone(),
            request(Method::GET, "/v1/tenants", None, &owner_a),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{tlist_a}");
        let a_ids: Vec<&str> = tlist_a
            .as_array()
            .expect("array")
            .iter()
            .map(|row| row["id"].as_str().expect("id"))
            .collect();
        assert_eq!(
            a_ids,
            vec![tenant_a_id.as_str()],
            "owner A sees only tenant A"
        );

        // Control: the global owner sees both tenants and can read tenant B's entity.
        let (status, tlist_g) = send_raw(
            state.clone(),
            request(Method::GET, "/v1/tenants", None, &global_owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{tlist_g}");
        assert!(
            tlist_g.as_array().expect("array").len() >= 3,
            "default + A + B"
        );
        let (status, _) = send_raw(
            state,
            request(
                Method::GET,
                &format!("/v1/entities/{entity_b_id}"),
                None,
                &global_owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    /// **Authorize-path gate (wp27-e2).** The tenant collection is gated on the DEDICATED `Tenant*`
    /// verbs, not the entity verbs. A `Gestor` holds `entity.create` + `entity.read` at Global yet
    /// carries no tenant verb, so it is refused every tenant operation — proving the CRUD no longer
    /// rides on `EntityCreate`/`EntityRead`. A role holding only `tenant.read` may read/list but still
    /// cannot create, proving `tenant.create` is a distinct authority.
    #[tokio::test]
    async fn tenant_crud_requires_the_dedicated_tenant_permissions() {
        use chancela_authz::{COMPANY_OWNER_ROLE_ID, Permission, Role};

        let state = AppState::default();
        install_default_tenant(&state).await;
        let default_id = chancela_core::DEFAULT_TENANT_ID.to_string();

        // A Gestor at Global: has entity.create + entity.read, but NO tenant.* verb.
        let gestor =
            token_for_role_at(&state, "gestor", COMPANY_OWNER_ROLE_ID, Scope::Global).await;

        // create → 403 (lacks tenant.create, even though it holds entity.create).
        let (status, _) = send_raw(
            state.clone(),
            request(
                Method::POST,
                "/v1/tenants",
                Some(json!({"name": "Encosto Estratégico, Lda"})),
                &gestor,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "create must require tenant.create, not entity.create"
        );

        // get → 403 (lacks tenant.read, even though it holds entity.read).
        let (status, _) = send_raw(
            state.clone(),
            request(
                Method::GET,
                &format!("/v1/tenants/{default_id}"),
                None,
                &gestor,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "get must require tenant.read, not entity.read"
        );

        // list → 200 but EMPTY: the per-row `tenant.read` filter admits nothing for the Gestor.
        let (status, list) = send_raw(
            state.clone(),
            request(Method::GET, "/v1/tenants", None, &gestor),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        assert!(
            list.as_array().expect("array").is_empty(),
            "a caller without tenant.read must see no tenants: {list}"
        );

        // A custom role holding ONLY tenant.read at Global.
        let reader_role_id = RoleId(Uuid::new_v4());
        state.roles.write().await.insert(Role {
            id: reader_role_id,
            name: "Tenant Reader".to_owned(),
            permission_set: [Permission::TenantRead].into_iter().collect(),
            protected: false,
        });
        let reader = token_for_role_at(&state, "reader", reader_role_id, Scope::Global).await;

        // With tenant.read it now sees the default tenant on list…
        let (status, list) = send_raw(
            state.clone(),
            request(Method::GET, "/v1/tenants", None, &reader),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        assert!(
            list.as_array()
                .expect("array")
                .iter()
                .any(|row| row["id"] == default_id),
            "tenant.read holder must see the default tenant: {list}"
        );

        // …and can read it by id…
        let (status, _) = send_raw(
            state.clone(),
            request(
                Method::GET,
                &format!("/v1/tenants/{default_id}"),
                None,
                &reader,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // …but tenant.read alone does NOT grant creation (that needs tenant.create → 403).
        let (status, _) = send_raw(
            state,
            request(
                Method::POST,
                "/v1/tenants",
                Some(json!({"name": "Encosto Estratégico, Lda"})),
                &reader,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "tenant.read must not imply tenant.create"
        );
    }

    /// `create_entity` with no `tenant_id` in the body stays byte-identical to the pre-tenancy
    /// behaviour: the entity lands in the singleton default tenant (single-tenant deployments never
    /// have to name a tenant).
    #[tokio::test]
    async fn create_entity_without_tenant_id_defaults_to_the_default_tenant() {
        let state = AppState::default();
        let owner = token_for_role_at(&state, "amelia.marques", OWNER_ROLE_ID, Scope::Global).await;
        let (status, entity) = send_raw(
            state.clone(),
            request(
                Method::POST,
                "/v1/entities",
                Some(json!({
                    "name": "Encosto Estratégico, Lda",
                    "nipc": "503004642",
                    "seat": "Lisboa",
                    "kind": "SociedadePorQuotas",
                })),
                &owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{entity}");
        assert_eq!(
            entity["tenant_id"],
            chancela_core::DEFAULT_TENANT_ID.to_string()
        );
    }
}
