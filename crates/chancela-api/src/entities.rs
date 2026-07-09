//! Entity endpoints (contract §2.3) — unchanged from the scaffold, moved here for the
//! module split. Entities are the root object: books belong to an entity, acts to a book.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chancela_authz::{Permission, Scope};
use chancela_core::{Entity, EntityId, EntityKind, Nipc, StatuteOverrides};
use serde::Deserialize;
use time::{Date, Month};
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{authorizer, require_permission, scope_of_entity};
use crate::dto::{EntityView, read_redaction_for_actor};
use crate::error::ApiError;

/// Justification recorded on the `entity.created` event when the NIPC-validation override stored
/// an unvalidated identifier (see [`create_entity`]). Frozen wording so the override is greppable
/// in the audit trail.
const NIPC_OVERRIDE_JUSTIFICATION: &str = "nipc validation overridden (stored unvalidated)";

/// Request body for `POST /v1/entities`.
///
/// The [`EntityId`] and [`chancela_core::EntityFamily`] are derived server-side (the family
/// from `kind`), so callers cannot forge an inconsistent entity.
#[derive(Deserialize)]
pub struct CreateEntity {
    name: String,
    /// Raw NIPC; validated (format + control digit) before the entity is built, unless
    /// `allow_invalid_nipc` is set and validation fails (see that field).
    nipc: String,
    seat: String,
    kind: EntityKind,
    /// NIPC-validation override. When `false` (the default) an invalid NIPC is rejected with
    /// `422`, exactly as before. When `true` **and** the NIPC fails [`Nipc::parse`], the raw
    /// identifier is stored [`unvalidated`](Nipc::unvalidated) and the entity is created anyway —
    /// for foreign entities, special registrations, or legacy data that legitimately lack a
    /// control-digit-valid PT NIPC. A NIPC that *does* parse is always stored validated, override
    /// or not.
    #[serde(default)]
    allow_invalid_nipc: bool,
    /// Fiscal year end as `MM-DD`, if recorded for the entity.
    fiscal_year_end: Option<String>,
}

/// Create an entity, record an `entity.created` ledger event, and return it with `201`.
pub async fn create_entity(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateEntity>,
) -> Result<(StatusCode, Json<EntityView>), ApiError> {
    // RBAC (t64-E3): creating an entity is a Global op (no entity exists yet to scope to).
    require_permission(&state, &actor, Permission::EntityCreate, Scope::Global).await?;
    // A parseable NIPC is always stored validated; the override only rescues a parse failure.
    let nipc = match Nipc::parse(&req.nipc) {
        Ok(nipc) => nipc,
        Err(_) if req.allow_invalid_nipc => Nipc::unvalidated(&req.nipc),
        Err(e) => return Err(e.into()),
    };
    let overridden = !nipc.is_validated();
    let fiscal_year_end = normalize_fiscal_year_end(req.fiscal_year_end)?;
    let mut entity = Entity::new(req.name, nipc, req.seat, req.kind);
    entity.fiscal_year_end = fiscal_year_end;

    // Digest the created entity into the audit chain before it becomes queryable, so the
    // ledger is the source of truth for "what happened" (DAT-10). The entity's own serialization
    // already carries `nipc.validated: false` for an override; the justification makes the
    // deliberate skip explicit and greppable in the audit trail.
    let payload = serde_json::to_vec(&entity)?;
    let justification = overridden.then_some(NIPC_OVERRIDE_JUSTIFICATION);
    let actor = actor.resolve("api");
    let scope = entity.id.to_string();
    {
        // Append the event and, when persistent, durably write the event + the new entity row in
        // one transaction. A store failure rolls back the append and returns 500 without mutating
        // the read model (below), so memory and disk never diverge.
        let mut ledger = state.ledger.write().await;
        ledger.append(&actor, &scope, "entity.created", justification, &payload);
        state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_entity(&entity))?;
        state.attest_latest(&attestor, &ledger).await;
    }

    let view = EntityView::from(&entity);
    state.entities.write().await.insert(entity.id, entity);
    Ok((StatusCode::CREATED, Json(view)))
}

/// Justification recorded on the `entity.statute_updated` event (ENT-03 audit trail). Frozen
/// wording so a statute-overlay edit is greppable in the ledger.
const STATUTE_UPDATE_JUSTIFICATION: &str = "entity statute overlay updated";

/// Request body for `PATCH /v1/entities/{id}`. Currently the statute overlay only (ENT-03); the
/// body is extendable. Uses [`double_option`](crate::dto::double_option) so an absent key leaves
/// the overlay untouched, an explicit `null` clears it, and an object sets it.
#[derive(Deserialize)]
pub struct PatchEntity {
    #[serde(default, deserialize_with = "crate::dto::double_option")]
    statute: Option<Option<StatuteOverrides>>,
    #[serde(default, deserialize_with = "crate::dto::double_option")]
    fiscal_year_end: Option<Option<String>>,
}

/// `PATCH /v1/entities/{id}` — edit the per-entity statute overlay (ENT-03), append an
/// `entity.statute_updated` ledger event, durably write the entity through, and return the
/// updated [`EntityView`]. `404` when the entity is unknown.
pub async fn patch_entity(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchEntity>,
) -> Result<Json<EntityView>, ApiError> {
    // RBAC (t64-E3): editing an entity is scoped to that entity.
    require_permission(
        &state,
        &actor,
        Permission::EntityUpdate,
        scope_of_entity(EntityId(id)),
    )
    .await?;
    let actor = actor.resolve("api");
    // entities → ledger (the global lock order); attestation sidecar acquired last.
    let mut entities = state.entities.write().await;
    let mut ledger = state.ledger.write().await;

    let entity = entities.get_mut(&EntityId(id)).ok_or(ApiError::NotFound)?;

    // Apply to a clone so the in-memory map is mutated only after the durable write commits (a
    // store failure rolls back the appended event and leaves the entity untouched).
    let mut next = entity.clone();
    if let Some(statute) = req.statute {
        next.statute = statute;
    }
    if let Some(fiscal_year_end) = req.fiscal_year_end {
        next.fiscal_year_end = normalize_fiscal_year_end(fiscal_year_end)?;
    }

    let scope = next.id.to_string();
    let payload = serde_json::to_vec(&next)?;
    ledger.append(
        &actor,
        &scope,
        "entity.statute_updated",
        Some(STATUTE_UPDATE_JUSTIFICATION),
        &payload,
    );
    state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_entity(&next))?;
    state.attest_latest(&attestor, &ledger).await;
    *entity = next;

    Ok(Json(EntityView::from(&*entity)))
}

pub(crate) fn normalize_fiscal_year_end(value: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    let Some((month, day)) = value.split_once('-') else {
        return Err(invalid_fiscal_year_end());
    };
    if month.len() != 2 || day.len() != 2 {
        return Err(invalid_fiscal_year_end());
    }
    let month = month.parse::<u8>().map_err(|_| invalid_fiscal_year_end())?;
    let day = day.parse::<u8>().map_err(|_| invalid_fiscal_year_end())?;
    let month = Month::try_from(month).map_err(|_| invalid_fiscal_year_end())?;
    Date::from_calendar_date(2000, month, day).map_err(|_| invalid_fiscal_year_end())?;
    let month_num = month as u8;
    Ok(Some(format!("{month_num:02}-{day:02}")))
}

fn invalid_fiscal_year_end() -> ApiError {
    ApiError::Unprocessable("fiscal_year_end must be MM-DD".to_owned())
}

/// List entities the caller may read (contract §2.3; RBAC list-filtering, plan §3.3 note²): requires
/// a valid session and returns only rows the caller holds `entity.read` at (a Global reader sees all;
/// an entity-scoped reader only their entity). No enumeration of unreadable rows — a caller with no
/// read authority gets an empty list, never a status that reveals what exists.
pub async fn list_entities(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<EntityView>>, ApiError> {
    let authz = crate::authz::authorizer(&state, &actor).await?;
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    let entities = state.entities.read().await;
    let out = entities
        .values()
        .filter(|e| authz.permits(Permission::EntityRead, scope_of_entity(e.id)))
        .map(|e| EntityView::build(e, redaction))
        .collect();
    Ok(Json(out))
}

/// Fetch one entity by id, or return `404`. RBAC (t64-E3): `entity.read` scoped to the entity.
pub async fn get_entity(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<EntityView>, ApiError> {
    let authz = authorizer(&state, &actor).await?;
    authz.require(Permission::EntityRead, scope_of_entity(EntityId(id)))?;
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    let entities = state.entities.read().await;
    entities
        .get(&EntityId(id))
        .map(|e| Json(EntityView::build(e, redaction)))
        .ok_or(ApiError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use chancela_authz::{
        GUEST_ROLE_ID, LEITOR_ROLE_ID, OWNER_ROLE_ID, RoleAssignment, RoleCatalog, RoleId, Scope,
    };
    use serde_json::{Value, json};
    use tower::ServiceExt;

    async fn send_raw(state: AppState, req: Request<Body>) -> (StatusCode, Value) {
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

    fn with_session(mut req: Request<Body>, token: &str) -> Request<Body> {
        req.headers_mut().insert(
            "x-chancela-session",
            token.parse().expect("valid session header"),
        );
        req
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request builds")
    }

    fn post_json(uri: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request builds")
    }

    async fn token_for_role(state: &AppState, username: &str, role_id: RoleId) -> String {
        use crate::users::{User, UserId};
        use time::format_description::well_known::Rfc3339;

        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
        }

        let uid = UserId(Uuid::new_v4());
        let user = User {
            id: uid,
            username: username.to_owned(),
            display_name: username.to_owned(),
            created_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: None,
            attestation_key: None,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(role_id, Scope::Global)],
        };
        state.users.write().await.insert(uid, user);

        let token = Uuid::new_v4().to_string();
        let now = time::OffsetDateTime::now_utc();
        state.sessions.write().await.insert(
            token.clone(),
            crate::session::SessionEntry {
                user_id: uid,
                unlocked_key: None,
                expires_at: now + time::Duration::seconds(crate::actor::SESSION_TTL_SECS),
            },
        );
        token
    }

    #[tokio::test]
    async fn guest_entity_redaction_hides_nipc_and_seat_while_leitor_keeps_them() {
        let state = AppState::default();
        let owner = token_for_role(&state, "owner", OWNER_ROLE_ID).await;
        let (status, created) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({
                        "name": "Encosto Estratégico, S.A.",
                        "nipc": "503004642",
                        "seat": "Rua da Liberdade, Lisboa",
                        "kind": "SociedadeAnonima",
                    }),
                ),
                &owner,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["id"].as_str().expect("entity id");

        let guest = token_for_role(&state, "guest", GUEST_ROLE_ID).await;
        let (status, guest_detail) = send_raw(
            state.clone(),
            with_session(get(&format!("/v1/entities/{id}")), &guest),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(guest_detail["nipc"], crate::dto::REDACTED);
        assert_eq!(guest_detail["nipc_validated"], false);
        assert_eq!(guest_detail["seat"], crate::dto::REDACTED);

        let (status, guest_list) =
            send_raw(state.clone(), with_session(get("/v1/entities"), &guest)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(guest_list[0]["nipc"], crate::dto::REDACTED);
        assert_eq!(guest_list[0]["seat"], crate::dto::REDACTED);

        let redacted = guest_list.to_string();
        assert!(!redacted.contains("503004642"), "NIPC leaked: {redacted}");
        assert!(
            !redacted.contains("Rua da Liberdade"),
            "seat leaked: {redacted}"
        );

        let leitor = token_for_role(&state, "leitor", LEITOR_ROLE_ID).await;
        let (status, reader_detail) = send_raw(
            state,
            with_session(get(&format!("/v1/entities/{id}")), &leitor),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reader_detail["nipc"], "503004642");
        assert_eq!(reader_detail["nipc_validated"], true);
        assert_eq!(reader_detail["seat"], "Rua da Liberdade, Lisboa");
    }
}
