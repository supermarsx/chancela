//! Entity endpoints (contract §2.3) — unchanged from the scaffold, moved here for the
//! module split. Entities are the root object: books belong to an entity, acts to a book.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chancela_core::{Entity, EntityId, EntityKind, Nipc, StatuteOverrides};
use serde::Deserialize;
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::dto::EntityView;
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
}

/// Create an entity, record an `entity.created` ledger event, and return it with `201`.
pub async fn create_entity(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateEntity>,
) -> Result<(StatusCode, Json<EntityView>), ApiError> {
    // A parseable NIPC is always stored validated; the override only rescues a parse failure.
    let nipc = match Nipc::parse(&req.nipc) {
        Ok(nipc) => nipc,
        Err(_) if req.allow_invalid_nipc => Nipc::unvalidated(&req.nipc),
        Err(e) => return Err(e.into()),
    };
    let overridden = !nipc.is_validated();
    let entity = Entity::new(req.name, nipc, req.seat, req.kind);

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

/// List every entity currently in memory (unordered).
pub async fn list_entities(State(state): State<AppState>) -> Json<Vec<EntityView>> {
    let entities = state.entities.read().await;
    Json(entities.values().map(EntityView::from).collect())
}

/// Fetch one entity by id, or return `404`.
pub async fn get_entity(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<EntityView>, ApiError> {
    let entities = state.entities.read().await;
    entities
        .get(&EntityId(id))
        .map(|e| Json(EntityView::from(e)))
        .ok_or(ApiError::NotFound)
}
