//! Act (ata) endpoints (contract §2.5): draft, fetch, working-content PATCH, lifecycle
//! advance, compliance check, seal, and archive.
//!
//! Every mutating handler appends the matching ledger event — `act.drafted`, `act.advanced`,
//! `act.sealed` (via `seal_act`), `act.archived` — **except** PATCH, which edits working
//! state only: an act's payload is not frozen until sealing, so a draft edit is not itself an
//! auditable event (only the sealed content is). Multi-lock handlers follow the fixed global
//! order **entities → books → acts → ledger**.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chancela_core::{
    Act, ActError, ActId, BookId, Entity, EntityFamily, EntityKind, Severity, rule_pack_for,
    seal_act,
};
use uuid::Uuid;

use chancela_authz::Permission;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{require_permission, scope_of_act, scope_of_book};
use crate::dto::{
    ActView, AdvanceAct, ArchiveAct, ComplianceResponse, ConveningAdvisory, DispatchConvening,
    DraftAct, IssueView, PatchAct, SealAct, SealResponse,
};
use crate::error::ApiError;

/// `POST /v1/acts` — draft a new ata inside an open book (WFL-14).
pub async fn draft_act(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<DraftAct>,
) -> Result<(StatusCode, Json<ActView>), ApiError> {
    let book_id = BookId(req.book_id);
    // RBAC (t64-E3): drafting an act is scoped to the target book (resolved from the body).
    require_permission(&state, &actor, Permission::ActDraft, scope_of_book(book_id)).await?;
    let actor = actor.resolve(&req.actor);
    // books → acts → ledger.
    let books = state.books.read().await;
    let book = books.get(&book_id).ok_or(ApiError::NotFound)?;
    if !book.is_open() {
        return Err(ApiError::Conflict(format!(
            "book {book_id} is not open; acts may only be drafted in an open book"
        )));
    }
    let entity_id = book.entity_id;

    let mut acts = state.acts.write().await;
    let mut ledger = state.ledger.write().await;

    let mut act = Act::draft(book_id, req.title, req.channel);
    if let Some(r) = req.retifies {
        act.retifies = Some(ActId(r));
    }

    let scope = format!("entity:{}/book:{}/act:{}", entity_id, act.book_id, act.id);
    let payload = serde_json::to_vec(&act)?;
    // Validating append (t54): reject a chain-breaking append before mutating the ledger.
    crate::try_append_event(&mut ledger, &actor, &scope, "act.drafted", None, &payload)?;
    state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_act(&act))?;
    state.attest_latest(&attestor, &ledger).await;

    let view = ActView::from(&act);
    acts.insert(act.id, act);
    Ok((StatusCode::CREATED, Json(view)))
}

/// `GET /v1/acts/{id}` — one act, or `404`.
pub async fn get_act(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<ActView>, ApiError> {
    // RBAC (t64-E3): `act.read` scoped to the act's owning book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::ActRead, scope).await?;
    let acts = state.acts.read().await;
    acts.get(&ActId(id))
        .map(|a| Json(ActView::from(a)))
        .ok_or(ApiError::NotFound)
}

/// `PATCH /v1/acts/{id}` — update working content. Appends **no** ledger event: the payload
/// is frozen only at sealing, so pre-seal edits are working state, not auditable events.
pub async fn patch_act(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    Json(req): Json<PatchAct>,
) -> Result<Json<ActView>, ApiError> {
    // RBAC (t64-E3): editing an act's working content is `act.edit` scoped to its book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::ActEdit, scope).await?;
    let mut acts = state.acts.write().await;
    let act = acts.get_mut(&ActId(id)).ok_or(ApiError::NotFound)?;

    // Reject edits to a sealed/archived act (maps ActError::Sealed → 409).
    if !act.is_mutable() {
        return Err(ApiError::Conflict(ActError::Sealed.to_string()));
    }

    if let Some(title) = req.title {
        act.title = title;
    }
    if let Some(channel) = req.channel {
        act.channel = channel;
    }
    if let Some(meeting_date) = req.meeting_date {
        act.meeting_date = match meeting_date {
            Some(s) => Some(crate::dto::parse_date(&s)?),
            None => None,
        };
    }
    if let Some(meeting_time) = req.meeting_time {
        act.meeting_time = match meeting_time {
            Some(s) => Some(crate::dto::parse_time(&s)?),
            None => None,
        };
    }
    if let Some(place) = req.place {
        act.place = place;
    }
    if let Some(mesa) = req.mesa {
        act.mesa = mesa.into();
    }
    if let Some(agenda) = req.agenda {
        act.agenda = agenda.into_iter().map(Into::into).collect();
    }
    if let Some(attendance_reference) = req.attendance_reference {
        act.attendance_reference = attendance_reference;
    }
    if let Some(members_present) = req.members_present {
        act.members_present = members_present;
    }
    if let Some(members_represented) = req.members_represented {
        act.members_represented = members_represented;
    }
    if let Some(referenced_documents) = req.referenced_documents {
        act.referenced_documents = referenced_documents.into_iter().map(Into::into).collect();
    }
    if let Some(deliberations) = req.deliberations {
        act.deliberations = deliberations;
    }
    if let Some(deliberation_items) = req.deliberation_items {
        act.deliberation_items = deliberation_items.into_iter().map(Into::into).collect();
    }
    if let Some(telematic_evidence) = req.telematic_evidence {
        act.telematic_evidence = telematic_evidence;
    }
    if let Some(attachments) = req.attachments {
        let mut converted = Vec::with_capacity(attachments.len());
        for a in attachments {
            converted.push(a.into_core()?);
        }
        act.attachments = converted;
    }
    if let Some(signatories) = req.signatories {
        act.signatories = signatories.into_iter().map(Into::into).collect();
    }
    // G1 convening (double_option): absent ⇒ leave, explicit null ⇒ clear, value ⇒ replace. Parsing
    // (into_core) validates dates before any mutation (a malformed date ⇒ 422, act untouched).
    if let Some(convening) = req.convening {
        act.convening = match convening {
            Some(c) => Some(c.into_core()?),
            None => None,
        };
    }
    // G2 attendance (replace-when-present, [] clears). Convert first so a validation failure
    // (permilage/proxy ⇒ 422) leaves the act untouched.
    if let Some(attendees) = req.attendees {
        let mut converted = Vec::with_capacity(attendees.len());
        for a in attendees {
            converted.push(a.into_core()?);
        }
        act.attendees = converted;
    }

    Ok(Json(ActView::from(&*act)))
}

/// `POST /v1/acts/{id}/advance` — one forward lifecycle step (Draft→…→Signing).
pub async fn advance_act(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<AdvanceAct>,
) -> Result<Json<ActView>, ApiError> {
    // RBAC (t64-E3): advancing an act is `act.advance` scoped to its book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::ActAdvance, scope).await?;
    let actor = actor.resolve(&req.actor);
    // books → acts → ledger (books only to resolve the entity id for the event scope).
    let books = state.books.read().await;
    let mut acts = state.acts.write().await;
    let mut ledger = state.ledger.write().await;

    let act = acts.get_mut(&ActId(id)).ok_or(ApiError::NotFound)?;
    let entity_id = books.get(&act.book_id).map(|b| b.entity_id);

    // Apply the transition to a clone, so the in-memory map is only mutated after the durable write
    // succeeds (nothing to roll back on a store failure). Invalid transition → 422 (contract §2.5).
    let mut next = act.clone();
    next.advance_to(req.to)
        .map_err(|e| ApiError::Unprocessable(e.to_string()))?;

    let scope = match entity_id {
        Some(eid) => format!("entity:{}/book:{}/act:{}", eid, next.book_id, next.id),
        None => format!("book:{}/act:{}", next.book_id, next.id),
    };
    let justification = format!("advance to {:?}", req.to);
    let payload = serde_json::to_vec(&next)?;
    crate::try_append_event(
        &mut ledger,
        &actor,
        &scope,
        "act.advanced",
        Some(&justification),
        &payload,
    )?;
    state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_act(&next))?;
    state.attest_latest(&attestor, &ledger).await;
    *act = next;

    Ok(Json(ActView::from(&*act)))
}

/// `GET /v1/acts/{id}/compliance` — run the CSC art. 63.º rule pack against the act.
pub async fn get_compliance(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<ComplianceResponse>, ApiError> {
    // RBAC (t64-E3): the compliance report is `act.read` scoped to the act's book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::ActRead, scope).await?;
    // entities → books → acts.
    let entities = state.entities.read().await;
    let books = state.books.read().await;
    let acts = state.acts.read().await;

    let act = acts.get(&ActId(id)).ok_or(ApiError::NotFound)?;
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;

    // Per-family dispatch (R4 / LEG-02): the rule pack is selected from the entity's profile
    // (family baseline + statute overlay), not a hardcoded CSC pack.
    let pack = rule_pack_for(entity);
    let issues = pack.check_act(act, entity);
    let errors = issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .count() as u32;
    let warnings = issues
        .iter()
        .filter(|i| i.severity == Severity::Warning)
        .count() as u32;
    let seal_allowed = errors == 0 && act.state == chancela_core::ActState::Signing;

    Ok(Json(ComplianceResponse {
        rule_pack: pack.id().to_owned(),
        family: entity.family,
        statute_overlay: entity.statute.is_some(),
        issues: issues.iter().map(IssueView::from).collect(),
        errors,
        warnings,
        seal_allowed,
        convening_advisories: convening_advisories_for(entity, act),
    }))
}

/// The statutory-antecedence threshold id for an entity, or `None` for families whose convening
/// regime is a `Clause` (Association / Foundation) rather than a numeric day-count — those get no
/// numeric antecedence advisory (t61-E1, plan §3). CSC splits SA vs. quotas by [`EntityKind`].
fn antecedence_threshold_id(entity: &Entity) -> Option<&'static str> {
    match entity.family {
        EntityFamily::CommercialCompany => Some(match entity.kind {
            EntityKind::SociedadeAnonima | EntityKind::SociedadeEmComanditaPorAcoes => {
                "csc.sa.convocatoria.antecedencia_dias"
            }
            _ => "csc.quotas.convocatoria.antecedencia_dias",
        }),
        EntityFamily::Condominium => Some("condominio.convocatoria.antecedencia_dias"),
        EntityFamily::Cooperative => Some("cooperativa.convocatoria.antecedencia_dias"),
        // Clause regimes (no numeric antecedence to compare against).
        EntityFamily::Association | EntityFamily::Foundation => None,
    }
}

/// Compute the convening-antecedence advisories for an act. Empty unless the act carries a
/// convening, the family has a numeric threshold, that threshold is *resolved* to `Days(min)`, and
/// the actual antecedence is below it. **Never blocks** (advisory only).
fn convening_advisories_for(entity: &Entity, act: &Act) -> Vec<ConveningAdvisory> {
    let Some(convening) = &act.convening else {
        return Vec::new();
    };
    let Some(threshold_id) = antecedence_threshold_id(entity) else {
        return Vec::new();
    };
    // The resolved minimum, or `None` while the threshold is `[a definir]` (dormant).
    let minimum_days = match chancela_templates::find_threshold(threshold_id).and_then(|t| t.value)
    {
        Some(chancela_templates::ThresholdValue::Days(n)) => Some(n),
        _ => None,
    };
    antecedence_advisory(threshold_id, minimum_days, convening.antecedence_days)
        .into_iter()
        .collect()
}

/// Pure antecedence check (unit-testable without the global registry): a `Warning` iff both the
/// statutory `minimum_days` is resolved AND the `actual_days` given is strictly below it. Any `None`
/// (dormant threshold or no actual antecedence recorded) yields no advisory.
fn antecedence_advisory(
    threshold_id: &str,
    minimum_days: Option<u16>,
    actual_days: Option<u16>,
) -> Option<ConveningAdvisory> {
    let minimum = minimum_days?;
    let actual = actual_days?;
    if actual >= minimum {
        return None;
    }
    Some(ConveningAdvisory {
        code: "convening.antecedence.below_minimum".to_owned(),
        severity: "Warning".to_owned(),
        message: format!(
            "A antecedência da convocatória ({actual} dias) é inferior à antecedência mínima \
             legal ({minimum} dias)."
        ),
        threshold_id: threshold_id.to_owned(),
        actual_days: Some(actual),
        minimum_days: Some(minimum),
    })
}

/// `POST /v1/acts/{id}/seal` — compliance-gated seal (WFL-20). On refusal the compliance
/// variants return structured `issues`/`warnings` (contract §2.5).
pub async fn seal_act_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Option<Json<SealAct>>,
) -> Result<Response, ApiError> {
    // RBAC (t64-E3): sealing an act requires `signing.perform` scoped to its book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let actor = actor.resolve(&req.actor);

    // entities → books → acts → ledger (the full order; seal touches all four).
    let entities = state.entities.read().await;
    let mut books = state.books.write().await;
    let mut acts = state.acts.write().await;
    let mut ledger = state.ledger.write().await;

    let act = acts.get_mut(&ActId(id)).ok_or(ApiError::NotFound)?;
    let book = books.get_mut(&act.book_id).ok_or(ApiError::NotFound)?;
    let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;

    // Per-family dispatch (R4): seal against the pack selected from the entity's profile.
    let pack = rule_pack_for(entity);

    // Seal against clones so the read model is mutated only after the durable write commits. A store
    // failure rolls back the appended `act.sealed` event and leaves the maps untouched (a failed
    // seal never touches the ledger, so the error paths below see the original act/book).
    let mut book_next = book.clone();
    let mut act_next = act.clone();
    match seal_act(
        &mut book_next,
        &mut act_next,
        entity,
        &*pack,
        &actor,
        req.acknowledge_warnings,
        &mut ledger,
    ) {
        Ok(outcome) => {
            // The dispatched pack (`Box<dyn RulePack>`, not `Send`) is not needed past here; drop
            // it before the `.await` below so the handler future stays `Send` (axum's bound).
            drop(pack);

            // Document production (t48 / D4): render the sealed ata → PDF/A-2u → persist the row +
            // a `document.generated` event **inside the SAME durable commit** as `act.sealed`. A
            // render/write failure rolls the just-appended `act.sealed` event back out of the
            // in-memory ledger so a failed seal leaves no trace (the seal transaction is atomic).
            // A family without a template yet yields `None`: the seal proceeds without a document
            // (documented fallback), never blocking the seal.
            let generated = match crate::documents::generate_for_act(
                &act_next,
                entity,
                req.template_id.as_deref(),
            ) {
                Ok(g) => g,
                Err(e) => {
                    AppState::rollback_ledger_events(&mut ledger, 1);
                    return Err(e);
                }
            };

            let document = match generated {
                Some(made) => {
                    // Bind the document into the tamper-evident chain (TPL-02 / §3.4) and persist
                    // it with the sealed act + book counter in one commit (event_count = 2).
                    let scope = format!(
                        "entity:{}/book:{}/act:{}",
                        entity.id, act_next.book_id, act_next.id
                    );
                    let payload = serde_json::to_vec(&made.event_payload)?;
                    // Validating append (t54); a rejection rolls back the just-appended `act.sealed`
                    // (core) event so a failed seal leaves no trace (the seal transaction is atomic).
                    if let Err(e) = crate::try_append_event(
                        &mut ledger,
                        &actor,
                        &scope,
                        "document.generated",
                        None,
                        &payload,
                    ) {
                        AppState::rollback_ledger_events(&mut ledger, 1);
                        return Err(e);
                    }
                    state.persist_write_through(&mut ledger, 2, |tx| {
                        tx.upsert_book(&book_next)?;
                        tx.upsert_act(&act_next)?;
                        tx.upsert_document(&made.stored)
                    })?;
                    // Publish to the live document read model (GET source; store is durability).
                    state
                        .documents
                        .write()
                        .await
                        .insert(act_next.id, made.stored.clone());
                    Some(crate::dto::SealDocument {
                        id: made.stored.id,
                        pdf_digest: made.stored.pdf_digest,
                        template_id: made.stored.template_id,
                    })
                }
                None => {
                    // No template bound for this family yet — persist the seal as before (1 event).
                    state.persist_write_through(&mut ledger, 1, |tx| {
                        tx.upsert_book(&book_next)?;
                        tx.upsert_act(&act_next)
                    })?;
                    None
                }
            };

            state.attest_latest(&attestor, &ledger).await;
            *book = book_next;
            *act = act_next;
            let resp = SealResponse {
                act: ActView::from(&*act),
                ata_number: outcome.ata_number,
                event_seq: outcome.event_seq,
                payload_digest: crate::hex::hex(&outcome.payload_digest),
                acknowledged_warnings: outcome
                    .acknowledged_warnings
                    .iter()
                    .map(IssueView::from)
                    .collect(),
                document,
            };
            Ok((StatusCode::OK, Json(resp)).into_response())
        }
        // Re-run the dispatched pack to surface the structured blocking issues (all Error severity).
        Err(chancela_core::SealError::ComplianceBlocked(message)) => {
            let issues = pack
                .check_act(act, entity)
                .iter()
                .filter(|i| i.severity == Severity::Error)
                .map(IssueView::from)
                .collect();
            Err(ApiError::ComplianceBlocked { message, issues })
        }
        Err(chancela_core::SealError::WarningsNotAcknowledged(message)) => {
            let warnings = pack
                .check_act(act, entity)
                .iter()
                .filter(|i| i.severity == Severity::Warning)
                .map(IssueView::from)
                .collect();
            Err(ApiError::WarningsNotAcknowledged { message, warnings })
        }
        // Wrong book / not-Signing → 409; serialize failure → 500 (via From<SealError>).
        Err(other) => Err(other.into()),
    }
}

/// `POST /v1/acts/{id}/archive` — archive a sealed act (Sealed→Archived).
pub async fn archive_act(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Option<Json<ArchiveAct>>,
) -> Result<Json<ActView>, ApiError> {
    // RBAC (t64-E3): archiving an act is `act.archive` scoped to its book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::ActArchive, scope).await?;
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let actor = actor.resolve(&req.actor);

    // books → acts → ledger (books only to resolve the entity id for the event scope).
    let books = state.books.read().await;
    let mut acts = state.acts.write().await;
    let mut ledger = state.ledger.write().await;

    let act = acts.get_mut(&ActId(id)).ok_or(ApiError::NotFound)?;
    let entity_id = books.get(&act.book_id).map(|b| b.entity_id);

    // Archive a clone (Sealed→Archived), committing to the map only after the durable write. Only a
    // sealed act can be archived, else 409.
    let mut next = act.clone();
    next.archive()
        .map_err(|e| ApiError::Conflict(e.to_string()))?;

    let scope = match entity_id {
        Some(eid) => format!("entity:{}/book:{}/act:{}", eid, next.book_id, next.id),
        None => format!("book:{}/act:{}", next.book_id, next.id),
    };
    let payload = serde_json::to_vec(&next)?;
    crate::try_append_event(&mut ledger, &actor, &scope, "act.archived", None, &payload)?;
    state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_act(&next))?;
    state.attest_latest(&attestor, &ledger).await;
    *act = next;

    Ok(Json(ActView::from(&*act)))
}

/// `POST /v1/acts/{id}/convening/dispatch` — record that the convening notice was dispatched
/// (t61-E1). Stamps `dispatched_at` (+ optional `channel`/`reference`) on the matching
/// `convening.recipients` and appends a chained `convening.dispatched` ledger event — unlike a draft
/// PATCH, dispatch is a real evidentiary action, so it IS auditable. Honest scope: this records the
/// operator's assertion that the notice was sent; the actual sending stays external/manual.
///
/// `404` unknown act · `409` sealed/immutable act · `422` no convening, no recipients (or none
/// matching the requested names), or a malformed `dispatched_at`.
pub async fn convening_dispatch(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<DispatchConvening>,
) -> Result<Json<ActView>, ApiError> {
    // RBAC (t61-E1): stamping dispatch is an act write, gated at the act's owning book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::ActEdit, scope).await?;
    let actor = actor.resolve(&req.actor);
    let dispatched_at = crate::dto::parse_date(&req.dispatched_at)?;

    // books → acts → ledger (books only to resolve the entity id for the event scope).
    let books = state.books.read().await;
    let mut acts = state.acts.write().await;
    let mut ledger = state.ledger.write().await;

    let act = acts.get_mut(&ActId(id)).ok_or(ApiError::NotFound)?;
    // A sealed/archived act's convening is frozen (maps ActError::Sealed → 409).
    if !act.is_mutable() {
        return Err(ApiError::Conflict(ActError::Sealed.to_string()));
    }
    let entity_id = books.get(&act.book_id).map(|b| b.entity_id);

    // Stamp a clone; commit to the map only after the durable write succeeds.
    let mut next = act.clone();
    let convening = next
        .convening
        .as_mut()
        .ok_or_else(|| ApiError::Unprocessable("act has no convening to dispatch".to_owned()))?;
    if convening.recipients.is_empty() {
        return Err(ApiError::Unprocessable(
            "convening has no recipients to dispatch".to_owned(),
        ));
    }
    // A name filter selects a subset; omitted ⇒ every recipient is stamped.
    let mut stamped = 0u32;
    for recipient in convening.recipients.iter_mut() {
        let selected = match &req.recipients {
            Some(names) => names.iter().any(|n| n == &recipient.name),
            None => true,
        };
        if !selected {
            continue;
        }
        recipient.dispatched_at = Some(dispatched_at);
        if req.channel.is_some() {
            recipient.channel = req.channel;
        }
        if req.reference.is_some() {
            recipient.reference = req.reference.clone();
        }
        stamped += 1;
    }
    if stamped == 0 {
        return Err(ApiError::Unprocessable(
            "no matching recipients to dispatch".to_owned(),
        ));
    }

    let scope = match entity_id {
        Some(eid) => format!("entity:{}/book:{}/act:{}", eid, next.book_id, next.id),
        None => format!("book:{}/act:{}", next.book_id, next.id),
    };
    let justification = format!("convening dispatched to {stamped} recipient(s)");
    let payload = serde_json::to_vec(&next)?;
    crate::try_append_event(
        &mut ledger,
        &actor,
        &scope,
        "convening.dispatched",
        Some(&justification),
        &payload,
    )?;
    state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_act(&next))?;
    state.attest_latest(&attestor, &ledger).await;
    *act = next;

    Ok(Json(ActView::from(&*act)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chancela_core::Nipc;

    fn entity_of(kind: EntityKind) -> Entity {
        Entity::new(
            "Encosto Estratégico Lda",
            Nipc::parse("503004642").expect("valid NIPC"),
            "Rua das Amoreiras, n.º 12, 1250-020 Lisboa",
            kind,
        )
    }

    /// The pure antecedence check: a Warning only when a resolved minimum is strictly above the
    /// actual antecedence; dormant (None) when the threshold is `[a definir]` or no actual is given.
    #[test]
    fn antecedence_advisory_warns_only_below_a_resolved_minimum() {
        // Resolved minimum, actual below ⇒ a Warning carrying both day-counts.
        let warn =
            antecedence_advisory("csc.sa.convocatoria.antecedencia_dias", Some(21), Some(10))
                .expect("warns below the minimum");
        assert_eq!(warn.severity, "Warning");
        assert_eq!(warn.actual_days, Some(10));
        assert_eq!(warn.minimum_days, Some(21));
        assert_eq!(warn.threshold_id, "csc.sa.convocatoria.antecedencia_dias");
        assert_eq!(warn.code, "convening.antecedence.below_minimum");

        // Actual meets/exceeds the minimum ⇒ no advisory.
        assert!(antecedence_advisory("x", Some(21), Some(21)).is_none());
        assert!(antecedence_advisory("x", Some(21), Some(30)).is_none());
        // Dormant threshold ([a definir]: value None) ⇒ no advisory even with a short actual.
        assert!(antecedence_advisory("x", None, Some(1)).is_none());
        // No actual antecedence recorded ⇒ nothing to compare.
        assert!(antecedence_advisory("x", Some(21), None).is_none());
    }

    /// Family → numeric-threshold mapping: CSC splits SA/quotas by kind; condominium + cooperative
    /// have a numeric threshold; association + foundation are Clause regimes (no numeric check).
    #[test]
    fn threshold_id_maps_families_and_skips_clause_regimes() {
        assert_eq!(
            antecedence_threshold_id(&entity_of(EntityKind::SociedadeAnonima)),
            Some("csc.sa.convocatoria.antecedencia_dias")
        );
        assert_eq!(
            antecedence_threshold_id(&entity_of(EntityKind::SociedadePorQuotas)),
            Some("csc.quotas.convocatoria.antecedencia_dias")
        );
        assert_eq!(
            antecedence_threshold_id(&entity_of(EntityKind::Condominio)),
            Some("condominio.convocatoria.antecedencia_dias")
        );
        assert_eq!(
            antecedence_threshold_id(&entity_of(EntityKind::Cooperativa)),
            Some("cooperativa.convocatoria.antecedencia_dias")
        );
        // Clause regimes → no numeric antecedence advisory.
        assert_eq!(
            antecedence_threshold_id(&entity_of(EntityKind::Associacao)),
            None
        );
        assert_eq!(
            antecedence_threshold_id(&entity_of(EntityKind::Fundacao)),
            None
        );
    }

    /// The registry ships every convocatória-antecedence threshold as `[a definir]` (value None), so
    /// the advisory is **dormant** in production: even a 1-day antecedence produces no warning until a
    /// lawyer resolves the value. This locks the honest-disclosure contract (plan D3 / risk 3).
    #[test]
    fn advisory_is_dormant_while_the_threshold_is_a_definir() {
        let mut act = Act::draft(
            BookId(uuid::Uuid::nil()),
            "Ata",
            chancela_core::MeetingChannel::Physical,
        );
        act.convening = Some(chancela_core::Convening {
            antecedence_days: Some(1),
            ..Default::default()
        });
        for kind in [
            EntityKind::SociedadeAnonima,
            EntityKind::SociedadePorQuotas,
            EntityKind::Condominio,
            EntityKind::Cooperativa,
        ] {
            assert!(
                convening_advisories_for(&entity_of(kind), &act).is_empty(),
                "{kind:?}: advisory must stay dormant while the threshold is [a definir]"
            );
        }
    }
}
