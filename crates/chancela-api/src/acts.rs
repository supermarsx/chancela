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
    Act, ActError, ActId, Book, BookId, Entity, EntityFamily, EntityKind, Severity, rule_pack_for,
    seal_act,
};
use uuid::Uuid;

use chancela_authz::Permission;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{require_permission, scope_of_act, scope_of_book};
use crate::dto::{
    ActView, AdvanceAct, ArchiveAct, ComplianceResponse, ConveningAdvisory, DispatchConvening,
    DraftAct, IssueView, PatchAct, SealAct, SealResponse, read_redaction_for_actor,
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
    if let Some(convening) = req.convening {
        act.convening = Some(convening.into_core()?);
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
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    let acts = state.acts.read().await;
    acts.get(&ActId(id))
        .map(|a| Json(ActView::build(a, redaction)))
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
    // books -> acts. A closed/non-open book freezes all existing acts in it too.
    let books = state.books.read().await;
    let mut acts = state.acts.write().await;
    let act = acts.get_mut(&ActId(id)).ok_or(ApiError::NotFound)?;
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    ensure_book_open_for_act_mutation(book)?;

    // Reject edits to a sealed/archived act (maps ActError::Sealed → 409).
    if !act.is_mutable() {
        return Err(ApiError::Conflict(ActError::Sealed.to_string()));
    }

    let mut next = act.clone();
    if let Some(title) = req.title {
        next.title = title;
    }
    if let Some(channel) = req.channel {
        next.channel = channel;
    }
    if let Some(meeting_date) = req.meeting_date {
        next.meeting_date = match meeting_date {
            Some(s) => Some(crate::dto::parse_date(&s)?),
            None => None,
        };
    }
    if let Some(meeting_time) = req.meeting_time {
        next.meeting_time = match meeting_time {
            Some(s) => Some(crate::dto::parse_time(&s)?),
            None => None,
        };
    }
    if let Some(place) = req.place {
        next.place = place;
    }
    if let Some(mesa) = req.mesa {
        next.mesa = mesa.into();
    }
    if let Some(agenda) = req.agenda {
        next.agenda = agenda.into_iter().map(Into::into).collect();
    }
    if let Some(attendance_reference) = req.attendance_reference {
        next.attendance_reference = attendance_reference;
    }
    if let Some(members_present) = req.members_present {
        next.members_present = members_present;
    }
    if let Some(members_represented) = req.members_represented {
        next.members_represented = members_represented;
    }
    if let Some(referenced_documents) = req.referenced_documents {
        next.referenced_documents = referenced_documents.into_iter().map(Into::into).collect();
    }
    if let Some(deliberations) = req.deliberations {
        next.deliberations = deliberations;
    }
    if let Some(deliberation_items) = req.deliberation_items {
        next.deliberation_items = deliberation_items.into_iter().map(Into::into).collect();
    }
    if let Some(telematic_evidence) = req.telematic_evidence {
        next.telematic_evidence = telematic_evidence;
    }
    if let Some(attachments) = req.attachments {
        let mut converted = Vec::with_capacity(attachments.len());
        for a in attachments {
            converted.push(a.into_core()?);
        }
        next.attachments = converted;
    }
    if let Some(signatories) = req.signatories {
        let mut converted = Vec::with_capacity(signatories.len());
        for signatory in signatories {
            if let Some(p @ 1001..) = signatory.permilage {
                return Err(ApiError::Unprocessable(format!(
                    "signatory {:?}: permilage {p} exceeds 1000",
                    signatory.name
                )));
            }
            converted.push(signatory.into_core()?);
        }
        next.signatories = converted;
    }
    // G1 convening (double_option): absent ⇒ leave, explicit null ⇒ clear, value ⇒ replace. Parsing
    // (into_core) validates dates before any mutation (a malformed date ⇒ 422, act untouched).
    if let Some(convening) = req.convening {
        next.convening = match convening {
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
        next.attendees = converted;
    }

    if let Some(store) = &state.store {
        store.persist(|tx| tx.upsert_act(&next)).map_err(|e| {
            ApiError::Internal(format!("failed to persist to the durable store: {e}"))
        })?;
    }
    *act = next;

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
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    ensure_book_open_for_act_mutation(book)?;
    let entity_id = book.entity_id;

    // Apply the transition to a clone, so the in-memory map is only mutated after the durable write
    // succeeds (nothing to roll back on a store failure). Invalid transition → 422 (contract §2.5).
    let mut next = act.clone();
    next.advance_to(req.to)
        .map_err(|e| ApiError::Unprocessable(e.to_string()))?;

    let scope = format!("entity:{}/book:{}/act:{}", entity_id, next.book_id, next.id);
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

const STATUTE_NOTICE_THRESHOLD_ID: &str = "entity.statute.convocation_notice_days";

/// Compute the convening-antecedence advisories for an act. Statute notice advisories fire when
/// the entity has a recorded statute minimum and the act's actual notice is below it or missing.
/// The family-threshold path stays dormant unless its legal threshold is resolved. **Never blocks**
/// (advisory only).
fn convening_advisories_for(entity: &Entity, act: &Act) -> Vec<ConveningAdvisory> {
    let actual_days = act.convening.as_ref().and_then(|c| c.antecedence_days);
    let mut advisories = Vec::new();

    if let Some(minimum_days) = entity
        .statute
        .as_ref()
        .and_then(|statute| statute.convocation_notice_days)
    {
        if let Some(advisory) = statute_notice_advisory(minimum_days, actual_days) {
            advisories.push(advisory);
        }
    }

    let Some(convening) = &act.convening else {
        return advisories;
    };
    let Some(threshold_id) = antecedence_threshold_id(entity) else {
        return advisories;
    };
    // The resolved minimum, or `None` while the threshold is `[a definir]` (dormant).
    let minimum_days = match chancela_templates::find_threshold(threshold_id).and_then(|t| t.value)
    {
        Some(chancela_templates::ThresholdValue::Days(n)) => Some(n),
        _ => None,
    };
    advisories.extend(antecedence_advisory(
        threshold_id,
        minimum_days,
        convening.antecedence_days,
    ));
    advisories
}

/// Statute notice advisory: a Warning when the recorded statute minimum cannot be verified from
/// the act, or when the captured actual notice is below that minimum. Advisory only.
fn statute_notice_advisory(
    minimum_days: u16,
    actual_days: Option<u16>,
) -> Option<ConveningAdvisory> {
    match actual_days {
        Some(actual) if actual >= minimum_days => None,
        Some(actual) => Some(ConveningAdvisory {
            code: "convening.statute_notice.below_minimum".to_owned(),
            severity: "Warning".to_owned(),
            message: format!(
                "Os estatutos registados exigem convocatória com pelo menos {minimum_days} dias \
                 de antecedência; a ata regista {actual} dias. Aviso não bloqueante."
            ),
            threshold_id: STATUTE_NOTICE_THRESHOLD_ID.to_owned(),
            actual_days: Some(actual),
            minimum_days: Some(minimum_days),
        }),
        None => Some(ConveningAdvisory {
            code: "convening.statute_notice.missing_actual".to_owned(),
            severity: "Warning".to_owned(),
            message: format!(
                "Os estatutos registados exigem convocatória com pelo menos {minimum_days} dias \
                 de antecedência, mas a ata não regista a antecedência efetiva. Confirme \
                 manualmente. Aviso não bloqueante."
            ),
            threshold_id: STATUTE_NOTICE_THRESHOLD_ID.to_owned(),
            actual_days: None,
            minimum_days: Some(minimum_days),
        }),
    }
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
    ensure_book_open_for_act_mutation(book)?;
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
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    ensure_book_open_for_act_mutation(book)?;
    let entity_id = book.entity_id;

    // Archive a clone (Sealed→Archived), committing to the map only after the durable write. Only a
    // sealed act can be archived, else 409.
    let mut next = act.clone();
    next.archive()
        .map_err(|e| ApiError::Conflict(e.to_string()))?;

    let scope = format!("entity:{}/book:{}/act:{}", entity_id, next.book_id, next.id);
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
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    ensure_book_open_for_act_mutation(book)?;
    // A sealed/archived act's convening is frozen (maps ActError::Sealed → 409).
    if !act.is_mutable() {
        return Err(ApiError::Conflict(ActError::Sealed.to_string()));
    }
    let entity_id = book.entity_id;

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

    let scope = format!("entity:{}/book:{}/act:{}", entity_id, next.book_id, next.id);
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

fn ensure_book_open_for_act_mutation(book: &Book) -> Result<(), ApiError> {
    if book.is_open() {
        return Ok(());
    }
    Err(ApiError::Conflict(format!(
        "book {} is {:?}; acts in a non-open book are read-only",
        book.id, book.state
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path as FsPath, PathBuf};

    use axum::extract::State;
    use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, Scope};
    use chancela_core::{Book, BookKind, MeetingChannel, Nipc};
    use serde_json::json;
    use time::format_description::well_known::Rfc3339;

    use crate::users::{User, UserId};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("chancela-api-acts-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("temp dir created");
            TempDir { path }
        }

        fn path(&self) -> &FsPath {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn entity_of(kind: EntityKind) -> Entity {
        Entity::new(
            "Encosto Estratégico Lda",
            Nipc::parse("503004642").expect("valid NIPC"),
            "Rua das Amoreiras, n.º 12, 1250-020 Lisboa",
            kind,
        )
    }

    async fn seed_owner(state: &AppState) -> CurrentActor {
        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
        }
        let uid = UserId(Uuid::new_v4());
        let username = "patch.owner".to_owned();
        let user = User {
            id: uid,
            username: username.clone(),
            display_name: "Patch Owner".to_owned(),
            email: None,
            created_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: None,
            attestation_key: None,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        };
        state.users.write().await.insert(uid, user);
        CurrentActor::from_session_username(Some(username))
    }

    #[tokio::test]
    async fn patch_act_writes_working_state_through_without_ledger_event() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;
        let entity = entity_of(EntityKind::SociedadePorQuotas);
        let book = Book::new(entity.id, BookKind::AssembleiaGeral);
        let act = Act::draft(book.id, "Draft title", MeetingChannel::Physical);

        state
            .store
            .as_ref()
            .expect("store")
            .persist(|tx| {
                tx.upsert_entity(&entity)?;
                tx.upsert_book(&book)?;
                tx.upsert_act(&act)
            })
            .expect("seed persisted");
        state.entities.write().await.insert(entity.id, entity);
        state.books.write().await.insert(book.id, book);
        state.acts.write().await.insert(act.id, act.clone());

        let before_events = state.ledger.read().await.len();
        let req: PatchAct = serde_json::from_value(json!({
            "title": "Draft edit survives restart",
            "deliberations": "Working text persisted before sealing."
        }))
        .expect("patch body");
        let Json(view) = patch_act(State(state.clone()), Path(act.id.0), actor, Json(req))
            .await
            .expect("patch succeeds");

        assert_eq!(view.title, "Draft edit survives restart");
        assert_eq!(state.ledger.read().await.len(), before_events);

        let restarted = AppState::with_data_dir(tmp.path());
        let acts = restarted.acts.read().await;
        let loaded = acts.get(&act.id).expect("act reloads");
        assert_eq!(loaded.title, "Draft edit survives restart");
        assert_eq!(
            loaded.deliberations,
            "Working text persisted before sealing."
        );
    }

    #[test]
    fn patch_permilage_rejects_non_numeric_wire_values() {
        for (label, permilage) in [
            ("numeric string", json!("250")),
            ("non-numeric string", json!("duzentos")),
            ("negative number", json!(-1)),
            ("object", json!({ "value": 250 })),
        ] {
            let signatory_body = json!({
                "signatories": [{
                    "name": "Fração A",
                    "capacity": "CondoOwner",
                    "permilage": permilage.clone(),
                }]
            });
            assert!(
                serde_json::from_value::<PatchAct>(signatory_body).is_err(),
                "signatory {label} must not deserialize as a u16 permilage"
            );

            let attendee_body = json!({
                "attendees": [{
                    "name": "Fração A",
                    "quality": "CondoOwner",
                    "presence": "InPerson",
                    "weight": { "Permilage": permilage },
                }]
            });
            assert!(
                serde_json::from_value::<PatchAct>(attendee_body).is_err(),
                "attendee {label} must not deserialize as a u32 permilage"
            );
        }
    }

    #[tokio::test]
    async fn patch_permilage_accepts_zero_and_rejects_over_1000() {
        let state = AppState::default();
        let actor = seed_owner(&state).await;
        let entity = entity_of(EntityKind::Condominio);
        let book = Book::new(entity.id, BookKind::AssembleiaGeral);
        let act = Act::draft(book.id, "Ata", MeetingChannel::Physical);
        let act_id = act.id;

        state.entities.write().await.insert(entity.id, entity);
        state.books.write().await.insert(book.id, book);
        state.acts.write().await.insert(act.id, act);

        let zero_req: PatchAct = serde_json::from_value(json!({
            "signatories": [{
                "name": "Fração A",
                "capacity": "CondoOwner",
                "permilage": 0
            }]
        }))
        .expect("zero permilage request deserializes");
        let Json(view) = patch_act(
            State(state.clone()),
            Path(act_id.0),
            actor.clone(),
            Json(zero_req),
        )
        .await
        .expect("zero permilage is accepted");
        assert_eq!(view.signatories[0].permilage, Some(0));

        let attendee_zero_req: PatchAct = serde_json::from_value(json!({
            "attendees": [{
                "name": "Fração A",
                "quality": "CondoOwner",
                "presence": "InPerson",
                "weight": { "Permilage": 0 }
            }]
        }))
        .expect("zero attendee permilage request deserializes");
        let Json(view) = patch_act(
            State(state.clone()),
            Path(act_id.0),
            actor.clone(),
            Json(attendee_zero_req),
        )
        .await
        .expect("zero attendee permilage is accepted");
        assert_eq!(
            view.attendees[0].weight,
            Some(chancela_core::AttendanceWeight::Permilage(0))
        );

        let too_high_req: PatchAct = serde_json::from_value(json!({
            "signatories": [{
                "name": "Fração B",
                "capacity": "CondoOwner",
                "permilage": 1001
            }]
        }))
        .expect("over-limit permilage request deserializes before semantic validation");
        let err = match patch_act(
            State(state.clone()),
            Path(act_id.0),
            actor.clone(),
            Json(too_high_req),
        )
        .await
        {
            Ok(_) => panic!("over-1000 permilage must be rejected"),
            Err(err) => err,
        };
        match err {
            ApiError::Unprocessable(msg) => {
                assert!(msg.contains("permilage 1001 exceeds 1000"), "{msg}");
            }
            other => panic!("expected 422, got {other:?}"),
        }

        let too_high_attendee_req: PatchAct = serde_json::from_value(json!({
            "attendees": [{
                "name": "Fração B",
                "quality": "CondoOwner",
                "presence": "InPerson",
                "weight": { "Permilage": 1001 }
            }]
        }))
        .expect("over-limit attendee permilage deserializes before semantic validation");
        let err = match patch_act(
            State(state.clone()),
            Path(act_id.0),
            actor,
            Json(too_high_attendee_req),
        )
        .await
        {
            Ok(_) => panic!("over-1000 attendee permilage must be rejected"),
            Err(err) => err,
        };
        match err {
            ApiError::Unprocessable(msg) => {
                assert!(msg.contains("permilage 1001 exceeds 1000"), "{msg}");
            }
            other => panic!("expected 422, got {other:?}"),
        }

        let acts = state.acts.read().await;
        let stored = acts.get(&act_id).expect("act remains stored");
        assert_eq!(
            stored.signatories[0].permilage,
            Some(0),
            "failed over-limit patch leaves the previous accepted value untouched"
        );
        assert_eq!(
            stored.attendees[0].weight,
            Some(chancela_core::AttendanceWeight::Permilage(0)),
            "failed over-limit attendee patch leaves the previous accepted value untouched"
        );
    }

    #[tokio::test]
    async fn patch_signatory_email_round_trips_and_invalid_email_leaves_act_unchanged() {
        let state = AppState::default();
        let actor = seed_owner(&state).await;
        let entity = entity_of(EntityKind::SociedadePorQuotas);
        let book = Book::new(entity.id, BookKind::AssembleiaGeral);
        let act = Act::draft(book.id, "Ata", MeetingChannel::Physical);
        let act_id = act.id;

        state.entities.write().await.insert(entity.id, entity);
        state.books.write().await.insert(book.id, book);
        state.acts.write().await.insert(act.id, act);

        let valid_req: PatchAct = serde_json::from_value(json!({
            "signatories": [{
                "name": "Ana Marques",
                "email": "  Ana.Marques@Example.PT ",
                "capacity": "Chair",
                "signed": true
            }]
        }))
        .expect("valid signatory email request deserializes");
        let Json(view) = patch_act(
            State(state.clone()),
            Path(act_id.0),
            actor.clone(),
            Json(valid_req),
        )
        .await
        .expect("valid signatory email is accepted");
        assert_eq!(
            view.signatories[0].email.as_deref(),
            Some("ana.marques@example.pt")
        );

        let invalid_req: PatchAct = serde_json::from_value(json!({
            "signatories": [{
                "name": "Ana Marques",
                "email": "ana at example.pt",
                "capacity": "Chair"
            }]
        }))
        .expect("invalid email request deserializes before semantic validation");
        let err = match patch_act(
            State(state.clone()),
            Path(act_id.0),
            actor,
            Json(invalid_req),
        )
        .await
        {
            Ok(_) => panic!("invalid signatory email must be rejected"),
            Err(err) => err,
        };
        match err {
            ApiError::Unprocessable(msg) => {
                assert!(msg.contains("signatory.email"), "{msg}");
            }
            other => panic!("expected 422, got {other:?}"),
        }

        let acts = state.acts.read().await;
        let stored = acts.get(&act_id).expect("act remains stored");
        assert_eq!(
            stored.signatories[0].email.as_deref(),
            Some("ana.marques@example.pt"),
            "failed invalid-email patch leaves the previous accepted signatory untouched"
        );
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

    #[test]
    fn statute_notice_advisories_use_entity_statute_and_act_notice_days() {
        let mut entity = entity_of(EntityKind::SociedadePorQuotas);
        entity.statute = Some(chancela_core::StatuteOverrides {
            convocation_notice_days: Some(8),
            ..Default::default()
        });
        let mut act = Act::draft(
            BookId(uuid::Uuid::nil()),
            "Ata",
            chancela_core::MeetingChannel::Physical,
        );

        act.convening = Some(chancela_core::Convening {
            antecedence_days: Some(5),
            ..Default::default()
        });
        let below = convening_advisories_for(&entity, &act);
        assert_eq!(below.len(), 1);
        assert_eq!(below[0].severity, "Warning");
        assert_eq!(below[0].code, "convening.statute_notice.below_minimum");
        assert_eq!(below[0].threshold_id, STATUTE_NOTICE_THRESHOLD_ID);
        assert_eq!(below[0].actual_days, Some(5));
        assert_eq!(below[0].minimum_days, Some(8));

        act.convening = Some(chancela_core::Convening {
            antecedence_days: None,
            ..Default::default()
        });
        let missing = convening_advisories_for(&entity, &act);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].code, "convening.statute_notice.missing_actual");
        assert_eq!(missing[0].actual_days, None);
        assert_eq!(missing[0].minimum_days, Some(8));

        act.convening = Some(chancela_core::Convening {
            antecedence_days: Some(8),
            ..Default::default()
        });
        assert!(convening_advisories_for(&entity, &act).is_empty());
    }

    #[test]
    fn statute_notice_advisory_edges_are_warn_only_and_skip_absent_minimums() {
        let missing = statute_notice_advisory(8, None).expect("missing actual notice warns");
        assert_eq!(missing.severity, "Warning");
        assert_eq!(missing.code, "convening.statute_notice.missing_actual");
        assert_eq!(missing.actual_days, None);
        assert_eq!(missing.minimum_days, Some(8));

        let below = statute_notice_advisory(8, Some(7)).expect("below minimum warns");
        assert_eq!(below.severity, "Warning");
        assert_eq!(below.code, "convening.statute_notice.below_minimum");
        assert_eq!(below.actual_days, Some(7));
        assert_eq!(below.minimum_days, Some(8));

        assert!(statute_notice_advisory(8, Some(8)).is_none());
        assert!(statute_notice_advisory(8, Some(9)).is_none());

        let mut entity = entity_of(EntityKind::Associacao);
        let act = Act::draft(
            BookId(uuid::Uuid::nil()),
            "Ata",
            chancela_core::MeetingChannel::Physical,
        );
        entity.statute = Some(chancela_core::StatuteOverrides::default());
        assert!(
            convening_advisories_for(&entity, &act).is_empty(),
            "a statute overlay without convocation_notice_days contributes no notice advisory"
        );

        entity.statute = None;
        assert!(
            convening_advisories_for(&entity, &act).is_empty(),
            "no statute overlay contributes no statute notice advisory"
        );

        entity.statute = Some(chancela_core::StatuteOverrides {
            convocation_notice_days: Some(8),
            ..Default::default()
        });
        let advisories = convening_advisories_for(&entity, &act);
        assert_eq!(advisories.len(), 1);
        assert_eq!(
            advisories[0].code,
            "convening.statute_notice.missing_actual"
        );
    }

    #[test]
    fn statute_majority_counts_mixed_votes_and_abstentions_as_an_advisory() {
        let mut entity = entity_of(EntityKind::SociedadeAnonima);
        entity.statute = Some(chancela_core::StatuteOverrides {
            majority: Some(chancela_core::Majority {
                numerator: 2,
                denominator: 3,
            }),
            ..Default::default()
        });
        let mut act = Act::draft(
            BookId(uuid::Uuid::nil()),
            "Ata",
            chancela_core::MeetingChannel::Physical,
        );
        act.deliberation_items = vec![chancela_core::DeliberationItem {
            agenda_number: Some(1),
            text: "Deliberada a alteração estatutária.".to_owned(),
            vote: Some(chancela_core::VoteResult::Recorded {
                em_favor: 2,
                contra: 0,
                abstencoes: 2,
            }),
            statements: Vec::new(),
        }];

        let issues = rule_pack_for(&entity).check_act(&act, &entity);
        let majority = issues
            .iter()
            .find(|i| i.rule_id == "STATUTE/majority")
            .unwrap_or_else(|| panic!("2/4 should miss a 2/3 majority: {issues:?}"));
        assert_eq!(majority.severity, Severity::Warning);
        assert!(
            majority.message.contains("2/4"),
            "message should disclose the computed mixed total: {majority:?}"
        );

        act.deliberation_items[0].vote = Some(chancela_core::VoteResult::Recorded {
            em_favor: 2,
            contra: 0,
            abstencoes: 1,
        });
        let issues = rule_pack_for(&entity).check_act(&act, &entity);
        assert!(
            !issues.iter().any(|i| i.rule_id == "STATUTE/majority"),
            "2/3 exactly meets the statutory majority even with an abstention: {issues:?}"
        );
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
