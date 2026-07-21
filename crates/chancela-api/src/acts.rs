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
use chancela_core::act::AiHumanVerificationStatus;
use chancela_core::{
    Act, ActBody, ActError, ActId, ActState, Book, BookId, DEFAULT_TENANT_ID, Entity, EntityFamily,
    EntityKind, PresenceMode, SealEvidence, Severity, SupersededSigningSnapshot, rule_pack_for,
    seal_act_with_evidence,
};
use chancela_store::{StoredDocument, StoredSignedDocument};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use chancela_authz::Permission;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{require_permission, scope_of_act, scope_of_book};
use crate::dto::{
    ActBodyPreviewResponse, ActView, AdvanceAct, ArchiveAct, ComplianceResponse, ConveningAdvisory,
    DispatchConvening, DraftAct, HumanVerificationDecision, IssueView, PatchAct, PreviewActBody,
    ReopenAct, ReopenActResponse, SealAct, SealResponse, SupersededSigningSnapshotView,
    VerifyAiHumanReview, WrittenResolutionEvidenceStatusView, read_redaction_for_actor,
};
use crate::error::ApiError;
use time::format_description::well_known::Rfc3339;

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
    // entities → books → acts → ledger. The entity read is acquired first (fixed global lock
    // order) so the act genesis can carry the parent entity's tenant (wp27-e3).
    let entities = state.entities.read().await;
    let books = state.books.read().await;
    let book = books.get(&book_id).ok_or(ApiError::NotFound)?;
    if !book.is_open() {
        return Err(ApiError::Conflict(format!(
            "book {book_id} is not open; acts may only be drafted in an open book"
        )));
    }
    let entity_id = book.entity_id;
    // Tenancy (wp27-e3): the act genesis joins its tenant chain, mirroring e1's entity/`book.opened`
    // change. Derive the tenant from the parent entity; a single-tenant deployment (or an entity not
    // yet in the read model) resolves to the default tenant, keeping behaviour byte-identical.
    let tenant_id = entities
        .get(&entity_id)
        .map_or(DEFAULT_TENANT_ID, |entity| entity.tenant_id);

    let mut acts = state.acts.write().await;
    let mut ledger = state.ledger.write().await;

    let mut act = Act::draft(book_id, req.title, req.channel);
    if let Some(r) = req.retifies {
        act.retifies = Some(ActId(r));
    }
    if let Some(convening) = req.convening {
        act.convening = Some(convening.into_core()?);
    }
    if let Some(waiver) = req.convening_waiver {
        act.convening_waiver = Some(waiver.into_core()?);
    }
    if let Some(ai_provenance) = req.ai_provenance {
        act.ai_provenance = Some(ai_provenance.into_core()?);
    }

    // Non-default tenant → the act genesis joins its tenant chain; the default tenant keeps the
    // exact pre-tenancy `entity:/book:/act:` scope (single-tenant byte-identical).
    let scope = if tenant_id == DEFAULT_TENANT_ID {
        format!("entity:{}/book:{}/act:{}", entity_id, act.book_id, act.id)
    } else {
        format!(
            "tenant:{}/entity:{}/book:{}/act:{}",
            tenant_id, entity_id, act.book_id, act.id
        )
    };
    let payload = serde_json::to_vec(&act)?;
    // Validating append (t54): reject a chain-breaking append before mutating the ledger.
    crate::try_append_event(&mut ledger, &actor, &scope, "act.drafted", None, &payload)?;
    let act_for_store = act.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| tx.upsert_act(&act_for_store))
        .await?;
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

fn act_updated_event_payload(next: &Act) -> Result<Vec<u8>, ApiError> {
    let content_bytes = serde_json::to_vec(next)?;
    let content_digest = crate::hex::hex(&Sha256::digest(&content_bytes).into());
    Ok(serde_json::to_vec(&json!({
        "act_id": next.id.to_string(),
        "book_id": next.book_id.to_string(),
        "state": next.state,
        "content_sha256": content_digest,
        "content_bytes": content_bytes.len(),
        "secrets_in_payload": false
    }))?)
}

/// `PATCH /v1/acts/{id}` — update working content and append a content-bound `act.updated` event in
/// the same durable transaction. The event carries digests and sizes, never the private act text.
pub async fn patch_act(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchAct>,
) -> Result<Json<ActView>, ApiError> {
    // RBAC (t64-E3): editing an act's working content is `act.edit` scoped to its book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::ActEdit, scope).await?;
    let actor_name = actor.resolve("api");
    // books -> acts -> ledger. A closed/non-open book freezes all existing acts in it too.
    let books = state.books.read().await;
    let mut acts = state.acts.write().await;
    let mut ledger = state.ledger.write().await;
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
    if let Some(evidence) = req.written_resolution_evidence {
        next.written_resolution_evidence = match evidence {
            Some(evidence) => {
                let evidence = evidence.into_core()?;
                ensure_written_resolution_review_receipts_append_only(
                    act.written_resolution_evidence.as_ref(),
                    &evidence,
                )?;
                Some(evidence)
            }
            None => {
                ensure_written_resolution_evidence_can_clear(
                    act.written_resolution_evidence.as_ref(),
                )?;
                None
            }
        };
    }
    if let Some(deliberations) = req.deliberations {
        next.deliberations = deliberations;
    }
    // The markup body (t74). Validated *here*, on save, so a malformed placeholder or a construct
    // the frozen block set cannot represent is a 422 while the operator is still editing — not a
    // surprise at the seal gate, by which point the act is no longer mutable and cannot be fixed.
    //
    // Never touches `deliberations`, in either direction: the two are separate stores and plain
    // prose is never migrated into markup.
    if let Some(body) = req.body {
        next.body = match body {
            Some(input) => {
                chancela_templates::body_render::check_markdown_body(&input.source)?;
                Some(ActBody {
                    format: input.format,
                    source: input.source,
                    // Both are facts about what the server compiled at content freeze, which has not
                    // happened yet. The digest is empty until then rather than a guess: the body is
                    // still editable, so any value recorded now would be about text the operator can
                    // still change.
                    compiler_id: chancela_templates::markdown::COMPILER_ID.to_owned(),
                    compiled_digest: String::new(),
                })
            }
            None => None,
        };
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
    // The no-convocatória basis, same double_option semantics. Setting one does **not** clear
    // `convening` here: which of the two is stale is the caller's call, and the rule packs raise
    // `CONV/waiver-conflict` when both survive, so the contradiction is surfaced rather than
    // silently resolved by whichever field was patched last.
    if let Some(waiver) = req.convening_waiver {
        next.convening_waiver = match waiver {
            Some(w) => Some(w.into_core()?),
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

    // DAT-10: bind the full updated content without copying personal act content into ledger
    // metadata. The digest is over the exact durable Act JSON; the event and row commit together.
    let event_payload = act_updated_event_payload(&next)?;
    let audit_scope = format!(
        "entity:{}/book:{}/act:{}",
        book.entity_id, next.book_id, next.id
    );
    crate::try_append_event(
        &mut ledger,
        &actor_name,
        &audit_scope,
        "act.updated",
        None,
        &event_payload,
    )?;
    #[cfg(test)]
    if next.title == "__chancela_test_fail_patch_persist__" {
        state
            .persist_write_through(&mut ledger, 1, |_tx| {
                Err(chancela_store::StoreError::BadBackup(
                    "injected patch persistence failure".to_owned(),
                ))
            })
            .await?;
        unreachable!("injected persistence failure must return an error");
    }
    let next_for_store = next.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| tx.upsert_act(&next_for_store))
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    *act = next;

    Ok(Json(ActView::from(&*act)))
}

/// The blocking (`Error`-severity) findings of the act's dispatched rule pack.
///
/// One evaluation, shared by the seal gate and the `Signing` entry gate. Deliberately not a second
/// hand-maintained list of "what blocks an advance": a list that could drift from what blocks a
/// seal would recreate the dead end in a new form. Synchronous so the non-`Send` `Box<dyn RulePack>`
/// cannot be held across an await.
fn blocking_compliance_issues(act: &Act, entity: &Entity) -> Vec<IssueView> {
    rule_pack_for(entity)
        .check_act(act, entity)
        .iter()
        .filter(|issue| issue.severity == Severity::Error)
        .map(IssueView::from)
        .collect()
}

/// Render issues the way the core seal refusal renders them, so both messages read alike.
fn render_issue_views(issues: &[IssueView]) -> String {
    issues
        .iter()
        .map(|issue| format!("[{}] {}", issue.rule_id, issue.message))
        .collect::<Vec<_>>()
        .join("; ")
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
    let target_state = req.to;
    let template_id = req.template_id;

    // A canonical Ata may only be created once, exactly as the act enters Signing. Pre-existing Ata
    // rows are never silently replaced or reinterpreted as the new snapshot.
    if target_state == ActState::Signing
        && crate::documents::load_document(&state, ActId(id))
            .await?
            .is_some()
    {
        return Err(ApiError::Conflict(
            "a canonical act document already exists; explicit invalidation is required before creating a new signing snapshot"
                .to_owned(),
        ));
    }

    // entities → books → acts → ledger (Signing snapshot generation needs the profile).
    let entities = state.entities.read().await;
    let books = state.books.read().await;
    let mut acts = state.acts.write().await;
    let mut ledger = state.ledger.write().await;

    let act = acts.get_mut(&ActId(id)).ok_or(ApiError::NotFound)?;
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    ensure_book_open_for_act_mutation(book)?;
    let entity_id = book.entity_id;
    let entity = entities.get(&entity_id).ok_or(ApiError::NotFound)?;

    // Apply the transition to a clone, so the in-memory map is only mutated after the durable write
    // succeeds (nothing to roll back on a store failure). Invalid transition → 422 (contract §2.5).
    let mut next = act.clone();
    if next.state == ActState::TextApproved
        && target_state == ActState::Signing
        && next.requires_ai_human_verification()
    {
        return Err(ApiError::Conflict(
            "AI-assisted act requires accepted human review before Signing; accepted means human reviewed only"
                .to_owned(),
        ));
    }
    next.advance_to(target_state)
        .map_err(|e| ApiError::Unprocessable(e.to_string()))?;

    // Entering `Signing` freezes the act: `is_mutable()` goes false, so the act can no longer be
    // corrected, while the seal gate refuses on any blocking compliance error. Advancing an act
    // that already carries one therefore stranded it — neither sealable nor fixable. Run the *same*
    // rule pack the seal gate runs, against the same act, at the last moment the operator can still
    // fix what it names. Warnings never block here, exactly as they never block a seal the operator
    // acknowledges; only `Error` severity does.
    if target_state == ActState::Signing {
        let blocking = blocking_compliance_issues(&next, entity);
        if !blocking.is_empty() {
            return Err(ApiError::ComplianceBlocked {
                message: format!(
                    "advance to Signing blocked by compliance errors: {}",
                    render_issue_views(&blocking)
                ),
                issues: blocking,
            });
        }
    }

    // t74 §1 — CONTENT FREEZE. This is the moment the act stops being mutable, so it is the moment
    // the markdown body compiles: exactly once, recording `compiler_id` and the `compiled_digest` of
    // what it produced. The seal then binds source *and* output together, so a later compiler change
    // cannot silently alter what a sealed act says — the two stop agreeing and the mismatch becomes
    // detectable. Compiling later, per render, would leave nothing to compare against.
    //
    // Assigned directly rather than through `set_body`, which is correctly refused here: `next` has
    // already advanced to `Signing` and is no longer mutable. This is not an edit to the operator's
    // content — `source` is carried through verbatim — it only fills in what the server compiled.
    if target_state == ActState::Signing
        && let Some((frozen, _blocks)) = crate::documents::freeze_act_body(&next, entity)?
    {
        next.body = Some(frozen);
    }

    let signing_snapshot = if target_state == ActState::Signing {
        Some(
            crate::documents::generate_for_act(&next, entity, template_id.as_deref())?.ok_or_else(
                || {
                    ApiError::Conflict(
                        "no canonical Ata template is available for this act; signing cannot start"
                            .to_owned(),
                    )
                },
            )?,
        )
    } else {
        None
    };

    let scope = format!("entity:{}/book:{}/act:{}", entity_id, next.book_id, next.id);
    let justification = format!("advance to {target_state:?}");
    let payload = serde_json::to_vec(&next)?;
    crate::try_append_event(
        &mut ledger,
        &actor,
        &scope,
        "act.advanced",
        Some(&justification),
        &payload,
    )?;

    if let Some(snapshot) = &signing_snapshot {
        let snapshot_payload = serde_json::to_vec(&snapshot.event_payload)?;
        if let Err(error) = crate::try_append_event(
            &mut ledger,
            &actor,
            &scope,
            "document.generated",
            Some("canonical signing snapshot"),
            &snapshot_payload,
        ) {
            AppState::rollback_ledger_events(&mut ledger, 1);
            return Err(error);
        }
    }

    let appended_events = 1 + usize::from(signing_snapshot.is_some());
    let next_for_store = next.clone();
    // `Generated` is not `Clone`; capture only the owned `stored` document the tx needs.
    let snapshot_stored_for_store = signing_snapshot.as_ref().map(|s| s.stored.clone());
    state
        .persist_write_through(&mut ledger, appended_events, move |tx| {
            tx.upsert_act(&next_for_store)?;
            if let Some(stored) = &snapshot_stored_for_store {
                tx.upsert_document(stored)?;
            }
            Ok(())
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    *act = next;

    if let Some(snapshot) = &signing_snapshot {
        crate::documents::publish_generated_document_read_model(&state, &snapshot.stored).await;
    }

    Ok(Json(ActView::from(&*act)))
}

/// `POST /v1/acts/{id}/reopen` — pull a `Signing` act back to `TextApproved` for correction.
///
/// The rescue path for the dead end this endpoint's sibling gate now prevents: an act that reached
/// `Signing` with a blocking compliance defect is frozen (`is_mutable()` false) and unsealable
/// (the seal gate refuses), so before this existed it could never leave `Signing`.
///
/// Refused, in order, when: a signature has been collected (a reopen would invalidate somebody's
/// assent — correct such an act with a new act that retifies it, WFL-21); the book is under legal
/// hold; the book is not open; or the act is not in `Signing`. On success the canonical signing
/// snapshot is **superseded**: its bytes stay in the store and its `document.generated` event stays
/// in the chain, but it stops resolving as this act's signing document, so no one can sign or seal
/// against it and a re-advance mints a fresh snapshot over the corrected content.
pub async fn reopen_act(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<ReopenAct>,
) -> Result<Json<ReopenActResponse>, ApiError> {
    let act_id = ActId(id);
    // RBAC: reopening is a state regression on an evidentiary object, so it is gated on **both**
    // the permission governing the `Signing → Sealed` boundary it walks back (`signing.perform`)
    // and the permission to make the correction it exists for (`act.edit`). No new permission is
    // minted. The pair lands on Gestor / Tenant Administrator / Platform Administrator / Owner and
    // deliberately excludes Signatário, which holds `signing.perform` but not `act.edit`: a
    // signatory must not be able to pull a document back out from under a collection in progress.
    let scope = scope_of_act(&state, act_id).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    require_permission(&state, &actor, Permission::ActEdit, scope).await?;

    let reason = req.reason.trim().to_owned();
    if reason.is_empty() {
        return Err(ApiError::Unprocessable(
            "reopen requires a non-empty reason; the regression must be reconstructable from the ledger"
                .to_owned(),
        ));
    }
    let actor = actor.resolve(&req.actor);

    // A collected cryptographic signature is checked before anything is touched. `signatories[]`
    // slots are checked too, inside `reopen_for_correction`.
    if crate::signature::load_signed(&state, act_id)
        .await?
        .is_some()
    {
        return Err(ApiError::Conflict(
            ActError::SignaturesCollected.to_string(),
        ));
    }
    // Read outside the write locks, mirroring the seal handler.
    let canonical = crate::documents::load_document(&state, act_id).await?;

    // books → acts → ledger.
    let books = state.books.read().await;
    let mut acts = state.acts.write().await;
    let mut ledger = state.ledger.write().await;

    let act = acts.get_mut(&act_id).ok_or(ApiError::NotFound)?;
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    ensure_book_open_for_act_mutation(book)?;
    // Legal hold: a held book's acts must not move. The disposal paths already honour holds and
    // this is the same class of mutation — a hold is exactly the circumstance in which the state
    // an act is preserved in matters most.
    if let Some(hold) = &book.legal_hold {
        return Err(ApiError::Conflict(format!(
            "book {} is under legal hold ({:?}); reopening an act is refused while the hold stands",
            book.id, hold.reason
        )));
    }
    let entity_id = book.entity_id;

    // Reopen a clone, so the read model moves only after the durable write commits.
    let mut next = act.clone();
    let released_page_count = next
        .reopen_for_correction()
        .map_err(|e| ApiError::Conflict(e.to_string()))?;

    let reopened_at = time::OffsetDateTime::now_utc();
    let superseded = canonical.as_ref().map(|doc| SupersededSigningSnapshot {
        document_id: doc.id.clone(),
        pdf_digest: doc.pdf_digest.clone(),
        actor: actor.clone(),
        superseded_at: reopened_at,
        reason: reason.clone(),
    });
    if let Some(snapshot) = superseded.clone() {
        next.record_superseded_signing_snapshot(snapshot);
    }

    let scope = format!("entity:{}/book:{}/act:{}", entity_id, next.book_id, next.id);
    let justification = format!("reopen for correction: {reason}");
    let payload = serde_json::to_vec(&json!({
        "act_id": next.id.to_string(),
        "book_id": next.book_id.to_string(),
        "from": ActState::Signing,
        "to": next.state,
        "actor": actor,
        "reopened_at": reopened_at.format(&Rfc3339).unwrap_or_default(),
        "reason": reason,
        "superseded_signing_snapshot": superseded.as_ref().map(|snapshot| json!({
            "document_id": snapshot.document_id,
            "pdf_digest": snapshot.pdf_digest,
        })),
        "released_page_count": released_page_count,
        "collected_signatures": 0,
    }))?;
    crate::try_append_event(
        &mut ledger,
        &actor,
        &scope,
        "act.reopened",
        Some(&justification),
        &payload,
    )?;
    let event_seq = ledger.events().last().map(|event| event.seq);
    let next_for_store = next.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| tx.upsert_act(&next_for_store))
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    *act = next;

    Ok(Json(ReopenActResponse {
        act: ActView::from(&*act),
        from: ActState::Signing,
        to: act.state,
        event_seq,
        superseded_signing_snapshot: superseded
            .as_ref()
            .map(SupersededSigningSnapshotView::from_core),
        released_page_count,
    }))
}

/// `POST /v1/acts/{id}/human-verification` — accept/reject human review of AI-assisted draft text.
pub async fn verify_ai_human_review(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<VerifyAiHumanReview>,
) -> Result<Json<ActView>, ApiError> {
    // RBAC: human verification controls the Signing gate, so it uses the same scoped lifecycle
    // permission as advancing the act.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::ActAdvance, scope).await?;
    let actor = actor.resolve(&req.actor);
    // books → acts → ledger (books only to resolve event scope and open-book mutation rules).
    let books = state.books.read().await;
    let mut acts = state.acts.write().await;
    let mut ledger = state.ledger.write().await;

    let act = acts.get_mut(&ActId(id)).ok_or(ApiError::NotFound)?;
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    ensure_book_open_for_act_mutation(book)?;
    if !act.is_mutable() {
        return Err(ApiError::Conflict(ActError::Sealed.to_string()));
    }
    if act.ai_provenance.is_none() {
        return Err(ApiError::Conflict(
            "act has no AI provenance to human-review".to_owned(),
        ));
    }

    let mut next = act.clone();
    let status = match req.decision {
        HumanVerificationDecision::Accept => AiHumanVerificationStatus::Accepted,
        HumanVerificationDecision::Reject => AiHumanVerificationStatus::Rejected,
    };
    next.set_ai_human_verification(
        status,
        actor.clone(),
        time::OffsetDateTime::now_utc(),
        req.note,
    )
    .map_err(|e| ApiError::Conflict(e.to_string()))?;

    let scope = format!(
        "entity:{}/book:{}/act:{}",
        book.entity_id, next.book_id, next.id
    );
    let justification = match status {
        AiHumanVerificationStatus::Accepted => {
            "AI human verification accepted; human review only, not legal validity"
        }
        AiHumanVerificationStatus::Rejected => {
            "AI human verification rejected; human review only, not legal validity"
        }
        AiHumanVerificationStatus::Pending => "AI human verification pending",
    };
    let payload = serde_json::to_vec(&next)?;
    crate::try_append_event(
        &mut ledger,
        &actor,
        &scope,
        "act.ai_human_verification",
        Some(justification),
        &payload,
    )?;
    let next_for_store = next.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| tx.upsert_act(&next_for_store))
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    *act = next;

    Ok(Json(ActView::from(&*act)))
}

/// `POST /v1/acts/{id}/body/preview` — compile a markdown body source into `Block[]` (t74 §6).
///
/// **This exists so the editor never compiles document content.** The preview runs the same
/// `render_markdown_body` that content freeze runs, against the same act context, so the operator
/// previews exactly the blocks that will be sealed. A client-side markdown renderer would be a
/// second implementation that could drift from the authoritative one, and the operator would be
/// approving something other than what gets sealed.
///
/// `POST` rather than `GET` because the source is request *content* — a body being edited is far
/// larger than a URL may safely carry, and it does not belong in access logs or browser history.
///
/// Deliberately usable on a sealed act: previewing is read-only and never writes the body back.
/// A rejected construct is the same structured 422 the save path returns.
pub async fn preview_act_body(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    Json(req): Json<PreviewActBody>,
) -> Result<Json<ActBodyPreviewResponse>, ApiError> {
    // Reading an act's body and its render context is `act.read`, the same scope the compliance
    // report uses. No write permission: this endpoint mutates nothing.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::ActRead, scope).await?;
    let entities = state.entities.read().await;
    let books = state.books.read().await;
    let acts = state.acts.read().await;

    let act = acts.get(&ActId(id)).ok_or(ApiError::NotFound)?;
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;

    // The unsaved editor buffer when supplied, else whatever is stored. An act with neither has an
    // empty preview rather than a 404: "nothing written yet" is a normal editing state.
    let source = match req.source.as_deref() {
        Some(source) => source,
        None => act.body.as_ref().map(|b| b.source.as_str()).unwrap_or(""),
    };

    let blocks = crate::documents::preview_act_body(act, entity, source)?;
    Ok(Json(ActBodyPreviewResponse {
        compiler_id: chancela_templates::markdown::COMPILER_ID,
        blocks,
    }))
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
        written_resolution_evidence_status: WrittenResolutionEvidenceStatusView::from_summary(
            chancela_core::written_resolution_evidence_summary(act),
        ),
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
        && let Some(advisory) = statute_notice_advisory(minimum_days, actual_days)
    {
        advisories.push(advisory);
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

fn should_generate_condominium_absent_owner_communication(act: &Act, entity: &Entity) -> bool {
    entity.family == EntityFamily::Condominium
        && act
            .attendees
            .iter()
            .any(|attendee| attendee.presence == PresenceMode::Absent)
}

const SEAL_EVIDENCE_REQUIRED: &str = "seal requires either a complete validated signed PDF bound to the canonical signing snapshot, or manual_signature_original_reference for a retained manually signed original";

struct ResolvedSealEvidence {
    core: SealEvidence,
    validation_report: Option<Vec<u8>>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    crate::hex::hex(&Sha256::digest(bytes).into())
}

fn validate_canonical_signing_snapshot(document: &StoredDocument) -> Result<String, ApiError> {
    let observed = sha256_hex(&document.pdf_bytes);
    if observed != document.pdf_digest {
        return Err(ApiError::Conflict(
            "canonical signing snapshot failed its stored SHA-256 fixity check".to_owned(),
        ));
    }
    Ok(observed)
}

fn validate_digital_seal_evidence(
    act_id: ActId,
    canonical: &StoredDocument,
    signed: &StoredSignedDocument,
) -> Result<ResolvedSealEvidence, ApiError> {
    let signing_snapshot_digest = validate_canonical_signing_snapshot(canonical)?;
    if signed.act_id != act_id || signed.document_id != canonical.id {
        return Err(ApiError::Conflict(
            "signed PDF evidence is not bound to this act's canonical signing snapshot".to_owned(),
        ));
    }
    if !signed.signed_pdf_bytes.starts_with(&canonical.pdf_bytes) {
        return Err(ApiError::Conflict(
            "signed PDF evidence does not extend the canonical signing snapshot byte-for-byte"
                .to_owned(),
        ));
    }
    let signed_pdf_digest = sha256_hex(&signed.signed_pdf_bytes);
    if signed_pdf_digest != signed.signed_pdf_digest {
        return Err(ApiError::Conflict(
            "signed PDF evidence failed its stored SHA-256 fixity check".to_owned(),
        ));
    }
    let report = crate::signature::validate_signed_pdf_with_incremental_updates(
        &signed.signed_pdf_bytes,
        &signed.signer_cert_der,
    )
    .map_err(|_| {
        ApiError::Conflict(
            "signed PDF evidence failed cryptographic or signer-certificate validation".to_owned(),
        )
    })?;
    if !report.coverage.covers_rendered_document() {
        return Err(ApiError::Conflict(
            "signed PDF evidence does not cover the rendered document".to_owned(),
        ));
    }

    let validation_report = serde_json::to_vec(&json!({
        "schema": "chancela.signature-seal-validation/v1",
        "act_id": act_id.to_string(),
        "document_id": canonical.id,
        "signing_snapshot_digest": signing_snapshot_digest,
        "signed_pdf_digest": signed_pdf_digest,
        "signature_family": signed.signature_family,
        "evidentiary_level": signed.evidentiary_level,
        "checks": {
            "canonical_snapshot_fixity": "valid",
            "signed_pdf_fixity": "valid",
            "canonical_snapshot_prefix_match": true,
            "pades_cryptographic_validation": "valid",
            "signer_certificate_match": true,
            "covers_signed_revision_except_contents": report.covers_signed_revision_except_contents,
            "covers_rendered_document": true
        },
        "status_scope": "technical_evidence_only",
        "qualified_status_claimed_by_report": false,
        "legal_validity_claimed": false
    }))?;
    let signature_validation_report_digest = sha256_hex(&validation_report);
    Ok(ResolvedSealEvidence {
        core: SealEvidence::Digital {
            signing_snapshot_digest,
            signed_pdf_digest,
            signature_validation_report_digest,
        },
        validation_report: Some(validation_report),
    })
}

async fn latest_signed_document_for_seal(
    state: &AppState,
    act_id: ActId,
) -> Result<Option<StoredSignedDocument>, ApiError> {
    // The seal handler calls this while holding the ledger write lock, after all earlier signature
    // transactions have committed. Prefer the durable row so a just-appended LTV revision cannot
    // be shadowed by a briefly stale in-memory projection.
    if let Some(store) = &state.store {
        // wp28: offload the sync postgres read (called under the ledger write lock) onto the
        // blocking pool; holding the tokio guard across this await is safe (the task never needs it).
        return store
            .read_blocking_async(move |s| s.signed_document_for_act(act_id))
            .await
            .map_err(|error| ApiError::Internal(format!("signed document read failed: {error}")));
    }
    Ok(state.signed_documents.read().await.get(&act_id).cloned())
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
    let SealAct {
        actor: requested_actor,
        acknowledge_warnings,
        manual_signature_original_reference,
        template_id,
    } = body.map(|Json(b)| b).unwrap_or_default();
    let actor = actor.resolve(&requested_actor);
    let manual_signature_original_reference = manual_signature_original_reference
        .map(|reference| reference.into_core())
        .transpose()?;
    let canonical = crate::documents::load_document(&state, ActId(id))
        .await?
        .ok_or_else(|| {
            ApiError::Conflict(
                "canonical signing snapshot is missing; advance the act to Signing first"
                    .to_owned(),
            )
        })?;
    if let Some(asserted_template_id) = template_id.as_deref()
        && asserted_template_id != canonical.template_id
    {
        return Err(ApiError::Conflict(format!(
            "seal template_id {asserted_template_id:?} does not match frozen signing snapshot template {:?}",
            canonical.template_id
        )));
    }
    validate_canonical_signing_snapshot(&canonical)?;

    // entities → books → acts → ledger (the full order; seal touches all four).
    let entities = state.entities.read().await;
    let mut books = state.books.write().await;
    let mut acts = state.acts.write().await;
    let mut ledger = state.ledger.write().await;

    let act = acts.get_mut(&ActId(id)).ok_or(ApiError::NotFound)?;
    let book = books.get_mut(&act.book_id).ok_or(ApiError::NotFound)?;
    ensure_book_open_for_act_mutation(book)?;
    let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;
    if act.state != ActState::Signing {
        return Err(ApiError::Conflict(format!(
            "seal requires act state Signing, found {:?}",
            act.state
        )));
    }

    let signed = latest_signed_document_for_seal(&state, ActId(id)).await?;
    let evidence = match (signed.as_ref(), manual_signature_original_reference) {
        (Some(_), Some(_)) => {
            return Err(ApiError::Conflict(
                "seal evidence is ambiguous; choose the validated signed-PDF path or the explicit manual-original path"
                    .to_owned(),
            ));
        }
        (Some(signed), None) => validate_digital_seal_evidence(ActId(id), &canonical, signed)?,
        (None, Some(original_reference)) => ResolvedSealEvidence {
            core: SealEvidence::Manual { original_reference },
            validation_report: None,
        },
        (None, None) => return Err(ApiError::Conflict(SEAL_EVIDENCE_REQUIRED.to_owned())),
    };

    // Per-family dispatch (R4): seal against the pack selected from the entity's profile.
    let pack = rule_pack_for(entity);

    // Seal against clones so the read model is mutated only after the durable write commits. A store
    // failure rolls back the appended `act.sealed` event and leaves the maps untouched (a failed
    // seal never touches the ledger, so the error paths below see the original act/book).
    let mut book_next = book.clone();
    let mut act_next = act.clone();
    match seal_act_with_evidence(
        &mut book_next,
        &mut act_next,
        entity,
        &*pack,
        &actor,
        acknowledge_warnings,
        evidence.core,
        &mut ledger,
    ) {
        Ok(outcome) => {
            // The dispatched pack (`Box<dyn RulePack>`, not `Send`) is not needed past here; drop
            // it before the `.await` below so the handler future stays `Send` (axum's bound).
            drop(pack);

            // Digital seals retain the exact deterministic technical validation report whose digest
            // is frozen in `seal_metadata`. It is appended after `act.sealed`, but both events and
            // every row below commit atomically.
            let mut base_events = 1usize;
            if let Some(validation_report) = evidence.validation_report.as_deref() {
                let scope = format!(
                    "entity:{}/book:{}/act:{}",
                    entity.id, act_next.book_id, act_next.id
                );
                if let Err(error) = crate::try_append_event(
                    &mut ledger,
                    &actor,
                    &scope,
                    "document.signature.validated_for_seal",
                    Some("technical evidence only"),
                    validation_report,
                ) {
                    AppState::rollback_ledger_events(&mut ledger, 1);
                    return Err(error);
                }
                base_events += 1;
            }

            // The canonical Ata was generated and persisted before signing. Seal-time generation is
            // limited to separate post-act instruments; it can never replace the signed snapshot.
            let mut generated_docs = Vec::new();
            if should_generate_condominium_absent_owner_communication(&act_next, entity) {
                match crate::documents::generate_condominium_absent_owner_communication(
                    &act_next, &book_next, entity,
                ) {
                    Ok(made) => generated_docs.push(made),
                    Err(e) => {
                        AppState::rollback_ledger_events(&mut ledger, base_events);
                        return Err(e);
                    }
                }
            }

            if !generated_docs.is_empty() {
                // Bind all generated documents into the tamper-evident chain (TPL-02 / §3.4) and
                // persist them with the sealed act + book counter in one commit.
                let scope = format!(
                    "entity:{}/book:{}/act:{}",
                    entity.id, act_next.book_id, act_next.id
                );
                for (appended_doc_events, made) in generated_docs.iter().enumerate() {
                    let payload = serde_json::to_vec(&made.event_payload)?;
                    // Validating append (t54); a rejection rolls back `act.sealed` and any document
                    // events already appended in this seal attempt.
                    if let Err(e) = crate::try_append_event(
                        &mut ledger,
                        &actor,
                        &scope,
                        "document.generated",
                        None,
                        &payload,
                    ) {
                        AppState::rollback_ledger_events(
                            &mut ledger,
                            base_events + appended_doc_events,
                        );
                        return Err(e);
                    }
                }
            }
            let book_for_store = book_next.clone();
            let act_for_store = act_next.clone();
            // `Generated` is not `Clone`; capture only the owned `stored` documents the tx needs.
            let docs_stored_for_store: Vec<_> = generated_docs
                .iter()
                .map(|made| made.stored.clone())
                .collect();
            state
                .persist_write_through(&mut ledger, base_events + generated_docs.len(), move |tx| {
                    tx.upsert_book(&book_for_store)?;
                    tx.upsert_act(&act_for_store)?;
                    for stored in &docs_stored_for_store {
                        tx.upsert_document(stored)?;
                    }
                    Ok(())
                })
                .await?;
            for made in &generated_docs {
                crate::documents::publish_generated_document_read_model(&state, &made.stored).await;
            }

            let document = Some(crate::dto::SealDocument {
                id: canonical.id.clone(),
                pdf_digest: canonical.pdf_digest.clone(),
                template_id: canonical.template_id.clone(),
            });

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
    let canonical = crate::documents::load_document(&state, ActId(id)).await?;
    let signed = crate::signature::load_signed(&state, ActId(id)).await?;

    // books → acts → ledger (books only to resolve the entity id for the event scope).
    let books = state.books.read().await;
    let mut acts = state.acts.write().await;
    let mut ledger = state.ledger.write().await;

    let act = acts.get_mut(&ActId(id)).ok_or(ApiError::NotFound)?;
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    ensure_book_open_for_act_mutation(book)?;
    let entity_id = book.entity_id;

    let metadata = act.seal_metadata.as_ref().ok_or_else(|| {
        ApiError::Conflict(
            "legacy incomplete sealed act has no immutable seal evidence metadata; archive is refused pending explicit evidence remediation"
                .to_owned(),
        )
    })?;
    if metadata.manual_signature_original_reference.is_none() {
        if !metadata.has_complete_digital_signature_evidence() {
            return Err(ApiError::Conflict(
                "sealed act has incomplete digital signature evidence metadata; archive is refused"
                    .to_owned(),
            ));
        }
        let canonical = canonical.as_ref().ok_or_else(|| {
            ApiError::Conflict(
                "sealed act's canonical signing snapshot is missing; archive is refused".to_owned(),
            )
        })?;
        let signed = signed.as_ref().ok_or_else(|| {
            ApiError::Conflict(
                "sealed act's signed PDF evidence is missing; archive is refused".to_owned(),
            )
        })?;
        let resolved = validate_digital_seal_evidence(ActId(id), canonical, signed)?;
        let SealEvidence::Digital {
            signing_snapshot_digest,
            signed_pdf_digest,
            signature_validation_report_digest,
        } = resolved.core
        else {
            unreachable!("digital validator only returns digital seal evidence")
        };
        if metadata.signing_snapshot_digest.as_deref() != Some(&signing_snapshot_digest)
            || metadata.signed_pdf_digest.as_deref() != Some(&signed_pdf_digest)
            || metadata.signature_validation_report_digest.as_deref()
                != Some(&signature_validation_report_digest)
        {
            return Err(ApiError::Conflict(
                "sealed act evidence no longer matches its immutable seal digest tuple; archive is refused"
                    .to_owned(),
            ));
        }
    }

    // Archive a clone (Sealed→Archived), committing to the map only after the durable write. Only a
    // sealed act can be archived, else 409.
    let mut next = act.clone();
    next.archive()
        .map_err(|e| ApiError::Conflict(e.to_string()))?;

    let scope = format!("entity:{}/book:{}/act:{}", entity_id, next.book_id, next.id);
    let payload = serde_json::to_vec(&next)?;
    crate::try_append_event(&mut ledger, &actor, &scope, "act.archived", None, &payload)?;
    let next_for_store = next.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| tx.upsert_act(&next_for_store))
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    *act = next;

    Ok(Json(ActView::from(&*act)))
}

/// `POST /v1/acts/{id}/convening/dispatch` — record that the convening notice was dispatched
/// (t61-E1). Stamps `dispatched_at` (+ optional `channel`/dispatch-proof `reference`) on the matching
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
    let next_for_store = next.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| tx.upsert_act(&next_for_store))
        .await?;
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

fn ensure_written_resolution_review_receipts_append_only(
    current: Option<&chancela_core::WrittenResolutionEvidence>,
    next: &chancela_core::WrittenResolutionEvidence,
) -> Result<(), ApiError> {
    let Some(current) = current else {
        return Ok(());
    };
    if next.review_receipts.len() < current.review_receipts.len() {
        return Err(ApiError::Unprocessable(
            "written_resolution_evidence review_receipts are append-only".to_owned(),
        ));
    }
    if !current
        .review_receipts
        .iter()
        .zip(next.review_receipts.iter())
        .all(|(current, next)| current == next)
    {
        return Err(ApiError::Unprocessable(
            "written_resolution_evidence review_receipts are append-only".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_written_resolution_evidence_can_clear(
    current: Option<&chancela_core::WrittenResolutionEvidence>,
) -> Result<(), ApiError> {
    if current.is_some_and(|evidence| !evidence.review_receipts.is_empty()) {
        return Err(ApiError::Unprocessable(
            "written_resolution_evidence with review_receipts cannot be cleared".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path as FsPath, PathBuf};

    use axum::extract::State;
    use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, Scope};
    use chancela_core::{
        AgendaItem, Book, BookKind, MeetingChannel, Mesa, Nipc, NumberingScheme, TermoDeAbertura,
    };
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

    fn opened_book(entity: &Entity, kind: BookKind) -> Book {
        let mut book = Book::new(entity.id, kind);
        book.open(TermoDeAbertura {
            entity_name: entity.name.clone(),
            entity_nipc: entity.nipc.to_string(),
            entity_seat: entity.seat.clone(),
            purpose: "Livro de atas de teste".to_owned(),
            numbering_scheme: NumberingScheme::Sequential,
            opening_date: time::Date::from_calendar_date(2026, time::Month::January, 15)
                .expect("valid opening date"),
            required_signatories: vec!["Administrador".to_owned()],
            required_signatory_records: Vec::new(),
            ..Default::default()
        })
        .expect("test book opens");
        book
    }

    fn text_approved_act(book: &Book) -> Act {
        let mut act = Act::draft(book.id, "Ata de aprovação", MeetingChannel::Physical);
        act.meeting_date = Some(
            time::Date::from_calendar_date(2026, time::Month::March, 30).expect("meeting date"),
        );
        act.meeting_time = Some(time::Time::from_hms(10, 0, 0).expect("meeting time"));
        act.place = Some("Sede social".to_owned());
        act.mesa.presidente = Some("Ana Presidente".to_owned());
        act.mesa.secretarios = vec!["Rui Secretário".to_owned()];
        act.agenda = vec![AgendaItem {
            number: 1,
            text: "Aprovação das contas".to_owned(),
        }];
        act.attendance_reference = Some("Lista de presenças".to_owned());
        act.deliberations = "A deliberação foi aprovada.".to_owned();
        for state in [
            ActState::Review,
            ActState::Convened,
            ActState::Deliberated,
            ActState::TextApproved,
        ] {
            act.advance_to(state).expect("valid lifecycle step");
        }
        act
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
            password_hash: Some(crate::attestation::hash_secret("Teste-Forte7!X").unwrap()),
            attestation_key: None,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
            language: Default::default(),
        };
        state.users.write().await.insert(uid, user);
        CurrentActor::from_session_username(Some(username))
    }

    async fn seed_opened_book_ledger(state: &AppState, entity: &Entity, book: &Book) {
        let mut ledger = state.ledger.write().await;
        crate::try_append_event(
            &mut ledger,
            "patch.owner",
            &format!("entity:{}", entity.id),
            "entity.created",
            None,
            b"entity",
        )
        .expect("entity genesis");
        crate::try_append_event(
            &mut ledger,
            "patch.owner",
            &format!("entity:{}/book:{}", entity.id, book.id),
            "book.opened",
            None,
            b"book",
        )
        .expect("book genesis");
        state
            .persist_write_through(&mut ledger, 2, |_tx| Ok(()))
            .await
            .expect("ledger genesis persists");
    }

    /// wp27-e3 (Part 2): drafting an act emits its `act.drafted` genesis on a `tenant:{t}/...`
    /// scope so the act joins its tenant chain (ChainId::Tenant), mirroring e1's entity change. The
    /// tenant is derived from the parent entity; a non-default tenant proves the derivation is real
    /// (not a hard-stamped default).
    #[tokio::test]
    async fn draft_act_emits_tenant_scoped_genesis() {
        let state = AppState::default();
        let actor = seed_owner(&state).await;
        let tenant = chancela_core::TenantId::new();
        let entity = entity_of(EntityKind::SociedadePorQuotas).in_tenant(tenant);
        let entity_id = entity.id;
        let book = opened_book(&entity, BookKind::AssembleiaGeral);
        let book_id = book.id;
        state.entities.write().await.insert(entity_id, entity);
        state.books.write().await.insert(book_id, book);
        // Seed the tenant-scoped genesis chain (entity.created → book.opened) so the act.drafted
        // append validates against a real book-chain genesis, as it does in production.
        {
            let mut ledger = state.ledger.write().await;
            crate::try_append_event(
                &mut ledger,
                "amelia.marques",
                &format!("tenant:{tenant}/entity:{entity_id}"),
                "entity.created",
                None,
                b"entity",
            )
            .expect("entity genesis");
            crate::try_append_event(
                &mut ledger,
                "amelia.marques",
                &format!("tenant:{tenant}/entity:{entity_id}/book:{book_id}"),
                "book.opened",
                None,
                b"book",
            )
            .expect("book genesis");
            state
                .persist_write_through(&mut ledger, 2, |_tx| Ok(()))
                .await
                .expect("genesis persists");
        }

        let req = DraftAct {
            book_id: book_id.0,
            title: "Ata inaugural".to_owned(),
            channel: MeetingChannel::Physical,
            ai_provenance: None,
            convening: None,
            convening_waiver: None,
            retifies: None,
            actor: "amelia.marques".to_owned(),
        };
        let (status, _view) = draft_act(
            State(state.clone()),
            actor,
            CurrentAttestor::default(),
            Json(req),
        )
        .await
        .expect("draft succeeds");
        assert_eq!(status, StatusCode::CREATED);

        let ledger = state.ledger.read().await;
        let event = ledger
            .events()
            .iter()
            .find(|e| e.kind == "act.drafted")
            .expect("act.drafted emitted");
        assert!(
            event.scope.starts_with(&format!(
                "tenant:{tenant}/entity:{entity_id}/book:{book_id}/act:"
            )),
            "act.drafted scope `{}` lacks the tenant segment",
            event.scope
        );
        let memberships = chancela_ledger::Ledger::memberships(&event.scope, "act.drafted");
        assert!(
            memberships.contains(&chancela_ledger::ChainId::Tenant(tenant.to_string())),
            "act.drafted must join its tenant chain, got {memberships:?}"
        );
    }

    // --- t74 markdown ata body -----------------------------------------------------------------

    /// Seed a persisted draft act in an entity named `entity_name`, ready for PATCH/preview.
    async fn seed_act_for_body(state: &AppState, entity_name: &str) -> (CurrentActor, Act) {
        let actor = seed_owner(state).await;
        let mut entity = entity_of(EntityKind::SociedadePorQuotas);
        entity.name = entity_name.to_owned();
        let book = opened_book(&entity, BookKind::AssembleiaGeral);
        seed_opened_book_ledger(state, &entity, &book).await;
        let act = Act::draft(book.id, "Ata", MeetingChannel::Physical);
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
        (actor, act)
    }

    #[tokio::test]
    async fn patch_act_accepts_a_markdown_body_and_leaves_deliberations_alone() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let (actor, act) = seed_act_for_body(&state, "Encosto Estratégico Lda").await;

        let req: PatchAct = serde_json::from_value(json!({
            "deliberations": "Prosa antiga com **asteriscos** literais.",
            "body": { "format": "Markdown", "source": "# Ata\n\nTexto **relevante**." }
        }))
        .expect("patch body");
        let Json(view) = patch_act(
            State(state.clone()),
            Path(act.id.0),
            actor,
            CurrentAttestor::default(),
            Json(req),
        )
        .await
        .expect("patch succeeds");

        let body = view.body.expect("body is returned");
        assert_eq!(body.source, "# Ata\n\nTexto **relevante**.");
        assert_eq!(body.compiler_id, "md-block/v1");
        assert!(
            body.compiled_digest.is_empty(),
            "nothing is compiled until content freeze; a digest now would be about editable text"
        );
        // t74 §9.2, the subtlest hazard in the design: the two are separate stores and plain prose
        // is never migrated into markup nor re-read as markup.
        assert_eq!(
            view.deliberations,
            "Prosa antiga com **asteriscos** literais."
        );
    }

    #[tokio::test]
    async fn patch_act_rejects_an_unsupported_construct_at_edit_time() {
        // The whole point of validating on save: at the seal gate the act is no longer mutable, so
        // a rejection there would strand it.
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let (actor, act) = seed_act_for_body(&state, "Encosto Estratégico Lda").await;

        let req: PatchAct = serde_json::from_value(json!({
            "body": { "format": "Markdown", "source": "- uma lista" }
        }))
        .expect("patch body");
        // `ActView` is not `Debug`, so unwrap the Result by hand rather than via `expect_err`.
        let err = match patch_act(
            State(state.clone()),
            Path(act.id.0),
            actor,
            CurrentAttestor::default(),
            Json(req),
        )
        .await
        {
            Ok(_) => panic!("a list must be rejected"),
            Err(e) => e,
        };

        let ApiError::InvalidActBody { code, offset, .. } = err else {
            panic!("expected a structured 422, got {err:?}");
        };
        assert_eq!(code, "unsupported_markdown");
        assert!(offset.is_some());
        // And the act is untouched — a rejected edit must not half-apply.
        assert!(
            state.acts.read().await[&act.id].body.is_none(),
            "a rejected body must not be stored"
        );
    }

    #[tokio::test]
    async fn patch_act_rejects_a_malformed_placeholder_at_edit_time() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let (actor, act) = seed_act_for_body(&state, "Encosto Estratégico Lda").await;

        let req: PatchAct = serde_json::from_value(json!({
            "body": { "format": "Markdown", "source": "Ata n.º {{ unclosed" }
        }))
        .expect("patch body");
        let err = match patch_act(
            State(state.clone()),
            Path(act.id.0),
            actor,
            CurrentAttestor::default(),
            Json(req),
        )
        .await
        {
            Ok(_) => panic!("a malformed placeholder must be rejected"),
            Err(e) => e,
        };
        assert!(
            matches!(&err, ApiError::InvalidActBody { code, .. } if *code == "invalid_placeholder"),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn preview_compiles_server_side_and_escapes_structure_from_a_company_name() {
        // t74 §4 + §6 together: the operator previews exactly what will be sealed, and an entity
        // name carrying `#`/`**` contributes text, never document structure.
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let (actor, act) = seed_act_for_body(&state, "# Encosto **Estratégico** Lda").await;

        let req: PreviewActBody = serde_json::from_value(json!({
            "source": "Presente a sociedade {{ entity.name }}."
        }))
        .expect("preview body");
        let Json(preview) =
            preview_act_body(State(state.clone()), Path(act.id.0), actor, Json(req))
                .await
                .expect("preview succeeds");

        assert_eq!(preview.compiler_id, "md-block/v1");
        assert_eq!(preview.blocks.len(), 1, "{:?}", preview.blocks);
        let chancela_core::Block::Paragraph { runs } = &preview.blocks[0] else {
            panic!("the `#` became structure: {:?}", preview.blocks[0]);
        };
        assert!(runs.iter().all(|r| !r.bold), "the `**` became emphasis");
        let text: String = runs.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(text, "Presente a sociedade # Encosto **Estratégico** Lda.");
    }

    #[tokio::test]
    async fn preview_matches_what_freeze_produces() {
        // The identity the endpoint exists to guarantee. If these could differ, the preview would be
        // a second implementation and the operator would approve something other than what seals.
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let (actor, act) = seed_act_for_body(&state, "# Encosto **Lda**").await;
        let source = "# Ata\n\nPresente: **{{ entity.name }}**.";

        let req: PreviewActBody =
            serde_json::from_value(json!({ "source": source })).expect("preview body");
        let Json(preview) =
            preview_act_body(State(state.clone()), Path(act.id.0), actor, Json(req))
                .await
                .expect("preview succeeds");

        let mut frozen_act = act.clone();
        frozen_act.body = Some(ActBody {
            format: chancela_core::BodyFormat::Markdown,
            source: source.to_owned(),
            compiler_id: chancela_templates::markdown::COMPILER_ID.to_owned(),
            compiled_digest: String::new(),
        });
        let entity = {
            let books = state.books.read().await;
            let entities = state.entities.read().await;
            entities[&books[&act.book_id].entity_id].clone()
        };
        let (_body, frozen_blocks) = crate::documents::freeze_act_body(&frozen_act, &entity)
            .expect("freeze")
            .expect("has body");

        assert_eq!(
            preview.blocks, frozen_blocks,
            "the preview must be byte-for-byte what content freeze compiles"
        );
    }

    #[tokio::test]
    async fn advancing_to_signing_with_a_body_is_refused_while_no_template_can_carry_one() {
        // The fail-closed gate at the handler boundary (t74 §9.3 through the placement seam). Until
        // an ata template carries a placement anchor, an act with a narrative body must not reach a
        // sealed PDF/A that omits it. The operator is told; nothing is dropped quietly.
        //
        // Freeze mechanics themselves are covered by `documents::tests::
        // freezing_records_the_compiler_and_a_digest_of_what_it_compiled`, which does not have to
        // walk the lifecycle to assert them.
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let (actor, act) = seed_act_for_body(&state, "Encosto Estratégico Lda").await;

        let patch: PatchAct = serde_json::from_value(json!({
            "body": { "format": "Markdown", "source": "# Ata\n\nTexto." }
        }))
        .expect("patch body");
        patch_act(
            State(state.clone()),
            Path(act.id.0),
            actor.clone(),
            CurrentAttestor::default(),
            Json(patch),
        )
        .await
        .expect("body saved");

        // Satisfy the art. 63.º baseline. Deliberately **no** `deliberations` and no
        // `deliberation_items`: the markup body alone now satisfies the substance rule
        // (`has_substance`), which is what lets this act reach the placement gate at all instead of
        // being turned away earlier for recording no substance.
        {
            let mut acts = state.acts.write().await;
            let seeded = acts.get_mut(&act.id).expect("seeded act");
            seeded.meeting_date = Some(time::macros::date!(2026 - 07 - 19));
            seeded.place = Some("Lisboa".to_owned());
            seeded.attendance_reference = Some("Lista de presenças anexa".to_owned());
            seeded.mesa.presidente = Some("Amélia Marques".to_owned());
        }

        for target in ["Review", "Convened", "Deliberated", "TextApproved"] {
            let req: AdvanceAct =
                serde_json::from_value(json!({ "to": target })).expect("advance body");
            advance_act(
                State(state.clone()),
                Path(act.id.0),
                actor.clone(),
                CurrentAttestor::default(),
                Json(req),
            )
            .await
            .unwrap_or_else(|e| panic!("advance to {target} failed: {e:?}"));
        }

        let req: AdvanceAct = serde_json::from_value(json!({ "to": "Signing" })).expect("body");
        let err = match advance_act(
            State(state.clone()),
            Path(act.id.0),
            actor,
            CurrentAttestor::default(),
            Json(req),
        )
        .await
        {
            Ok(_) => panic!("advancing with an unplaceable body must be refused"),
            Err(e) => e,
        };
        assert!(
            matches!(&err, ApiError::Unprocessable(m) if m.contains("no place for this act's narrative body")),
            "the refusal must say why: {err:?}"
        );
        // ...and the act is not left half-advanced.
        assert_ne!(state.acts.read().await[&act.id].state, ActState::Signing);
    }

    #[tokio::test]
    async fn patch_act_persists_content_bound_audit_event() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;
        let entity = entity_of(EntityKind::SociedadePorQuotas);
        let book = opened_book(&entity, BookKind::AssembleiaGeral);
        seed_opened_book_ledger(&state, &entity, &book).await;
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
        let Json(view) = patch_act(
            State(state.clone()),
            Path(act.id.0),
            actor,
            CurrentAttestor::default(),
            Json(req),
        )
        .await
        .expect("patch succeeds");

        assert_eq!(view.title, "Draft edit survives restart");
        let updated = state
            .acts
            .read()
            .await
            .get(&act.id)
            .cloned()
            .expect("updated act");
        let expected_event_payload = act_updated_event_payload(&updated).expect("event payload");
        let expected_digest: [u8; 32] = Sha256::digest(&expected_event_payload).into();
        let ledger = state.ledger.read().await;
        assert_eq!(ledger.len(), before_events + 1);
        let event = ledger.events().last().expect("act.updated event");
        assert_eq!(event.kind, "act.updated");
        assert_eq!(event.payload_digest, expected_digest);
        let payload: serde_json::Value =
            serde_json::from_slice(&expected_event_payload).expect("audit payload JSON");
        assert_eq!(payload["act_id"], act.id.to_string());
        assert_eq!(payload["content_sha256"].as_str().map(str::len), Some(64));
        assert_eq!(payload["secrets_in_payload"], false);
        assert!(payload.get("title").is_none());
        drop(ledger);

        let restarted = AppState::with_data_dir(tmp.path());
        let acts = restarted.acts.read().await;
        let loaded = acts.get(&act.id).expect("act reloads");
        assert_eq!(loaded.title, "Draft edit survives restart");
        assert_eq!(
            loaded.deliberations,
            "Working text persisted before sealing."
        );
    }

    #[tokio::test]
    async fn patch_act_persistence_failure_rolls_back_event_and_read_model() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;
        let entity = entity_of(EntityKind::SociedadePorQuotas);
        let book = opened_book(&entity, BookKind::AssembleiaGeral);
        seed_opened_book_ledger(&state, &entity, &book).await;
        let act = Act::draft(book.id, "Original title", MeetingChannel::Physical);

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
        let request: PatchAct = serde_json::from_value(json!({
            "title": "__chancela_test_fail_patch_persist__"
        }))
        .expect("patch body");
        let error = match patch_act(
            State(state.clone()),
            Path(act.id.0),
            actor,
            CurrentAttestor::default(),
            Json(request),
        )
        .await
        {
            Ok(_) => panic!("injected persistence failure must reject the patch"),
            Err(error) => error,
        };
        assert!(matches!(error, ApiError::Internal(_)));
        assert_eq!(state.ledger.read().await.len(), before_events);
        assert_eq!(
            state
                .acts
                .read()
                .await
                .get(&act.id)
                .map(|row| row.title.as_str()),
            Some("Original title")
        );

        let restarted = AppState::with_data_dir(tmp.path());
        assert_eq!(
            restarted
                .acts
                .read()
                .await
                .get(&act.id)
                .map(|row| row.title.as_str()),
            Some("Original title")
        );
    }

    /// wp27-e9 invariant #4 (atomicity across the async boundary): `persist_write_through` is now an
    /// `async fn` that offloads the durable transaction onto tokio's blocking pool via
    /// `Store::persist_blocking_async` (`spawn_blocking`). A durable-write failure — surfaced from
    /// inside that offloaded closure — must still leave the in-memory ledger UNMUTATED (rebuilt
    /// without the just-appended tail) and must NOT advance the durable chain. This runs on the
    /// **multi-threaded** runtime (the production flavor), so the failure is observed after a real
    /// worker→blocking-thread→worker handoff, and the ledger write guard is held across the whole
    /// `.await` (no release/reacquire), which is what keeps sequence numbers from interleaving.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_persist_leaves_in_memory_ledger_unmutated_across_async_boundary() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let entity = entity_of(EntityKind::SociedadePorQuotas);
        let book = opened_book(&entity, BookKind::AssembleiaGeral);
        seed_opened_book_ledger(&state, &entity, &book).await;

        let events_before = state.ledger.read().await.len();

        // Append an event in memory, then attempt a durable persist whose `upserts` closure fails
        // *inside* the offloaded blocking task. The write guard is held across the `.await`.
        let error = {
            let mut ledger = state.ledger.write().await;
            crate::try_append_event(
                &mut ledger,
                "patch.owner",
                &format!("entity:{}/book:{}", entity.id, book.id),
                "book.metadata_noted",
                None,
                b"tail event that must be rolled back",
            )
            .expect("append tail event");
            assert_eq!(
                ledger.len(),
                events_before + 1,
                "the event is appended to the in-memory ledger before the durable write"
            );
            state
                .persist_write_through(&mut ledger, 1, |_tx| {
                    Err(chancela_store::StoreError::BadBackup(
                        "injected durable-write failure across the async boundary".to_owned(),
                    ))
                })
                .await
                .expect_err("a failed durable persist must return an error")
        };
        assert!(matches!(error, ApiError::Internal(_)));

        // The in-memory ledger was rebuilt WITHOUT the just-appended tail event.
        assert_eq!(
            state.ledger.read().await.len(),
            events_before,
            "a failed persist must leave the in-memory ledger unmutated"
        );

        // The durable chain never advanced: a fresh state hydrated from the same data dir reloads
        // exactly the pre-failure length.
        let restarted = AppState::with_data_dir(tmp.path());
        assert_eq!(
            restarted.ledger.read().await.len(),
            events_before,
            "a failed persist must not extend the durable chain"
        );
    }

    #[tokio::test]
    async fn signing_snapshot_precedes_seal_and_manual_evidence_can_archive() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;
        let entity = entity_of(EntityKind::SociedadePorQuotas);
        let book = opened_book(&entity, BookKind::AssembleiaGeral);
        seed_opened_book_ledger(&state, &entity, &book).await;
        let act = text_approved_act(&book);
        let act_id = act.id;

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
        state.acts.write().await.insert(act_id, act);

        let advance: AdvanceAct =
            serde_json::from_value(json!({ "to": "Signing" })).expect("advance body");
        let _ = advance_act(
            State(state.clone()),
            Path(act_id.0),
            actor.clone(),
            CurrentAttestor::default(),
            Json(advance),
        )
        .await
        .expect("enter Signing and create snapshot");
        assert_eq!(
            state.acts.read().await.get(&act_id).map(|row| row.state),
            Some(ActState::Signing)
        );
        let canonical = crate::documents::load_document(&state, act_id)
            .await
            .expect("document read")
            .expect("canonical signing snapshot");
        assert_eq!(sha256_hex(&canonical.pdf_bytes), canonical.pdf_digest);

        let edit: PatchAct =
            serde_json::from_value(json!({ "title": "Late replacement" })).expect("patch body");
        let edit_error = match patch_act(
            State(state.clone()),
            Path(act_id.0),
            actor.clone(),
            CurrentAttestor::default(),
            Json(edit),
        )
        .await
        {
            Ok(_) => panic!("Signing content must be immutable"),
            Err(error) => error,
        };
        assert!(matches!(edit_error, ApiError::Conflict(_)));

        let before_unsigned_seal = state.ledger.read().await.len();
        let unsigned_error = seal_act_handler(
            State(state.clone()),
            Path(act_id.0),
            actor.clone(),
            CurrentAttestor::default(),
            None,
        )
        .await
        .expect_err("unsigned digital seal must be rejected");
        assert!(
            matches!(unsigned_error, ApiError::Conflict(message) if message == SEAL_EVIDENCE_REQUIRED)
        );
        assert_eq!(state.ledger.read().await.len(), before_unsigned_seal);
        assert_eq!(
            state.acts.read().await.get(&act_id).map(|row| row.state),
            Some(ActState::Signing)
        );

        let manual: SealAct = serde_json::from_value(json!({
            "manual_signature_original_reference": {
                "storage_reference": "Arquivo A / Pasta 2026 / original assinado",
                "custodian": "Secretariado"
            }
        }))
        .expect("manual seal body");
        let response = seal_act_handler(
            State(state.clone()),
            Path(act_id.0),
            actor.clone(),
            CurrentAttestor::default(),
            Some(Json(manual)),
        )
        .await
        .expect("manual evidence seal");
        assert_eq!(response.status(), StatusCode::OK);
        let sealed = state
            .acts
            .read()
            .await
            .get(&act_id)
            .cloned()
            .expect("sealed act");
        assert_eq!(sealed.state, ActState::Sealed);
        let metadata = sealed.seal_metadata.expect("seal metadata");
        assert!(metadata.manual_signature_original_reference.is_some());
        assert!(metadata.signed_pdf_digest.is_none());

        let _ = archive_act(
            State(state.clone()),
            Path(act_id.0),
            actor,
            CurrentAttestor::default(),
            None,
        )
        .await
        .expect("manual-evidence act archives");
        assert_eq!(
            state.acts.read().await.get(&act_id).map(|row| row.state),
            Some(ActState::Archived)
        );
    }

    #[tokio::test]
    async fn patch_act_written_resolution_evidence_round_trips_and_persists() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;
        let entity = entity_of(EntityKind::SociedadePorQuotas);
        let book = opened_book(&entity, BookKind::AssembleiaGeral);
        seed_opened_book_ledger(&state, &entity, &book).await;
        let act = Act::draft(
            book.id,
            "Written resolution",
            MeetingChannel::WrittenResolution,
        );
        let act_id = act.id;

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
        state.acts.write().await.insert(act.id, act);

        let digest = "11".repeat(32);
        let req: PatchAct = serde_json::from_value(json!({
            "written_resolution_evidence": {
                "note": "operator-private evidence note",
                "checklist": [{
                    "label": "Signed approvals pack",
                    "reference": "doc:written-approvals",
                    "digest": digest,
                    "note": "retained in document store"
                }],
                "review_receipts": [{
                    "reviewer": "operator@example.test",
                    "reviewed_at": "2026-07-13T10:15:00Z",
                    "status": "reviewed",
                    "guardrail_acknowledgements": [
                        "local_metadata_only",
                        "no_consent_quorum_identity_or_legal_proof"
                    ],
                    "evidence": [{
                        "label": "Approval pack digest checked",
                        "locator": "doc:written-approvals",
                        "digest": digest
                    }],
                    "note": "local evidence review completed",
                    "consent_proof_claimed": false,
                    "quorum_proof_claimed": false,
                    "identity_proof_claimed": false,
                    "legal_acceptance_claimed": false,
                    "legal_sufficiency_claimed": false,
                    "external_validation_claimed": false,
                    "automatic_approval_claimed": false,
                    "authority_certified_claimed": false
                }]
            }
        }))
        .expect("patch body");
        let Json(view) = patch_act(
            State(state.clone()),
            Path(act_id.0),
            actor.clone(),
            CurrentAttestor::default(),
            Json(req),
        )
        .await
        .expect("patch succeeds");

        let evidence = view
            .written_resolution_evidence
            .expect("evidence metadata returned");
        assert_eq!(evidence.status.status, "bound_present");
        assert_eq!(evidence.status.bound_count, 1);
        assert_eq!(evidence.status.digested_checklist_items, 1);
        assert_eq!(evidence.status.review_receipts, 1);
        assert_eq!(
            evidence.status.latest_review_status.as_deref(),
            Some("reviewed")
        );
        assert_eq!(evidence.status.reviewed_evidence_locators, 1);
        assert_eq!(evidence.status.reviewed_evidence_digests, 1);
        assert_eq!(
            evidence.checklist[0].digest.as_deref(),
            Some(digest.as_str())
        );
        let receipt = &evidence.review_receipts[0];
        assert_eq!(receipt.reviewer, "operator@example.test");
        assert_eq!(receipt.reviewed_at, "2026-07-13T10:15:00Z");
        assert_eq!(receipt.status, "reviewed");
        assert!(!receipt.legal_sufficiency_claimed);
        assert!(!receipt.authority_certified_claimed);

        let restarted = AppState::with_data_dir(tmp.path());
        let acts = restarted.acts.read().await;
        let loaded = acts.get(&act_id).expect("act reloads");
        let loaded_evidence = loaded
            .written_resolution_evidence
            .as_ref()
            .expect("evidence persisted");
        assert_eq!(
            loaded_evidence.note.as_deref(),
            Some("operator-private evidence note")
        );
        assert_eq!(loaded_evidence.checklist[0].digest, Some([0x11; 32]));
        assert_eq!(loaded_evidence.review_receipts.len(), 1);
        assert_eq!(
            loaded_evidence.review_receipts[0].guardrail_acknowledgements,
            vec![
                "local_metadata_only".to_owned(),
                "no_consent_quorum_identity_or_legal_proof".to_owned()
            ]
        );

        drop(acts);
        let clear_req: PatchAct = serde_json::from_value(json!({
            "written_resolution_evidence": null
        }))
        .expect("clear body");
        let err = match patch_act(
            State(state),
            Path(act_id.0),
            actor,
            CurrentAttestor::default(),
            Json(clear_req),
        )
        .await
        {
            Ok(_) => panic!("receipt history cannot be cleared"),
            Err(err) => err,
        };
        match err {
            ApiError::Unprocessable(message) => {
                assert!(message.contains("review_receipts"));
                assert!(message.contains("cannot be cleared"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn patch_act_written_resolution_review_receipts_reject_proof_claims() {
        let state = AppState::default();
        let actor = seed_owner(&state).await;
        let entity = entity_of(EntityKind::SociedadePorQuotas);
        let book = opened_book(&entity, BookKind::AssembleiaGeral);
        seed_opened_book_ledger(&state, &entity, &book).await;
        let act = Act::draft(
            book.id,
            "Written resolution",
            MeetingChannel::WrittenResolution,
        );
        let act_id = act.id;

        state.entities.write().await.insert(entity.id, entity);
        state.books.write().await.insert(book.id, book);
        state.acts.write().await.insert(act.id, act);

        let req: PatchAct = serde_json::from_value(json!({
            "written_resolution_evidence": {
                "review_receipts": [{
                    "reviewer": "operator@example.test",
                    "reviewed_at": "2026-07-13T10:15:00Z",
                    "status": "reviewed",
                    "guardrail_acknowledgements": ["local_metadata_only"],
                    "evidence": [{
                        "label": "Approval folder",
                        "locator": "folder:approvals"
                    }],
                    "legal_sufficiency_claimed": true
                }]
            }
        }))
        .expect("patch body");

        let err = match patch_act(
            State(state),
            Path(act_id.0),
            actor,
            CurrentAttestor::default(),
            Json(req),
        )
        .await
        {
            Ok(_) => panic!("proof/legal claims are rejected"),
            Err(err) => err,
        };
        match err {
            ApiError::Unprocessable(message) => {
                assert!(message.contains("legal_sufficiency_claimed"));
                assert!(message.contains("must be false"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn compliance_reports_written_resolution_evidence_status_only() {
        let state = AppState::default();
        let actor = seed_owner(&state).await;
        let entity = entity_of(EntityKind::SociedadeAnonima);
        let book = opened_book(&entity, BookKind::AssembleiaGeral);
        let mut act = Act::draft(
            book.id,
            "Written resolution",
            MeetingChannel::WrittenResolution,
        );
        act.meeting_date =
            Some(time::Date::from_calendar_date(2026, time::Month::March, 1).expect("valid date"));
        act.meeting_time = Some(time::Time::from_hms(10, 0, 0).expect("valid time"));
        act.place = Some("Sede social".to_owned());
        act.mesa = Mesa {
            presidente: Some("Presidente".to_owned()),
            secretarios: vec!["Secretario".to_owned()],
        };
        act.agenda = vec![AgendaItem {
            number: 1,
            text: "Ponto unico".to_owned(),
        }];
        act.attendance_reference = Some("Lista de presencas".to_owned());
        act.deliberations = "Deliberacao por escrito registada.".to_owned();
        act.written_resolution_evidence = Some(chancela_core::WrittenResolutionEvidence {
            checklist: vec![chancela_core::WrittenResolutionEvidenceItem {
                label: "Approval reference".to_owned(),
                reference: Some("folder:approvals".to_owned()),
                digest: None,
                note: Some("reference only".to_owned()),
            }],
            review_receipts: vec![],
            note: None,
        });
        let act_id = act.id;

        state.entities.write().await.insert(entity.id, entity);
        state.books.write().await.insert(book.id, book);
        state.acts.write().await.insert(act.id, act);

        let Json(report) = get_compliance(State(state.clone()), Path(act_id.0), actor.clone())
            .await
            .expect("compliance succeeds");
        assert_eq!(
            report.written_resolution_evidence_status.status,
            "referenced_only"
        );
        assert_eq!(
            report.written_resolution_evidence_status.boundary,
            chancela_core::WRITTEN_RESOLUTION_EVIDENCE_STATUS_BOUNDARY
        );
        assert_eq!(
            report
                .written_resolution_evidence_status
                .referenced_checklist_items,
            1
        );
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.rule_id == "CSC-54/written-resolution-evidence")
        );

        {
            let mut acts = state.acts.write().await;
            let act = acts.get_mut(&act_id).expect("act exists");
            act.written_resolution_evidence.as_mut().unwrap().checklist[0].digest =
                Some([0x22; 32]);
        }

        let Json(report) = get_compliance(State(state.clone()), Path(act_id.0), actor.clone())
            .await
            .expect("compliance succeeds");
        assert_eq!(
            report.written_resolution_evidence_status.status,
            "bound_present"
        );
        assert_eq!(report.written_resolution_evidence_status.bound_count, 1);
        assert!(
            !report
                .issues
                .iter()
                .any(|issue| issue.rule_id == "CSC-54/written-resolution-evidence")
        );

        {
            let mut acts = state.acts.write().await;
            acts.get_mut(&act_id).expect("act exists").channel = MeetingChannel::Physical;
        }
        let Json(report) = get_compliance(State(state), Path(act_id.0), actor)
            .await
            .expect("compliance succeeds");
        assert_eq!(
            report.written_resolution_evidence_status.status,
            "not_applicable"
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
        let book = opened_book(&entity, BookKind::AssembleiaGeral);
        seed_opened_book_ledger(&state, &entity, &book).await;
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
            CurrentAttestor::default(),
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
            CurrentAttestor::default(),
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
            CurrentAttestor::default(),
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
            CurrentAttestor::default(),
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
        let book = opened_book(&entity, BookKind::AssembleiaGeral);
        seed_opened_book_ledger(&state, &entity, &book).await;
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
            CurrentAttestor::default(),
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
            CurrentAttestor::default(),
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
