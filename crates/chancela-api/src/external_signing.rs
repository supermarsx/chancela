//! External signing envelope API.
//!
//! This is a thin API slice over `chancela-core`'s external-signing model. It records workflow
//! state and evidence locators/digests only; it does not assert legal effect, certificate level, or
//! qualified electronic signature status.

use std::collections::HashMap;
use std::path::{Path as FsPath, PathBuf};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chancela_authz::Permission;
use chancela_core::external_signing::ExternalSignerIdentityRequirement;
use chancela_core::{
    ActId, ExternalSignatureCompletionSummary, ExternalSignatureEnvelope,
    ExternalSignatureEnvelopeId, ExternalSignatureEvidence, ExternalSignerSlot,
    ExternalSignerSlotId, ExternalSignerSlotStatus, ExternalSigningError,
    ExternalSigningOrderPolicy,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{require_permission, scope_of_act};
use crate::error::ApiError;
use crate::{AppState, try_append_event};

pub(crate) const EXTERNAL_SIGNING_ENVELOPES_FILE: &str = "external-signing-envelopes.json";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSigningOrderPolicyDto {
    #[default]
    Parallel,
    Sequential,
}

impl From<ExternalSigningOrderPolicyDto> for ExternalSigningOrderPolicy {
    fn from(value: ExternalSigningOrderPolicyDto) -> Self {
        match value {
            ExternalSigningOrderPolicyDto::Parallel => Self::Parallel,
            ExternalSigningOrderPolicyDto::Sequential => Self::Sequential,
        }
    }
}

impl From<ExternalSigningOrderPolicy> for ExternalSigningOrderPolicyDto {
    fn from(value: ExternalSigningOrderPolicy) -> Self {
        match value {
            ExternalSigningOrderPolicy::Parallel => Self::Parallel,
            ExternalSigningOrderPolicy::Sequential => Self::Sequential,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSignerIdentityRequirementDto {
    ContactControl,
    ProviderIdentityAssertion,
    GovernmentIdCheck,
    RepresentativeCapacity,
}

impl From<ExternalSignerIdentityRequirementDto> for ExternalSignerIdentityRequirement {
    fn from(value: ExternalSignerIdentityRequirementDto) -> Self {
        match value {
            ExternalSignerIdentityRequirementDto::ContactControl => Self::ContactControl,
            ExternalSignerIdentityRequirementDto::ProviderIdentityAssertion => {
                Self::ProviderIdentityAssertion
            }
            ExternalSignerIdentityRequirementDto::GovernmentIdCheck => Self::GovernmentIdCheck,
            ExternalSignerIdentityRequirementDto::RepresentativeCapacity => {
                Self::RepresentativeCapacity
            }
        }
    }
}

impl From<ExternalSignerIdentityRequirement> for ExternalSignerIdentityRequirementDto {
    fn from(value: ExternalSignerIdentityRequirement) -> Self {
        match value {
            ExternalSignerIdentityRequirement::ContactControl => Self::ContactControl,
            ExternalSignerIdentityRequirement::ProviderIdentityAssertion => {
                Self::ProviderIdentityAssertion
            }
            ExternalSignerIdentityRequirement::GovernmentIdCheck => Self::GovernmentIdCheck,
            ExternalSignerIdentityRequirement::RepresentativeCapacity => {
                Self::RepresentativeCapacity
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSignerSlotStatusDto {
    Pending,
    Initiated,
    Signed,
    Declined,
    Revoked,
    Expired,
}

impl From<ExternalSignerSlotStatusDto> for ExternalSignerSlotStatus {
    fn from(value: ExternalSignerSlotStatusDto) -> Self {
        match value {
            ExternalSignerSlotStatusDto::Pending => Self::Pending,
            ExternalSignerSlotStatusDto::Initiated => Self::Initiated,
            ExternalSignerSlotStatusDto::Signed => Self::Signed,
            ExternalSignerSlotStatusDto::Declined => Self::Declined,
            ExternalSignerSlotStatusDto::Revoked => Self::Revoked,
            ExternalSignerSlotStatusDto::Expired => Self::Expired,
        }
    }
}

impl From<ExternalSignerSlotStatus> for ExternalSignerSlotStatusDto {
    fn from(value: ExternalSignerSlotStatus) -> Self {
        match value {
            ExternalSignerSlotStatus::Pending => Self::Pending,
            ExternalSignerSlotStatus::Initiated => Self::Initiated,
            ExternalSignerSlotStatus::Signed => Self::Signed,
            ExternalSignerSlotStatus::Declined => Self::Declined,
            ExternalSignerSlotStatus::Revoked => Self::Revoked,
            ExternalSignerSlotStatus::Expired => Self::Expired,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateEnvelopeRequest {
    #[serde(default)]
    pub order_policy: ExternalSigningOrderPolicyDto,
    pub slots: Vec<CreateSlotRequest>,
    #[serde(default)]
    pub actor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSlotRequest {
    pub signer_label: String,
    #[serde(default)]
    pub contact_hint: Option<String>,
    #[serde(default)]
    pub identity_requirements: Vec<ExternalSignerIdentityRequirementDto>,
    #[serde(default = "default_required")]
    pub required: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchEnvelopeRequest {
    #[serde(default)]
    pub slots: Vec<PatchSlotRequest>,
    #[serde(default)]
    pub complete: bool,
    #[serde(default)]
    pub actor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchSlotRequest {
    pub id: Uuid,
    pub status: ExternalSignerSlotStatusDto,
    #[serde(default)]
    pub evidence: Vec<EvidenceRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRequest {
    pub label: String,
    pub reference: String,
    #[serde(default)]
    pub identity_requirement: Option<ExternalSignerIdentityRequirementDto>,
    #[serde(default)]
    pub digest: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EnvelopeView {
    pub id: String,
    pub act_id: String,
    pub order_policy: ExternalSigningOrderPolicyDto,
    pub slots: Vec<SlotView>,
    pub completed: bool,
    pub completion: CompletionSummaryView,
    pub notice: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SlotView {
    pub id: String,
    pub signer_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_hint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub identity_requirements: Vec<ExternalSignerIdentityRequirementDto>,
    pub required: bool,
    pub status: ExternalSignerSlotStatusDto,
    pub evidence: Vec<EvidenceView>,
}

#[derive(Debug, Serialize)]
pub struct EvidenceView {
    pub label: String,
    pub reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_requirement: Option<ExternalSignerIdentityRequirementDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CompletionSummaryView {
    pub completed: bool,
    pub required_slot_count: usize,
    pub signed_required_slot_count: usize,
    pub blocking_required_slot_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkedExternalInviteSlotSignOutcome {
    Signed,
    AlreadySigned,
    IdentityRequirementsPresent,
}

pub(crate) struct LinkedExternalInviteSlotSignedPdfEvidence<'a> {
    pub(crate) actor: &'a str,
    pub(crate) attestor: &'a CurrentAttestor,
    pub(crate) act_id: ActId,
    pub(crate) envelope_id: ExternalSignatureEnvelopeId,
    pub(crate) slot_id: ExternalSignerSlotId,
    pub(crate) invite_id: Uuid,
    pub(crate) document_id: &'a str,
    pub(crate) signed_pdf_digest: &'a str,
}

pub async fn create_envelope(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateEnvelopeRequest>,
) -> Result<(StatusCode, Json<EnvelopeView>), ApiError> {
    let act_id = ActId(id);
    let scope = scope_of_act(&state, act_id).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    ensure_act_exists(&state, act_id).await?;
    let actor_name = actor.resolve(req.actor.as_deref().unwrap_or("api"));

    let slots = req
        .slots
        .into_iter()
        .map(|slot| {
            let id = ExternalSignerSlotId::new();
            let identity_requirements = slot
                .identity_requirements
                .into_iter()
                .map(Into::into)
                .collect();
            let slot = if slot.required {
                ExternalSignerSlot::required(
                    id,
                    slot.signer_label,
                    clean_optional(slot.contact_hint),
                )
            } else {
                ExternalSignerSlot::optional(
                    id,
                    slot.signer_label,
                    clean_optional(slot.contact_hint),
                )
            };
            slot.with_identity_requirements(identity_requirements)
        })
        .collect();
    let envelope = ExternalSignatureEnvelope::new(act_id, req.order_policy.into(), slots)
        .map_err(map_external_signing_error)?;
    let view = EnvelopeView::from(&envelope);

    state
        .external_signing_envelopes
        .write()
        .await
        .insert(envelope.id, envelope);
    persist_envelopes(&state).await?;
    record_envelope_event(
        &state,
        &actor_name,
        &attestor,
        act_id,
        "signature.external_envelope.created",
        &view,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(view)))
}

pub async fn list_envelopes_for_act(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<Vec<EnvelopeView>>, ApiError> {
    let act_id = ActId(id);
    let scope = scope_of_act(&state, act_id).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    ensure_act_exists(&state, act_id).await?;
    let mut views: Vec<_> = state
        .external_signing_envelopes
        .read()
        .await
        .values()
        .filter(|envelope| envelope.act_id == act_id)
        .map(EnvelopeView::from)
        .collect();
    views.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(Json(views))
}

pub async fn get_envelope(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<EnvelopeView>, ApiError> {
    let envelope = find_envelope(&state, ExternalSignatureEnvelopeId(id)).await?;
    let scope = scope_of_act(&state, envelope.act_id).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    Ok(Json(EnvelopeView::from(&envelope)))
}

pub async fn patch_envelope(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchEnvelopeRequest>,
) -> Result<Json<EnvelopeView>, ApiError> {
    if req.slots.is_empty() && !req.complete {
        return Err(ApiError::Unprocessable(
            "at least one slot update or complete=true is required".to_owned(),
        ));
    }

    let envelope_id = ExternalSignatureEnvelopeId(id);
    let mut envelope = find_envelope(&state, envelope_id).await?;
    let scope = scope_of_act(&state, envelope.act_id).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    let actor_name = actor.resolve(req.actor.as_deref().unwrap_or("api"));

    for slot in req.slots {
        apply_slot_update(&mut envelope, slot)?;
    }
    if req.complete {
        envelope.complete().map_err(map_external_signing_error)?;
    }
    let view = EnvelopeView::from(&envelope);

    state
        .external_signing_envelopes
        .write()
        .await
        .insert(envelope_id, envelope);
    persist_envelopes(&state).await?;
    record_envelope_event(
        &state,
        &actor_name,
        &attestor,
        view.act_id
            .parse::<Uuid>()
            .map(ActId)
            .map_err(|e| ApiError::Internal(format!("envelope view act id invalid: {e}")))?,
        "signature.external_envelope.updated",
        &view,
    )
    .await?;

    Ok(Json(view))
}

pub(crate) struct PreparedExternalInviteSlotInitiation {
    envelope_id: ExternalSignatureEnvelopeId,
    previous: ExternalSignatureEnvelope,
    updated: ExternalSignatureEnvelope,
    view: EnvelopeView,
}

impl PreparedExternalInviteSlotInitiation {
    pub(crate) fn view(&self) -> &EnvelopeView {
        &self.view
    }
}

pub(crate) struct CommittedExternalInviteSlotInitiation {
    envelope_id: ExternalSignatureEnvelopeId,
    previous: ExternalSignatureEnvelope,
    view: EnvelopeView,
}

impl CommittedExternalInviteSlotInitiation {
    pub(crate) fn view(&self) -> &EnvelopeView {
        &self.view
    }

    pub(crate) async fn rollback(self, state: &AppState) -> Result<(), ApiError> {
        restore_envelope_snapshot(state, self.envelope_id, self.previous).await
    }
}

pub(crate) async fn prepare_envelope_slot_for_external_invite(
    state: &AppState,
    act_id: ActId,
    envelope_id: ExternalSignatureEnvelopeId,
    slot_id: ExternalSignerSlotId,
) -> Result<PreparedExternalInviteSlotInitiation, ApiError> {
    let previous = find_envelope(state, envelope_id).await?;
    if previous.act_id != act_id || previous.slot(slot_id).is_none() {
        return Err(ApiError::NotFound);
    }

    let mut updated = previous.clone();
    updated
        .initiate_slot(slot_id)
        .map_err(map_external_signing_error)?;
    let view = EnvelopeView::from(&updated);

    Ok(PreparedExternalInviteSlotInitiation {
        envelope_id,
        previous,
        updated,
        view,
    })
}

pub(crate) async fn commit_envelope_slot_for_external_invite(
    state: &AppState,
    prepared: PreparedExternalInviteSlotInitiation,
) -> Result<CommittedExternalInviteSlotInitiation, ApiError> {
    let PreparedExternalInviteSlotInitiation {
        envelope_id,
        previous,
        updated,
        view,
    } = prepared;

    {
        let mut envelopes = state.external_signing_envelopes.write().await;
        match envelopes.get(&envelope_id) {
            Some(current) if current == &previous => {
                envelopes.insert(envelope_id, updated);
            }
            Some(_) => {
                return Err(ApiError::Conflict(
                    "external signing envelope changed while creating linked invite".to_owned(),
                ));
            }
            None => return Err(ApiError::NotFound),
        }
    }

    if let Err(err) = persist_envelopes(state).await {
        if let Err(rollback_err) =
            restore_envelope_snapshot(state, envelope_id, previous.clone()).await
        {
            eprintln!(
                "warning: failed to roll back linked external invite slot initiation after persist error: {rollback_err:?}"
            );
        }
        return Err(err);
    }

    Ok(CommittedExternalInviteSlotInitiation {
        envelope_id,
        previous,
        view,
    })
}

pub(crate) async fn sign_linked_external_invite_slot_from_signed_pdf(
    state: &AppState,
    req: LinkedExternalInviteSlotSignedPdfEvidence<'_>,
) -> Result<LinkedExternalInviteSlotSignOutcome, ApiError> {
    let digest = crate::hex::parse_hex32(req.signed_pdf_digest).ok_or_else(|| {
        ApiError::Internal("stored signed PDF digest is not a SHA-256 hex digest".to_owned())
    })?;
    let evidence =
        linked_external_invite_signed_pdf_evidence(req.invite_id, req.document_id, digest);

    let previous = find_envelope(state, req.envelope_id).await?;
    if previous.act_id != req.act_id {
        return Err(ApiError::NotFound);
    }
    let slot = previous.slot(req.slot_id).ok_or(ApiError::NotFound)?;
    if !slot.identity_requirements.is_empty() {
        return Ok(LinkedExternalInviteSlotSignOutcome::IdentityRequirementsPresent);
    }
    if slot.status == ExternalSignerSlotStatus::Signed {
        if linked_external_invite_slot_has_evidence(slot, &evidence) {
            return Ok(LinkedExternalInviteSlotSignOutcome::AlreadySigned);
        }
        return Err(ApiError::Conflict(
            "linked external envelope slot is already signed with different evidence".to_owned(),
        ));
    }

    let mut updated = previous;
    updated
        .sign_slot_with_evidence(req.slot_id, evidence)
        .map_err(map_external_signing_error)?;
    let view = EnvelopeView::from(&updated);

    state
        .external_signing_envelopes
        .write()
        .await
        .insert(req.envelope_id, updated);
    persist_envelopes(state).await?;
    record_envelope_event(
        state,
        req.actor,
        req.attestor,
        req.act_id,
        "signature.external_envelope.updated",
        &view,
    )
    .await?;

    Ok(LinkedExternalInviteSlotSignOutcome::Signed)
}

fn linked_external_invite_signed_pdf_evidence(
    invite_id: Uuid,
    document_id: &str,
    digest: [u8; 32],
) -> Vec<ExternalSignatureEvidence> {
    vec![
        ExternalSignatureEvidence::new(
            "external signed PDF artifact",
            format!("act-signed-document:{document_id}"),
            Some(digest),
        ),
        ExternalSignatureEvidence::new(
            "external invite upload source",
            format!("external-invite-upload:{invite_id}:signed-pdf"),
            Some(digest),
        ),
    ]
}

fn linked_external_invite_slot_has_evidence(
    slot: &ExternalSignerSlot,
    expected: &[ExternalSignatureEvidence],
) -> bool {
    expected
        .iter()
        .all(|item| slot.evidence.iter().any(|existing| existing == item))
}

async fn restore_envelope_snapshot(
    state: &AppState,
    envelope_id: ExternalSignatureEnvelopeId,
    envelope: ExternalSignatureEnvelope,
) -> Result<(), ApiError> {
    state
        .external_signing_envelopes
        .write()
        .await
        .insert(envelope_id, envelope);
    persist_envelopes(state).await
}

pub(crate) fn load_envelopes(
    path: &FsPath,
) -> Option<HashMap<ExternalSignatureEnvelopeId, ExternalSignatureEnvelope>> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<ExternalSignatureEnvelope>>(&bytes) {
        Ok(list) => Some(
            list.into_iter()
                .map(|envelope| (envelope.id, envelope))
                .collect(),
        ),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid external signing envelope document ({e}); ignoring it",
                path.display()
            );
            None
        }
    }
}

pub(crate) fn write_envelopes_atomic(
    path: &FsPath,
    envelopes: &HashMap<ExternalSignatureEnvelopeId, ExternalSignatureEnvelope>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut list: Vec<&ExternalSignatureEnvelope> = envelopes.values().collect();
    list.sort_by(|a, b| a.act_id.0.cmp(&b.act_id.0).then(a.id.0.cmp(&b.id.0)));
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

async fn find_envelope(
    state: &AppState,
    id: ExternalSignatureEnvelopeId,
) -> Result<ExternalSignatureEnvelope, ApiError> {
    state
        .external_signing_envelopes
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or(ApiError::NotFound)
}

async fn ensure_act_exists(state: &AppState, act_id: ActId) -> Result<(), ApiError> {
    if state.acts.read().await.contains_key(&act_id) {
        Ok(())
    } else {
        Err(ApiError::NotFound)
    }
}

fn apply_slot_update(
    envelope: &mut ExternalSignatureEnvelope,
    req: PatchSlotRequest,
) -> Result<(), ApiError> {
    let slot_id = ExternalSignerSlotId(req.id);
    match req.status.into() {
        ExternalSignerSlotStatus::Pending => Err(ApiError::Unprocessable(
            "external signer slots cannot transition back to pending".to_owned(),
        )),
        ExternalSignerSlotStatus::Initiated => {
            reject_evidence_for_non_terminal(&req.evidence)?;
            envelope
                .initiate_slot(slot_id)
                .map_err(map_external_signing_error)
        }
        ExternalSignerSlotStatus::Signed => {
            if req.evidence.is_empty() {
                return Err(ApiError::Unprocessable(
                    "signed slot updates require at least one evidence reference".to_owned(),
                ));
            }
            let evidence = req
                .evidence
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?;
            envelope
                .sign_slot_with_evidence(slot_id, evidence)
                .map_err(map_external_signing_error)
        }
        ExternalSignerSlotStatus::Declined => {
            let evidence = optional_single_evidence(req.evidence)?;
            envelope
                .decline_slot(slot_id, evidence)
                .map_err(map_external_signing_error)
        }
        ExternalSignerSlotStatus::Revoked => {
            let evidence = optional_single_evidence(req.evidence)?;
            envelope
                .revoke_slot(slot_id, evidence)
                .map_err(map_external_signing_error)
        }
        ExternalSignerSlotStatus::Expired => {
            let evidence = optional_single_evidence(req.evidence)?;
            envelope
                .expire_slot(slot_id, evidence)
                .map_err(map_external_signing_error)
        }
    }
}

fn reject_evidence_for_non_terminal(evidence: &[EvidenceRequest]) -> Result<(), ApiError> {
    if evidence.is_empty() {
        Ok(())
    } else {
        Err(ApiError::Unprocessable(
            "initiated slot updates cannot attach evidence".to_owned(),
        ))
    }
}

fn optional_single_evidence(
    evidence: Vec<EvidenceRequest>,
) -> Result<Option<ExternalSignatureEvidence>, ApiError> {
    if evidence.len() > 1 {
        return Err(ApiError::Unprocessable(
            "declined, revoked, and expired updates accept at most one evidence reference"
                .to_owned(),
        ));
    }
    evidence
        .into_iter()
        .next()
        .map(TryInto::try_into)
        .transpose()
}

impl TryFrom<EvidenceRequest> for ExternalSignatureEvidence {
    type Error = ApiError;

    fn try_from(value: EvidenceRequest) -> Result<Self, Self::Error> {
        let evidence = ExternalSignatureEvidence::new(
            clean_required(value.label, "evidence.label")?,
            clean_required(value.reference, "evidence.reference")?,
            value.digest.map(parse_sha256_hex).transpose()?,
        );
        Ok(match value.identity_requirement {
            Some(requirement) => evidence.satisfying_identity_requirement(requirement.into()),
            None => evidence,
        })
    }
}

impl From<&ExternalSignatureEnvelope> for EnvelopeView {
    fn from(envelope: &ExternalSignatureEnvelope) -> Self {
        Self {
            id: envelope.id.to_string(),
            act_id: envelope.act_id.to_string(),
            order_policy: envelope.order_policy.into(),
            slots: envelope.slots.iter().map(SlotView::from).collect(),
            completed: envelope.completed,
            completion: CompletionSummaryView::from(envelope.completion_summary()),
            notice: "External signing envelope workflow only; no legal, qualified-signature, or certificate-level claim is made.",
        }
    }
}

impl From<&ExternalSignerSlot> for SlotView {
    fn from(slot: &ExternalSignerSlot) -> Self {
        Self {
            id: slot.id.to_string(),
            signer_label: slot.signer_label.clone(),
            contact_hint: slot.contact_hint.clone(),
            identity_requirements: slot
                .identity_requirements
                .iter()
                .copied()
                .map(Into::into)
                .collect(),
            required: slot.required,
            status: slot.status.into(),
            evidence: slot.evidence.iter().map(EvidenceView::from).collect(),
        }
    }
}

impl From<&ExternalSignatureEvidence> for EvidenceView {
    fn from(evidence: &ExternalSignatureEvidence) -> Self {
        Self {
            label: evidence.label.clone(),
            reference: evidence.reference.clone(),
            identity_requirement: evidence.identity_requirement.map(Into::into),
            digest: evidence.digest.map(|digest| crate::hex::hex(&digest)),
        }
    }
}

impl From<ExternalSignatureCompletionSummary> for CompletionSummaryView {
    fn from(summary: ExternalSignatureCompletionSummary) -> Self {
        Self {
            completed: summary.completed,
            required_slot_count: summary.required_slot_count,
            signed_required_slot_count: summary.signed_required_slot_count,
            blocking_required_slot_ids: summary
                .blocking_required_slot_ids
                .into_iter()
                .map(|id| id.to_string())
                .collect(),
        }
    }
}

async fn persist_envelopes(state: &AppState) -> Result<(), ApiError> {
    if let Some(path) = &state.external_signing_envelopes_path {
        let envelopes = state.external_signing_envelopes.read().await;
        write_envelopes_atomic(path, &envelopes)
            .map_err(|e| ApiError::Internal(format!("failed to persist envelopes: {e}")))?;
    }
    Ok(())
}

async fn record_envelope_event(
    state: &AppState,
    actor: &str,
    attestor: &CurrentAttestor,
    act_id: ActId,
    kind: &str,
    view: &EnvelopeView,
) -> Result<(), ApiError> {
    let payload = serde_json::to_vec(&json!({
        "envelope_id": view.id,
        "act_id": view.act_id,
        "order_policy": view.order_policy,
        "completed": view.completed,
        "completion": view.completion,
    }))?;
    let scope = act_audit_scope(state, act_id).await?;
    let mut ledger = state.ledger.write().await;
    try_append_event(&mut ledger, actor, &scope, kind, None, &payload)?;
    state.persist_write_through(&mut ledger, 1, |_| Ok(()))?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

async fn act_audit_scope(state: &AppState, act_id: ActId) -> Result<String, ApiError> {
    let entities = state.entities.read().await;
    let books = state.books.read().await;
    let acts = state.acts.read().await;
    let act = acts.get(&act_id).ok_or(ApiError::NotFound)?;
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;
    Ok(format!(
        "entity:{}/book:{}/act:{}",
        entity.id, act.book_id, act.id
    ))
}

fn clean_required(value: String, field: &str) -> Result<String, ApiError> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        Err(ApiError::Unprocessable(format!("{field} is required")))
    } else {
        Ok(value)
    }
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_owned();
        if value.is_empty() { None } else { Some(value) }
    })
}

fn parse_sha256_hex(value: String) -> Result<[u8; 32], ApiError> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::Unprocessable(
            "evidence.digest must be a 64-character lowercase or uppercase hex SHA-256 digest"
                .to_owned(),
        ));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|e| {
            ApiError::Unprocessable(format!("evidence.digest is not valid SHA-256 hex: {e}"))
        })?;
    }
    Ok(out)
}

fn map_external_signing_error(err: ExternalSigningError) -> ApiError {
    match err {
        ExternalSigningError::SlotNotFound(_) => ApiError::NotFound,
        ExternalSigningError::EnvelopeAlreadyCompleted(_) => ApiError::Conflict(err.to_string()),
        ExternalSigningError::InvalidSlotTransition { .. }
        | ExternalSigningError::SequentialOrderBlocked { .. } => {
            ApiError::Conflict(err.to_string())
        }
        ExternalSigningError::RequiredSlotsNotSigned { .. }
        | ExternalSigningError::NoRequiredSlots
        | ExternalSigningError::DuplicateSlotId(_)
        | ExternalSigningError::DuplicateIdentityRequirement { .. }
        | ExternalSigningError::MissingIdentityEvidence { .. }
        | ExternalSigningError::EmptySignatureEvidence { .. }
        | ExternalSigningError::SecretLikeMarker { .. }
        | ExternalSigningError::EmptyEvidenceReference { .. }
        | ExternalSigningError::EmptySignerLabel { .. } => ApiError::Unprocessable(err.to_string()),
    }
}

fn tmp_path(path: &FsPath) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| EXTERNAL_SIGNING_ENVELOPES_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

fn default_required() -> bool {
    true
}
