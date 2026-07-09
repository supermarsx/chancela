//! External signer envelopes.
//!
//! This module is a pure domain model for collecting signatures outside the core signing
//! pipeline. It records envelope/slot state, signer-facing labels, contact hints, and evidence
//! locators/digests only. It deliberately does not claim legal effect, certificate level, or
//! qualified-electronic-signature status; those checks belong to later signing/API layers.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::act::ActId;

/// Opaque identifier for an [`ExternalSignatureEnvelope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExternalSignatureEnvelopeId(pub Uuid);

impl ExternalSignatureEnvelopeId {
    /// Mint a fresh random identifier.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ExternalSignatureEnvelopeId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ExternalSignatureEnvelopeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Opaque identifier for a signer slot inside an external envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExternalSignerSlotId(pub Uuid);

impl ExternalSignerSlotId {
    /// Mint a fresh random identifier.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ExternalSignerSlotId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ExternalSignerSlotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Whether signer slots may be worked in any order or must follow the declared slot order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ExternalSigningOrderPolicy {
    /// Any pending signer slot may be initiated or signed.
    #[default]
    Parallel,
    /// Later slots wait until every earlier required slot is signed or otherwise resolved.
    Sequential,
}

/// State of one external signer slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ExternalSignerSlotStatus {
    /// Slot exists but has not yet been presented to the signer.
    #[default]
    Pending,
    /// Signature collection has been initiated for this signer.
    Initiated,
    /// A signature was collected; evidence references should point to the artifact/proof.
    Signed,
    /// The signer declined to sign.
    Declined,
    /// The slot/invite was revoked by the operator or workflow.
    Revoked,
    /// The slot/invite expired before signature collection completed.
    Expired,
}

impl ExternalSignerSlotStatus {
    /// True once this slot can no longer progress through normal signer action.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Signed | Self::Declined | Self::Revoked | Self::Expired
        )
    }

    fn resolves_sequential_order(self) -> bool {
        self.is_terminal()
    }

    fn can_transition_to(self, to: Self) -> bool {
        matches!(
            (self, to),
            (Self::Pending, Self::Initiated)
                | (Self::Pending, Self::Signed)
                | (Self::Pending, Self::Declined)
                | (Self::Pending, Self::Revoked)
                | (Self::Pending, Self::Expired)
                | (Self::Initiated, Self::Signed)
                | (Self::Initiated, Self::Declined)
                | (Self::Initiated, Self::Revoked)
                | (Self::Initiated, Self::Expired)
        )
    }
}

/// Evidence recorded for a slot transition.
///
/// The `reference` is an opaque document-store key, provider event id, URI, or similar locator.
/// The model stores no raw signing token, password, private key, or signature bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalSignatureEvidence {
    /// Human label for the evidence reference.
    pub label: String,
    /// Opaque locator for the artifact/proof held outside this model.
    pub reference: String,
    /// Optional SHA-256 digest of the referenced artifact/proof bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<[u8; 32]>,
}

impl ExternalSignatureEvidence {
    /// Build a new evidence reference.
    pub fn new(
        label: impl Into<String>,
        reference: impl Into<String>,
        digest: Option<[u8; 32]>,
    ) -> Self {
        Self {
            label: label.into(),
            reference: reference.into(),
            digest,
        }
    }

    fn validate_for_slot(&self, slot_id: ExternalSignerSlotId) -> Result<(), ExternalSigningError> {
        if self.reference.trim().is_empty() {
            return Err(ExternalSigningError::EmptyEvidenceReference { slot_id });
        }
        if contains_secret_like_marker(&self.reference) {
            return Err(ExternalSigningError::SecretLikeMarker {
                slot_id,
                field: "evidence.reference",
            });
        }
        Ok(())
    }
}

/// One ordered signer slot in an external envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalSignerSlot {
    /// Stable slot id. Must be unique within the envelope.
    pub id: ExternalSignerSlotId,
    /// Signer-facing label, e.g. a name or role. This is not an authentication secret.
    pub signer_label: String,
    /// Optional non-secret contact hint, e.g. a masked email or phone suffix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_hint: Option<String>,
    /// Required slots must be signed before the envelope can complete.
    #[serde(default = "default_required")]
    pub required: bool,
    /// Current slot state.
    #[serde(default)]
    pub status: ExternalSignerSlotStatus,
    /// Evidence locators/digests accumulated for this slot.
    #[serde(default)]
    pub evidence: Vec<ExternalSignatureEvidence>,
}

impl ExternalSignerSlot {
    /// Create a required slot in `Pending` status.
    pub fn required(
        id: ExternalSignerSlotId,
        signer_label: impl Into<String>,
        contact_hint: Option<String>,
    ) -> Self {
        Self {
            id,
            signer_label: signer_label.into(),
            contact_hint,
            required: true,
            status: ExternalSignerSlotStatus::Pending,
            evidence: Vec::new(),
        }
    }

    /// Create an optional slot in `Pending` status.
    pub fn optional(
        id: ExternalSignerSlotId,
        signer_label: impl Into<String>,
        contact_hint: Option<String>,
    ) -> Self {
        Self {
            required: false,
            ..Self::required(id, signer_label, contact_hint)
        }
    }

    fn validate(&self) -> Result<(), ExternalSigningError> {
        if self.signer_label.trim().is_empty() {
            return Err(ExternalSigningError::EmptySignerLabel { slot_id: self.id });
        }
        if self
            .contact_hint
            .as_deref()
            .is_some_and(contains_secret_like_marker)
        {
            return Err(ExternalSigningError::SecretLikeMarker {
                slot_id: self.id,
                field: "slot.contact_hint",
            });
        }
        for evidence in &self.evidence {
            evidence.validate_for_slot(self.id)?;
        }
        Ok(())
    }
}

/// Pure domain envelope for an act's external signature collection workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalSignatureEnvelope {
    /// Stable envelope id.
    pub id: ExternalSignatureEnvelopeId,
    /// Act whose signatures this envelope collects.
    pub act_id: ActId,
    /// Slot ordering rule.
    #[serde(default)]
    pub order_policy: ExternalSigningOrderPolicy,
    /// Ordered signer slots. Vec order is the sequential-signing order.
    pub slots: Vec<ExternalSignerSlot>,
    /// Domain completion flag. This only means every required slot was signed under this model.
    #[serde(default)]
    pub completed: bool,
}

impl ExternalSignatureEnvelope {
    /// Create a new envelope and validate its static shape.
    pub fn new(
        act_id: ActId,
        order_policy: ExternalSigningOrderPolicy,
        slots: Vec<ExternalSignerSlot>,
    ) -> Result<Self, ExternalSigningError> {
        let envelope = Self {
            id: ExternalSignatureEnvelopeId::new(),
            act_id,
            order_policy,
            slots,
            completed: false,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validate deterministic invariants that do not require external services.
    pub fn validate(&self) -> Result<(), ExternalSigningError> {
        let mut seen = HashSet::with_capacity(self.slots.len());
        for slot in &self.slots {
            if !seen.insert(slot.id) {
                return Err(ExternalSigningError::DuplicateSlotId(slot.id));
            }
            slot.validate()?;
        }
        if self.completed {
            self.ensure_completable()?;
        }
        Ok(())
    }

    /// Return a slot by id.
    pub fn slot(&self, slot_id: ExternalSignerSlotId) -> Option<&ExternalSignerSlot> {
        self.slots.iter().find(|slot| slot.id == slot_id)
    }

    /// Whether the envelope has been completed by this model's domain rules.
    pub fn is_complete(&self) -> bool {
        self.completed
    }

    /// Deterministic completion summary for callers that need progress without mutating state.
    pub fn completion_summary(&self) -> ExternalSignatureCompletionSummary {
        let required_slot_count = self.slots.iter().filter(|slot| slot.required).count();
        let signed_required_slot_count = self
            .slots
            .iter()
            .filter(|slot| slot.required && slot.status == ExternalSignerSlotStatus::Signed)
            .count();
        let blocking_required_slot_ids = self
            .slots
            .iter()
            .filter(|slot| slot.required && slot.status != ExternalSignerSlotStatus::Signed)
            .map(|slot| slot.id)
            .collect();

        ExternalSignatureCompletionSummary {
            completed: self.completed,
            required_slot_count,
            signed_required_slot_count,
            blocking_required_slot_ids,
        }
    }

    /// Initiate collection for a slot, honoring sequential ordering.
    pub fn initiate_slot(
        &mut self,
        slot_id: ExternalSignerSlotId,
    ) -> Result<(), ExternalSigningError> {
        self.transition_slot(slot_id, ExternalSignerSlotStatus::Initiated, Vec::new())
    }

    /// Mark a slot signed and attach the evidence reference for that signature.
    pub fn sign_slot(
        &mut self,
        slot_id: ExternalSignerSlotId,
        evidence: ExternalSignatureEvidence,
    ) -> Result<(), ExternalSigningError> {
        self.transition_slot(slot_id, ExternalSignerSlotStatus::Signed, vec![evidence])
    }

    /// Mark a slot declined, optionally attaching provider/operator evidence.
    pub fn decline_slot(
        &mut self,
        slot_id: ExternalSignerSlotId,
        evidence: Option<ExternalSignatureEvidence>,
    ) -> Result<(), ExternalSigningError> {
        self.transition_slot(
            slot_id,
            ExternalSignerSlotStatus::Declined,
            evidence.into_iter().collect(),
        )
    }

    /// Revoke a pending/initiated slot.
    pub fn revoke_slot(
        &mut self,
        slot_id: ExternalSignerSlotId,
        evidence: Option<ExternalSignatureEvidence>,
    ) -> Result<(), ExternalSigningError> {
        self.transition_slot(
            slot_id,
            ExternalSignerSlotStatus::Revoked,
            evidence.into_iter().collect(),
        )
    }

    /// Expire a pending/initiated slot.
    pub fn expire_slot(
        &mut self,
        slot_id: ExternalSignerSlotId,
        evidence: Option<ExternalSignatureEvidence>,
    ) -> Result<(), ExternalSigningError> {
        self.transition_slot(
            slot_id,
            ExternalSignerSlotStatus::Expired,
            evidence.into_iter().collect(),
        )
    }

    /// Complete the envelope if every required slot has been signed.
    pub fn complete(&mut self) -> Result<(), ExternalSigningError> {
        self.ensure_not_completed()?;
        self.validate()?;
        self.ensure_completable()?;
        self.completed = true;
        Ok(())
    }

    fn transition_slot(
        &mut self,
        slot_id: ExternalSignerSlotId,
        to: ExternalSignerSlotStatus,
        evidence: Vec<ExternalSignatureEvidence>,
    ) -> Result<(), ExternalSigningError> {
        self.ensure_not_completed()?;
        self.validate()?;
        for item in &evidence {
            item.validate_for_slot(slot_id)?;
        }

        let slot_index = self.slot_index(slot_id)?;
        self.ensure_order_allows(slot_index)?;

        let slot = &mut self.slots[slot_index];
        if !slot.status.can_transition_to(to) {
            return Err(ExternalSigningError::InvalidSlotTransition {
                slot_id,
                from: slot.status,
                to,
            });
        }

        slot.status = to;
        slot.evidence.extend(evidence);
        Ok(())
    }

    fn slot_index(&self, slot_id: ExternalSignerSlotId) -> Result<usize, ExternalSigningError> {
        self.slots
            .iter()
            .position(|slot| slot.id == slot_id)
            .ok_or(ExternalSigningError::SlotNotFound(slot_id))
    }

    fn ensure_order_allows(&self, slot_index: usize) -> Result<(), ExternalSigningError> {
        if self.order_policy != ExternalSigningOrderPolicy::Sequential {
            return Ok(());
        }

        let blocked = self.slots[slot_index].id;
        for slot in &self.slots[..slot_index] {
            if slot.required && !slot.status.resolves_sequential_order() {
                return Err(ExternalSigningError::SequentialOrderBlocked {
                    blocked,
                    waiting_on: slot.id,
                });
            }
        }
        Ok(())
    }

    fn ensure_not_completed(&self) -> Result<(), ExternalSigningError> {
        if self.completed {
            Err(ExternalSigningError::EnvelopeAlreadyCompleted(self.id))
        } else {
            Ok(())
        }
    }

    fn ensure_completable(&self) -> Result<(), ExternalSigningError> {
        let blocking_required_slot_ids: Vec<_> = self
            .slots
            .iter()
            .filter(|slot| slot.required && slot.status != ExternalSignerSlotStatus::Signed)
            .map(|slot| slot.id)
            .collect();
        if !blocking_required_slot_ids.is_empty() {
            return Err(ExternalSigningError::RequiredSlotsNotSigned {
                slot_ids: blocking_required_slot_ids,
            });
        }
        if !self.slots.iter().any(|slot| slot.required) {
            return Err(ExternalSigningError::NoRequiredSlots);
        }
        Ok(())
    }
}

/// Completion progress without legal/certificate assertions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalSignatureCompletionSummary {
    /// Whether [`ExternalSignatureEnvelope::complete`] has succeeded.
    pub completed: bool,
    /// Number of slots marked required.
    pub required_slot_count: usize,
    /// Number of required slots currently signed.
    pub signed_required_slot_count: usize,
    /// Required slots that still block completion.
    pub blocking_required_slot_ids: Vec<ExternalSignerSlotId>,
}

/// Deterministic validation/transition failures for external signer envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExternalSigningError {
    /// The same slot id appears more than once in an envelope.
    #[error("duplicate external signer slot id {0}")]
    DuplicateSlotId(ExternalSignerSlotId),
    /// No slot with the requested id exists in the envelope.
    #[error("external signer slot {0} was not found")]
    SlotNotFound(ExternalSignerSlotId),
    /// A slot cannot progress because an earlier required slot is unresolved.
    #[error("external signer slot {blocked} waits for earlier required slot {waiting_on}")]
    SequentialOrderBlocked {
        /// Later slot being blocked.
        blocked: ExternalSignerSlotId,
        /// Earlier required slot that is still pending/initiated.
        waiting_on: ExternalSignerSlotId,
    },
    /// The requested slot transition is not legal from the current status.
    #[error("invalid external signer slot transition for {slot_id} from {from:?} to {to:?}")]
    InvalidSlotTransition {
        /// Slot being transitioned.
        slot_id: ExternalSignerSlotId,
        /// Current status.
        from: ExternalSignerSlotStatus,
        /// Requested status.
        to: ExternalSignerSlotStatus,
    },
    /// Completion was attempted before every required slot had signed.
    #[error("required external signer slots are not signed: {slot_ids:?}")]
    RequiredSlotsNotSigned {
        /// Required slot ids that still block completion.
        slot_ids: Vec<ExternalSignerSlotId>,
    },
    /// Completion requires at least one required slot.
    #[error("external signature envelope has no required slots")]
    NoRequiredSlots,
    /// A completed envelope is append-only for this model.
    #[error("external signature envelope {0} is already completed")]
    EnvelopeAlreadyCompleted(ExternalSignatureEnvelopeId),
    /// Evidence references and contact hints must not carry raw token/password-like material.
    #[error("external signer slot {slot_id} has a secret-like marker in {field}")]
    SecretLikeMarker {
        /// Slot containing the rejected field.
        slot_id: ExternalSignerSlotId,
        /// Rejected field name.
        field: &'static str,
    },
    /// Evidence references must be non-empty locators.
    #[error("external signer slot {slot_id} has an empty evidence reference")]
    EmptyEvidenceReference {
        /// Slot containing the rejected evidence reference.
        slot_id: ExternalSignerSlotId,
    },
    /// Signer slots need a non-empty label so later UI/API layers can address them safely.
    #[error("external signer slot {slot_id} has an empty signer label")]
    EmptySignerLabel {
        /// Slot with the empty signer label.
        slot_id: ExternalSignerSlotId,
    },
}

fn default_required() -> bool {
    true
}

fn contains_secret_like_marker(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase().replace('-', "_");
    SECRET_LIKE_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
}

const SECRET_LIKE_MARKERS: &[&str] = &[
    "token=",
    "token:",
    "access_token=",
    "refresh_token=",
    "password=",
    "password:",
    "passwd=",
    "pwd=",
    "secret=",
    "client_secret=",
    "api_key=",
    "apikey=",
    "authorization:",
    "bearer ",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(reference: &str) -> ExternalSignatureEvidence {
        ExternalSignatureEvidence::new("provider event", reference, Some([7u8; 32]))
    }

    fn required_slot(label: &str) -> ExternalSignerSlot {
        ExternalSignerSlot::required(ExternalSignerSlotId::new(), label, Some("***1234".into()))
    }

    fn envelope(
        order_policy: ExternalSigningOrderPolicy,
        slots: Vec<ExternalSignerSlot>,
    ) -> ExternalSignatureEnvelope {
        ExternalSignatureEnvelope::new(ActId::new(), order_policy, slots).unwrap()
    }

    #[test]
    fn sequential_order_blocks_later_required_slots_until_earlier_resolves() {
        let first = required_slot("Chair");
        let second = required_slot("Secretary");
        let first_id = first.id;
        let second_id = second.id;
        let mut envelope = envelope(ExternalSigningOrderPolicy::Sequential, vec![first, second]);

        assert!(matches!(
            envelope.initiate_slot(second_id),
            Err(ExternalSigningError::SequentialOrderBlocked { blocked, waiting_on })
                if blocked == second_id && waiting_on == first_id
        ));

        envelope
            .decline_slot(first_id, Some(evidence("audit:event:first-declined")))
            .unwrap();
        envelope.initiate_slot(second_id).unwrap();
        assert_eq!(
            envelope.slot(second_id).unwrap().status,
            ExternalSignerSlotStatus::Initiated
        );
    }

    #[test]
    fn duplicate_slot_ids_are_rejected() {
        let slot_id = ExternalSignerSlotId::new();
        let first = ExternalSignerSlot::required(slot_id, "Chair", None);
        let second = ExternalSignerSlot::required(slot_id, "Secretary", None);

        assert!(matches!(
            ExternalSignatureEnvelope::new(
                ActId::new(),
                ExternalSigningOrderPolicy::Parallel,
                vec![first, second],
            ),
            Err(ExternalSigningError::DuplicateSlotId(id)) if id == slot_id
        ));
    }

    #[test]
    fn evidence_references_reject_token_and_password_markers() {
        let slot = required_slot("Chair");
        let slot_id = slot.id;
        let mut envelope = envelope(ExternalSigningOrderPolicy::Parallel, vec![slot]);

        assert!(matches!(
            envelope.sign_slot(slot_id, evidence("https://qtsp.example/sign?token=raw")),
            Err(ExternalSigningError::SecretLikeMarker { slot_id: id, field })
                if id == slot_id && field == "evidence.reference"
        ));

        assert!(matches!(
            envelope.sign_slot(slot_id, evidence("provider://event/password:raw")),
            Err(ExternalSigningError::SecretLikeMarker { slot_id: id, field })
                if id == slot_id && field == "evidence.reference"
        ));
    }

    #[test]
    fn completion_requires_all_required_slots_to_be_signed() {
        let first = required_slot("Chair");
        let second = required_slot("Secretary");
        let first_id = first.id;
        let second_id = second.id;
        let mut envelope = envelope(ExternalSigningOrderPolicy::Parallel, vec![first, second]);

        envelope
            .sign_slot(first_id, evidence("provider:event:first-signed"))
            .unwrap();
        assert!(matches!(
            envelope.complete(),
            Err(ExternalSigningError::RequiredSlotsNotSigned { slot_ids })
                if slot_ids == vec![second_id]
        ));

        envelope
            .sign_slot(second_id, evidence("provider:event:second-signed"))
            .unwrap();
        envelope.complete().unwrap();
        assert!(envelope.is_complete());
        assert_eq!(
            envelope.completion_summary(),
            ExternalSignatureCompletionSummary {
                completed: true,
                required_slot_count: 2,
                signed_required_slot_count: 2,
                blocking_required_slot_ids: Vec::new(),
            }
        );
    }

    #[test]
    fn completion_model_serializes_without_legal_or_qualified_claim_flags() {
        let slot = required_slot("Chair");
        let slot_id = slot.id;
        let mut envelope = envelope(ExternalSigningOrderPolicy::Parallel, vec![slot]);
        envelope
            .sign_slot(slot_id, evidence("provider:event:first-signed"))
            .unwrap();
        envelope.complete().unwrap();

        let json = serde_json::to_string(&envelope)
            .unwrap()
            .to_ascii_lowercase();
        assert!(!json.contains("legal"));
        assert!(!json.contains("qualified"));
        assert!(!json.contains("qes"));
        assert!(!json.contains("eidas"));
    }
}
