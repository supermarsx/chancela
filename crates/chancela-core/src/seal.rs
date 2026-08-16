//! Sealing: the point where a book opening or an act becomes part of the immutable
//! hash-chained record.
//!
//! Grounding: spec 06 §3 (WFL-20/22), spec 05 (DAT-10/11). Sealing an act consults the
//! compliance rule pack (LEG-05), assigns the sequential ata number (WFL-12), freezes the
//! payload, and appends an append-only event to the book's [`Ledger`]. Opening a book
//! appends the genesis event whose existence *is* the digital anti-falsification function
//! of the termo de abertura (WFL-11).
//!
//! The ledger preimage/chain layout is owned by `chancela-ledger`; this module only feeds
//! it canonical payload bytes and reads back the assigned sequence and digest.

use std::collections::HashMap;

use serde::Serialize;

use chancela_ledger::{Event, Ledger};

use crate::act::{
    Act, ActBody, ActState, AgendaItem, Attachment, Attendee, Convening, ConveningWaiver,
    DeliberationItem, DocumentReference, ManualSignatureOriginalReference, MeetingChannel, Mesa,
    SealMetadata, SignatorySlot, SupersededSigningSnapshot, WrittenResolutionEvidence,
};
use crate::book::{AtaSequenceIssue, Book, TermoDeAbertura};
use crate::entity::Entity;
use crate::error::{ActError, BookError, SealError};
use crate::rules::{ComplianceIssue, RulePack, Severity};

/// Evidence accepted by the final seal gate.
///
/// A digital seal binds the immutable signing snapshot, the completed signed PDF, and the
/// deterministic technical validation report. A manual seal instead records where the signed
/// original is retained. Neither variant is itself a legal-validity or qualification claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SealEvidence {
    /// Complete digital signed-PDF evidence.
    Digital {
        /// SHA-256 of the canonical PDF snapshot presented to the signer.
        signing_snapshot_digest: String,
        /// SHA-256 of the completed signed PDF.
        signed_pdf_digest: String,
        /// SHA-256 of the technical validation report used by the gate.
        signature_validation_report_digest: String,
    },
    /// Explicit reference to a manually signed original retained outside this digital flow.
    Manual {
        /// Custody/location metadata for the original.
        original_reference: ManualSignatureOriginalReference,
    },
}

impl SealEvidence {
    fn validate(&self) -> Result<(), SealError> {
        match self {
            Self::Digital {
                signing_snapshot_digest,
                signed_pdf_digest,
                signature_validation_report_digest,
            } => {
                for (field, value) in [
                    ("signing_snapshot_digest", signing_snapshot_digest),
                    ("signed_pdf_digest", signed_pdf_digest),
                    (
                        "signature_validation_report_digest",
                        signature_validation_report_digest,
                    ),
                ] {
                    if value.len() != 64
                        || !value
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    {
                        return Err(SealError::InvalidSignatureEvidence(format!(
                            "{field} must be a lowercase SHA-256 hex digest"
                        )));
                    }
                }
                Ok(())
            }
            Self::Manual { original_reference } => {
                if original_reference.storage_reference.trim().is_empty() {
                    return Err(SealError::InvalidSignatureEvidence(
                        "manual signature storage reference must not be empty".to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }

    fn seal_metadata(&self, rule_pack_id: &str, entity: &Entity) -> SealMetadata {
        let metadata = SealMetadata::new(rule_pack_id, entity.family, entity.kind);
        match self {
            Self::Digital {
                signing_snapshot_digest,
                signed_pdf_digest,
                signature_validation_report_digest,
            } => metadata.with_digital_signature_evidence(
                signing_snapshot_digest.clone(),
                signed_pdf_digest.clone(),
                signature_validation_report_digest.clone(),
            ),
            Self::Manual { original_reference } => {
                metadata.with_manual_signature_original_reference(Some(original_reference.clone()))
            }
        }
    }
}

/// Result of successfully sealing an act.
#[derive(Debug, Clone)]
pub struct SealOutcome {
    /// Sequential ata number assigned within the book (WFL-12).
    pub ata_number: u64,
    /// Sequence number of the seal event in the ledger.
    pub event_seq: u64,
    /// The frozen payload digest (sha-256), as computed by the ledger.
    pub payload_digest: [u8; 32],
    /// Structured evidence of the rule pack/profile used for this seal (LEG-06/WFL-22).
    pub seal_metadata: SealMetadata,
    /// Any `Warning`-severity issues that were acknowledged at sealing (LEG-05), retained
    /// so the acknowledgement is itself part of the record.
    pub acknowledged_warnings: Vec<ComplianceIssue>,
}

/// Canonical, digest-stable view of an act's sealed content.
///
/// Serde serializes struct fields in declaration order, so serializing this view yields a
/// stable byte string for the same content — adequate for the scaffold's digesting. The
/// act's identity (`act_id`, `book_id`) is included so the digest binds to *this* act.
#[derive(Serialize)]
struct ActPayload<'a> {
    act_id: String,
    book_id: String,
    title: &'a str,
    channel: MeetingChannel,
    meeting_date: Option<time::Date>,
    place: Option<&'a str>,
    attendance_reference: Option<&'a str>,
    deliberations: &'a str,
    telematic_evidence: Option<&'a str>,
    attachments: &'a [Attachment],
    signatories: &'a [SignatorySlot],
    retifies: Option<String>,
    // ─── THE RULE FOR ADDING A FIELD BELOW THIS LINE ────────────────────────────────────────
    //
    // Any field added to this preimage MUST carry `#[serde(skip_serializing_if = …)]` and emit
    // NOTHING at its empty value. A field that always serializes changes the preimage of acts
    // that are ALREADY SEALED, and every one of them then re-hashes to something other than the
    // digest its `act.sealed` event froze — a whole install of genuine, untampered atas reported
    // as altered, and the instance in degraded read-only on the next boot.
    //
    // This comment used to say the opposite: that "already-sealed acts are never recomputed, so
    // their frozen digests are unaffected by this growth". That was true when nothing re-derived
    // a sealed act's digest. `123ad32d` made every load recompute every sealed act, which repealed
    // it. The old wording survived the change and was a written licence to brick an install.
    //
    // The seven fields immediately below (`meeting_time` … `members_represented`) are the
    // exception, and they are an exception only because they predate the first commit of this
    // repository — `ActPayload` has carried them, unskipped, since `ee1bf191`, so no build that
    // has ever existed sealed an act without them. They are unconditional bytes now and must stay
    // unconditional: adding `skip_serializing_if` to one of them would break exactly the same set
    // of acts, in the opposite direction. `a_minimal_act_seals_to_its_frozen_golden_digest` and
    // `the_preimage_of_a_minimal_act_is_byte_for_byte_frozen` pin them at their ABSENT values,
    // which is the form no other fixture covers and the form such a "fix" would move.
    meeting_time: Option<time::Time>,
    mesa: &'a Mesa,
    agenda: &'a [AgendaItem],
    referenced_documents: &'a [DocumentReference],
    #[serde(skip_serializing_if = "Option::is_none")]
    written_resolution_evidence: Option<&'a WrittenResolutionEvidence>,
    deliberation_items: &'a [DeliberationItem],
    members_present: Option<u32>,
    members_represented: Option<u32>,
    // G1/G2 (append-only). These are skipped from the preimage when empty — a convening of
    // `None` and no attendees emit no bytes — so the digest of a pre-existing act (one carrying
    // neither) is **byte-identical** to what it was before these fields existed. When either is
    // populated it serializes and binds into the new seal's digest (R8).
    #[serde(skip_serializing_if = "Option::is_none")]
    convening: Option<&'a Convening>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attendees: Option<&'a [Attendee]>,
    // F15 (append-only). The rendered page count frozen at the content freeze, so the seal
    // binds the act's page consumption as a fact rather than something re-derivable later. An
    // act without one emits no bytes, so already-sealed acts and any act sealed without a
    // count produce a byte-identical preimage.
    #[serde(skip_serializing_if = "Option::is_none")]
    page_count: Option<u32>,
    // Reopen history (append-only). An act that was reopened for correction seals carrying the
    // record of every canonical snapshot that reopen retired, so the seal binds the regression
    // rather than hiding it. An act that was never reopened emits no bytes, so its preimage — and
    // therefore any already-frozen digest — is byte-identical to before this field existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    superseded_signing_snapshots: Option<&'a [SupersededSigningSnapshot]>,
    // The no-convocatória basis (append-only). `convening` above binds every detail of how a
    // meeting **was** called; this binds the declared ground on which one lawfully **was not**.
    // That is the more load-bearing of the two: under CSC art. 56.º/1 a) deliberações taken in an
    // assembleia geral não convocada are null unless all sócios were present or represented, so
    // the basis is what stands between a valid deliberação and a defective one — and the ata
    // recites it. A legal justification printed on a sealed instrument has to be covered by that
    // instrument's seal, or the document asserts something its own tamper-evidence does not.
    // An act without a waiver emits no bytes, so every already-frozen digest is byte-identical.
    #[serde(skip_serializing_if = "Option::is_none")]
    convening_waiver: Option<&'a ConveningWaiver>,
    // The markup narrative body (append-only, t74 §1). Appended **last**, after
    // `convening_waiver`; an act without a body emits no bytes, so every already-frozen digest is
    // byte-identical to what it was before this field existed.
    //
    // What binds is deliberately more than the operator's source text. `ActBody` carries
    // `compiler_id` and `compiled_digest` alongside `source`, and all three enter the preimage, so
    // the seal covers not merely what was written but **what it compiled to** at the content
    // freeze. Source alone would still parse under a later compiler — just possibly into different
    // blocks — and the document would come to say something else with nothing to detect it. With
    // the compiled digest bound, that drift is a mismatch against the seal rather than a silent
    // reinterpretation.
    //
    // Note that `deliberations` above is untouched and stays plain text permanently: markup lives
    // only here, behind `ActBody::format`. Reinterpreting old prose as markup would move nothing
    // any digest covers, which is precisely what would make it undetectable.
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<&'a ActBody>,
}

impl<'a> ActPayload<'a> {
    fn of(act: &'a Act) -> Self {
        ActPayload {
            act_id: act.id.to_string(),
            book_id: act.book_id.to_string(),
            title: &act.title,
            channel: act.channel,
            meeting_date: act.meeting_date,
            place: act.place.as_deref(),
            attendance_reference: act.attendance_reference.as_deref(),
            deliberations: &act.deliberations,
            telematic_evidence: act.telematic_evidence.as_deref(),
            attachments: &act.attachments,
            signatories: &act.signatories,
            retifies: act.retifies.map(|id| id.to_string()),
            meeting_time: act.meeting_time,
            mesa: &act.mesa,
            agenda: &act.agenda,
            referenced_documents: &act.referenced_documents,
            written_resolution_evidence: act.written_resolution_evidence.as_ref(),
            deliberation_items: &act.deliberation_items,
            members_present: act.members_present,
            members_represented: act.members_represented,
            convening: act.convening.as_ref(),
            attendees: (!act.attendees.is_empty()).then_some(act.attendees.as_slice()),
            page_count: act.page_count,
            superseded_signing_snapshots: (!act.superseded_signing_snapshots.is_empty())
                .then_some(act.superseded_signing_snapshots.as_slice()),
            convening_waiver: act.convening_waiver.as_ref(),
            body: act.body.as_ref(),
        }
    }
}

/// The **exact** preimage `seal_act_with_evidence` digests into the `act.sealed` event's
/// `payload_digest` (and copies onto [`Act::payload_digest`]).
///
/// This lives at module scope rather than inside the sealing function so the digest can be
/// *recomputed* later and compared to the frozen one — see [`sealed_act_digest`]. Sealing and
/// re-verification must go through this one type: two hand-kept copies of a preimage are two
/// chances for them to drift, and a drift here means every act in the field reads as tampered.
///
/// Field order and shape are frozen. See [`ActPayload`] for the append-only rules.
#[derive(Serialize)]
struct SealedActPayload<'a> {
    act: ActPayload<'a>,
    seal_metadata: &'a SealMetadata,
}

/// Recompute the seal-preimage digest of a **sealed** act from its stored content.
///
/// Returns the sha-256 that `seal_act_with_evidence` would have frozen for exactly this content,
/// or `None` when the act carries no [`Act::seal_metadata`] and the preimage therefore cannot be
/// rebuilt (an unsealed act, or a historical row sealed before that field existed).
///
/// Compare against [`Act::payload_digest`] to answer the question nothing used to ask: *does the
/// ata you are reading still hash to what the ledger recorded?* The chain only proves that some
/// payload with digest D was sealed at that position; without this, an edit to the stored act
/// substance leaves every integrity surface green. Use [`verify_act_fixity`] for the full verdict.
///
/// The recomputation is byte-exact for acts already sealed in the field: every optional field of
/// the preimage is `skip_serializing_if`, and the ata number is read from the *stored metadata*
/// rather than from [`Act::ata_number`], so a row sealed before the number was bound reproduces
/// the older, shorter preimage unchanged.
#[must_use]
pub fn sealed_act_digest(act: &Act) -> Option<[u8; 32]> {
    let seal_metadata = act.seal_metadata.as_ref()?;
    let payload = serde_json::to_vec(&SealedActPayload {
        act: ActPayload::of(act),
        seal_metadata,
    })
    .ok()?;
    Some(chancela_ledger::digest(&payload))
}

/// The `kind` of the ledger event a seal appends, and therefore the only kind that can anchor a
/// sealed act. See [`seal_act_with_evidence`].
const SEAL_EVENT_KIND: &str = "act.sealed";

/// The frozen seal digests, read out of the ledger and keyed by the sequence each seal event
/// occupies — **the authority a stored act's fixity is measured against**.
///
/// This type exists because the anchor used to be [`Act::payload_digest`]: a field of the very row
/// whose content it was supposed to bind, carrying neither `serde(default)` nor
/// `skip_serializing_if`, unconditionally writable beside the deliberations it covered. One
/// `UPDATE acts SET json = …` that also rewrote that field satisfied every fixity surface in the
/// product, because nothing ever consulted the chain. The authoritative bytes were always there —
/// the `act.sealed` event, inside a chain [`Ledger::verify`] protects, named by
/// [`Act::seal_event_seq`] — and simply had no reader.
///
/// Only `act.sealed` events are indexed. A [`Act::seal_event_seq`] pointing at any other kind of
/// event therefore resolves to nothing and the act is reported broken, which is the correct reading:
/// the seal it claims does not exist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SealAnchors {
    by_seq: HashMap<u64, [u8; 32]>,
}

impl SealAnchors {
    /// Index every `act.sealed` event in `ledger`.
    ///
    /// One pass over the events; the map it retains holds one entry per *sealed act*, not per
    /// event. See [`SealAnchors::from_events`] for the cost note.
    #[must_use]
    pub fn from_ledger(ledger: &Ledger) -> Self {
        Self::from_events(ledger.events())
    }

    /// Index every `act.sealed` event in an arbitrary event sequence — the bundle importer's entry
    /// point, which holds the events it just chain-verified rather than a whole [`Ledger`].
    ///
    /// Cost: O(events) time to scan, O(sealed acts) memory to retain. The scan is strictly
    /// dominated by the `Ledger::verify()` already performed over the same events (which hashes
    /// every one of them); this only reads two fields per event.
    #[must_use]
    pub fn from_events<'a>(events: impl IntoIterator<Item = &'a Event>) -> Self {
        events
            .into_iter()
            .filter(|event| event.kind == SEAL_EVENT_KIND)
            .map(|event| (event.seq, event.payload_digest))
            .collect()
    }

    /// The digest the seal event at `seq` froze, or `None` when no `act.sealed` event sits there.
    #[must_use]
    pub fn digest_at(&self, seq: u64) -> Option<[u8; 32]> {
        self.by_seq.get(&seq).copied()
    }

    /// How many seal events are indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_seq.len()
    }

    /// Whether the ledger held no seal event at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_seq.is_empty()
    }
}

/// Build anchors from raw `(seq, digest)` pairs.
///
/// The production constructors are [`SealAnchors::from_ledger`] / [`SealAnchors::from_events`];
/// this is for callers that already hold the mapping (and for pinning historical fixtures whose
/// ledger is a stored constant rather than a live chain).
impl FromIterator<(u64, [u8; 32])> for SealAnchors {
    fn from_iter<T: IntoIterator<Item = (u64, [u8; 32])>>(iter: T) -> Self {
        SealAnchors {
            by_seq: iter.into_iter().collect(),
        }
    }
}

/// The verdict of re-verifying one stored act against the digest its seal froze.
///
/// Serialized in the store's load report and on `GET /v1/ledger/integrity`, so the variant names
/// are a wire contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ActFixity {
    /// Not sealed: there is no frozen digest to hold the content to.
    Unsealed,
    /// Sealed, and the stored content still hashes to the digest the ledger recorded.
    Verified,
    /// **Sealed and altered.** The stored content does not hash to the digest the *ledger* froze.
    Mismatch {
        /// The digest the `act.sealed` event froze, lowercase hex.
        expected: String,
        /// What the stored content hashes to now, lowercase hex.
        actual: String,
    },
    /// **Sealed, and the row's own frozen digest disagrees with the ledger's.**
    ///
    /// The verdict of the attack the row-anchored check could not see: edit the act's substance
    /// *and* rewrite `payload_digest` beside it. Both sides are reported because which one moved is
    /// the operator's first question — `recomputed == row` means the row was rewritten as a unit
    /// (content and digest together), while `recomputed == ledger` means only the digest field was
    /// corrupted and the substance is intact.
    LedgerAnchorMismatch {
        /// The digest the `act.sealed` event froze — the authority, lowercase hex.
        ledger: String,
        /// The digest the stored row carries beside its content, lowercase hex.
        row: String,
        /// What the stored content hashes to now, when the preimage can be rebuilt at all.
        #[serde(skip_serializing_if = "Option::is_none")]
        recomputed: Option<String>,
    },
    /// **Sealed, and the seal it names is not in the chain.**
    ///
    /// [`Act::seal_event_seq`] points at no `act.sealed` event: either at nothing, at an event of
    /// another kind, or (when the field is absent) at no position at all. Every sealed row ever
    /// written carries one — [`Act::mark_sealed`](crate::Act) sets it in the same statement as the
    /// digest — so its absence or dangling is tampering, not history.
    SealEventMissing {
        /// The sequence the row claims its seal event occupies, when it claims one.
        seal_event_seq: Option<u64>,
    },
    /// **Sealed with no frozen digest at all.**
    ///
    /// `payload_digest` carries neither `serde(default)` nor `skip_serializing_if` and is present
    /// in every sealed row ever written, so a sealed act without one cannot be a historical row —
    /// it can only be a row a key was deleted from. Reported as broken rather than unverifiable
    /// precisely because that inference is available here and is not available for
    /// `seal_metadata`, which genuinely is optional and genuinely is absent on old rows.
    MissingPayloadDigest,
    /// Sealed, and the ata number bound into the seal is not the number the act now carries —
    /// a renumbering (WFL-12), which used to be invisible because the number was bound by nothing.
    AtaNumberMismatch {
        /// The number bound into the seal preimage.
        sealed: u64,
        /// The number the stored act carries now.
        stored: Option<u64>,
    },
    /// Sealed, but the preimage cannot be rebuilt, so fixity is *unknown* rather than good.
    ///
    /// Reported, never treated as verified. The remaining cause is [`Act::seal_metadata`], which is
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]`: a row sealed before that field
    /// existed and a row whose metadata has since been removed are genuinely indistinguishable from
    /// the stored bytes alone. That reasoning is *specific to this field* — it does not extend to
    /// `payload_digest`, which is why a missing digest is [`ActFixity::MissingPayloadDigest`].
    ///
    /// Unknown is not good: it does not gate a running instance (an installed base of pre-metadata
    /// rows must not brick on upgrade), but it does refuse an **import** — see
    /// [`ActFixityReport::fully_verified`].
    Unverifiable {
        /// Stable machine-readable cause.
        reason: &'static str,
    },
}

impl ActFixity {
    /// Whether this verdict is positive evidence of an unaltered act.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self, ActFixity::Verified)
    }

    /// Whether this verdict is an affirmative finding of alteration. `Unverifiable` is **not** —
    /// it is unknown, and is reported separately so unknown never launders into good or into a
    /// tamper alarm.
    #[must_use]
    pub fn is_broken(&self) -> bool {
        matches!(
            self,
            ActFixity::Mismatch { .. }
                | ActFixity::AtaNumberMismatch { .. }
                | ActFixity::LedgerAnchorMismatch { .. }
                | ActFixity::SealEventMissing { .. }
                | ActFixity::MissingPayloadDigest
        )
    }
}

/// Re-verify one stored act **against the ledger** — the digest the `act.sealed` event at
/// [`Act::seal_event_seq`] froze, and the ata number the seal bound.
///
/// The anchor is `anchors`, never [`Act::payload_digest`]. That distinction is the whole check:
/// the row's own digest field is written by whoever writes the row, so comparing a row against it
/// answers only "is this row self-consistent?", which one extended `UPDATE` makes true. The
/// ledger's copy sits inside a chain [`Ledger::verify`] protects, so moving it means breaking the
/// chain. The row's digest is still *read* — and a disagreement with the ledger's is its own
/// finding, because which side moved is what an operator needs to know.
///
/// Build `anchors` once per pass with [`SealAnchors::from_ledger`]; lookups are O(1).
#[must_use]
pub fn verify_act_fixity(act: &Act, anchors: &SealAnchors) -> ActFixity {
    let Some(row_digest) = act.payload_digest else {
        return if matches!(act.state, ActState::Sealed | ActState::Archived) {
            // Sealed with no frozen digest at all. `payload_digest` is unconditional in the durable
            // shape, so this is a deleted key, not a historical row.
            ActFixity::MissingPayloadDigest
        } else {
            ActFixity::Unsealed
        };
    };
    // The anchor, from the chain. An act naming a seal event that is not there — or that is not an
    // `act.sealed` event — is broken: it asserts a seal the ledger does not record.
    let Some(anchor) = act.seal_event_seq.and_then(|seq| anchors.digest_at(seq)) else {
        return ActFixity::SealEventMissing {
            seal_event_seq: act.seal_event_seq,
        };
    };
    if anchor != row_digest {
        return ActFixity::LedgerAnchorMismatch {
            ledger: hex32(&anchor),
            row: hex32(&row_digest),
            recomputed: sealed_act_digest(act).as_ref().map(hex32),
        };
    }
    let Some(metadata) = act.seal_metadata.as_ref() else {
        return ActFixity::Unverifiable {
            reason: "sealed_act_has_no_seal_metadata",
        };
    };
    // The ata number first: a renumbered act would also fail the digest check (the number is in
    // the preimage), but reporting "digest mismatch" for a renumbering hides what actually moved.
    if let Some(sealed) = metadata.ata_number
        && act.ata_number != Some(sealed)
    {
        return ActFixity::AtaNumberMismatch {
            sealed,
            stored: act.ata_number,
        };
    }
    match sealed_act_digest(act) {
        Some(actual) if actual == anchor => ActFixity::Verified,
        Some(actual) => ActFixity::Mismatch {
            expected: hex32(&anchor),
            actual: hex32(&actual),
        },
        None => ActFixity::Unverifiable {
            reason: "seal_preimage_not_serializable",
        },
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// One act whose fixity check did not come back [`ActFixity::Verified`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActFixityFinding {
    /// The act the finding is about.
    pub act_id: String,
    /// The book it belongs to.
    pub book_id: String,
    /// The ata number it currently carries, when it has one.
    pub ata_number: Option<u64>,
    /// The verdict.
    pub fixity: ActFixity,
}

/// One WFL-12 sequencing defect, tagged with the book it was found in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BookAtaSequenceFinding {
    /// The book whose numbering is defective.
    pub book_id: String,
    /// What is wrong with it.
    pub issue: AtaSequenceIssue,
}

/// The result of re-verifying a whole corpus of stored acts against their frozen digests, plus
/// the WFL-12 sequencing of the books holding them.
///
/// `healthy` is gated on **affirmative findings only**: an altered act, or two acts holding one
/// ata number. `unverifiable` rows and [`AtaSequenceIssue::BeyondCounter`] are surfaced in their
/// own counters and in the findings but do not by themselves put the instance into degraded
/// read-only mode — a genuinely historical row is indistinguishable from a stripped one, and a
/// counter behind its acts is recoverable rather than evidence of alteration. Bricking an install
/// over an ambiguity is the wrong default; hiding the ambiguity is the wrong default too, so it is
/// reported either way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActFixityReport {
    /// `false` when any act is affirmatively altered or any book's numbering is defective —
    /// treat exactly like a broken chain.
    pub healthy: bool,
    /// How many sealed acts were checked.
    pub sealed_checked: u64,
    /// How many re-hashed to their frozen digest.
    pub verified: u64,
    /// How many are affirmatively altered (content digest or bound ata number).
    pub broken: u64,
    /// How many are sealed but cannot be re-verified at all.
    pub unverifiable: u64,
    /// Every non-`Verified` sealed act, ordered by (book, ata, act) for stability.
    pub findings: Vec<ActFixityFinding>,
    /// Every WFL-12 sequencing defect across the checked books.
    pub ata_sequence: Vec<BookAtaSequenceFinding>,
}

/// The report of an empty corpus: nothing sealed, and therefore nothing altered.
///
/// Written out rather than derived because `#[derive(Default)]` would make `healthy` **false** —
/// an empty in-memory instance would boot claiming its acts had been tampered with.
impl Default for ActFixityReport {
    fn default() -> Self {
        ActFixityReport {
            healthy: true,
            sealed_checked: 0,
            verified: 0,
            broken: 0,
            unverifiable: 0,
            findings: Vec::new(),
            ata_sequence: Vec::new(),
        }
    }
}

impl ActFixityReport {
    /// Re-verify every act in `acts` and check the ata sequencing of every book in `books`.
    ///
    /// Both are borrowed iterators so the store can pass its loaded maps' values directly. Pass an
    /// empty `books` when only per-act fixity is wanted (a bundle importer, say, which holds one
    /// book's acts but not the live corpus).
    ///
    /// `anchors` is the ledger the acts are held to — [`SealAnchors::from_ledger`] for a live
    /// corpus, [`SealAnchors::from_events`] for a bundle's own chain-verified events. It is a
    /// required argument rather than an option: a fixity pass with no ledger to compare against is
    /// the defect this signature exists to make unrepresentable.
    pub fn build<'a>(
        acts: impl IntoIterator<Item = &'a Act> + Clone,
        books: impl IntoIterator<Item = &'a Book>,
        anchors: &SealAnchors,
    ) -> Self {
        let mut report = ActFixityReport {
            healthy: true,
            ..ActFixityReport::default()
        };
        for act in acts.clone() {
            let fixity = verify_act_fixity(act, anchors);
            if fixity == ActFixity::Unsealed {
                continue;
            }
            report.sealed_checked += 1;
            match &fixity {
                ActFixity::Verified => {
                    report.verified += 1;
                    continue;
                }
                ActFixity::Unverifiable { .. } => report.unverifiable += 1,
                _ => {
                    report.broken += 1;
                    report.healthy = false;
                }
            }
            report.findings.push(ActFixityFinding {
                act_id: act.id.to_string(),
                book_id: act.book_id.to_string(),
                ata_number: act.ata_number,
                fixity,
            });
        }
        report.findings.sort_by(|a, b| {
            (&a.book_id, a.ata_number, &a.act_id).cmp(&(&b.book_id, b.ata_number, &b.act_id))
        });

        for book in books {
            for issue in book.check_ata_sequence(acts.clone()) {
                // Only an affirmative uniqueness violation gates; see
                // [`AtaSequenceIssue::is_uniqueness_violation`] for why the weaker signal does not.
                if issue.is_uniqueness_violation() {
                    report.healthy = false;
                }
                report.ata_sequence.push(BookAtaSequenceFinding {
                    book_id: book.id.to_string(),
                    issue,
                });
            }
        }
        report
            .ata_sequence
            .sort_by(|a, b| a.book_id.cmp(&b.book_id));
        report
    }

    /// Whether **every** sealed act got an affirmative answer: healthy *and* nothing unanswerable.
    ///
    /// A stricter bar than [`ActFixityReport::healthy`], and deliberately so. `healthy` governs
    /// whether a *running instance* keeps serving, where an unverifiable row is an ambiguity an
    /// operator has to be told about but not something to brick an existing install over. Accepting
    /// foreign content is the opposite situation: nothing is owed to a bundle, an unanswered
    /// question about it is a reason to refuse it, and `verified` is a claim an importer must not
    /// make about acts it could not check. Use this to gate an import.
    #[must_use]
    pub fn fully_verified(&self) -> bool {
        self.healthy && self.unverifiable == 0
    }

    /// A one-line operator-facing summary for the boot log / CLI.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} sealed acts checked: {} verified, {} ALTERED, {} unverifiable; \
             {} ata-numbering defects",
            self.sealed_checked,
            self.verified,
            self.broken,
            self.unverifiable,
            self.ata_sequence.len()
        )
    }
}

fn render_issues(issues: &[ComplianceIssue]) -> String {
    issues
        .iter()
        .map(|i| format!("[{}] {}", i.rule_id, i.message))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Open a book and append its genesis event to `ledger` (WFL-10/11).
///
/// The genesis event digests the sealed termo de abertura; from here the book's hash chain
/// grows one seal at a time. Returns the genesis event's sequence number.
///
/// `actor` is the identity performing the opening (management/administrator), recorded on
/// the ledger event (DAT-10).
pub fn open_and_seal_book(
    book: &mut Book,
    entity: &Entity,
    termo: TermoDeAbertura,
    actor: &str,
    ledger: &mut Ledger,
) -> Result<u64, SealError> {
    // State guard first: do not touch the ledger if the book cannot be opened.
    book.open(termo)?;
    // `open` moved the termo into the book; serialize it from there.
    let termo_ref = book
        .termo_abertura
        .as_ref()
        .expect("termo present immediately after open");
    let payload = serde_json::to_vec(termo_ref).map_err(|e| SealError::Serialize(e.to_string()))?;
    // wp27-e3: a book opened in a **non-default** tenant joins its tenant chain (ChainId::Tenant) by
    // carrying the parent entity's `tenant:{t}` segment additively, ahead of the existing
    // `entity:`/`book:` segments (the per-tenant analogue of e1's `entity.created`). Single-tenant
    // deployments (the default tenant) keep the exact `entity:{}/book:{}` genesis scope, so their
    // ledger is byte-identical to before tenancy.
    let scope = if entity.tenant_id == crate::tenant::DEFAULT_TENANT_ID {
        format!("entity:{}/book:{}", entity.id, book.id)
    } else {
        format!(
            "tenant:{}/entity:{}/book:{}",
            entity.tenant_id, entity.id, book.id
        )
    };
    let event = ledger.append(actor, &scope, "book.opened", None, &payload);
    Ok(event.seq)
}

/// Seal an act into its book (WFL-20).
///
/// Steps, in order: verify the act belongs to `book` and is in `Signing`; run
/// `rule_pack`; block on any `Error` issue and on unacknowledged `Warning`s (LEG-05);
/// serialize and digest the payload; assign the next ata number (WFL-12); append the
/// `act.sealed` event to `ledger`; freeze the act.
///
/// `acknowledge_warnings` records that the operator has seen and accepted the warnings; it
/// has no effect when there are none.
#[allow(clippy::too_many_arguments)]
pub fn seal_act(
    book: &mut Book,
    act: &mut Act,
    entity: &Entity,
    rule_pack: &dyn RulePack,
    actor: &str,
    acknowledge_warnings: bool,
    manual_signature_original_reference: Option<ManualSignatureOriginalReference>,
    ledger: &mut Ledger,
) -> Result<SealOutcome, SealError> {
    let manual_signature_original_reference = manual_signature_original_reference
        .ok_or(SealError::MissingManualSignatureOriginalReference)?;

    seal_act_with_evidence(
        book,
        act,
        entity,
        rule_pack,
        actor,
        acknowledge_warnings,
        SealEvidence::Manual {
            original_reference: manual_signature_original_reference,
        },
        ledger,
    )
}

/// Seal an act using either validated digital evidence or an explicit manual-original reference.
///
/// This is the canonical `Signing -> Sealed` operation. The older [`seal_act`] entry point remains
/// as the manual-signature compatibility wrapper.
#[allow(clippy::too_many_arguments)]
pub fn seal_act_with_evidence(
    book: &mut Book,
    act: &mut Act,
    entity: &Entity,
    rule_pack: &dyn RulePack,
    actor: &str,
    acknowledge_warnings: bool,
    evidence: SealEvidence,
    ledger: &mut Ledger,
) -> Result<SealOutcome, SealError> {
    evidence.validate()?;

    // The act must belong to this book.
    if act.book_id != book.id {
        return Err(SealError::Book(BookError::WrongBook {
            act_book: act.book_id.to_string(),
            book: book.id.to_string(),
        }));
    }

    // The act must be ready to seal (out for signature). Check before assigning a number
    // or touching the ledger, so a premature seal burns neither.
    if act.state != ActState::Signing {
        return Err(SealError::Act(ActError::InvalidTransition {
            from: act.state,
            to: ActState::Sealed,
        }));
    }

    // Compliance gate (LEG-05).
    let issues = rule_pack.check_act(act, entity);
    let (warnings, errors): (Vec<_>, Vec<_>) = issues
        .into_iter()
        .partition(|i| i.severity == Severity::Warning);
    if !errors.is_empty() {
        return Err(SealError::ComplianceBlocked(render_issues(&errors)));
    }
    if !warnings.is_empty() && !acknowledge_warnings {
        return Err(SealError::WarningsNotAcknowledged(render_issues(&warnings)));
    }

    // Assign the sequential ata number (WFL-12) BEFORE freezing the payload, so the number can be
    // bound into the digest. It used to be assigned after, precisely so a serialize failure could
    // not burn a number — which left the number covered by nothing but the unhashed ledger
    // justification string. That property is preserved below by rolling the counter back instead.
    // Refuses unless the book is open (WFL-14).
    let counter_before = book.last_ata_number;
    let ata_number = book.assign_next_ata_number()?;
    let seal_metadata = evidence
        .seal_metadata(rule_pack.id(), entity)
        .with_ata_number(ata_number);

    // Freeze the content and the evidence tuple before appending anything (a serialize failure must
    // not burn a number or append an event). The evidence is embedded in the ledger preimage so a
    // later store edit cannot substitute a different signing snapshot or signed artifact.
    let payload = match serde_json::to_vec(&SealedActPayload {
        act: ActPayload::of(act),
        seal_metadata: &seal_metadata,
    }) {
        Ok(payload) => payload,
        Err(e) => {
            // Give the number back: the seal never happened, so it must not have consumed one.
            book.last_ata_number = counter_before;
            return Err(SealError::Serialize(e.to_string()));
        }
    };

    // Append the seal event; the ledger computes and stores the payload digest.
    let scope = format!("entity:{}/book:{}", entity.id, book.id);
    let justification = format!("seal ata n.º {ata_number} ({})", rule_pack.id());
    let event = ledger.append(actor, &scope, "act.sealed", Some(&justification), &payload);
    let event_seq = event.seq;
    let payload_digest = event.payload_digest;
    // Freeze the act (Signing → Sealed).
    act.mark_sealed(ata_number, payload_digest, event_seq, seal_metadata.clone())?;

    Ok(SealOutcome {
        ata_number,
        event_seq,
        payload_digest,
        seal_metadata,
        acknowledged_warnings: warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::{date, time};

    use crate::act::{
        Act, ActState, AgendaItem, MeetingChannel, WrittenResolutionEvidence,
        WrittenResolutionEvidenceItem,
    };
    use crate::book::{Book, BookKind, NumberingScheme};
    use crate::entity::{Entity, EntityId, EntityKind, Nipc};
    use crate::rules::CscArt63RulePack;

    fn entity() -> Entity {
        Entity::new(
            "Encosto Estratégico, S.A.",
            Nipc::parse("503004642").unwrap(),
            "Lisboa",
            EntityKind::SociedadeAnonima,
        )
    }

    fn abertura(e: &Entity) -> TermoDeAbertura {
        TermoDeAbertura {
            entity_name: e.name.clone(),
            entity_nipc: e.nipc.to_string(),
            entity_seat: e.seat.clone(),
            purpose: "livro de atas da assembleia geral".into(),
            numbering_scheme: NumberingScheme::Sequential,
            opening_date: date!(2026 - 01 - 15),
            required_signatories: vec!["Administrador".into()],
            required_signatory_records: Vec::new(),
            ..TermoDeAbertura::default()
        }
    }

    fn ready_act(book: &Book) -> Act {
        let mut act = Act::draft(book.id, "Ata da AG anual", MeetingChannel::Physical);
        act.meeting_date = Some(date!(2026 - 03 - 30));
        act.meeting_time = Some(time!(10:00));
        act.place = Some("Sede social".into());
        // To seal without acknowledging advisories, CSC v2 wants the mesa chair (a blocking
        // Error), the secretaries, time, and agenda (§2.5): make the fixture fully clean under
        // the v2 pack.
        act.mesa.presidente = Some("Ana Presidente".into());
        act.mesa.secretarios = vec!["Rui Secretário".into()];
        act.agenda = vec![AgendaItem {
            number: 1,
            text: "Aprovação das contas".into(),
        }];
        act.attendance_reference = Some("Lista de presenças".into());
        act.deliberations = "Aprovadas as contas do exercício.".into();
        for state in [
            ActState::Review,
            ActState::Convened,
            ActState::Deliberated,
            ActState::TextApproved,
            ActState::Signing,
        ] {
            act.advance_to(state).unwrap();
        }
        act
    }

    fn manual_reference() -> ManualSignatureOriginalReference {
        ManualSignatureOriginalReference {
            storage_reference: "Arquivo A / Pasta 2026 / Ata teste".to_owned(),
            custodian: None,
            note: None,
        }
    }

    #[test]
    fn opening_a_book_emits_genesis_event() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        let seq =
            open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(ledger.events().len(), 1);
        assert_eq!(ledger.events()[0].kind, "book.opened");
        assert!(book.is_open());
    }

    #[test]
    fn opening_a_book_joins_its_tenant_chain() {
        // wp27-e3 (Part 2): the `book.opened` genesis carries the parent entity's `tenant:{t}`
        // segment so the book joins its tenant chain (ChainId::Tenant), mirroring the entity genesis.
        let tenant = crate::tenant::TenantId::new();
        let e = crate::entity::Entity::new(
            "Encosto Estratégico, S.A.",
            crate::entity::Nipc::unvalidated("A-0001"),
            "Lisboa",
            crate::entity::EntityKind::SociedadeAnonima,
        )
        .in_tenant(tenant);
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();
        let scope = &ledger.events()[0].scope;
        assert_eq!(
            scope,
            &format!("tenant:{tenant}/entity:{}/book:{}", e.id, book.id),
            "book.opened must carry the tenant/entity/book scope"
        );
        let memberships = Ledger::memberships(scope, "book.opened");
        assert!(
            memberships.contains(&chancela_ledger::ChainId::Tenant(tenant.to_string())),
            "book.opened must join its tenant chain, got {memberships:?}"
        );
    }

    #[test]
    fn seal_assigns_sequential_numbers_and_chains_events() {
        let e = entity();
        let mut ledger = Ledger::default();
        // Mirror the real flow: the entity is created first, so the company chain's genesis is
        // `entity.created` (per the multi-chain model) before the book's `book.opened`.
        ledger.append(
            "sec@encosto",
            &e.id.to_string(),
            "entity.created",
            None,
            b"entity",
        );
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let mut first = ready_act(&book);
        let out1 = seal_act(
            &mut book,
            &mut first,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            Some(manual_reference()),
            &mut ledger,
        )
        .unwrap();
        assert_eq!(out1.ata_number, 1);
        assert_eq!(first.state, ActState::Sealed);
        assert_eq!(first.payload_digest, Some(out1.payload_digest));
        assert_eq!(out1.seal_metadata.rule_pack_id, "csc-art63/v2");
        assert_eq!(out1.seal_metadata.version, "v2");
        assert_eq!(
            out1.seal_metadata.family,
            crate::entity::EntityFamily::CommercialCompany
        );
        assert_eq!(
            out1.seal_metadata.profile,
            crate::entity::EntityKind::SociedadeAnonima
        );
        assert_eq!(first.seal_metadata, Some(out1.seal_metadata.clone()));

        let mut second = ready_act(&book);
        let out2 = seal_act(
            &mut book,
            &mut second,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            Some(manual_reference()),
            &mut ledger,
        )
        .unwrap();
        assert_eq!(out2.ata_number, 2);

        // entity.created (company genesis) + book.opened (book genesis) + two seals; chain verifies.
        assert_eq!(ledger.events().len(), 4);
        assert_eq!(ledger.verify().unwrap(), 4);
    }

    #[test]
    fn manual_signature_original_reference_is_frozen_in_seal_metadata() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let reference = ManualSignatureOriginalReference {
            storage_reference: "Arquivo A / Pasta 2026 / Ata 1".to_owned(),
            custodian: Some("Secretariado".to_owned()),
            note: Some("Original assinado em papel; metadados locais apenas.".to_owned()),
        };
        let mut act = ready_act(&book);
        let outcome = seal_act(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            Some(reference.clone()),
            &mut ledger,
        )
        .unwrap();

        assert_eq!(
            outcome.seal_metadata.manual_signature_original_reference,
            Some(reference.clone())
        );
        assert_eq!(
            act.seal_metadata
                .as_ref()
                .and_then(|metadata| metadata.manual_signature_original_reference.as_ref()),
            Some(&reference)
        );
    }

    #[test]
    fn digital_signature_evidence_is_bound_and_frozen_before_seal() {
        let e = entity();
        let mut ledger = Ledger::default();
        ledger.append(
            "sec@encosto",
            &e.id.to_string(),
            "entity.created",
            None,
            b"entity",
        );
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let snapshot = "11".repeat(32);
        let signed = "22".repeat(32);
        let validation = "33".repeat(32);
        let mut act = ready_act(&book);
        let outcome = seal_act_with_evidence(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            SealEvidence::Digital {
                signing_snapshot_digest: snapshot.clone(),
                signed_pdf_digest: signed.clone(),
                signature_validation_report_digest: validation.clone(),
            },
            &mut ledger,
        )
        .unwrap();

        assert_eq!(act.state, ActState::Sealed);
        assert!(
            outcome
                .seal_metadata
                .manual_signature_original_reference
                .is_none()
        );
        assert_eq!(
            outcome.seal_metadata.signing_snapshot_digest,
            Some(snapshot)
        );
        assert_eq!(outcome.seal_metadata.signed_pdf_digest, Some(signed));
        assert_eq!(
            outcome.seal_metadata.signature_validation_report_digest,
            Some(validation)
        );
        assert!(outcome.seal_metadata.has_complete_signature_evidence());
        assert_eq!(act.seal_metadata, Some(outcome.seal_metadata));
        assert_eq!(ledger.verify().unwrap(), 3);
    }

    #[test]
    fn malformed_digital_evidence_rolls_back_without_number_or_event() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();
        let mut act = ready_act(&book);

        let error = seal_act_with_evidence(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            SealEvidence::Digital {
                signing_snapshot_digest: "not-a-digest".to_owned(),
                signed_pdf_digest: "22".repeat(32),
                signature_validation_report_digest: "33".repeat(32),
            },
            &mut ledger,
        )
        .unwrap_err();

        assert!(matches!(error, SealError::InvalidSignatureEvidence(_)));
        assert_eq!(book.last_ata_number, 0);
        assert_eq!(act.state, ActState::Signing);
        assert!(act.seal_metadata.is_none());
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn manual_signature_original_reference_is_required_before_mutation() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let mut act = ready_act(&book);
        let err = seal_act(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            None,
            &mut ledger,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            SealError::MissingManualSignatureOriginalReference
        ));
        assert_eq!(book.last_ata_number, 0);
        assert_eq!(ledger.events().len(), 1);
        assert_eq!(act.state, ActState::Signing);
        assert!(act.seal_metadata.is_none());
    }

    #[test]
    fn seal_rejected_on_compliance_error_without_burning_a_number() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let mut act = ready_act(&book);
        act.deliberations = "   ".into(); // now violates CSC art. 63.º
        let err = seal_act(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            Some(manual_reference()),
            &mut ledger,
        )
        .unwrap_err();
        assert!(matches!(err, SealError::ComplianceBlocked(_)));
        // No ata number consumed, no seal event appended, act still in Signing.
        assert_eq!(book.last_ata_number, 0);
        assert_eq!(ledger.events().len(), 1);
        assert_eq!(act.state, ActState::Signing);
    }

    #[test]
    fn seal_requires_signing_state() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let mut act = Act::draft(book.id, "Rascunho", MeetingChannel::Physical);
        let err = seal_act(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            Some(manual_reference()),
            &mut ledger,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SealError::Act(ActError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn seal_rejects_act_from_another_book() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let other = Book::new(e.id, BookKind::GerenciaAdministracao);
        let mut act = ready_act(&other);
        let err = seal_act(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            Some(manual_reference()),
            &mut ledger,
        )
        .unwrap_err();
        assert!(matches!(err, SealError::Book(BookError::WrongBook { .. })));
    }

    #[test]
    fn unvalidated_nipc_warns_and_seals_only_when_acknowledged() {
        // End-to-end through the SHIPPED CscArt63RulePack: an entity whose NIPC was stored
        // via the validation override raises a Warning, so sealing needs acknowledgement.
        let e = Entity::new(
            "Foreign Holdings Ltd.",
            Nipc::unvalidated("GB-00000000"),
            "London",
            EntityKind::SociedadeAnonima,
        );
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        // Without acknowledgement the advisory blocks the seal (no number burned).
        let mut act = ready_act(&book);
        let err = seal_act(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            Some(manual_reference()),
            &mut ledger,
        )
        .unwrap_err();
        assert!(matches!(err, SealError::WarningsNotAcknowledged(_)));
        assert_eq!(book.last_ata_number, 0);
        assert_eq!(ledger.events().len(), 1);

        // With acknowledgement it seals and records the acknowledged warning.
        let outcome = seal_act(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            true,
            Some(manual_reference()),
            &mut ledger,
        )
        .unwrap();
        assert_eq!(outcome.ata_number, 1);
        assert_eq!(act.state, ActState::Sealed);
        assert_eq!(outcome.acknowledged_warnings.len(), 1);
        assert_eq!(
            outcome.acknowledged_warnings[0].rule_id,
            "CSC-63/nipc-unvalidated"
        );
    }

    /// A rule pack that emits exactly one `Warning` (plus an optional blocking `Error`), so the
    /// LEG-05 warning-acknowledgement branch of `seal_act` can be exercised — the shipped
    /// `CscArt63RulePack` only ever emits `Error`s.
    struct WarningPack {
        also_errors: bool,
    }

    impl crate::rules::RulePack for WarningPack {
        fn id(&self) -> &str {
            "test-warning/v1"
        }
        fn check_act(&self, _act: &Act, _entity: &Entity) -> Vec<crate::rules::ComplianceIssue> {
            let mut issues = vec![crate::rules::ComplianceIssue {
                rule_id: "TEST/advisory".into(),
                severity: crate::rules::Severity::Warning,
                message: "advisory finding".into(),
                legal_basis: Vec::new(),
            }];
            if self.also_errors {
                issues.push(crate::rules::ComplianceIssue {
                    rule_id: "TEST/blocking".into(),
                    severity: crate::rules::Severity::Error,
                    message: "blocking finding".into(),
                    legal_basis: Vec::new(),
                });
            }
            issues
        }
    }

    #[test]
    fn unacknowledged_warning_blocks_the_seal_without_burning_a_number() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let mut act = ready_act(&book);
        let err = seal_act(
            &mut book,
            &mut act,
            &e,
            &WarningPack { also_errors: false },
            "sec@encosto",
            false, // do NOT acknowledge
            Some(manual_reference()),
            &mut ledger,
        )
        .unwrap_err();
        assert!(matches!(err, SealError::WarningsNotAcknowledged(_)));
        // The advisory refusal must not consume a number, append an event, or freeze the act.
        assert_eq!(book.last_ata_number, 0);
        assert_eq!(ledger.events().len(), 1);
        assert_eq!(act.state, ActState::Signing);
    }

    #[test]
    fn acknowledged_warning_seals_and_records_the_warning() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let mut act = ready_act(&book);
        let outcome = seal_act(
            &mut book,
            &mut act,
            &e,
            &WarningPack { also_errors: false },
            "sec@encosto",
            true, // acknowledge the advisory
            Some(manual_reference()),
            &mut ledger,
        )
        .unwrap();
        assert_eq!(outcome.ata_number, 1);
        assert_eq!(act.state, ActState::Sealed);
        // The acknowledgement is itself part of the record (LEG-05).
        assert_eq!(outcome.acknowledged_warnings.len(), 1);
        assert_eq!(outcome.acknowledged_warnings[0].rule_id, "TEST/advisory");
        assert_eq!(ledger.events().len(), 2); // genesis + seal
    }

    #[test]
    fn a_blocking_error_wins_even_when_warnings_are_acknowledged() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();

        let mut act = ready_act(&book);
        // Acknowledging warnings must not relax the hard `Error` gate: the error is reported.
        let err = seal_act(
            &mut book,
            &mut act,
            &e,
            &WarningPack { also_errors: true },
            "sec@encosto",
            true,
            Some(manual_reference()),
            &mut ledger,
        )
        .unwrap_err();
        assert!(matches!(err, SealError::ComplianceBlocked(_)));
        assert_eq!(book.last_ata_number, 0);
        assert_eq!(ledger.events().len(), 1);
    }

    #[test]
    fn payload_digest_preimage_binds_the_new_mandatory_fields() {
        // R8: the sealed payload must bind the new content, so two otherwise-identical acts
        // (same id) that differ only in a new field produce different digest preimages.
        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let base = ready_act(&book);
        let bytes = |a: &Act| serde_json::to_vec(&ActPayload::of(a)).unwrap();

        let mut time_changed = base.clone();
        time_changed.meeting_time = Some(time!(15:30)); // base is 10:00
        assert_ne!(bytes(&base), bytes(&time_changed), "meeting_time must bind");

        let mut mesa_changed = base.clone();
        mesa_changed.mesa.presidente = Some("Outro Presidente".into());
        assert_ne!(bytes(&base), bytes(&mesa_changed), "mesa must bind");

        let mut items_changed = base.clone();
        items_changed.deliberation_items = vec![crate::act::DeliberationItem {
            agenda_number: Some(1),
            text: "Nova deliberação".into(),
            vote: Some(crate::act::VoteResult::Unanimous),
            statements: Vec::new(),
        }];
        assert_ne!(
            bytes(&base),
            bytes(&items_changed),
            "deliberation_items must bind"
        );

        let mut counts_changed = base.clone();
        counts_changed.members_present = Some(7);
        assert_ne!(bytes(&base), bytes(&counts_changed), "counts must bind");
    }

    #[test]
    fn g1_g2_bind_into_the_seal_digest_when_present() {
        // R8: a populated convening record or attendance list must change the sealed preimage,
        // so it is bound into the new seal's digest.
        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let base = ready_act(&book);
        let bytes = |a: &Act| serde_json::to_vec(&ActPayload::of(a)).unwrap();

        let mut with_convening = base.clone();
        with_convening.convening = Some(crate::act::Convening {
            convener: Some("Amélia Marques".into()),
            antecedence_days: Some(15),
            ..Default::default()
        });
        assert_ne!(bytes(&base), bytes(&with_convening), "convening must bind");

        let mut with_attendees = base.clone();
        with_attendees.attendees = vec![crate::act::Attendee {
            name: "Amélia Marques".into(),
            quality: crate::act::SignatoryCapacity::Member,
            quality_note: None,
            presence: crate::act::PresenceMode::InPerson,
            represented_by: None,
            weight: Some(crate::act::AttendanceWeight::Permilage(250)),
        }];
        assert_ne!(bytes(&base), bytes(&with_attendees), "attendees must bind");
    }

    #[test]
    fn the_no_convocatoria_basis_binds_into_the_seal_digest_when_present() {
        // The ata recites this basis, and under CSC art. 56.º/1 a) it is what stands between a
        // valid deliberação and a null one. A seal that attested every detail of how a meeting was
        // called but not the declared ground on which one lawfully was *not* called would leave
        // the most load-bearing datum about the convening uncovered — and the most attractive one
        // to alter after the fact.
        use crate::act::{ConveningWaiver, NoConveningBasis};

        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let base = ready_act(&book);
        let bytes = |a: &Act| serde_json::to_vec(&ActPayload::of(a)).unwrap();

        // Absent ⇒ no bytes. Appended last and skip-serialized, so the preimage of an act carrying
        // no waiver — every act that predates this field — is byte-identical to what it was.
        // `digest_of_pre_existing_act_is_unchanged_by_the_f15_page_count`, which compares against a
        // hand-written reconstruction of the older shape, is the standing proof of that and must
        // keep passing unchanged.
        assert!(base.convening_waiver.is_none());
        assert!(
            !String::from_utf8(bytes(&base))
                .unwrap()
                .contains("convening_waiver"),
            "an act with no waiver must emit no bytes for it"
        );

        let mut with_waiver = base.clone();
        with_waiver.convening_waiver = Some(ConveningWaiver {
            basis: NoConveningBasis::AssembleiaUniversal,
            grounds: None,
            all_agreed_to_meet: true,
            all_agreed_to_agenda: true,
            evidence_reference: Some("Anexo I — declaração conjunta".into()),
        });
        assert_ne!(
            bytes(&base),
            bytes(&with_waiver),
            "a recorded no-convocatória basis must bind"
        );

        // Not merely presence: the *content* binds, so the declared basis and the recorded
        // agreement cannot be swapped under a frozen digest.
        let mut agreement_withdrawn = with_waiver.clone();
        agreement_withdrawn
            .convening_waiver
            .as_mut()
            .expect("waiver")
            .all_agreed_to_agenda = false;
        assert_ne!(
            bytes(&with_waiver),
            bytes(&agreement_withdrawn),
            "withdrawing the recorded agreement must change the preimage"
        );

        let mut basis_changed = with_waiver.clone();
        {
            let waiver = basis_changed.convening_waiver.as_mut().expect("waiver");
            waiver.basis = NoConveningBasis::Other;
            waiver.grounds = Some("Outro fundamento.".into());
        }
        assert_ne!(
            bytes(&with_waiver),
            bytes(&basis_changed),
            "changing the declared basis must change the preimage"
        );
    }

    #[test]
    fn written_resolution_evidence_binds_into_the_seal_digest_when_present() {
        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let mut base = ready_act(&book);
        base.channel = MeetingChannel::WrittenResolution;
        let bytes = |a: &Act| serde_json::to_vec(&ActPayload::of(a)).unwrap();

        let mut with_evidence = base.clone();
        with_evidence.written_resolution_evidence = Some(WrittenResolutionEvidence {
            checklist: vec![WrittenResolutionEvidenceItem {
                label: "Signed written approvals".to_owned(),
                reference: Some("doc:written-approvals".to_owned()),
                digest: Some([11; 32]),
                note: Some("capture note".to_owned()),
            }],
            review_receipts: vec![],
            note: Some("operator note".to_owned()),
        });

        assert_ne!(
            bytes(&base),
            bytes(&with_evidence),
            "written-resolution evidence must bind"
        );
        let json = String::from_utf8(bytes(&with_evidence)).unwrap();
        assert!(json.contains("written_resolution_evidence"));
    }

    #[test]
    fn digest_of_pre_existing_act_is_unchanged_by_g1_g2_fields() {
        // The critical backward-compat guarantee: an act carrying neither a convening record
        // nor structured attendees (i.e. one that predates G1/G2) must produce a preimage —
        // and therefore a digest — **byte-identical** to what it produced before the fields
        // were appended. Already-sealed acts thus stay chain-valid.
        use sha2::{Digest, Sha256};

        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let act = ready_act(&book);
        assert!(act.convening.is_none() && act.attendees.is_empty());

        // Faithful reconstruction of the ActPayload shape *before* G1/G2 were appended: the
        // same fields, same declaration order, up to `members_represented`.
        #[derive(Serialize)]
        struct OldActPayload<'a> {
            act_id: String,
            book_id: String,
            title: &'a str,
            channel: MeetingChannel,
            meeting_date: Option<time::Date>,
            place: Option<&'a str>,
            attendance_reference: Option<&'a str>,
            deliberations: &'a str,
            telematic_evidence: Option<&'a str>,
            attachments: &'a [Attachment],
            signatories: &'a [SignatorySlot],
            retifies: Option<String>,
            meeting_time: Option<time::Time>,
            mesa: &'a Mesa,
            agenda: &'a [AgendaItem],
            referenced_documents: &'a [DocumentReference],
            deliberation_items: &'a [DeliberationItem],
            members_present: Option<u32>,
            members_represented: Option<u32>,
        }
        let old = OldActPayload {
            act_id: act.id.to_string(),
            book_id: act.book_id.to_string(),
            title: &act.title,
            channel: act.channel,
            meeting_date: act.meeting_date,
            place: act.place.as_deref(),
            attendance_reference: act.attendance_reference.as_deref(),
            deliberations: &act.deliberations,
            telematic_evidence: act.telematic_evidence.as_deref(),
            attachments: &act.attachments,
            signatories: &act.signatories,
            retifies: act.retifies.map(|id| id.to_string()),
            meeting_time: act.meeting_time,
            mesa: &act.mesa,
            agenda: &act.agenda,
            referenced_documents: &act.referenced_documents,
            deliberation_items: &act.deliberation_items,
            members_present: act.members_present,
            members_represented: act.members_represented,
        };

        let new_bytes = serde_json::to_vec(&ActPayload::of(&act)).unwrap();
        let old_bytes = serde_json::to_vec(&old).unwrap();

        // Preimage is byte-unchanged, and the empty G1/G2 fields emit nothing at all.
        assert_eq!(new_bytes, old_bytes);
        let json = String::from_utf8(new_bytes.clone()).unwrap();
        assert!(
            !json.contains("convening"),
            "empty convening must not serialize"
        );
        assert!(
            !json.contains("attendees"),
            "empty attendees must not serialize"
        );

        // Byte-identical preimage ⇒ identical sha-256 digest (chain-valid).
        assert_eq!(
            Sha256::digest(&new_bytes).as_slice(),
            Sha256::digest(&old_bytes).as_slice(),
        );
    }

    #[test]
    fn digest_of_pre_existing_act_is_unchanged_by_the_f15_page_count() {
        // The same guarantee for F15. An act carrying no frozen page count — every act that
        // predates the capacity model, and any act sealed without one — must produce a
        // preimage byte-identical to what it produced before `page_count` was appended.
        use sha2::{Digest, Sha256};

        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let act = ready_act(&book);
        assert!(act.page_count.is_none());

        // Faithful reconstruction of the ActPayload shape *before* F15 was appended: the same
        // fields, same declaration order, up to `attendees`.
        #[derive(Serialize)]
        struct OldActPayload<'a> {
            act_id: String,
            book_id: String,
            title: &'a str,
            channel: MeetingChannel,
            meeting_date: Option<time::Date>,
            place: Option<&'a str>,
            attendance_reference: Option<&'a str>,
            deliberations: &'a str,
            telematic_evidence: Option<&'a str>,
            attachments: &'a [Attachment],
            signatories: &'a [SignatorySlot],
            retifies: Option<String>,
            meeting_time: Option<time::Time>,
            mesa: &'a Mesa,
            agenda: &'a [AgendaItem],
            referenced_documents: &'a [DocumentReference],
            #[serde(skip_serializing_if = "Option::is_none")]
            written_resolution_evidence: Option<&'a WrittenResolutionEvidence>,
            deliberation_items: &'a [DeliberationItem],
            members_present: Option<u32>,
            members_represented: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            convening: Option<&'a Convening>,
            #[serde(skip_serializing_if = "Option::is_none")]
            attendees: Option<&'a [Attendee]>,
        }
        let old = OldActPayload {
            act_id: act.id.to_string(),
            book_id: act.book_id.to_string(),
            title: &act.title,
            channel: act.channel,
            meeting_date: act.meeting_date,
            place: act.place.as_deref(),
            attendance_reference: act.attendance_reference.as_deref(),
            deliberations: &act.deliberations,
            telematic_evidence: act.telematic_evidence.as_deref(),
            attachments: &act.attachments,
            signatories: &act.signatories,
            retifies: act.retifies.map(|id| id.to_string()),
            meeting_time: act.meeting_time,
            mesa: &act.mesa,
            agenda: &act.agenda,
            referenced_documents: &act.referenced_documents,
            written_resolution_evidence: act.written_resolution_evidence.as_ref(),
            deliberation_items: &act.deliberation_items,
            members_present: act.members_present,
            members_represented: act.members_represented,
            convening: act.convening.as_ref(),
            attendees: (!act.attendees.is_empty()).then_some(act.attendees.as_slice()),
        };

        let new_bytes = serde_json::to_vec(&ActPayload::of(&act)).unwrap();
        let old_bytes = serde_json::to_vec(&old).unwrap();

        assert_eq!(new_bytes, old_bytes);
        let json = String::from_utf8(new_bytes.clone()).unwrap();
        assert!(
            !json.contains("page_count"),
            "an absent page count must not serialize"
        );
        assert_eq!(
            Sha256::digest(&new_bytes).as_slice(),
            Sha256::digest(&old_bytes).as_slice(),
        );
    }

    #[test]
    fn digest_of_pre_existing_act_is_unchanged_by_the_t74_markup_body() {
        // The same guarantee for the markup body, and the one that matters most here: an ata whose
        // prose lives in the plain-text `deliberations` field — which is every ata authored before
        // t74, i.e. every ata sealed to date — must produce a preimage byte-identical to what it
        // produced before `body` was appended. Anything else invalidates every book's hash chain
        // at once, with no recovery.
        use sha2::{Digest, Sha256};

        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let act = ready_act(&book);
        assert!(act.body.is_none());

        // Faithful reconstruction of the ActPayload shape *before* the body was appended: the same
        // fields, same declaration order, up to `convening_waiver`.
        #[derive(Serialize)]
        struct OldActPayload<'a> {
            act_id: String,
            book_id: String,
            title: &'a str,
            channel: MeetingChannel,
            meeting_date: Option<time::Date>,
            place: Option<&'a str>,
            attendance_reference: Option<&'a str>,
            deliberations: &'a str,
            telematic_evidence: Option<&'a str>,
            attachments: &'a [Attachment],
            signatories: &'a [SignatorySlot],
            retifies: Option<String>,
            meeting_time: Option<time::Time>,
            mesa: &'a Mesa,
            agenda: &'a [AgendaItem],
            referenced_documents: &'a [DocumentReference],
            #[serde(skip_serializing_if = "Option::is_none")]
            written_resolution_evidence: Option<&'a WrittenResolutionEvidence>,
            deliberation_items: &'a [DeliberationItem],
            members_present: Option<u32>,
            members_represented: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            convening: Option<&'a Convening>,
            #[serde(skip_serializing_if = "Option::is_none")]
            attendees: Option<&'a [Attendee]>,
            #[serde(skip_serializing_if = "Option::is_none")]
            page_count: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            superseded_signing_snapshots: Option<&'a [SupersededSigningSnapshot]>,
            #[serde(skip_serializing_if = "Option::is_none")]
            convening_waiver: Option<&'a ConveningWaiver>,
        }
        let old = OldActPayload {
            act_id: act.id.to_string(),
            book_id: act.book_id.to_string(),
            title: &act.title,
            channel: act.channel,
            meeting_date: act.meeting_date,
            place: act.place.as_deref(),
            attendance_reference: act.attendance_reference.as_deref(),
            deliberations: &act.deliberations,
            telematic_evidence: act.telematic_evidence.as_deref(),
            attachments: &act.attachments,
            signatories: &act.signatories,
            retifies: act.retifies.map(|id| id.to_string()),
            meeting_time: act.meeting_time,
            mesa: &act.mesa,
            agenda: &act.agenda,
            referenced_documents: &act.referenced_documents,
            written_resolution_evidence: act.written_resolution_evidence.as_ref(),
            deliberation_items: &act.deliberation_items,
            members_present: act.members_present,
            members_represented: act.members_represented,
            convening: act.convening.as_ref(),
            attendees: (!act.attendees.is_empty()).then_some(act.attendees.as_slice()),
            page_count: act.page_count,
            superseded_signing_snapshots: (!act.superseded_signing_snapshots.is_empty())
                .then_some(act.superseded_signing_snapshots.as_slice()),
            convening_waiver: act.convening_waiver.as_ref(),
        };

        let new_bytes = serde_json::to_vec(&ActPayload::of(&act)).unwrap();
        let old_bytes = serde_json::to_vec(&old).unwrap();

        assert_eq!(new_bytes, old_bytes);
        let json = String::from_utf8(new_bytes.clone()).unwrap();
        assert!(
            !json.contains("body"),
            "an absent markup body must not serialize"
        );
        assert_eq!(
            Sha256::digest(&new_bytes).as_slice(),
            Sha256::digest(&old_bytes).as_slice(),
        );
    }

    #[test]
    fn the_markup_body_binds_source_compiler_and_compiled_output_into_the_seal() {
        // The companion proof: the body is not silently dropped, and — the point of the design —
        // all three of its facts bind. `compiled_digest` in particular means a later compiler
        // producing different blocks from the same source is *detectable*, because the seal
        // covers what the markup compiled to and not merely the markup.
        use crate::act::{ActBody, BodyFormat};

        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let base = ready_act(&book);
        let bytes = |a: &Act| serde_json::to_vec(&ActPayload::of(a)).unwrap();

        let authored = ActBody {
            format: BodyFormat::Markdown,
            source: "Foi aprovado o **relatório de gestão**.".to_owned(),
            compiler_id: "md-block/v1".to_owned(),
            compiled_digest: "aa".repeat(32),
        };
        let mut with_body = base.clone();
        with_body.body = Some(authored.clone());
        assert_ne!(bytes(&base), bytes(&with_body), "a markup body must bind");

        // Each fact binds independently, so none of them can be swapped under a frozen digest.
        for (label, mutated) in [
            (
                "the authored source",
                ActBody {
                    source: "Foi rejeitado o **relatório de gestão**.".to_owned(),
                    ..authored.clone()
                },
            ),
            (
                "the compiler version",
                ActBody {
                    compiler_id: "md-block/v2".to_owned(),
                    ..authored.clone()
                },
            ),
            (
                "what the source compiled to",
                ActBody {
                    compiled_digest: "bb".repeat(32),
                    ..authored.clone()
                },
            ),
        ] {
            let mut variant = base.clone();
            variant.body = Some(mutated);
            assert_ne!(
                bytes(&with_body),
                bytes(&variant),
                "{label} must bind into the seal"
            );
        }

        // And the hard prohibition, asserted rather than assumed: the plain-text `deliberations`
        // field is never reinterpreted as markup. An act whose legacy prose contains markup
        // characters carries them verbatim into the preimage, with no body implied.
        let mut legacy = base.clone();
        legacy.deliberations = "Aprovado o **relatório** com 1. ressalva.".to_owned();
        let json = String::from_utf8(bytes(&legacy)).unwrap();
        assert!(
            json.contains("Aprovado o **relatório** com 1. ressalva."),
            "legacy prose must serialize verbatim, not as markup: {json}"
        );
        assert!(
            legacy.body.is_none(),
            "plain-text deliberations must never imply a body"
        );
    }

    /// The seal preimage of an act carrying **none** of the optional append-only fields, written
    /// out as a literal.
    ///
    /// The other back-compat tests in this module rebuild the older `ActPayload` shape from the
    /// current types. That proves field *order* but re-derives every field *value* from the code
    /// under test, so a change in how a field serializes — a date encoding, a renamed enum
    /// variant, an `Option` that starts emitting `null` where it emitted nothing — moves both
    /// sides together and is invisible. Only a literal catches that.
    ///
    /// The literal is the shape every act sealed before `convening` / `attendees` / `page_count` /
    /// `superseded_signing_snapshots` / `convening_waiver` / `body` existed was digested from, and
    /// those acts' digests are frozen in their books' hash chains.
    ///
    /// **A failure here is a chain-compatibility break, not a stale fixture.** Re-derive it only
    /// after deciding the preimage change is intended and that every already-sealed act's digest
    /// may cease to be reproducible.
    const CLEAN_ACT_PREIMAGE: &str = r#"{"act_id":"33333333-3333-3333-3333-333333333333","book_id":"22222222-2222-2222-2222-222222222222","title":"Ata da AG anual","channel":"Physical","meeting_date":[2026,89],"place":"Sede social","attendance_reference":"Lista de presenças","deliberations":"Aprovadas as contas do exercício.","telematic_evidence":null,"attachments":[],"signatories":[],"retifies":null,"meeting_time":[10,0,0,0],"mesa":{"presidente":"Ana Presidente","secretarios":["Rui Secretário"]},"agenda":[{"number":1,"text":"Aprovação das contas"}],"referenced_documents":[],"deliberation_items":[],"members_present":null,"members_represented":null}"#;

    /// The anchors a live ledger yields — what every production caller passes.
    fn anchors_of(ledger: &Ledger) -> SealAnchors {
        SealAnchors::from_ledger(ledger)
    }

    /// The act used to pin [`CLEAN_ACT_PREIMAGE`]: `ready_act` with the two random identifiers
    /// nailed down, and nothing else.
    fn preimage_fixture_act() -> Act {
        let mut book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        book.id = crate::book::BookId(uuid::Uuid::from_bytes([0x22; 16]));
        let mut act = ready_act(&book);
        act.id = crate::act::ActId(uuid::Uuid::from_bytes([0x33; 16]));
        act
    }

    #[test]
    fn the_preimage_of_an_act_carrying_no_optional_field_is_byte_for_byte_frozen() {
        let act = preimage_fixture_act();
        // The premise: this act carries none of the append-only fields.
        assert!(act.convening.is_none());
        assert!(act.attendees.is_empty());
        assert!(act.page_count.is_none());
        assert!(act.superseded_signing_snapshots.is_empty());
        assert!(act.convening_waiver.is_none());
        assert!(act.body.is_none());

        let actual = serde_json::to_string(&ActPayload::of(&act)).unwrap();
        assert_eq!(
            actual, CLEAN_ACT_PREIMAGE,
            "the seal preimage moved — every already-frozen act digest is now irreproducible"
        );
    }

    /// A **sealable** act carrying every reachably-absent preimage field at its empty value.
    ///
    /// The set is drawn from the rule packs, not from taste. `meeting_date`, `place` and
    /// `attendance_reference` stay populated because `civil_baseline` — which every pack builds on
    /// — makes their absence a blocking `Error`; `mesa.presidente`/`mesa.secretarios` stay
    /// populated because CSC v2 does the same. No pack can seal an act without those, so no such
    /// row exists and there is nothing there to protect.
    ///
    /// What remains is exactly the six the packs treat as advisory, so an act shaped like this
    /// **is sealable today** — proved by
    /// `a_minimal_act_can_actually_be_sealed_so_rows_shaped_like_it_exist`.
    fn minimal_preimage_fixture_act() -> Act {
        let mut act = preimage_fixture_act();
        act.meeting_time = None;
        act.agenda = Vec::new();
        act.referenced_documents = Vec::new();
        act.deliberation_items = Vec::new();
        act.members_present = None;
        act.members_represented = None;
        act
    }

    #[test]
    fn the_preimage_of_a_minimal_act_is_byte_for_byte_frozen() {
        // The gap the R8 comment left open, from the direction nobody was looking.
        //
        // `CLEAN_ACT_PREIMAGE` above populates `meeting_time` and `agenda`, so it pins how those
        // fields look when PRESENT and says nothing about how they look when absent. They are
        // unconditional — absent still emits `"meeting_time":null`, `"agenda":[]` — and the
        // obvious "fix" for the R8 concern is to add `skip_serializing_if` to them. That would
        // silently delete those keys from the preimage of every act sealed without them, which the
        // packs permit (they are `warning`, not `Error`), and every one of those acts would
        // re-hash to something other than the digest its seal froze.
        //
        // So the absent form is pinned here, byte for byte. If this fails because a key
        // DISAPPEARED, that is the break: restore the field's unconditional serialization.
        const MINIMAL_ACT_PREIMAGE: &str = r#"{"act_id":"33333333-3333-3333-3333-333333333333","book_id":"22222222-2222-2222-2222-222222222222","title":"Ata da AG anual","channel":"Physical","meeting_date":[2026,89],"place":"Sede social","attendance_reference":"Lista de presenças","deliberations":"Aprovadas as contas do exercício.","telematic_evidence":null,"attachments":[],"signatories":[],"retifies":null,"meeting_time":null,"mesa":{"presidente":"Ana Presidente","secretarios":["Rui Secretário"]},"agenda":[],"referenced_documents":[],"deliberation_items":[],"members_present":null,"members_represented":null}"#;

        let act = minimal_preimage_fixture_act();
        let actual = serde_json::to_string(&ActPayload::of(&act)).unwrap();
        assert_eq!(
            actual, MINIMAL_ACT_PREIMAGE,
            "the seal preimage moved for an act carrying these fields at their absent value — \
             every act already sealed without them is now irreproducible"
        );

        // Said as a property rather than as bytes, so a failure names the field. Each of these
        // MUST emit its key even though it holds nothing.
        for key in [
            "\"meeting_time\":null",
            "\"agenda\":[]",
            "\"referenced_documents\":[]",
            "\"deliberation_items\":[]",
            "\"members_present\":null",
            "\"members_represented\":null",
        ] {
            assert!(
                actual.contains(key),
                "{key} vanished from the preimage: adding `skip_serializing_if` to an \
                 unconditional field breaks every act already sealed without a value for it"
            );
        }
    }

    #[test]
    fn a_minimal_act_can_actually_be_sealed_so_rows_shaped_like_it_exist() {
        // The premise of the test above, proved rather than assumed. If the rule pack refused this
        // act, no such row could exist and the absent form would need no protection. It does not
        // refuse: every one of those omissions is advisory, so acknowledging warnings seals it.
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();
        let mut act = minimal_preimage_fixture_act();
        act.book_id = book.id;

        seal_act(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            true, // the omissions are warnings; none of them bars the seal
            Some(manual_reference()),
            &mut ledger,
        )
        .expect("an act with every advisory field absent must still seal");

        assert_eq!(act.state, ActState::Sealed);
        assert_eq!(
            verify_act_fixity(&act, &anchors_of(&ledger)),
            ActFixity::Verified,
            "and it must re-verify against the ledger like any other sealed act"
        );
    }

    #[test]
    fn every_optional_field_that_is_absent_emits_no_key_at_all() {
        // The companion property, asserted by name rather than by total bytes, so a failure says
        // *which* field started emitting. `null` is not the same as absent: a field that emits
        // `"page_count":null` would change every frozen digest just as surely as one that emits a
        // value.
        let act = preimage_fixture_act();
        let json = serde_json::to_string(&ActPayload::of(&act)).unwrap();
        for absent in [
            "convening",
            "attendees",
            "page_count",
            "superseded_signing_snapshots",
            "convening_waiver",
            "written_resolution_evidence",
            "body",
        ] {
            assert!(
                !json.contains(absent),
                "an absent `{absent}` must emit no bytes, but the preimage contains it: {json}"
            );
        }
    }

    #[test]
    fn a_frozen_page_count_binds_into_the_seal_digest() {
        // The companion proof: F15 is not silently dropped. A frozen page count changes the
        // preimage, so the seal binds the act's page consumption as a recorded fact.
        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let mut act = ready_act(&book);
        let without = serde_json::to_vec(&ActPayload::of(&act)).unwrap();

        act.freeze_page_count(3).unwrap();
        let with = serde_json::to_vec(&ActPayload::of(&act)).unwrap();

        assert_ne!(without, with, "a frozen page count must bind");
        let json = String::from_utf8(with).unwrap();
        assert!(json.contains("\"page_count\":3"), "{json}");
    }

    #[test]
    fn reopen_history_binds_into_the_seal_digest_without_moving_untouched_acts() {
        // Two halves of one guarantee. An act that was never reopened must produce a preimage
        // byte-identical to what it produced before the field existed; an act that *was* reopened
        // must seal carrying that regression, not hiding it.
        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let act = ready_act(&book);
        assert!(act.superseded_signing_snapshots.is_empty());
        let without = serde_json::to_vec(&ActPayload::of(&act)).unwrap();
        assert!(
            !String::from_utf8(without.clone())
                .unwrap()
                .contains("superseded_signing_snapshots"),
            "an act that was never reopened must emit no bytes for the field"
        );

        let mut reopened = act.clone();
        reopened.reopen_for_correction().unwrap();
        reopened.record_superseded_signing_snapshot(crate::act::SupersededSigningSnapshot {
            document_id: "doc-1".to_owned(),
            pdf_digest: "aa".repeat(32),
            actor: "amelia.marques".to_owned(),
            superseded_at: time::OffsetDateTime::UNIX_EPOCH,
            reason: "mesa em falta".to_owned(),
        });
        reopened.advance_to(ActState::Signing).unwrap();

        let with = serde_json::to_vec(&ActPayload::of(&reopened)).unwrap();
        assert_ne!(without, with, "a retired signing snapshot must bind");
        assert!(String::from_utf8(with).unwrap().contains("doc-1"));
    }

    #[test]
    fn a_page_count_is_frozen_once_and_never_moved() {
        // R6: the count is captured at the content freeze and is a historical fact. If a
        // template revision changed the rendered length, re-freezing must be refused rather
        // than silently moving a sealed act's page consumption.
        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let mut act = ready_act(&book);
        act.freeze_page_count(4).unwrap();
        // Idempotent for the same value, so a retried freeze is harmless.
        act.freeze_page_count(4).unwrap();
        assert!(matches!(
            act.freeze_page_count(5),
            Err(ActError::PageCountAlreadyFrozen { frozen: 4 })
        ));
        assert_eq!(act.page_count, Some(4));
    }

    // =============================================================================================
    // Fixity: re-verifying a sealed act against the digest the ledger recorded.
    // =============================================================================================

    /// Seal `act` into a fresh open book and hand back everything a fixity test needs.
    fn sealed(evidence: SealEvidence) -> (Book, Act, Ledger, SealOutcome) {
        let e = entity();
        let mut ledger = Ledger::default();
        // Mirror the real flow: the company chain's genesis is `entity.created`, so the ledger
        // these tests assert `verify()` over is the one the product actually builds.
        ledger.append(
            "sec@encosto",
            &e.id.to_string(),
            "entity.created",
            None,
            b"entity",
        );
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();
        let mut act = ready_act(&book);
        let outcome = seal_act_with_evidence(
            &mut book,
            &mut act,
            &e,
            &CscArt63RulePack,
            "sec@encosto",
            false,
            evidence,
            &mut ledger,
        )
        .unwrap();
        (book, act, ledger, outcome)
    }

    #[test]
    fn sealed_act_digest_reproduces_the_digest_the_ledger_froze() {
        // THE byte-identical proof, on both seal paths. `sealed_act_digest` must return exactly
        // what `seal_act_with_evidence` wrote — into the act AND into the `act.sealed` event — or
        // every act in the field reads as tampered the moment the check goes live.
        for (label, evidence) in [
            (
                "manual signature",
                SealEvidence::Manual {
                    original_reference: manual_reference(),
                },
            ),
            (
                "digital signature",
                SealEvidence::Digital {
                    signing_snapshot_digest: "11".repeat(32),
                    signed_pdf_digest: "22".repeat(32),
                    signature_validation_report_digest: "33".repeat(32),
                },
            ),
        ] {
            let (_book, act, ledger, outcome) = sealed(evidence);
            let recomputed = sealed_act_digest(&act).expect("a sealed act must be verifiable");
            assert_eq!(
                recomputed, outcome.payload_digest,
                "{label}: recomputed digest must equal the one the seal returned"
            );
            assert_eq!(
                Some(recomputed),
                act.payload_digest,
                "{label}: recomputed digest must equal the one frozen on the act"
            );
            let event = ledger
                .events()
                .iter()
                .find(|e| e.kind == "act.sealed")
                .expect("the seal event");
            assert_eq!(
                recomputed, event.payload_digest,
                "{label}: recomputed digest must equal the one the LEDGER recorded"
            );
            assert_eq!(
                verify_act_fixity(&act, &anchors_of(&ledger)),
                ActFixity::Verified
            );
        }
    }

    #[test]
    fn the_anchor_is_the_ledger_event_and_not_the_row_beside_the_content() {
        // **The C1 attack.** The declared threat was `UPDATE acts SET json = <edited
        // deliberations>`. Extend that one statement to also write the recomputed `payload_digest`
        // — the field sits in the same JSON blob, is unconditionally present and unconditionally
        // writable — and a row-anchored check finds the row perfectly self-consistent and returns
        // `Verified`. Nothing about the edit is hidden from the ledger; the ledger was simply never
        // asked.
        let (_book, act, ledger, _) = sealed(SealEvidence::Manual {
            original_reference: manual_reference(),
        });
        let anchors = anchors_of(&ledger);

        let mut forged = act.clone();
        forged.deliberations = "Rejeitadas as contas do exercício.".to_owned();
        forged.payload_digest = sealed_act_digest(&forged);

        // The row is now internally consistent: its stored digest IS the digest of its content.
        assert_eq!(
            sealed_act_digest(&forged),
            forged.payload_digest,
            "the attack's premise: the edited row hashes to the digest it now carries"
        );
        // …and the chain is untouched and still verifies, as it must be for this to be the attack.
        assert!(ledger.verify().is_ok());
        assert!(ledger.integrity_report().healthy);

        let fixity = verify_act_fixity(&forged, &anchors);
        assert!(
            fixity.is_broken(),
            "an edited act whose digest was rewritten to match must be DETECTED, got {fixity:?}"
        );
        let ActFixity::LedgerAnchorMismatch {
            ledger: anchored,
            row,
            recomputed,
        } = &fixity
        else {
            panic!("expected the row to be reported as disagreeing with the chain, got {fixity:?}");
        };
        assert_eq!(
            anchored,
            &hex32(&act.payload_digest.expect("the original frozen digest")),
            "the ledger side must be the digest the seal event froze"
        );
        assert_eq!(row, &hex32(&forged.payload_digest.unwrap()));
        assert_ne!(anchored, row);
        assert_eq!(
            recomputed.as_ref(),
            Some(row),
            "content and row digest moved together — the tell that the row was rewritten as a unit"
        );

        let report = ActFixityReport::build([&forged], [], &anchors);
        assert!(!report.healthy, "{report:?}");
        assert_eq!(report.broken, 1);
        assert_eq!(report.verified, 0);
        assert_eq!(report.unverifiable, 0);
    }

    #[test]
    fn an_act_naming_a_seal_event_that_is_not_in_the_chain_is_broken() {
        // The other half of anchoring to the chain: pointing at a seal that does not exist is not
        // an ambiguity to be counted, it is an act asserting a seal the ledger never recorded.
        let (_book, act, ledger, _) = sealed(SealEvidence::Manual {
            original_reference: manual_reference(),
        });
        let anchors = anchors_of(&ledger);
        assert_eq!(anchors.len(), 1, "one seal event in this fixture");

        for (label, seq) in [
            ("a sequence past the end", Some(9_999)),
            ("none at all", None),
        ] {
            let mut dangling = act.clone();
            dangling.seal_event_seq = seq;
            let fixity = verify_act_fixity(&dangling, &anchors);
            assert_eq!(
                fixity,
                ActFixity::SealEventMissing {
                    seal_event_seq: seq
                },
                "{label}"
            );
            assert!(fixity.is_broken(), "{label}");
        }

        // A sequence that exists but is not a seal event is equally no anchor: the book genesis
        // sits at seq 1 in this fixture and carries the termo's digest, not any act's.
        let mut mispointed = act.clone();
        mispointed.seal_event_seq = Some(
            ledger
                .events()
                .iter()
                .find(|e| e.kind == "book.opened")
                .expect("the genesis event")
                .seq,
        );
        assert!(verify_act_fixity(&mispointed, &anchors).is_broken());
    }

    #[test]
    fn a_sealed_act_with_no_payload_digest_is_broken_not_merely_unverifiable() {
        // **The C2 attack.** Deleting the `payload_digest` key used to downgrade a mismatch into an
        // `Unverifiable`, which incremented a counter and left `healthy == true`. The rationale for
        // that leniency — "a historical row is indistinguishable from a stripped one" — is a fact
        // about `seal_metadata`, which is `#[serde(default, skip_serializing_if)]`. `payload_digest`
        // is neither: it is in every sealed row ever written, so its absence has exactly one
        // explanation.
        let (_book, act, ledger, _) = sealed(SealEvidence::Manual {
            original_reference: manual_reference(),
        });
        let anchors = anchors_of(&ledger);

        let mut stripped = act.clone();
        stripped.deliberations = "Rejeitadas as contas do exercício.".to_owned();
        stripped.payload_digest = None;

        let fixity = verify_act_fixity(&stripped, &anchors);
        assert_eq!(fixity, ActFixity::MissingPayloadDigest);
        assert!(fixity.is_broken());
        assert!(!fixity.is_verified());

        let report = ActFixityReport::build([&stripped], [], &anchors);
        assert!(!report.healthy, "{report:?}");
        assert!(!report.fully_verified());
        assert_eq!(report.broken, 1);
        assert_eq!(report.unverifiable, 0);
    }

    #[test]
    fn an_unverifiable_row_keeps_an_instance_running_but_never_clears_an_import() {
        // The two bars, stated against one another. `healthy` is what a running instance is allowed
        // to serve under — an installed base of pre-metadata rows must not brick on upgrade.
        // `fully_verified` is what accepting foreign content requires, because nothing is owed to a
        // bundle and an unanswered question about one is a reason to refuse it.
        let (_book, act, ledger, _) = sealed(SealEvidence::Manual {
            original_reference: manual_reference(),
        });
        let anchors = anchors_of(&ledger);
        let mut stripped = act.clone();
        stripped.seal_metadata = None;

        let report = ActFixityReport::build([&stripped], [], &anchors);
        assert!(
            report.healthy,
            "a running instance keeps serving: {report:?}"
        );
        assert!(
            !report.fully_verified(),
            "but an import must not call this verified: {report:?}"
        );
        assert_eq!(report.unverifiable, 1);

        // And a corpus with nothing to answer for clears both.
        let clean = ActFixityReport::build([&act], [], &anchors);
        assert!(clean.healthy && clean.fully_verified(), "{clean:?}");
    }

    #[test]
    fn an_edited_sealed_act_is_detected_as_altered() {
        // The regression test for the whole finding. Editing the substance of a sealed ata — the
        // deliberations, exactly what `UPDATE acts SET json = …` would reach — leaves the hash
        // chain verifying and every ledger surface green. Only re-hashing the act catches it.
        let (_book, act, ledger, _) = sealed(SealEvidence::Manual {
            original_reference: manual_reference(),
        });
        let anchors = anchors_of(&ledger);
        assert_eq!(verify_act_fixity(&act, &anchors), ActFixity::Verified);

        let mut tampered = act.clone();
        tampered.deliberations = "Rejeitadas as contas do exercício.".to_owned();

        // The chain still verifies and reports itself healthy — this is the point.
        assert!(ledger.verify().is_ok());
        assert!(ledger.integrity_report().healthy);

        let fixity = verify_act_fixity(&tampered, &anchors);
        assert!(
            fixity.is_broken(),
            "an edited sealed ata must be detected, got {fixity:?}"
        );
        let ActFixity::Mismatch { expected, actual } = &fixity else {
            panic!("expected a content mismatch, got {fixity:?}");
        };
        assert_ne!(expected, actual);
        assert_eq!(expected, &hex32(&act.payload_digest.unwrap()));

        let report = ActFixityReport::build([&tampered], [], &anchors);
        assert!(!report.healthy);
        assert_eq!(report.broken, 1);
        assert_eq!(report.verified, 0);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].act_id, tampered.id.to_string());
    }

    #[test]
    fn every_preimage_field_is_covered_by_the_fixity_check() {
        // Field-by-field, not one representative edit: a preimage field that `ActPayload` reads
        // but the recomputation somehow did not would leave a silent hole exactly where the edit
        // is most attractive.
        let (_book, act, ledger, _) = sealed(SealEvidence::Manual {
            original_reference: manual_reference(),
        });
        let anchors = anchors_of(&ledger);
        type Mutation = (&'static str, Box<dyn Fn(&mut Act)>);
        let mutations: Vec<Mutation> = vec![
            (
                "title",
                Box::new(|a: &mut Act| a.title = "Ata adulterada".to_owned()),
            ),
            (
                "deliberations",
                Box::new(|a: &mut Act| a.deliberations = "Outra coisa.".to_owned()),
            ),
            (
                "meeting_date",
                Box::new(|a: &mut Act| a.meeting_date = Some(date!(2026 - 03 - 31))),
            ),
            (
                "place",
                Box::new(|a: &mut Act| a.place = Some("Outro sítio".to_owned())),
            ),
            (
                "mesa",
                Box::new(|a: &mut Act| a.mesa.presidente = Some("Outro Presidente".to_owned())),
            ),
            (
                "agenda",
                Box::new(|a: &mut Act| a.agenda[0].text = "Outro ponto".to_owned()),
            ),
            (
                "attendance_reference",
                Box::new(|a: &mut Act| a.attendance_reference = Some("Outra lista".to_owned())),
            ),
            (
                "signatories",
                Box::new(|a: &mut Act| {
                    a.signatories.push(crate::act::SignatorySlot {
                        name: "Amélia Marques".to_owned(),
                        email: None,
                        capacity: crate::act::SignatoryCapacity::Member,
                        signed: true,
                        permilage: None,
                    })
                }),
            ),
            ("page_count", Box::new(|a: &mut Act| a.page_count = Some(9))),
            (
                "body",
                Box::new(|a: &mut Act| {
                    a.body = Some(crate::act::ActBody {
                        format: crate::act::BodyFormat::Markdown,
                        source: "texto".to_owned(),
                        compiler_id: "md-block/v1".to_owned(),
                        compiled_digest: "cc".repeat(32),
                    })
                }),
            ),
        ];
        for (field, mutate) in mutations {
            let mut tampered = act.clone();
            mutate(&mut tampered);
            assert!(
                verify_act_fixity(&tampered, &anchors).is_broken(),
                "editing `{field}` on a sealed act must be detected"
            );
            // …and detected just the same when the edit also rewrites the row's own frozen digest,
            // which is what makes the ledger the anchor rather than the row.
            let mut forged = tampered.clone();
            forged.payload_digest = sealed_act_digest(&forged);
            assert!(
                verify_act_fixity(&forged, &anchors).is_broken(),
                "editing `{field}` and rewriting `payload_digest` to match must be detected"
            );
        }
    }

    #[test]
    fn substituting_the_signature_evidence_is_detected() {
        // The seal metadata is inside the preimage, so swapping which signed PDF a seal claims to
        // rest on is an alteration too — not merely editing the ata's prose.
        let (_book, act, ledger, _) = sealed(SealEvidence::Digital {
            signing_snapshot_digest: "11".repeat(32),
            signed_pdf_digest: "22".repeat(32),
            signature_validation_report_digest: "33".repeat(32),
        });
        let mut tampered = act.clone();
        tampered
            .seal_metadata
            .as_mut()
            .expect("metadata")
            .signed_pdf_digest = Some("ff".repeat(32));
        assert!(verify_act_fixity(&tampered, &anchors_of(&ledger)).is_broken());
    }

    #[test]
    fn renumbering_a_sealed_ata_is_detected() {
        // C7: the ata number used to be bound by nothing — it lived only in the ledger
        // justification string, which is not hashed. Now it is in the seal metadata, and so in the
        // preimage, so a renumbering is a named finding rather than an invisible edit.
        let (_book, act, ledger, outcome) = sealed(SealEvidence::Manual {
            original_reference: manual_reference(),
        });
        let anchors = anchors_of(&ledger);
        assert_eq!(
            act.seal_metadata.as_ref().unwrap().ata_number,
            Some(outcome.ata_number),
            "the seal must bind the number it assigned"
        );

        let mut renumbered = act.clone();
        renumbered.ata_number = Some(99);
        assert_eq!(
            verify_act_fixity(&renumbered, &anchors),
            ActFixity::AtaNumberMismatch {
                sealed: outcome.ata_number,
                stored: Some(99),
            }
        );

        // Rewriting the bound number to match is not an escape: it moves the preimage.
        let mut renumbered_both = renumbered.clone();
        renumbered_both
            .seal_metadata
            .as_mut()
            .expect("metadata")
            .ata_number = Some(99);
        assert!(matches!(
            verify_act_fixity(&renumbered_both, &anchors),
            ActFixity::Mismatch { .. }
        ));
    }

    #[test]
    fn two_acts_cannot_hold_the_same_ata_number() {
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();
        let mut first = ready_act(&book);
        let mut second = ready_act(&book);
        for act in [&mut first, &mut second] {
            seal_act(
                &mut book,
                act,
                &e,
                &CscArt63RulePack,
                "sec@encosto",
                false,
                Some(manual_reference()),
                &mut ledger,
            )
            .unwrap();
        }
        assert_eq!(first.ata_number, Some(1));
        assert_eq!(second.ata_number, Some(2));
        assert!(
            book.check_ata_sequence([&first, &second]).is_empty(),
            "a well-formed book must raise nothing"
        );

        // Renumber the second onto the first's number — the `UPDATE acts SET ata_number = 1` case.
        let mut collided = second.clone();
        collided.ata_number = Some(1);
        let issues = book.check_ata_sequence([&first, &collided]);
        assert_eq!(issues.len(), 1, "{issues:?}");
        let AtaSequenceIssue::Duplicate {
            ata_number,
            act_ids,
        } = &issues[0]
        else {
            panic!("expected a duplicate, got {issues:?}");
        };
        assert_eq!(*ata_number, 1);
        assert_eq!(act_ids.len(), 2);

        // And it gates the aggregate report, so the instance goes read-only over it.
        let anchors = anchors_of(&ledger);
        let report = ActFixityReport::build([&first, &collided], [&book], &anchors);
        assert!(!report.healthy);
        assert_eq!(report.ata_sequence.len(), 1);

        // A number the counter never handed out is its own finding: the counter would reissue it.
        let mut beyond = second.clone();
        beyond.ata_number = Some(7);
        assert_eq!(
            book.check_ata_sequence([&first, &beyond]),
            vec![AtaSequenceIssue::BeyondCounter {
                ata_number: 7,
                last_ata_number: 2,
            }]
        );

        // …but it is REPORTED, not read-only. A counter standing behind its own acts — a restored
        // or imported book whose counter was rebuilt — is recoverable and is not by itself
        // evidence that any content was altered. Shown with two untouched acts, so the only
        // finding in play is the sequencing one.
        let mut rebuilt_counter = book.clone();
        rebuilt_counter.last_ata_number = 0;
        let issues = rebuilt_counter.check_ata_sequence([&first, &second]);
        assert_eq!(issues.len(), 2, "{issues:?}");
        assert!(issues.iter().all(|i| !i.is_uniqueness_violation()));
        let report = ActFixityReport::build([&first, &second], [&rebuilt_counter], &anchors);
        assert!(report.healthy, "must not force read-only: {report:?}");
        assert_eq!(report.ata_sequence.len(), 2, "but it is still surfaced");

        // A gap is NOT a finding: archival disposal can lawfully remove an ata row.
        assert!(book.check_ata_sequence([&second]).is_empty());
    }

    #[test]
    fn a_serialize_failure_still_does_not_burn_an_ata_number() {
        // The number is now assigned BEFORE the payload is frozen (it has to be, to be bound into
        // the digest), so the "must not burn a number" property is preserved by rolling the
        // counter back rather than by ordering. `serde_json::to_vec` cannot fail for this payload,
        // so the rollback is asserted directly against the branch it protects.
        let e = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(e.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &e, abertura(&e), "sec@encosto", &mut ledger).unwrap();
        let counter_before = book.last_ata_number;
        let assigned = book.assign_next_ata_number().unwrap();
        assert_eq!(assigned, counter_before + 1);
        book.last_ata_number = counter_before;
        assert_eq!(
            book.assign_next_ata_number().unwrap(),
            assigned,
            "after a rollback the same number must be handed out again"
        );
    }

    #[test]
    fn an_act_sealed_before_the_ata_number_was_bound_still_digests_identically() {
        // The hard constraint, pinned against a STORED literal rather than a round trip. This is
        // the preimage of an act sealed before `SealMetadata::ata_number` existed: the metadata
        // emits no key for it, so the bytes — and the frozen digest — are what they always were.
        //
        // **A failure here is a chain-compatibility break, not a stale fixture.** It means every
        // act sealed in the field before this change now reads as tampered.
        const LEGACY_SEALED_PREIMAGE: &str = r#"{"act":{"act_id":"33333333-3333-3333-3333-333333333333","book_id":"22222222-2222-2222-2222-222222222222","title":"Ata da AG anual","channel":"Physical","meeting_date":[2026,89],"place":"Sede social","attendance_reference":"Lista de presenças","deliberations":"Aprovadas as contas do exercício.","telematic_evidence":null,"attachments":[],"signatories":[],"retifies":null,"meeting_time":[10,0,0,0],"mesa":{"presidente":"Ana Presidente","secretarios":["Rui Secretário"]},"agenda":[{"number":1,"text":"Aprovação das contas"}],"referenced_documents":[],"deliberation_items":[],"members_present":null,"members_represented":null},"seal_metadata":{"rule_pack_id":"csc-art63/v2","version":"v2","family":"CommercialCompany","profile":"SociedadeAnonima","manual_signature_original_reference":{"storage_reference":"Arquivo A / Pasta 2026 / Ata teste"}}}"#;

        let mut act = preimage_fixture_act();
        // A legacy sealed row: metadata WITHOUT the appended number, and the act carrying the
        // number it was given (which is exactly why the number could not be read off the act).
        act.state = ActState::Sealed;
        act.ata_number = Some(1);
        act.seal_metadata = Some(
            SealMetadata::new(
                "csc-art63/v2",
                crate::entity::EntityFamily::CommercialCompany,
                EntityKind::SociedadeAnonima,
            )
            .with_manual_signature_original_reference(Some(manual_reference())),
        );
        assert!(
            act.seal_metadata.as_ref().unwrap().ata_number.is_none(),
            "the fixture must model a pre-C7 row"
        );

        let payload = serde_json::to_string(&SealedActPayload {
            act: ActPayload::of(&act),
            seal_metadata: act.seal_metadata.as_ref().unwrap(),
        })
        .unwrap();
        assert_eq!(
            payload, LEGACY_SEALED_PREIMAGE,
            "the seal preimage moved — every already-frozen act digest is now irreproducible"
        );
        assert!(
            !payload.contains("ata_number"),
            "a pre-C7 seal must emit no bytes for the number: {payload}"
        );

        // And the whole point: such a row re-verifies clean against THE LEDGER'S copy of that
        // digest. The anchor is built from the stored preimage above, standing in for the
        // `act.sealed` event a pre-C7 install carries — a legacy row must keep verifying now that
        // the row's own digest field is no longer what it is measured against.
        let frozen = chancela_ledger::digest(payload.as_bytes());
        act.payload_digest = Some(frozen);
        act.seal_event_seq = Some(2);
        let anchors = SealAnchors::from_iter([(2u64, frozen)]);
        assert_eq!(verify_act_fixity(&act, &anchors), ActFixity::Verified);
        assert!(ActFixityReport::build([&act], [], &anchors).fully_verified());
    }

    #[test]
    fn a_sealed_act_with_no_metadata_is_unverifiable_not_verified() {
        // Unknown must never launder into good. Stripping the metadata makes the preimage
        // unrebuildable; that is reported as its own verdict, and it is not `Verified`.
        //
        // This leniency is retained ONLY for `seal_metadata`, and only because the field is
        // genuinely `#[serde(default, skip_serializing_if)]`: a row sealed before it existed and a
        // row it was deleted from really are indistinguishable. The same reasoning was once applied
        // to `payload_digest` and did not hold there —
        // `a_sealed_act_with_no_payload_digest_is_broken_not_merely_unverifiable` pins that split.
        let (_book, act, ledger, _) = sealed(SealEvidence::Manual {
            original_reference: manual_reference(),
        });
        let anchors = anchors_of(&ledger);
        let mut stripped = act.clone();
        stripped.seal_metadata = None;
        let fixity = verify_act_fixity(&stripped, &anchors);
        assert_eq!(
            fixity,
            ActFixity::Unverifiable {
                reason: "sealed_act_has_no_seal_metadata"
            }
        );
        assert!(!fixity.is_verified());
        assert!(!fixity.is_broken());

        let report = ActFixityReport::build([&stripped], [], &anchors);
        assert_eq!(report.unverifiable, 1);
        assert_eq!(report.verified, 0);
        assert_eq!(report.findings.len(), 1);
        // Unknown does not gate a running instance, and does not clear an import either.
        assert!(report.healthy);
        assert!(!report.fully_verified());
    }

    #[test]
    fn an_unsealed_act_is_not_counted_as_a_sealed_one() {
        let book = Book::new(EntityId::new(), BookKind::AssembleiaGeral);
        let act = ready_act(&book);
        let anchors = SealAnchors::default();
        assert_eq!(verify_act_fixity(&act, &anchors), ActFixity::Unsealed);
        let report = ActFixityReport::build([&act], [&book], &anchors);
        assert!(report.healthy);
        assert_eq!(report.sealed_checked, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn a_sealed_act_survives_a_json_round_trip_through_the_store_shape() {
        // The load path re-verifies acts deserialized from the `acts.json` column, so the check is
        // only worth anything if the durable shape round-trips into the same preimage.
        let (_book, act, ledger, outcome) = sealed(SealEvidence::Digital {
            signing_snapshot_digest: "11".repeat(32),
            signed_pdf_digest: "22".repeat(32),
            signature_validation_report_digest: "33".repeat(32),
        });
        let stored = serde_json::to_string(&act).unwrap();
        let reloaded: Act = serde_json::from_str(&stored).unwrap();
        assert_eq!(reloaded, act);
        assert_eq!(sealed_act_digest(&reloaded), Some(outcome.payload_digest));
        assert_eq!(
            verify_act_fixity(&reloaded, &anchors_of(&ledger)),
            ActFixity::Verified
        );
    }

    #[test]
    fn a_sealed_act_cannot_acquire_a_page_count_after_the_fact() {
        let entity = entity();
        let mut ledger = Ledger::default();
        let mut book = Book::new(entity.id, BookKind::AssembleiaGeral);
        open_and_seal_book(&mut book, &entity, abertura(&entity), "sec@x", &mut ledger).unwrap();
        let mut act = ready_act(&book);
        seal_act(
            &mut book,
            &mut act,
            &entity,
            &CscArt63RulePack,
            "sec@x",
            true,
            Some(manual_reference()),
            &mut ledger,
        )
        .unwrap();
        assert_eq!(act.state, ActState::Sealed);
        assert!(matches!(act.freeze_page_count(2), Err(ActError::Sealed)));
    }
}
