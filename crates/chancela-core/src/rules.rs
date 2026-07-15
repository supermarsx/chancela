//! Compliance rule packs.
//!
//! Grounding: spec 06 (WFL-31 — "compliance logic MUST always be driven by law and the
//! entity's statutes, never by the template itself: templates are conveniences, rule
//! packs are authority") and LEG-05 (the warning model). A [`RulePack`] inspects an act
//! against its entity and returns [`ComplianceIssue`]s; sealing consults it (see
//! [`crate::seal::seal_act`]).

use crate::act::{
    Act, AttendanceWeight, MeetingChannel, PresenceMode, SignatoryCapacity, VoteResult,
    WRITTEN_RESOLUTION_EVIDENCE_STATUS_BOUNDARY, WrittenResolutionEvidenceStatus,
    written_resolution_evidence_summary,
};
use crate::entity::{Entity, EntityFamily, EntityKind, StatuteOverrides};

/// Severity of a compliance issue (LEG-05).
///
/// `Error` blocks sealing outright; `Warning` allows sealing only with an explicit
/// acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Advisory: sealing permitted if acknowledged.
    Warning,
    /// Blocking: sealing refused.
    Error,
}

/// Verification state of a legal basis attached to a compliance finding.
///
/// `Pending` means Chancela knows the structural citation but does not have complete,
/// authenticity-gated source text for it. Do not display pending references as verified law text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegalBasisVerification {
    /// Source text is complete and authenticity-gated.
    Verified,
    /// Structural citation only; no verified source text is claimed.
    Pending,
}

/// Structured legal-basis/source reference for a compliance finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegalBasis {
    /// Stable source id aligned with the law corpus where possible (e.g., `"csc"`).
    pub source_id: String,
    /// Human-readable legal source label.
    pub source_label: String,
    /// Canonical article number when the rule maps to a specific article.
    pub article: Option<String>,
    /// Human-readable article label when known (e.g., `"Artigo 63.º"`).
    pub article_label: Option<String>,
    /// Display-ready citation assembled from the structured fields.
    pub citation: String,
    /// Whether the source text behind this citation is authenticity-gated.
    pub verification: LegalBasisVerification,
    /// Complete source URL only when a verified article has one.
    pub source_url: Option<String>,
    /// Mirrors the corpus authenticity gate: false for pending structural citations.
    pub source_complete: bool,
}

impl LegalBasis {
    fn pending_law(
        source_id: &str,
        source_label: &str,
        article: Option<&str>,
        article_label: Option<&str>,
    ) -> Self {
        let citation = match article_label {
            Some(label) => format!("{source_label}, {label}"),
            None => source_label.to_owned(),
        };
        LegalBasis {
            source_id: source_id.to_owned(),
            source_label: source_label.to_owned(),
            article: article.map(str::to_owned),
            article_label: article_label.map(str::to_owned),
            citation,
            verification: LegalBasisVerification::Pending,
            source_url: None,
            source_complete: false,
        }
    }
}

/// A single compliance finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceIssue {
    /// Identifier of the rule that fired (e.g., `"CSC-63/deliberations"`).
    pub rule_id: String,
    /// Whether this blocks sealing.
    pub severity: Severity,
    /// Human-readable explanation.
    pub message: String,
    /// Structured legal-basis/source references for the rule.
    pub legal_basis: Vec<LegalBasis>,
}

impl ComplianceIssue {
    fn error(rule_id: &str, message: impl Into<String>) -> Self {
        ComplianceIssue {
            rule_id: rule_id.to_string(),
            severity: Severity::Error,
            message: message.into(),
            legal_basis: legal_basis_for_rule(rule_id),
        }
    }

    fn warning(rule_id: &str, message: impl Into<String>) -> Self {
        ComplianceIssue {
            rule_id: rule_id.to_string(),
            severity: Severity::Warning,
            message: message.into(),
            legal_basis: legal_basis_for_rule(rule_id),
        }
    }
}

fn legal_basis_for_rule(rule_id: &str) -> Vec<LegalBasis> {
    match rule_id
        .split_once('/')
        .map(|(prefix, _)| prefix)
        .unwrap_or(rule_id)
    {
        "CSC-63" => vec![LegalBasis::pending_law(
            "csc",
            "Código das Sociedades Comerciais",
            Some("63"),
            Some("Artigo 63.º"),
        )],
        "CSC-54" => vec![LegalBasis::pending_law(
            "csc",
            "Código das Sociedades Comerciais",
            Some("54"),
            Some("Artigo 54.º"),
        )],
        "CSC-377" => vec![LegalBasis::pending_law(
            "csc",
            "Código das Sociedades Comerciais",
            Some("377"),
            Some("Artigo 377.º"),
        )],
        "DL268" => vec![LegalBasis::pending_law(
            "dl-268-94",
            "Decreto-Lei n.º 268/94, de 25 de outubro",
            None,
            None,
        )],
        "CC" => vec![LegalBasis::pending_law("cc", "Código Civil", None, None)],
        "CCoop" if rule_id == "CCoop/one-member-one-vote" => {
            vec![LegalBasis::pending_law(
                "cod-cooperativo",
                "Código Cooperativo",
                Some("41"),
                Some("Artigo 41.º"),
            )]
        }
        "CCoop" => vec![LegalBasis::pending_law(
            "cod-cooperativo",
            "Código Cooperativo",
            None,
            None,
        )],
        _ => Vec::new(),
    }
}

/// A pluggable body of compliance authority for a family/profile.
///
/// Implementors cite their legal basis in doc comments and keep the logic honest: a rule
/// pack should encode what the law actually requires, not what a template happens to
/// contain (WFL-31).
pub trait RulePack {
    /// Stable identifier for this pack, recorded at sealing (LEG-06).
    fn id(&self) -> &str;

    /// Inspect `act` for `entity` and return any issues found (empty = clean).
    fn check_act(&self, act: &Act, entity: &Entity) -> Vec<ComplianceIssue>;
}

/// Whether an act carries substance — a resolution recorded on either the free-text or the
/// structured path (R3). The substance Error fires only when **both** are empty.
fn has_substance(act: &Act) -> bool {
    !act.deliberations.trim().is_empty()
        || act
            .deliberation_items
            .iter()
            .any(|item| !item.text.trim().is_empty())
}

/// The shared civil baseline every family requires: the ata must identify the entity and
/// record the date, place, attendance, and the substance of the deliberations. `prefix`
/// namespaces the rule ids to the family's legal basis (e.g. `"CSC-63"`, `"DL268"`, `"CC"`).
///
/// These are the common Errors (plus the unvalidated-NIPC Warning) so the family packs do
/// not duplicate them; each pack adds its own specifics on top.
fn civil_baseline(act: &Act, entity: &Entity, prefix: &str) -> Vec<ComplianceIssue> {
    let mut issues = Vec::new();

    // Entity identification: the ata identifies the entity.
    if entity.name.trim().is_empty() {
        issues.push(ComplianceIssue::error(
            &format!("{prefix}/entity"),
            "the entity has no name; the ata must identify the entity",
        ));
    }

    // A NIPC stored via the validation override (foreign/legacy/special registration)
    // identifies the entity less firmly. A Warning, not an Error: such entities are
    // legitimate, but the override should be seen and acknowledged before sealing (LEG-05).
    if !entity.nipc.is_validated() {
        issues.push(ComplianceIssue::warning(
            &format!("{prefix}/nipc-unvalidated"),
            format!(
                "the entity's identifier {:?} was stored without NIPC validation \
                 (control-digit check skipped); confirm it identifies the entity",
                entity.nipc.as_str()
            ),
        ));
    }

    // Date and place of the meeting.
    if act.meeting_date.is_none() {
        issues.push(ComplianceIssue::error(
            &format!("{prefix}/date"),
            "meeting date is missing (mandatory ata contents)",
        ));
    }
    if act.place.as_deref().unwrap_or("").trim().is_empty() {
        issues.push(ComplianceIssue::error(
            &format!("{prefix}/place"),
            "meeting place is missing (mandatory ata contents)",
        ));
    }

    // Attendance reference (who was present / represented).
    if act
        .attendance_reference
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        issues.push(ComplianceIssue::error(
            &format!("{prefix}/attendance"),
            "attendance reference is missing (mandatory ata contents)",
        ));
    }

    // Substance of the deliberations — free-text OR structured (R3).
    if !has_substance(act) {
        issues.push(ComplianceIssue::error(
            &format!("{prefix}/deliberations"),
            "no deliberations recorded (neither free-text nor structured); the ata must \
             record the substance of the resolutions taken",
        ));
    }

    issues
}

/// One advisory per structured deliberation item that carries no recorded voting result.
fn missing_vote_warnings(act: &Act, prefix: &str) -> Vec<ComplianceIssue> {
    act.deliberation_items
        .iter()
        .enumerate()
        .filter(|(_, item)| item.vote.is_none())
        .map(|(i, _)| {
            ComplianceIssue::warning(
                &format!("{prefix}/vote-result"),
                format!(
                    "deliberation item {} records no voting result; the ata should record \
                     how each resolution was carried",
                    i + 1
                ),
            )
        })
        .collect()
}

/// Advisory when the act uses a meeting channel the family does not permit (ENT-02(b)).
fn channel_warning(act: &Act, entity: &Entity, prefix: &str) -> Option<ComplianceIssue> {
    if crate::profile::allowed_channels(entity.family).contains(&act.channel) {
        None
    } else {
        Some(ComplianceIssue::warning(
            &format!("{prefix}/channel"),
            format!(
                "meeting channel {:?} is not among the channels this entity family permits",
                act.channel
            ),
        ))
    }
}

/// Written resolutions need a captured written-evidence surface. This check only reports the
/// technical evidence-presence status; it does not prove the legal threshold, participant set,
/// unanimity, signature qualification, timestamp sufficiency, enforceability, or validity.
fn written_resolution_evidence_warning(act: &Act, prefix: &str) -> Option<ComplianceIssue> {
    let summary = written_resolution_evidence_summary(act);
    match summary.status {
        WrittenResolutionEvidenceStatus::NotApplicable
        | WrittenResolutionEvidenceStatus::BoundPresent => None,
        WrittenResolutionEvidenceStatus::Missing => Some(ComplianceIssue::warning(
            &format!("{prefix}/written-resolution-evidence"),
            format!(
                "written-resolution channel has no signed signatory slot, digested attachment, \
                 or digested checklist item; technical evidence status is {} ({})",
                summary.status.as_str(),
                WRITTEN_RESOLUTION_EVIDENCE_STATUS_BOUNDARY
            ),
        )),
        WrittenResolutionEvidenceStatus::ReferencedOnly => Some(ComplianceIssue::warning(
            &format!("{prefix}/written-resolution-evidence"),
            format!(
                "written-resolution evidence is referenced, but no signed signatory slot, \
                 digested attachment, or digested checklist item is bound into the record; \
                 technical evidence status is {} ({})",
                summary.status.as_str(),
                WRITTEN_RESOLUTION_EVIDENCE_STATUS_BOUNDARY
            ),
        )),
    }
}

/// The weighted-voting unit a family can validate from today's attendance model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WeightKind {
    Capital,
    Permilage,
}

impl WeightKind {
    fn for_entity(entity: &Entity) -> Option<Self> {
        match entity.family {
            EntityFamily::CommercialCompany => Some(Self::Capital),
            EntityFamily::Condominium => Some(Self::Permilage),
            EntityFamily::Association | EntityFamily::Foundation | EntityFamily::Cooperative => {
                None
            }
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Capital => "capital",
            Self::Permilage => "permilagem",
        }
    }

    fn vote_total_rule(self, prefix: &str) -> String {
        match self {
            Self::Capital => format!("{prefix}/capital-vote-total"),
            Self::Permilage => format!("{prefix}/permilage-vote-total"),
        }
    }

    fn partial_rule(self, prefix: &str) -> String {
        match self {
            Self::Capital => format!("{prefix}/capital-weights-partial"),
            Self::Permilage => format!("{prefix}/permilage-weights-partial"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct WeightedAttendanceSummary {
    kind: WeightKind,
    present_rows: u32,
    present_weight: u128,
    expected_weight_rows: u32,
    other_weight_rows: u32,
    missing_weight_rows: u32,
}

impl WeightedAttendanceSummary {
    fn has_weight_metadata(self) -> bool {
        self.expected_weight_rows > 0 || self.other_weight_rows > 0
    }

    fn is_complete(self) -> bool {
        self.other_weight_rows == 0 && self.missing_weight_rows == 0
    }

    fn can_use_weight(self) -> bool {
        self.is_complete()
            && self.expected_weight_rows > 0
            && self.expected_weight_rows == self.present_rows
    }
}

fn attendance_summary(act: &Act, kind: WeightKind) -> Option<WeightedAttendanceSummary> {
    if act.attendees.is_empty() {
        return None;
    }

    let mut summary = WeightedAttendanceSummary {
        kind,
        present_rows: 0,
        present_weight: 0,
        expected_weight_rows: 0,
        other_weight_rows: 0,
        missing_weight_rows: 0,
    };

    for attendee in act
        .attendees
        .iter()
        .filter(|a| a.presence != PresenceMode::Absent)
    {
        summary.present_rows += 1;
        match (kind, attendee.weight) {
            (WeightKind::Capital, Some(AttendanceWeight::Capital(value))) => {
                summary.expected_weight_rows += 1;
                summary.present_weight += u128::from(value);
            }
            (WeightKind::Permilage, Some(AttendanceWeight::Permilage(value))) => {
                summary.expected_weight_rows += 1;
                summary.present_weight += u128::from(value);
            }
            (_, Some(_)) => {
                summary.other_weight_rows += 1;
            }
            (_, None) => {
                summary.missing_weight_rows += 1;
            }
        }
    }

    Some(summary)
}

fn attendance_count(act: &Act) -> Option<u32> {
    match (act.members_present, act.members_represented) {
        (None, None) if act.attendees.is_empty() => None,
        (None, None) => Some(
            act.attendees
                .iter()
                .filter(|a| a.presence != PresenceMode::Absent)
                .count() as u32,
        ),
        _ => Some(act.members_present.unwrap_or(0) + act.members_represented.unwrap_or(0)),
    }
}

fn recorded_vote_total(vote: VoteResult) -> Option<u128> {
    match vote {
        VoteResult::Recorded {
            em_favor,
            contra,
            abstencoes,
        } => Some(u128::from(em_favor) + u128::from(contra) + u128::from(abstencoes)),
        VoteResult::Unanimous => None,
    }
}

/// Consistency checks that need no legal threshold: when a profile has a complete weighted
/// attendance list and a resolution records an aggregate tally, the tally's total should match
/// the present/represented weight. If no weight metadata was captured, the old unweighted path is
/// left alone.
fn weighted_vote_warnings(act: &Act, entity: &Entity, prefix: &str) -> Vec<ComplianceIssue> {
    let Some(kind) = WeightKind::for_entity(entity) else {
        return Vec::new();
    };
    let Some(summary) = attendance_summary(act, kind) else {
        return Vec::new();
    };
    let recorded_items: Vec<_> = act
        .deliberation_items
        .iter()
        .enumerate()
        .filter_map(|(i, item)| {
            item.vote
                .and_then(recorded_vote_total)
                .map(|total| (i, total))
        })
        .collect();

    if recorded_items.is_empty() {
        return Vec::new();
    }

    if !summary.has_weight_metadata() {
        return Vec::new();
    }

    if !summary.is_complete() {
        return vec![ComplianceIssue::warning(
            &kind.partial_rule(prefix),
            format!(
                "the attendance list has partial or mismatched {} weights for present/represented \
                 attendees; weighted vote totals cannot be verified from the captured rows",
                kind.label()
            ),
        )];
    }

    recorded_items
        .into_iter()
        .filter(|(_, total)| *total != summary.present_weight)
        .map(|(i, total)| {
            ComplianceIssue::warning(
                &kind.vote_total_rule(prefix),
                format!(
                    "deliberation item {} records {} total vote units, but the present/represented \
                     {} total is {}; confirm the recorded tally uses the same weighted unit",
                    i + 1,
                    total,
                    kind.label(),
                    summary.present_weight
                ),
            )
        })
        .collect()
}

fn attendance_count_mismatch_warning(act: &Act, prefix: &str) -> Option<ComplianceIssue> {
    let recorded_count = act.members_present.unwrap_or(0) + act.members_represented.unwrap_or(0);
    if act.members_present.is_none() && act.members_represented.is_none() {
        return None;
    }

    let row_count = act
        .attendees
        .iter()
        .filter(|a| a.presence != PresenceMode::Absent)
        .count() as u32;
    if act.attendees.is_empty() || recorded_count == row_count {
        return None;
    }

    Some(ComplianceIssue::warning(
        &format!("{prefix}/attendance-count-mismatch"),
        format!(
            "present/represented counts record {recorded_count}, but the structured attendance \
             list has {row_count} present/represented row(s); confirm which source controls \
             quorum and vote review",
        ),
    ))
}

fn condominium_permilage_warnings(act: &Act) -> Vec<ComplianceIssue> {
    let mut issues = Vec::new();
    let mut present_total = 0_u32;
    let mut has_present_permilage = false;

    for attendee in act
        .attendees
        .iter()
        .filter(|a| a.presence != PresenceMode::Absent)
    {
        if let Some(AttendanceWeight::Permilage(value)) = attendee.weight {
            has_present_permilage = true;
            present_total = present_total.saturating_add(value);
            if value > 1000 {
                issues.push(ComplianceIssue::warning(
                    "DL268/permilage-value",
                    format!(
                        "attendance row {:?} records permilagem {value}, above the 1000 total \
                         scale; confirm the captured fraction",
                        attendee.name
                    ),
                ));
            }
        }
    }

    if has_present_permilage && present_total > 1000 {
        issues.push(ComplianceIssue::warning(
            "DL268/permilage-total",
            format!(
                "present/represented attendance permilagem totals {present_total}, above the \
                 1000 total scale; confirm the captured fractions",
            ),
        ));
    }

    for slot in &act.signatories {
        if slot.capacity == SignatoryCapacity::CondoOwner {
            if let Some(value) = slot.permilage {
                if value > 1000 {
                    issues.push(ComplianceIssue::warning(
                        "DL268/permilage-value",
                        format!(
                            "condómino {:?} records permilagem {value}, above the 1000 total \
                             scale; confirm the captured fraction",
                            slot.name
                        ),
                    ));
                }
            }
        }
    }

    issues
}

/// CSC art. 63.º rule pack (**v2**) for the mandatory ata contents (ENT-C2 / LEG-03).
///
/// Over the civil baseline (entity identity, date, place, attendance, substance) this pack
/// adds the CSC-specific art. 63.º elements: the **mesa** (chair — blocking — and secretaries
/// — advisory), the meeting **time**, the **agenda** (ordem de trabalhos), per-resolution
/// **voting results**, a **detached-document** beginning-of-proof advisory (ENT-C6), and the
/// art. 377.º telematic-SA evidence Error (ENT-C4). Severities follow R2: only the chair and
/// the art. 377.º evidence block; the rest are advisory so the free-text / historical / simple
/// ata (R1/R3) and old persisted acts stay sealable. Capital-weighted vote checks are bounded
/// consistency checks only: they fire when the attendance rows and recorded aggregate tallies carry
/// enough weight metadata, and they do not invent any legal majority/quorum threshold.
///
/// The type name is unchanged from v1 (callers importing `CscArt63RulePack` keep compiling);
/// only the checks and the [`ID`](Self::ID) version tag grew.
#[derive(Debug, Default, Clone, Copy)]
pub struct CscArt63RulePack;

impl CscArt63RulePack {
    /// The pack's identifier, including a coarse version tag for LEG-06 recording. Bumped
    /// `v1 → v2` for the materially expanded art. 63.º checks (LEG-06 records the version in
    /// force; historical sealed acts keep their recorded v1 justification).
    pub const ID: &'static str = "csc-art63/v2";
}

impl RulePack for CscArt63RulePack {
    fn id(&self) -> &str {
        Self::ID
    }

    fn check_act(&self, act: &Act, entity: &Entity) -> Vec<ComplianceIssue> {
        let mut issues = civil_baseline(act, entity, "CSC-63");

        // Mesa: the chair is a mandatory art. 63.º element (an ata with no chair identified is
        // defective) and blocks sealing; secretaries are advisory (small organs legitimately
        // have none). Re-promoted to a blocking Error in t31-e2 now that PatchAct carries a mesa
        // (the temporary t31-f1 Warning downgrade is retired).
        if act
            .mesa
            .presidente
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            issues.push(ComplianceIssue::error(
                "CSC-63/mesa-presidente",
                "the ata identifies no presidente da mesa (chair); CSC art. 63.º requires the \
                 presiding board to be recorded",
            ));
        }
        if act.mesa.secretarios.is_empty() {
            issues.push(ComplianceIssue::warning(
                "CSC-63/mesa-secretarios",
                "the ata records no secretário(s) da mesa",
            ));
        }

        // Meeting time (mandatory content; omission is a documentary defect, not a seal bar).
        if act.meeting_time.is_none() {
            issues.push(ComplianceIssue::warning(
                "CSC-63/time",
                "meeting time is missing (CSC art. 63.º mandatory contents)",
            ));
        }

        // Agenda / ordem de trabalhos (advisory: it often lives in the convocatória).
        if act.agenda.is_empty() {
            issues.push(ComplianceIssue::warning(
                "CSC-63/agenda",
                "no agenda (ordem de trabalhos) recorded on the ata",
            ));
        }

        // Per-resolution voting results (only checkable on the structured path).
        issues.extend(missing_vote_warnings(act, "CSC-63"));
        issues.extend(weighted_vote_warnings(act, entity, "CSC-63"));
        issues.extend(written_resolution_evidence_warning(act, "CSC-54"));

        // Detached-document beginning-of-proof advisory (ENT-C6 / R7).
        if act.attachments.iter().any(|a| a.beginning_of_proof) {
            issues.push(ComplianceIssue::warning(
                "CSC-63/detached-document",
                "a resolution is evidenced only by a detached private document; under CSC \
                 art. 63.º such a document is merely a beginning of proof (reduced weight)",
            ));
        }

        // SA + telematic → art. 377.º evidence note required (ENT-C4).
        if entity.kind == EntityKind::SociedadeAnonima
            && act.channel == MeetingChannel::Telematic
            && act
                .telematic_evidence
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
        {
            issues.push(ComplianceIssue::error(
                "CSC-377/telematic-evidence",
                "telematic SA general meeting lacks the art. 377.º evidence note \
                 (authenticity, communication security, recording of content and \
                 participants)",
            ));
        }

        // Channel permitted for the family (advisory).
        issues.extend(channel_warning(act, entity, "CSC-63"));

        issues
    }
}

/// Condominium rule pack — DL 268/94 (rev. Lei 8/2022), the assembleia de condóminos.
///
/// Distinct from the CSC pack: it does **not** require a mesa, an agenda, or art. 377.º. Over
/// the civil baseline it warns on unrecorded meeting time, per-resolution results, aggregate vote
/// tallies that do not match captured attendance *permilagem*, contradictory attendance counts,
/// impossible *permilagem* values/totals, and on a condómino signatory carrying no *permilagem*
/// (ENT-D6). These are deterministic data-quality checks, not hard-coded legal thresholds.
#[derive(Debug, Default, Clone, Copy)]
pub struct CondominioRulePack;

impl CondominioRulePack {
    /// Stable pack id (LEG-02/06).
    pub const ID: &'static str = "condominio-dl268/v1";
}

impl RulePack for CondominioRulePack {
    fn id(&self) -> &str {
        Self::ID
    }

    fn check_act(&self, act: &Act, entity: &Entity) -> Vec<ComplianceIssue> {
        let mut issues = civil_baseline(act, entity, "DL268");

        if act.meeting_time.is_none() {
            issues.push(ComplianceIssue::warning(
                "DL268/time",
                "meeting time is missing; record it when available so the condominium minutes \
                 identify the meeting occurrence precisely",
            ));
        }

        // Result of each deliberation (advisory).
        issues.extend(missing_vote_warnings(act, "DL268"));
        issues.extend(weighted_vote_warnings(act, entity, "DL268"));
        issues.extend(attendance_count_mismatch_warning(act, "DL268"));
        issues.extend(condominium_permilage_warnings(act));

        // A condómino signatory should carry their permilagem (ENT-D6).
        for slot in &act.signatories {
            if slot.capacity == SignatoryCapacity::CondoOwner && slot.permilage.is_none() {
                issues.push(ComplianceIssue::warning(
                    "DL268/permilage",
                    format!(
                        "condómino {:?} carries no permilagem (millésimos); record it so the \
                         assembleia's fractions are auditable",
                        slot.name
                    ),
                ));
            }
        }

        issues
    }
}

/// Association rule pack — Código Civil (arts. 167.º ff.). The civil baseline plus an agenda
/// advisory.
#[derive(Debug, Default, Clone, Copy)]
pub struct AssociacaoRulePack;

impl AssociacaoRulePack {
    /// Stable pack id (LEG-02/06).
    pub const ID: &'static str = "assoc-cc/v1";
}

impl RulePack for AssociacaoRulePack {
    fn id(&self) -> &str {
        Self::ID
    }

    fn check_act(&self, act: &Act, entity: &Entity) -> Vec<ComplianceIssue> {
        let mut issues = civil_baseline(act, entity, "CC");
        if act.agenda.is_empty() {
            issues.push(ComplianceIssue::warning(
                "CC/agenda",
                "no agenda (ordem de trabalhos) recorded on the ata",
            ));
        }
        issues.extend(written_resolution_evidence_warning(act, "CC"));
        issues
    }
}

/// Foundation rule pack — Lei-Quadro das Fundações (Lei 24/2012) over the Código Civil
/// baseline. The board / supervisory-organ split is noted and deferred; today it is the civil
/// baseline.
#[derive(Debug, Default, Clone, Copy)]
pub struct FundacaoRulePack;

impl FundacaoRulePack {
    /// Stable pack id (LEG-02/06).
    pub const ID: &'static str = "fundacao-cc/v1";
}

impl RulePack for FundacaoRulePack {
    fn id(&self) -> &str {
        Self::ID
    }

    fn check_act(&self, act: &Act, entity: &Entity) -> Vec<ComplianceIssue> {
        civil_baseline(act, entity, "CC")
    }
}

/// Cooperative rule pack — Código Cooperativo (Lei 119/2015). The civil baseline plus a
/// one-member-one-vote advisory on any recorded tally (art. 41.º: cooperative voting counts
/// members, not capital).
#[derive(Debug, Default, Clone, Copy)]
pub struct CooperativaRulePack;

impl CooperativaRulePack {
    /// Stable pack id (LEG-02/06).
    pub const ID: &'static str = "cooperativa-ccoop/v1";
}

impl RulePack for CooperativaRulePack {
    fn id(&self) -> &str {
        Self::ID
    }

    fn check_act(&self, act: &Act, entity: &Entity) -> Vec<ComplianceIssue> {
        let mut issues = civil_baseline(act, entity, "CCoop");
        if act
            .deliberation_items
            .iter()
            .any(|item| matches!(item.vote, Some(VoteResult::Recorded { .. })))
        {
            issues.push(ComplianceIssue::warning(
                "CCoop/one-member-one-vote",
                "a recorded tally is present; confirm it counts one vote per member \
                 (Código Cooperativo art. 41.º), not capital",
            ));
        }
        issues.extend(written_resolution_evidence_warning(act, "CCoop"));
        issues
    }
}

/// Statute overlay findings (ENT-03 / R5): advisory checks derived from an entity's own
/// statutes, applied on top of the family pack by [`crate::profile::ProfilePack`].
///
/// Only the knobs that can be genuinely checked against today's model fire: `majority`
/// against structured [`VoteResult::Recorded`] tallies, `quorum` against captured attendance
/// counts, and `convocation_notice_days` against recorded convening metadata. Use
/// [`statute_findings_for_entity`] when the entity is known so the overlay can also use complete
/// weighted attendance metadata.
pub fn statute_findings(act: &Act, statute: &StatuteOverrides) -> Vec<ComplianceIssue> {
    statute_findings_inner(act, None, statute)
}

pub(crate) fn statute_findings_for_entity(
    act: &Act,
    entity: &Entity,
    statute: &StatuteOverrides,
) -> Vec<ComplianceIssue> {
    statute_findings_inner(act, Some(entity), statute)
}

fn statute_findings_inner(
    act: &Act,
    entity: Option<&Entity>,
    statute: &StatuteOverrides,
) -> Vec<ComplianceIssue> {
    let mut issues = Vec::new();
    let weighted_attendance = entity
        .and_then(WeightKind::for_entity)
        .and_then(|kind| attendance_summary(act, kind));

    // Statutory majority: each non-unanimous recorded resolution must reach the fraction.
    if let Some(maj) = statute.majority {
        if maj.denominator == 0 {
            issues.push(ComplianceIssue::warning(
                "STATUTE/majority-invalid",
                "the statutes configure a majority fraction with denominator 0; the majority \
                 overlay cannot be checked",
            ));
        } else {
            let mut partial_weight_warning_emitted = false;
            for (i, item) in act.deliberation_items.iter().enumerate() {
                if let Some(VoteResult::Recorded {
                    em_favor,
                    contra,
                    abstencoes,
                }) = item.vote
                {
                    let total = u128::from(em_favor) + u128::from(contra) + u128::from(abstencoes);
                    let mut weighted_unit = None;

                    if let Some(summary) = weighted_attendance {
                        if summary.has_weight_metadata() && !summary.is_complete() {
                            if !partial_weight_warning_emitted {
                                issues.push(ComplianceIssue::warning(
                                    "STATUTE/majority-weight-unverified",
                                    format!(
                                        "the statutes set a majority, but the attendance list has \
                                         partial or mismatched {} weights; weighted majority must \
                                         be confirmed manually",
                                        summary.kind.label()
                                    ),
                                ));
                                partial_weight_warning_emitted = true;
                            }
                        } else if summary.can_use_weight() {
                            if total == summary.present_weight {
                                weighted_unit = Some(summary.kind.label());
                            } else if summary.has_weight_metadata() {
                                issues.push(ComplianceIssue::warning(
                                    "STATUTE/majority-weight-unverified",
                                    format!(
                                        "deliberation item {} records {} total vote units, but the \
                                         present/represented {} total is {}; weighted majority \
                                         must be confirmed manually",
                                        i + 1,
                                        total,
                                        summary.kind.label(),
                                        summary.present_weight
                                    ),
                                ));
                            }
                        }
                    }

                    // em_favor / total >= numerator / denominator, in integer arithmetic. Use
                    // u128 for the cross-multiply to prevent overflow when the counts are large.
                    // Abstentions remain in the denominator because the configured overlay is
                    // checked against the recorded aggregate tally, not a hard-coded legal rule.
                    if total > 0 {
                        let favor = u128::from(em_favor);
                        let den = u128::from(maj.denominator);
                        let num = u128::from(maj.numerator);
                        if favor * den < num * total {
                            let unit_note = weighted_unit
                                .map(|unit| format!(" {unit} vote units"))
                                .unwrap_or_default();
                            issues.push(ComplianceIssue::warning(
                                "STATUTE/majority",
                                format!(
                                    "deliberation item {} carried with {em_favor}/{total}{} in \
                                     favour, below the statutory majority of {}/{} \
                                     (abstentions included in the recorded denominator)",
                                    i + 1,
                                    unit_note,
                                    maj.numerator,
                                    maj.denominator
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    // Statutory quorum: present + represented must meet the configured minimum, when counts or
    // complete weighted attendance rows exist.
    if let Some(q) = statute.quorum {
        if let Some(summary) = weighted_attendance {
            if summary.has_weight_metadata() && !summary.is_complete() {
                issues.push(ComplianceIssue::warning(
                    "STATUTE/quorum-weight-unverified",
                    format!(
                        "the statutes set a quorum, but the attendance list has partial or \
                         mismatched {} weights; weighted quorum must be confirmed manually",
                        summary.kind.label()
                    ),
                ));
                return issues;
            }

            if summary.can_use_weight() {
                let present = summary.present_weight;
                if present < u128::from(q.min_present) {
                    issues.push(ComplianceIssue::warning(
                        "STATUTE/quorum",
                        format!(
                            "present/represented {} ({present}) is below the statutory quorum \
                             of {}",
                            summary.kind.label(),
                            q.min_present
                        ),
                    ));
                }
                return issues;
            }
        }

        match attendance_count(act) {
            None => {
                issues.push(ComplianceIssue::warning(
                    "STATUTE/quorum-unverified",
                    format!(
                        "the statutes set a quorum of {} but no present/represented counts \
                         were captured; confirm the quorum manually",
                        q.min_present
                    ),
                ));
            }
            Some(present) => {
                if present < q.min_present {
                    issues.push(ComplianceIssue::warning(
                        "STATUTE/quorum",
                        format!(
                            "present + represented ({present}) is below the statutory quorum \
                             of {}",
                            q.min_present
                        ),
                    ));
                }
            }
        }
    }

    if let Some(required_days) = statute.convocation_notice_days {
        match statute_convocation_notice_antecedence_days(act) {
            None => issues.push(ComplianceIssue::warning(
                "STATUTE/convocation-notice-unverified",
                format!(
                    "the statutes record a convocation notice period of {required_days} days, \
                     but the act does not have enough recorded convening metadata to verify the \
                     local antecedence advisory"
                ),
            )),
            Some(actual_days) => {
                if actual_days < i32::from(required_days) {
                    issues.push(ComplianceIssue::warning(
                        "STATUTE/convocation-notice",
                        format!(
                            "recorded convening notice antecedence ({actual_days} days) is below \
                             the statutory notice period recorded for this entity \
                             ({required_days} days); this is a local advisory over statute and \
                             convening metadata only"
                        ),
                    ));
                }
            }
        }
    }

    issues
}

fn statute_convocation_notice_antecedence_days(act: &Act) -> Option<i32> {
    let convening = act.convening.as_ref()?;
    if let Some(days) = convening.antecedence_days {
        return Some(i32::from(days));
    }

    let dispatch_date = convening.dispatch_date?;
    let meeting_date = act.meeting_date?;
    Some(meeting_date.to_julian_day() - dispatch_date.to_julian_day())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::act::{Act, AgendaItem, Convening};
    use crate::book::BookId;
    use crate::entity::{Entity, EntityKind, Nipc};
    use time::macros::{date, time};

    fn sa_entity() -> Entity {
        Entity::new(
            "Encosto Estratégico, S.A.",
            Nipc::parse("503004642").unwrap(),
            "Lisboa",
            EntityKind::SociedadeAnonima,
        )
    }

    /// A fully complete CSC v2 ata: every mandatory element present so a clean run under the
    /// v2 pack yields zero findings (mesa chair + secretaries, time, agenda, and substance).
    fn complete_act() -> Act {
        let mut act = Act::draft(BookId::new(), "Ata n.º 1", MeetingChannel::Physical);
        act.meeting_date = Some(date!(2026 - 03 - 01));
        act.meeting_time = Some(time!(10:00));
        act.place = Some("Sede social".into());
        act.mesa.presidente = Some("Ana Presidente".into());
        act.mesa.secretarios = vec!["Rui Secretário".into()];
        act.agenda = vec![AgendaItem {
            number: 1,
            text: "Aprovação do relatório de gestão".into(),
        }];
        act.attendance_reference = Some("Lista de presenças anexa".into());
        act.deliberations = "Aprovado o relatório de gestão.".into();
        act
    }

    #[test]
    fn clean_act_has_no_issues() {
        let issues = CscArt63RulePack.check_act(&complete_act(), &sa_entity());
        assert!(issues.is_empty(), "unexpected issues: {issues:?}");
    }

    #[test]
    fn statute_convocation_notice_missing_or_unverifiable_evidence_warns() {
        let mut act = complete_act();
        let statute = StatuteOverrides {
            convocation_notice_days: Some(8),
            ..StatuteOverrides::default()
        };

        let issues = statute_findings(&act, &statute);
        let issue = issues
            .iter()
            .find(|issue| issue.rule_id == "STATUTE/convocation-notice-unverified")
            .unwrap_or_else(|| panic!("missing unverified convocation notice warning: {issues:?}"));
        assert_eq!(issue.severity, Severity::Warning);
        assert!(
            issue.message.contains("local antecedence advisory"),
            "message must stay advisory: {issue:?}"
        );

        act.convening = Some(Convening {
            dispatch_date: Some(date!(2026 - 02 - 20)),
            ..Convening::default()
        });
        act.meeting_date = None;

        let issues = statute_findings(&act, &statute);
        assert!(
            issues
                .iter()
                .any(|issue| issue.rule_id == "STATUTE/convocation-notice-unverified"),
            "dispatch without a meeting date remains unverifiable: {issues:?}"
        );
    }

    #[test]
    fn statute_convocation_notice_short_recorded_or_computed_antecedence_warns() {
        let mut act = complete_act();
        act.convening = Some(Convening {
            dispatch_date: Some(date!(2026 - 02 - 25)),
            ..Convening::default()
        });
        let statute = StatuteOverrides {
            convocation_notice_days: Some(8),
            ..StatuteOverrides::default()
        };

        let issues = statute_findings(&act, &statute);
        let issue = issues
            .iter()
            .find(|issue| issue.rule_id == "STATUTE/convocation-notice")
            .unwrap_or_else(|| panic!("missing short convocation notice warning: {issues:?}"));
        assert_eq!(issue.severity, Severity::Warning);
        assert!(
            issue.message.contains("local advisory"),
            "message must avoid legal sufficiency claims: {issue:?}"
        );

        act.convening = Some(Convening {
            antecedence_days: Some(7),
            ..Convening::default()
        });
        let issues = statute_findings(&act, &statute);
        assert!(
            issues
                .iter()
                .any(|issue| issue.rule_id == "STATUTE/convocation-notice"),
            "recorded short antecedence should warn: {issues:?}"
        );
    }

    #[test]
    fn statute_convocation_notice_sufficient_dispatch_evidence_passes() {
        let mut act = complete_act();
        act.convening = Some(Convening {
            dispatch_date: Some(date!(2026 - 02 - 20)),
            ..Convening::default()
        });
        let statute = StatuteOverrides {
            convocation_notice_days: Some(8),
            ..StatuteOverrides::default()
        };

        let issues = statute_findings(&act, &statute);
        assert!(
            !issues
                .iter()
                .any(|issue| issue.rule_id.starts_with("STATUTE/convocation-notice")),
            "sufficient computed dispatch antecedence should pass: {issues:?}"
        );

        act.convening = Some(Convening {
            antecedence_days: Some(8),
            ..Convening::default()
        });
        let issues = statute_findings(&act, &statute);
        assert!(
            !issues
                .iter()
                .any(|issue| issue.rule_id.starts_with("STATUTE/convocation-notice")),
            "sufficient recorded antecedence should pass: {issues:?}"
        );
    }

    #[test]
    fn empty_draft_flags_every_mandatory_content() {
        // Migrated for v2: an empty draft raises advisory Warnings (secretaries, time, agenda)
        // alongside the blocking Errors, so the old "all Error" assertion no longer holds. Assert
        // that the blocking mandatory elements — including the mesa chair (re-promoted to Error in
        // t31-e2) — are present and are Errors.
        let act = Act::draft(BookId::new(), "Rascunho", MeetingChannel::Physical);
        let issues = CscArt63RulePack.check_act(&act, &sa_entity());
        for id in [
            "CSC-63/date",
            "CSC-63/place",
            "CSC-63/attendance",
            "CSC-63/deliberations",
            "CSC-63/mesa-presidente",
        ] {
            let issue = issues
                .iter()
                .find(|i| i.rule_id == id)
                .unwrap_or_else(|| panic!("missing {id}: {issues:?}"));
            assert_eq!(issue.severity, Severity::Error, "{id} must block");
        }
    }

    #[test]
    fn csc_findings_carry_pending_structural_legal_basis() {
        let act = Act::draft(BookId::new(), "Rascunho", MeetingChannel::Physical);
        let issues = CscArt63RulePack.check_act(&act, &sa_entity());
        let issue = issues
            .iter()
            .find(|i| i.rule_id == "CSC-63/mesa-presidente")
            .expect("missing mesa issue");
        let basis = issue.legal_basis.first().expect("legal basis");

        assert_eq!(basis.source_id, "csc");
        assert_eq!(basis.article.as_deref(), Some("63"));
        assert_eq!(basis.article_label.as_deref(), Some("Artigo 63.º"));
        assert_eq!(
            basis.citation,
            "Código das Sociedades Comerciais, Artigo 63.º"
        );
        assert_eq!(basis.verification, LegalBasisVerification::Pending);
        assert_eq!(basis.source_url, None);
        assert!(!basis.source_complete);
    }

    #[test]
    fn missing_mesa_presidente_blocks_but_secretaries_only_warn() {
        // The chair is a mandatory art. 63.º element and blocks sealing; the secretaries are
        // advisory (small organs legitimately have none).
        let mut act = complete_act();
        act.mesa.presidente = None;
        act.mesa.secretarios.clear();
        let issues = CscArt63RulePack.check_act(&act, &sa_entity());
        let pres = issues
            .iter()
            .find(|i| i.rule_id == "CSC-63/mesa-presidente")
            .expect("missing chair must be flagged");
        assert_eq!(pres.severity, Severity::Error);
        let sec = issues
            .iter()
            .find(|i| i.rule_id == "CSC-63/mesa-secretarios")
            .expect("missing secretaries flagged");
        assert_eq!(sec.severity, Severity::Warning);
    }

    #[test]
    fn structured_deliberations_alone_satisfy_the_substance_error() {
        // R3: substance may come from the structured path when free text is empty.
        use crate::act::DeliberationItem;
        let mut act = complete_act();
        act.deliberations = "   ".into();
        act.deliberation_items = vec![DeliberationItem {
            agenda_number: Some(1),
            text: "Aprovado por unanimidade.".into(),
            vote: Some(crate::act::VoteResult::Unanimous),
            statements: Vec::new(),
        }];
        let issues = CscArt63RulePack.check_act(&act, &sa_entity());
        assert!(
            !issues.iter().any(|i| i.rule_id == "CSC-63/deliberations"),
            "structured substance should satisfy the deliberations Error: {issues:?}"
        );
    }

    #[test]
    fn unvoted_structured_item_warns() {
        use crate::act::DeliberationItem;
        let mut act = complete_act();
        act.deliberation_items = vec![DeliberationItem {
            agenda_number: Some(1),
            text: "Aprovado.".into(),
            vote: None,
            statements: Vec::new(),
        }];
        let issues = CscArt63RulePack.check_act(&act, &sa_entity());
        let issue = issues
            .iter()
            .find(|i| i.rule_id == "CSC-63/vote-result")
            .expect("unvoted item should warn");
        assert_eq!(issue.severity, Severity::Warning);
    }

    #[test]
    fn beginning_of_proof_attachment_raises_detached_document_advisory() {
        use crate::act::{Attachment, AttachmentKind};
        let mut act = complete_act();
        act.attachments.push(Attachment {
            label: "Contrato assinado à parte".into(),
            kind: AttachmentKind::Exhibit,
            digest: None,
            beginning_of_proof: true,
        });
        let issues = CscArt63RulePack.check_act(&act, &sa_entity());
        let issue = issues
            .iter()
            .find(|i| i.rule_id == "CSC-63/detached-document")
            .expect("beginning-of-proof attachment should be flagged");
        assert_eq!(issue.severity, Severity::Warning);
    }

    #[test]
    fn written_resolution_without_bound_evidence_warns_as_pending_advisory() {
        use crate::act::{
            SignatorySlot, WrittenResolutionEvidence, WrittenResolutionEvidenceItem,
            written_resolution_evidence_summary,
        };

        let mut act = complete_act();
        act.channel = MeetingChannel::WrittenResolution;

        let summary = written_resolution_evidence_summary(&act);
        assert_eq!(summary.status, WrittenResolutionEvidenceStatus::Missing);
        let issues = CscArt63RulePack.check_act(&act, &sa_entity());
        let issue = issues
            .iter()
            .find(|i| i.rule_id == "CSC-54/written-resolution-evidence")
            .expect("written resolution without evidence should warn");
        assert_eq!(issue.severity, Severity::Warning);
        assert!(issue.message.contains("missing"));
        assert!(
            issue
                .message
                .contains(WRITTEN_RESOLUTION_EVIDENCE_STATUS_BOUNDARY)
        );
        let basis = issue.legal_basis.first().expect("CSC art. 54 basis");
        assert_eq!(basis.source_id, "csc");
        assert_eq!(basis.article.as_deref(), Some("54"));
        assert_eq!(basis.article_label.as_deref(), Some("Artigo 54.º"));
        assert_eq!(basis.verification, LegalBasisVerification::Pending);
        assert!(!basis.source_complete);

        act.written_resolution_evidence = Some(WrittenResolutionEvidence {
            checklist: vec![WrittenResolutionEvidenceItem {
                label: "Approval reference".into(),
                reference: Some("folder:approvals".into()),
                digest: None,
                note: Some("operator note".into()),
            }],
            review_receipts: vec![],
            note: Some("reference retained elsewhere".into()),
        });
        let summary = written_resolution_evidence_summary(&act);
        assert_eq!(
            summary.status,
            WrittenResolutionEvidenceStatus::ReferencedOnly
        );
        assert_eq!(summary.referenced_only_count(), 1);
        let issues = CscArt63RulePack.check_act(&act, &sa_entity());
        let issue = issues
            .iter()
            .find(|i| i.rule_id == "CSC-54/written-resolution-evidence")
            .expect("referenced-only evidence should warn");
        assert_eq!(issue.severity, Severity::Warning);
        assert!(issue.message.contains("referenced_only"));

        act.signatories.push(SignatorySlot {
            name: "Sócia A".into(),
            email: None,
            capacity: SignatoryCapacity::Member,
            signed: false,
            permilage: None,
        });
        let issues = CscArt63RulePack.check_act(&act, &sa_entity());
        assert!(
            issues
                .iter()
                .any(|i| i.rule_id == "CSC-54/written-resolution-evidence"),
            "unsigned signatory slots must not clear the evidence advisory"
        );

        act.signatories[0].signed = true;
        let summary = written_resolution_evidence_summary(&act);
        assert_eq!(
            summary.status,
            WrittenResolutionEvidenceStatus::BoundPresent
        );
        let issues = CscArt63RulePack.check_act(&act, &sa_entity());
        assert!(
            !issues
                .iter()
                .any(|i| i.rule_id == "CSC-54/written-resolution-evidence"),
            "signed signatory slots should clear the evidence advisory: {issues:?}"
        );

        act.signatories.clear();
        act.written_resolution_evidence.as_mut().unwrap().checklist[0].digest = Some([5; 32]);
        let summary = written_resolution_evidence_summary(&act);
        assert_eq!(
            summary.status,
            WrittenResolutionEvidenceStatus::BoundPresent
        );
        let issues = CscArt63RulePack.check_act(&act, &sa_entity());
        assert!(
            !issues
                .iter()
                .any(|i| i.rule_id == "CSC-54/written-resolution-evidence"),
            "digested checklist items should clear the evidence advisory: {issues:?}"
        );

        act.written_resolution_evidence = None;
        act.signatories.push(SignatorySlot {
            name: "Sócia A".into(),
            email: None,
            capacity: SignatoryCapacity::Member,
            signed: true,
            permilage: None,
        });
        let issues = CscArt63RulePack.check_act(&act, &sa_entity());
        assert!(
            !issues
                .iter()
                .any(|i| i.rule_id == "CSC-54/written-resolution-evidence"),
            "captured signatory slots should clear the evidence advisory: {issues:?}"
        );
    }

    #[test]
    fn csc_pack_checks_capital_weighted_tally_when_supported() {
        use crate::act::{AttendanceWeight, Attendee, DeliberationItem, PresenceMode};

        let mut act = complete_act();
        act.deliberation_items = vec![DeliberationItem {
            agenda_number: Some(1),
            text: "Aprovado o aumento de capital.".into(),
            vote: Some(VoteResult::Recorded {
                em_favor: 600_000,
                contra: 400_000,
                abstencoes: 0,
            }),
            statements: Vec::new(),
        }];
        act.attendees = vec![
            Attendee {
                name: "Sócia A".into(),
                quality: SignatoryCapacity::Member,
                presence: PresenceMode::InPerson,
                represented_by: None,
                weight: Some(AttendanceWeight::Capital(600_000)),
            },
            Attendee {
                name: "Sócio B".into(),
                quality: SignatoryCapacity::Member,
                presence: PresenceMode::Represented,
                represented_by: Some("Sócia A".into()),
                weight: Some(AttendanceWeight::Capital(400_000)),
            },
        ];

        let issues = CscArt63RulePack.check_act(&act, &sa_entity());
        assert!(
            !issues
                .iter()
                .any(|i| i.rule_id == "CSC-63/capital-vote-total"),
            "matching capital-weighted tally should not warn: {issues:?}"
        );

        act.deliberation_items[0].vote = Some(VoteResult::Recorded {
            em_favor: 6,
            contra: 4,
            abstencoes: 0,
        });
        let issues = CscArt63RulePack.check_act(&act, &sa_entity());
        let issue = issues
            .iter()
            .find(|i| i.rule_id == "CSC-63/capital-vote-total")
            .expect("count tally should not pass as capital-weighted");
        assert_eq!(issue.severity, Severity::Warning);
    }

    #[test]
    fn missing_entity_name_flags_identification() {
        let mut entity = sa_entity();
        entity.name = "   ".into();
        let issues = CscArt63RulePack.check_act(&complete_act(), &entity);
        assert!(issues.iter().any(|i| i.rule_id == "CSC-63/entity"));
    }

    #[test]
    fn telematic_sa_requires_art377_evidence() {
        let mut act = complete_act();
        act.channel = MeetingChannel::Telematic;
        let issues = CscArt63RulePack.check_act(&act, &sa_entity());
        let issue = issues
            .iter()
            .find(|i| i.rule_id == "CSC-377/telematic-evidence")
            .expect("telematic evidence should be flagged");
        assert_eq!(
            issue.legal_basis.first().and_then(|b| b.article.as_deref()),
            Some("377")
        );

        act.telematic_evidence = Some("Gravação e autenticação dos participantes.".into());
        let issues = CscArt63RulePack.check_act(&act, &sa_entity());
        assert!(
            !issues
                .iter()
                .any(|i| i.rule_id == "CSC-377/telematic-evidence")
        );
    }

    #[test]
    fn unvalidated_nipc_raises_a_warning_not_an_error() {
        let mut entity = sa_entity();
        entity.nipc = Nipc::unvalidated("FR-9920-XT");
        let issues = CscArt63RulePack.check_act(&complete_act(), &entity);
        let issue = issues
            .iter()
            .find(|i| i.rule_id == "CSC-63/nipc-unvalidated")
            .expect("unvalidated NIPC should be flagged");
        assert_eq!(issue.severity, Severity::Warning);
    }

    #[test]
    fn validated_nipc_raises_no_nipc_warning() {
        // sa_entity() carries a validated NIPC, so the override warning must not fire.
        let issues = CscArt63RulePack.check_act(&complete_act(), &sa_entity());
        assert!(
            !issues
                .iter()
                .any(|i| i.rule_id == "CSC-63/nipc-unvalidated"),
            "a validated NIPC must not raise the override warning"
        );
    }

    #[test]
    fn telematic_evidence_not_required_for_non_sa() {
        let mut act = complete_act();
        act.channel = MeetingChannel::Telematic;
        let condo = Entity::new(
            "Condomínio do Edifício Sol",
            Nipc::parse("503004642").unwrap(),
            "Porto",
            EntityKind::Condominio,
        );
        let issues = CscArt63RulePack.check_act(&act, &condo);
        assert!(
            !issues
                .iter()
                .any(|i| i.rule_id == "CSC-377/telematic-evidence")
        );
    }

    // ---- Non-CSC family packs ------------------------------------------------------------

    use crate::act::{
        AttendanceWeight, Attendee, DeliberationItem, PresenceMode, SignatoryCapacity,
        SignatorySlot, VoteResult,
    };

    fn family_entity(kind: EntityKind, name: &str) -> Entity {
        Entity::new(name, Nipc::parse("503004642").unwrap(), "Porto", kind)
    }

    /// A condo ata complete enough to satisfy the civil baseline, with a voted resolution.
    fn condo_act() -> Act {
        let mut act = Act::draft(BookId::new(), "Ata da assembleia", MeetingChannel::Physical);
        act.meeting_date = Some(date!(2026 - 03 - 01));
        act.meeting_time = Some(time!(21:00));
        act.place = Some("Hall do prédio".into());
        act.attendance_reference = Some("Folha de presenças".into());
        act.deliberation_items = vec![DeliberationItem {
            agenda_number: Some(1),
            text: "Aprovado o orçamento anual.".into(),
            vote: Some(VoteResult::Unanimous),
            statements: Vec::new(),
        }];
        act
    }

    #[test]
    fn condo_pack_seals_clean_and_ignores_mesa_agenda_and_377() {
        let e = family_entity(EntityKind::Condominio, "Condomínio do Edifício Sol");
        let mut act = condo_act();
        // Telematic + no mesa + no agenda: the condo pack must NOT flag any of these.
        act.channel = MeetingChannel::Telematic;
        let issues = CondominioRulePack.check_act(&act, &e);
        assert!(issues.is_empty(), "condo pack should be clean: {issues:?}");
        assert!(!issues.iter().any(|i| i.rule_id.contains("mesa")));
        assert!(!issues.iter().any(|i| i.rule_id.contains("agenda")));
        assert!(!issues.iter().any(|i| i.rule_id.contains("377")));
    }

    #[test]
    fn condo_pack_warns_on_missing_vote_result() {
        let e = family_entity(EntityKind::Condominio, "Condomínio");
        let mut act = condo_act();
        act.deliberation_items[0].vote = None;
        let issues = CondominioRulePack.check_act(&act, &e);
        let issue = issues
            .iter()
            .find(|i| i.rule_id == "DL268/vote-result")
            .expect("missing vote result should warn");
        let basis = issue.legal_basis.first().expect("DL 268 basis");
        assert_eq!(basis.source_id, "dl-268-94");
        assert_eq!(
            basis.source_label,
            "Decreto-Lei n.º 268/94, de 25 de outubro"
        );
        assert_eq!(basis.article, None);
        assert_eq!(basis.verification, LegalBasisVerification::Pending);
        assert!(!basis.source_complete);
    }

    #[test]
    fn condo_pack_flags_missing_meeting_date_and_time_separately() {
        let e = family_entity(EntityKind::Condominio, "Condomínio");
        let mut act = condo_act();
        act.meeting_date = None;
        act.meeting_time = None;
        let issues = CondominioRulePack.check_act(&act, &e);

        let date_issue = issues
            .iter()
            .find(|i| i.rule_id == "DL268/date")
            .expect("missing date should be flagged by the civil baseline");
        assert_eq!(date_issue.severity, Severity::Error);

        let time_issue = issues
            .iter()
            .find(|i| i.rule_id == "DL268/time")
            .expect("missing time should be flagged by the condominium pack");
        assert_eq!(time_issue.severity, Severity::Warning);
    }

    #[test]
    fn condo_pack_warns_on_condo_owner_without_permilage() {
        let e = family_entity(EntityKind::Condominio, "Condomínio");
        let mut act = condo_act();
        act.signatories.push(SignatorySlot {
            name: "Fração A".into(),
            email: None,
            capacity: SignatoryCapacity::CondoOwner,
            signed: false,
            permilage: None,
        });
        let issues = CondominioRulePack.check_act(&act, &e);
        let issue = issues
            .iter()
            .find(|i| i.rule_id == "DL268/permilage")
            .expect("owner without permilage should warn");
        assert_eq!(issue.severity, Severity::Warning);

        // With a permilage recorded, the warning clears.
        act.signatories[0].permilage = Some(125);
        let issues = CondominioRulePack.check_act(&act, &e);
        assert!(!issues.iter().any(|i| i.rule_id == "DL268/permilage"));
    }

    #[test]
    fn condo_pack_warns_on_impossible_permilage_values_and_totals() {
        let e = family_entity(EntityKind::Condominio, "Condomínio");
        let mut act = condo_act();
        act.attendees = vec![
            Attendee {
                name: "Fração A".into(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::InPerson,
                represented_by: None,
                weight: Some(AttendanceWeight::Permilage(700)),
            },
            Attendee {
                name: "Fração B".into(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::Represented,
                represented_by: Some("Fração A".into()),
                weight: Some(AttendanceWeight::Permilage(450)),
            },
            Attendee {
                name: "Fração C".into(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::Absent,
                represented_by: None,
                weight: Some(AttendanceWeight::Permilage(900)),
            },
        ];
        act.signatories.push(SignatorySlot {
            name: "Fração D".into(),
            email: None,
            capacity: SignatoryCapacity::CondoOwner,
            signed: false,
            permilage: Some(1001),
        });

        let issues = CondominioRulePack.check_act(&act, &e);
        assert!(
            issues.iter().any(|i| i.rule_id == "DL268/permilage-total"),
            "present/represented permilage above 1000 should warn: {issues:?}"
        );
        assert!(
            issues.iter().any(|i| i.rule_id == "DL268/permilage-value"),
            "individual permilage above 1000 should warn: {issues:?}"
        );
    }

    #[test]
    fn condo_pack_checks_recorded_votes_against_permilage_tally() {
        let e = family_entity(EntityKind::Condominio, "Condomínio");
        let mut act = condo_act();
        act.deliberation_items[0].vote = Some(VoteResult::Recorded {
            em_favor: 450,
            contra: 250,
            abstencoes: 0,
        });
        act.attendees = vec![
            Attendee {
                name: "Fração A".into(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::InPerson,
                represented_by: None,
                weight: Some(AttendanceWeight::Permilage(450)),
            },
            Attendee {
                name: "Fração B".into(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::Represented,
                represented_by: Some("Fração A".into()),
                weight: Some(AttendanceWeight::Permilage(250)),
            },
        ];

        let issues = CondominioRulePack.check_act(&act, &e);
        assert!(
            !issues
                .iter()
                .any(|i| i.rule_id == "DL268/permilage-vote-total"),
            "matching permilage tally should not warn: {issues:?}"
        );

        act.deliberation_items[0].vote = Some(VoteResult::Recorded {
            em_favor: 2,
            contra: 1,
            abstencoes: 0,
        });
        let issues = CondominioRulePack.check_act(&act, &e);
        let issue = issues
            .iter()
            .find(|i| i.rule_id == "DL268/permilage-vote-total")
            .expect("count tally should not pass as permilage-weighted");
        assert_eq!(issue.severity, Severity::Warning);
    }

    #[test]
    fn condo_pack_warns_when_quorum_counts_contradict_attendance_rows() {
        let e = family_entity(EntityKind::Condominio, "Condomínio");
        let mut act = condo_act();
        act.members_present = Some(3);
        act.members_represented = Some(1);
        act.attendees = vec![
            Attendee {
                name: "Fração A".into(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::InPerson,
                represented_by: None,
                weight: Some(AttendanceWeight::Permilage(400)),
            },
            Attendee {
                name: "Fração B".into(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::Absent,
                represented_by: None,
                weight: Some(AttendanceWeight::Permilage(300)),
            },
        ];

        let issues = CondominioRulePack.check_act(&act, &e);
        let issue = issues
            .iter()
            .find(|i| i.rule_id == "DL268/attendance-count-mismatch")
            .expect("contradictory count and row metadata should warn");
        assert_eq!(issue.severity, Severity::Warning);
    }

    #[test]
    fn condo_pack_blocks_on_the_civil_baseline() {
        let e = family_entity(EntityKind::Condominio, "Condomínio");
        let act = Act::draft(BookId::new(), "Rascunho", MeetingChannel::Physical);
        let issues = CondominioRulePack.check_act(&act, &e);
        for id in [
            "DL268/date",
            "DL268/place",
            "DL268/attendance",
            "DL268/deliberations",
        ] {
            let issue = issues.iter().find(|i| i.rule_id == id).expect(id);
            assert_eq!(issue.severity, Severity::Error);
        }
    }

    #[test]
    fn assoc_pack_is_baseline_plus_agenda() {
        let e = family_entity(EntityKind::Associacao, "Associação Cultural");
        let mut act = condo_act(); // baseline-complete
        let issues = AssociacaoRulePack.check_act(&act, &e);
        assert!(issues.iter().any(|i| i.rule_id == "CC/agenda"));
        // The pack must not require a mesa or art. 377.º.
        assert!(!issues.iter().any(|i| i.rule_id.contains("mesa")));
        assert!(!issues.iter().any(|i| i.rule_id.contains("377")));

        act.agenda = vec![AgendaItem {
            number: 1,
            text: "Ponto único".into(),
        }];
        let issues = AssociacaoRulePack.check_act(&act, &e);
        assert!(issues.is_empty(), "assoc pack should be clean: {issues:?}");
    }

    #[test]
    fn assoc_written_resolution_evidence_can_be_a_digested_attachment() {
        use crate::act::{Attachment, AttachmentKind};

        let e = family_entity(EntityKind::Associacao, "Associação Cultural");
        let mut act = condo_act();
        act.channel = MeetingChannel::WrittenResolution;
        act.agenda = vec![AgendaItem {
            number: 1,
            text: "Ponto único".into(),
        }];

        let issues = AssociacaoRulePack.check_act(&act, &e);
        let issue = issues
            .iter()
            .find(|i| i.rule_id == "CC/written-resolution-evidence")
            .expect("missing bound written evidence should warn");
        assert_eq!(issue.severity, Severity::Warning);
        assert_eq!(
            issue.legal_basis.first().map(|b| b.verification),
            Some(LegalBasisVerification::Pending)
        );

        act.attachments.push(Attachment {
            label: "Deliberação escrita assinada".into(),
            kind: AttachmentKind::Exhibit,
            digest: Some([7; 32]),
            beginning_of_proof: false,
        });
        let issues = AssociacaoRulePack.check_act(&act, &e);
        assert!(
            !issues
                .iter()
                .any(|i| i.rule_id == "CC/written-resolution-evidence"),
            "a digested attachment bound into the seal should clear the advisory: {issues:?}"
        );
    }

    #[test]
    fn fundacao_pack_is_the_civil_baseline() {
        let e = family_entity(EntityKind::Fundacao, "Fundação Beneficente");
        let act = condo_act();
        let issues = FundacaoRulePack.check_act(&act, &e);
        assert_eq!(FundacaoRulePack.id(), "fundacao-cc/v1");
        assert!(
            issues.is_empty(),
            "fundação baseline should be clean: {issues:?}"
        );
    }

    #[test]
    fn coop_pack_notes_one_member_one_vote_on_a_tally() {
        let e = family_entity(EntityKind::Cooperativa, "Cooperativa Agrícola");
        let mut act = condo_act();
        act.deliberation_items[0].vote = Some(VoteResult::Recorded {
            em_favor: 10,
            contra: 2,
            abstencoes: 1,
        });
        let issues = CooperativaRulePack.check_act(&act, &e);
        let issue = issues
            .iter()
            .find(|i| i.rule_id == "CCoop/one-member-one-vote")
            .expect("one-member-one-vote warning");
        let basis = issue.legal_basis.first().expect("cooperative basis");
        assert_eq!(basis.source_id, "cod-cooperativo");
        assert_eq!(basis.article.as_deref(), Some("41"));
        assert_eq!(basis.article_label.as_deref(), Some("Artigo 41.º"));
        assert_eq!(basis.verification, LegalBasisVerification::Pending);

        // A unanimous (no tally) resolution does not trigger the note.
        act.deliberation_items[0].vote = Some(VoteResult::Unanimous);
        let issues = CooperativaRulePack.check_act(&act, &e);
        assert!(
            !issues
                .iter()
                .any(|i| i.rule_id == "CCoop/one-member-one-vote")
        );
    }
}
