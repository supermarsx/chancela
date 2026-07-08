//! Compliance rule packs.
//!
//! Grounding: spec 06 (WFL-31 — "compliance logic MUST always be driven by law and the
//! entity's statutes, never by the template itself: templates are conveniences, rule
//! packs are authority") and LEG-05 (the warning model). A [`RulePack`] inspects an act
//! against its entity and returns [`ComplianceIssue`]s; sealing consults it (see
//! [`crate::seal::seal_act`]).

use crate::act::{Act, MeetingChannel, SignatoryCapacity, VoteResult};
use crate::entity::{Entity, EntityKind, StatuteOverrides};

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

/// A single compliance finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceIssue {
    /// Identifier of the rule that fired (e.g., `"CSC-63/deliberations"`).
    pub rule_id: String,
    /// Whether this blocks sealing.
    pub severity: Severity,
    /// Human-readable explanation.
    pub message: String,
}

impl ComplianceIssue {
    fn error(rule_id: &str, message: impl Into<String>) -> Self {
        ComplianceIssue {
            rule_id: rule_id.to_string(),
            severity: Severity::Error,
            message: message.into(),
        }
    }

    fn warning(rule_id: &str, message: impl Into<String>) -> Self {
        ComplianceIssue {
            rule_id: rule_id.to_string(),
            severity: Severity::Warning,
            message: message.into(),
        }
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

/// CSC art. 63.º rule pack (**v2**) for the mandatory ata contents (ENT-C2 / LEG-03).
///
/// Over the civil baseline (entity identity, date, place, attendance, substance) this pack
/// adds the CSC-specific art. 63.º elements: the **mesa** (chair — blocking — and secretaries
/// — advisory), the meeting **time**, the **agenda** (ordem de trabalhos), per-resolution
/// **voting results**, a **detached-document** beginning-of-proof advisory (ENT-C6), and the
/// art. 377.º telematic-SA evidence Error (ENT-C4). Severities follow R2: only the chair and
/// the art. 377.º evidence block; the rest are advisory so the free-text / historical / simple
/// ata (R1/R3) and old persisted acts stay sealable.
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
/// the civil baseline it warns on unrecorded per-resolution results and on a condómino
/// signatory carrying no *permilagem* (ENT-D6 — metadata only; weighted tallies are deferred).
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

        // Result of each deliberation (advisory).
        issues.extend(missing_vote_warnings(act, "DL268"));

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
        issues
    }
}

/// Statute overlay findings (ENT-03 / R5): advisory checks derived from an entity's own
/// statutes, applied on top of the family pack by [`crate::profile::ProfilePack`].
///
/// Only the knobs that can be genuinely checked against today's model fire: `majority`
/// against structured [`VoteResult::Recorded`] tallies, and `quorum` against the present /
/// represented counts. `convocation_notice_days` is stored/surfaced only (no dispatch date
/// is modeled).
pub fn statute_findings(act: &Act, statute: &StatuteOverrides) -> Vec<ComplianceIssue> {
    let mut issues = Vec::new();

    // Statutory majority: each non-unanimous recorded resolution must reach the fraction.
    if let Some(maj) = statute.majority {
        for (i, item) in act.deliberation_items.iter().enumerate() {
            if let Some(VoteResult::Recorded {
                em_favor,
                contra,
                abstencoes,
            }) = item.vote
            {
                let total = em_favor as u64 + contra as u64 + abstencoes as u64;
                // em_favor / total >= numerator / denominator, in integer arithmetic. Use u128
                // for the cross-multiply to prevent overflow when the counts are large.
                if total > 0 {
                    let favor: u128 = (em_favor as u64).into();
                    let den: u128 = (maj.denominator as u64).into();
                    let num: u128 = (maj.numerator as u64).into();
                    let total_u128: u128 = total.into();
                    if favor * den < num * total_u128 {
                        issues.push(ComplianceIssue::warning(
                            "STATUTE/majority",
                            format!(
                                "deliberation item {} carried with {em_favor}/{total} in favour, \
                                 below the statutory majority of {}/{}",
                                i + 1,
                                maj.numerator,
                                maj.denominator
                            ),
                        ));
                    }
                }
            }
        }
    }

    // Statutory quorum: present + represented must meet the minimum, when counts exist.
    if let Some(q) = statute.quorum {
        match (act.members_present, act.members_represented) {
            (None, None) => {
                issues.push(ComplianceIssue::warning(
                    "STATUTE/quorum-unverified",
                    format!(
                        "the statutes set a quorum of {} but no present/represented counts \
                         were captured; confirm the quorum manually",
                        q.min_present
                    ),
                ));
            }
            _ => {
                let present =
                    act.members_present.unwrap_or(0) + act.members_represented.unwrap_or(0);
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

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::act::{Act, AgendaItem};
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
        assert!(
            issues
                .iter()
                .any(|i| i.rule_id == "CSC-377/telematic-evidence")
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

    use crate::act::{DeliberationItem, SignatoryCapacity, SignatorySlot, VoteResult};

    fn family_entity(kind: EntityKind, name: &str) -> Entity {
        Entity::new(name, Nipc::parse("503004642").unwrap(), "Porto", kind)
    }

    /// A condo ata complete enough to satisfy the civil baseline, with a voted resolution.
    fn condo_act() -> Act {
        let mut act = Act::draft(BookId::new(), "Ata da assembleia", MeetingChannel::Physical);
        act.meeting_date = Some(date!(2026 - 03 - 01));
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
        assert!(issues.iter().any(|i| i.rule_id == "DL268/vote-result"));
    }

    #[test]
    fn condo_pack_warns_on_condo_owner_without_permilage() {
        let e = family_entity(EntityKind::Condominio, "Condomínio");
        let mut act = condo_act();
        act.signatories.push(SignatorySlot {
            name: "Fração A".into(),
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
        assert!(
            issues
                .iter()
                .any(|i| i.rule_id == "CCoop/one-member-one-vote")
        );

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
