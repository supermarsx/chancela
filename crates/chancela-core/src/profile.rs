//! Entity profiles and per-family compliance dispatch (ENT-02 / LEG-02).
//!
//! Grounding: spec 03 (Entity Type Profiles). Each [`EntityFamily`] binds a distinct unit of
//! legal behavior. An [`EntityProfile`] gathers the facets the platform derives from the
//! entity's legal type — its compliance rule pack, permitted meeting channels, signature
//! policy, template family, and calendar presets — and [`rule_pack_for`] is the dispatch that
//! selects the right pack (family baseline + statute overlay) for an entity, so the compliance
//! gate is legally right for all five families rather than checking everything against the CSC
//! commercial pack.

use serde::Serialize;

use crate::act::MeetingChannel;
use crate::entity::{Entity, EntityFamily, EntityKind, StatuteOverrides};
use crate::rules::{
    AssociacaoRulePack, ComplianceIssue, CondominioRulePack, CooperativaRulePack, CscArt63RulePack,
    FundacaoRulePack, RulePack, statute_findings,
};

/// Signature policy hint (ENT-02(c)). A **hint** only — signature enforcement is Wave D; this
/// tells the UI what to prefer, it does not gate sealing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SignaturePolicyHint {
    /// Qualified electronic signature preferred (commercial companies).
    QualifiedPreferred,
    /// Qualified or handwritten accepted (condominium — ENT-D3).
    QualifiedOrHandwritten,
    /// Manual attested signatures (association / foundation / cooperative baseline).
    ManualAttested,
}

/// A calendar preset seed (ENT-02(e)). **Seed only** — the reminder/calendar engine is Wave E;
/// this carries the canonical recurrence a family expects so the engine can later realize it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CalendarPreset {
    /// Stable preset id (e.g. `"csc-art376-annual"`).
    pub id: &'static str,
    /// Human label.
    pub label: &'static str,
    /// Months after fiscal-year end by which the meeting must be held, when applicable.
    pub months_after_fiscal_year_end: Option<u8>,
}

/// The bundle of facets the platform derives from an entity's legal type (ENT-02).
///
/// Carries `&'static str` seed ids (the rule-pack id, the template-family id) and so derives
/// `Serialize` but not `Deserialize`: it is always *produced* by [`profile_for`] from an
/// [`EntityKind`], never parsed back. Consumers (the api `EntityView`) read its fields and
/// build their own wire DTO. ENT-02(a) contents and (f) registry mapping are realized by the
/// rule pack and the existing registry importer respectively.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntityProfile {
    /// The entity family this profile describes.
    pub family: EntityFamily,
    /// The family's stable rule-pack id (LEG-02/06).
    pub rule_pack_id: &'static str,
    /// Meeting channels this family permits (ENT-02(b)).
    pub allowed_channels: Vec<MeetingChannel>,
    /// Signature policy hint (ENT-02(c)).
    pub signature_policy: SignaturePolicyHint,
    /// Template-family seed id (ENT-02(d); Wave C owns the engine).
    pub template_family: &'static str,
    /// Calendar preset seeds (ENT-02(e); Wave E owns the engine).
    pub calendar_presets: Vec<CalendarPreset>,
}

/// The meeting channels a family permits (ENT-02(b)). Used by both [`profile_for`] and the
/// packs' channel advisory.
pub(crate) fn allowed_channels(family: EntityFamily) -> Vec<MeetingChannel> {
    use MeetingChannel::*;
    match family {
        // Commercial companies: presencial, hybrid, telematic (art. 377.º), and unanimous
        // written resolutions (art. 54.º).
        EntityFamily::CommercialCompany => vec![Physical, Hybrid, Telematic, WrittenResolution],
        // Condominium assembleias meet; written unanimous resolutions are not the DL 268/94 path.
        EntityFamily::Condominium => vec![Physical, Hybrid, Telematic],
        EntityFamily::Association => vec![Physical, Hybrid, Telematic, WrittenResolution],
        EntityFamily::Foundation => vec![Physical, Hybrid, Telematic],
        EntityFamily::Cooperative => vec![Physical, Hybrid, Telematic, WrittenResolution],
    }
}

/// Build the [`EntityProfile`] for a legal type (ENT-02). Facets are family-anchored.
pub fn profile_for(kind: EntityKind) -> EntityProfile {
    let family = kind.family();
    let (rule_pack_id, signature_policy, template_family, calendar_presets) = match family {
        EntityFamily::CommercialCompany => (
            CscArt63RulePack::ID,
            SignaturePolicyHint::QualifiedPreferred,
            "csc-commercial",
            vec![CalendarPreset {
                id: "csc-art376-annual",
                label: "Assembleia geral anual (CSC art. 376.º)",
                months_after_fiscal_year_end: Some(3),
            }],
        ),
        EntityFamily::Condominium => (
            CondominioRulePack::ID,
            SignaturePolicyHint::QualifiedOrHandwritten,
            "condominio-dl268",
            vec![CalendarPreset {
                id: "condominio-annual",
                label: "Assembleia ordinária anual de condóminos (DL 268/94)",
                months_after_fiscal_year_end: None,
            }],
        ),
        EntityFamily::Association => (
            AssociacaoRulePack::ID,
            SignaturePolicyHint::ManualAttested,
            "assoc-cc",
            vec![CalendarPreset {
                id: "assoc-annual",
                label: "Assembleia geral ordinária anual (Código Civil)",
                months_after_fiscal_year_end: Some(3),
            }],
        ),
        EntityFamily::Foundation => (
            FundacaoRulePack::ID,
            SignaturePolicyHint::ManualAttested,
            "fundacao-cc",
            vec![CalendarPreset {
                id: "fundacao-annual",
                label: "Reunião anual do conselho de administração (Lei 24/2012)",
                months_after_fiscal_year_end: Some(3),
            }],
        ),
        EntityFamily::Cooperative => (
            CooperativaRulePack::ID,
            SignaturePolicyHint::ManualAttested,
            "cooperativa-ccoop",
            vec![CalendarPreset {
                id: "cooperativa-annual",
                label: "Assembleia geral anual (Código Cooperativo)",
                months_after_fiscal_year_end: Some(3),
            }],
        ),
    };

    EntityProfile {
        family,
        rule_pack_id,
        allowed_channels: allowed_channels(family),
        signature_policy,
        template_family,
        calendar_presets,
    }
}

/// A composite rule pack: the family baseline pack plus the entity's statute overlay (R4/R5).
///
/// Its [`check_act`](RulePack::check_act) concatenates the family pack's findings with the
/// statute-overlay findings, and its [`id`](RulePack::id) returns the **family pack id**
/// (stable and family-anchored). Whether a statute overlay contributed is visible through the
/// finding `rule_id`s (`STATUTE/*`), not through a mangled pack id.
pub struct ProfilePack {
    family: Box<dyn RulePack>,
    statute: Option<StatuteOverrides>,
}

impl RulePack for ProfilePack {
    fn id(&self) -> &str {
        self.family.id()
    }

    fn check_act(&self, act: &crate::act::Act, entity: &Entity) -> Vec<ComplianceIssue> {
        let mut issues = self.family.check_act(act, entity);
        if let Some(statute) = &self.statute {
            issues.extend(statute_findings(act, statute));
        }
        issues
    }
}

/// The per-family compliance dispatch (R4 / LEG-02): pick the family baseline pack for
/// `entity` and wrap it with the entity's statute overlay (ENT-03). The returned pack's
/// `id()` is the family pack id.
///
/// `seal_act`'s signature is untouched; the api builds the pack with this instead of
/// hardcoding a single pack.
pub fn rule_pack_for(entity: &Entity) -> Box<dyn RulePack> {
    let family: Box<dyn RulePack> = match entity.family {
        EntityFamily::CommercialCompany => Box::new(CscArt63RulePack),
        EntityFamily::Condominium => Box::new(CondominioRulePack),
        EntityFamily::Association => Box::new(AssociacaoRulePack),
        EntityFamily::Foundation => Box::new(FundacaoRulePack),
        EntityFamily::Cooperative => Box::new(CooperativaRulePack),
    };
    Box::new(ProfilePack {
        family,
        statute: entity.statute.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::act::{Act, DeliberationItem, MeetingChannel, VoteResult};
    use crate::book::BookId;
    use crate::entity::{Entity, EntityKind, Majority, Nipc, Quorum, StatuteOverrides};
    use time::macros::date;

    fn entity(kind: EntityKind) -> Entity {
        Entity::new(
            "Test, Lda.",
            Nipc::parse("503004642").unwrap(),
            "Lisboa",
            kind,
        )
    }

    fn structured_act(vote: VoteResult) -> Act {
        let mut act = Act::draft(BookId::new(), "Ata", MeetingChannel::Physical);
        act.meeting_date = Some(date!(2026 - 03 - 01));
        act.place = Some("Sede".into());
        act.attendance_reference = Some("Lista".into());
        act.deliberation_items = vec![DeliberationItem {
            agenda_number: Some(1),
            text: "Deliberação".into(),
            vote: Some(vote),
            statements: Vec::new(),
        }];
        act
    }

    #[test]
    fn dispatch_returns_the_family_pack_id() {
        assert_eq!(
            rule_pack_for(&entity(EntityKind::SociedadeAnonima)).id(),
            "csc-art63/v2"
        );
        assert_eq!(
            rule_pack_for(&entity(EntityKind::Condominio)).id(),
            "condominio-dl268/v1"
        );
        assert_eq!(
            rule_pack_for(&entity(EntityKind::Associacao)).id(),
            "assoc-cc/v1"
        );
        assert_eq!(
            rule_pack_for(&entity(EntityKind::Fundacao)).id(),
            "fundacao-cc/v1"
        );
        assert_eq!(
            rule_pack_for(&entity(EntityKind::Cooperativa)).id(),
            "cooperativa-ccoop/v1"
        );
    }

    #[test]
    fn profile_binds_family_facets() {
        let p = profile_for(EntityKind::SociedadeAnonima);
        assert_eq!(p.family, EntityFamily::CommercialCompany);
        assert_eq!(p.rule_pack_id, "csc-art63/v2");
        assert_eq!(p.signature_policy, SignaturePolicyHint::QualifiedPreferred);
        assert!(
            p.allowed_channels
                .contains(&MeetingChannel::WrittenResolution)
        );

        let condo = profile_for(EntityKind::Condominio);
        assert_eq!(
            condo.signature_policy,
            SignaturePolicyHint::QualifiedOrHandwritten
        );
        assert!(
            !condo
                .allowed_channels
                .contains(&MeetingChannel::WrittenResolution)
        );
    }

    #[test]
    fn statute_majority_overlay_is_a_real_check() {
        // 2/3 statutory majority; a resolution carried 60/100 in favour is below it → warns.
        let mut e = entity(EntityKind::SociedadeAnonima);
        e.statute = Some(StatuteOverrides {
            majority: Some(Majority {
                numerator: 2,
                denominator: 3,
            }),
            ..Default::default()
        });
        let mut act = structured_act(VoteResult::Recorded {
            em_favor: 60,
            contra: 40,
            abstencoes: 0,
        });
        // Fill the CSC mandatory content so only the statute finding is of interest.
        act.mesa.presidente = Some("Presidente".into());

        let pack = rule_pack_for(&e);
        let issues = pack.check_act(&act, &e);
        assert!(
            issues.iter().any(|i| i.rule_id == "STATUTE/majority"),
            "60% should miss a 2/3 majority: {issues:?}"
        );

        // Raise to 70/100 → clears the majority finding.
        act.deliberation_items[0].vote = Some(VoteResult::Recorded {
            em_favor: 70,
            contra: 30,
            abstencoes: 0,
        });
        let issues = pack.check_act(&act, &e);
        assert!(!issues.iter().any(|i| i.rule_id == "STATUTE/majority"));
    }

    #[test]
    fn statute_quorum_overlay_fires_below_min_and_reminds_without_counts() {
        let mut e = entity(EntityKind::Associacao);
        e.statute = Some(StatuteOverrides {
            quorum: Some(Quorum { min_present: 10 }),
            ..Default::default()
        });
        let mut act = structured_act(VoteResult::Unanimous);

        // No counts captured → advisory reminder.
        let issues = rule_pack_for(&e).check_act(&act, &e);
        assert!(
            issues
                .iter()
                .any(|i| i.rule_id == "STATUTE/quorum-unverified")
        );

        // Counts below the minimum → the below-min warning.
        act.members_present = Some(4);
        act.members_represented = Some(2);
        let issues = rule_pack_for(&e).check_act(&act, &e);
        assert!(issues.iter().any(|i| i.rule_id == "STATUTE/quorum"));

        // Counts meeting the minimum → neither fires.
        act.members_present = Some(8);
        act.members_represented = Some(2);
        let issues = rule_pack_for(&e).check_act(&act, &e);
        assert!(
            !issues
                .iter()
                .any(|i| i.rule_id.starts_with("STATUTE/quorum"))
        );
    }

    #[test]
    fn no_statute_means_no_overlay_findings() {
        let e = entity(EntityKind::SociedadeAnonima);
        let mut act = structured_act(VoteResult::Recorded {
            em_favor: 1,
            contra: 9,
            abstencoes: 0,
        });
        act.mesa.presidente = Some("Presidente".into());
        let issues = rule_pack_for(&e).check_act(&act, &e);
        assert!(!issues.iter().any(|i| i.rule_id.starts_with("STATUTE/")));
    }
}
