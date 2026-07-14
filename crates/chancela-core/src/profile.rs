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
use time::{Date, Month};

use crate::act::MeetingChannel;
use crate::entity::{Entity, EntityFamily, EntityKind, StatuteOverrides};
use crate::rules::{
    AssociacaoRulePack, ComplianceIssue, CondominioRulePack, CooperativaRulePack, CscArt63RulePack,
    FundacaoRulePack, RulePack, statute_findings_for_entity,
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

/// Calendar rule kind for the local advisory profile-calendar planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProfileCalendarRuleKind {
    /// Commercial-company annual general meeting/accounts spine.
    CommercialCompanyAnnualGeneralMeeting,
    /// Condominium ordinary annual assembly seed; no local due-date rule is encoded.
    CondominiumAnnualAssembly,
    /// Association annual general meeting spine.
    AssociationAnnualGeneralMeeting,
    /// Foundation annual governance-review spine.
    FoundationAnnualGovernanceReview,
    /// Cooperative annual general meeting spine.
    CooperativeAnnualGeneralMeeting,
}

impl ProfileCalendarRuleKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ProfileCalendarRuleKind::CommercialCompanyAnnualGeneralMeeting => {
                "commercial_company_annual_general_meeting"
            }
            ProfileCalendarRuleKind::CondominiumAnnualAssembly => "condominium_annual_assembly",
            ProfileCalendarRuleKind::AssociationAnnualGeneralMeeting => {
                "association_annual_general_meeting"
            }
            ProfileCalendarRuleKind::FoundationAnnualGovernanceReview => {
                "foundation_annual_governance_review"
            }
            ProfileCalendarRuleKind::CooperativeAnnualGeneralMeeting => {
                "cooperative_annual_general_meeting"
            }
        }
    }
}

/// Whether Chancela has a local due-date rule for a profile-calendar preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProfileCalendarRuleSupportStatus {
    /// A local advisory due-date rule is encoded.
    Supported,
    /// The preset is visible, but no local due-date rule is encoded.
    Unsupported,
}

impl ProfileCalendarRuleSupportStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ProfileCalendarRuleSupportStatus::Supported => "supported",
            ProfileCalendarRuleSupportStatus::Unsupported => "unsupported",
        }
    }
}

/// Review posture for the local profile-calendar rule metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProfileCalendarReviewStatus {
    /// Encoded as a local advisory rule; source/legal review remains pending.
    PendingSourceReview,
}

impl ProfileCalendarReviewStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ProfileCalendarReviewStatus::PendingSourceReview => "pending_source_review",
        }
    }
}

/// Source posture for profile-calendar law references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProfileCalendarSourceStatus {
    /// Structural reference only: source is not verified complete by this rule.
    PendingUnverified,
}

impl ProfileCalendarSourceStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ProfileCalendarSourceStatus::PendingUnverified => "pending_unverified",
        }
    }

    #[must_use]
    pub const fn dashboard_verification(self) -> &'static str {
        match self {
            ProfileCalendarSourceStatus::PendingUnverified => "Pending",
        }
    }
}

/// Explicit no-claim guardrails for local profile-calendar advisory output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProfileCalendarNoClaimFlags {
    pub local_advisory_only: bool,
    pub legal_deadline_authority_claimed: bool,
    pub legal_calendar_authority_claimed: bool,
    pub legal_compliance_claimed: bool,
    pub compliance_status_claimed: bool,
    pub workflow_completion_claimed: bool,
    pub external_delivery_claimed: bool,
    pub external_calendar_sync_claimed: bool,
    pub webhook_delivery_claimed: bool,
    pub legal_review_claimed: bool,
    pub dre_verification_claimed: bool,
    pub provider_effect_claimed: bool,
    pub certification_claimed: bool,
}

impl ProfileCalendarNoClaimFlags {
    #[must_use]
    pub const fn local_advisory() -> Self {
        ProfileCalendarNoClaimFlags {
            local_advisory_only: true,
            legal_deadline_authority_claimed: false,
            legal_calendar_authority_claimed: false,
            legal_compliance_claimed: false,
            compliance_status_claimed: false,
            workflow_completion_claimed: false,
            external_delivery_claimed: false,
            external_calendar_sync_claimed: false,
            webhook_delivery_claimed: false,
            legal_review_claimed: false,
            dre_verification_claimed: false,
            provider_effect_claimed: false,
            certification_claimed: false,
        }
    }
}

impl Default for ProfileCalendarNoClaimFlags {
    fn default() -> Self {
        Self::local_advisory()
    }
}

/// Structural law reference for profile-calendar rules.
///
/// These are intentionally pending/unverified metadata. They do not assert source completeness,
/// legal review, or legal-calendar authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProfileCalendarLawReference {
    pub diploma_id: &'static str,
    pub article: &'static str,
    pub label: &'static str,
    pub source_status: ProfileCalendarSourceStatus,
}

const CSC_ART_376_REF: [ProfileCalendarLawReference; 1] = [ProfileCalendarLawReference {
    diploma_id: "csc",
    article: "376",
    label: "Artigo 376.º",
    source_status: ProfileCalendarSourceStatus::PendingUnverified,
}];

const CC_ART_173_REF: [ProfileCalendarLawReference; 1] = [ProfileCalendarLawReference {
    diploma_id: "cc",
    article: "173",
    label: "Artigo 173.º",
    source_status: ProfileCalendarSourceStatus::PendingUnverified,
}];

const COOP_ART_33_REF: [ProfileCalendarLawReference; 1] = [ProfileCalendarLawReference {
    diploma_id: "cod-cooperativo",
    article: "33",
    label: "Artigo 33.º",
    source_status: ProfileCalendarSourceStatus::PendingUnverified,
}];

const EMPTY_CALENDAR_REFS: [ProfileCalendarLawReference; 0] = [];

/// Fiscal-year end used by local profile-calendar due-date rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FiscalYearEnd {
    pub month: u8,
    pub day: u8,
}

impl FiscalYearEnd {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let (month, day) = value.split_once('-')?;
        let month = month.parse::<u8>().ok()?;
        let day = day.parse::<u8>().ok()?;
        let month = Month::try_from(month).ok()?;
        Date::from_calendar_date(2000, month, day).ok()?;
        Some(FiscalYearEnd {
            month: month as u8,
            day,
        })
    }

    #[must_use]
    pub fn format_mm_dd(self) -> String {
        format!("{:02}-{:02}", self.month, self.day)
    }
}

/// Default local fiscal-year end when the entity has no readable value.
pub const DEFAULT_PROFILE_CALENDAR_FISCAL_YEAR_END: FiscalYearEnd =
    FiscalYearEnd { month: 12, day: 31 };

/// Why a profile-calendar preset cannot produce a local due date.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProfileCalendarUnsupportedReason {
    /// The preset is known, but no local due-date rule is encoded for it.
    MissingLocalDueDateRule,
}

impl ProfileCalendarUnsupportedReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ProfileCalendarUnsupportedReason::MissingLocalDueDateRule => {
                "missing_local_due_date_rule"
            }
        }
    }
}

/// Local due-date rule shape for profile-calendar presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProfileCalendarDueRule {
    /// Due date is a local fiscal-year-end offset.
    FiscalYearEndOffset {
        months_after_fiscal_year_end: u8,
        default_fiscal_year_end: FiscalYearEnd,
    },
    /// The preset has no local due-date rule.
    NotEncoded {
        reason: ProfileCalendarUnsupportedReason,
    },
}

impl ProfileCalendarDueRule {
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            ProfileCalendarDueRule::FiscalYearEndOffset { .. } => "fiscal_year_end_offset",
            ProfileCalendarDueRule::NotEncoded { .. } => "not_encoded",
        }
    }

    #[must_use]
    pub const fn local_due_date_rule_configured(self) -> bool {
        matches!(self, ProfileCalendarDueRule::FiscalYearEndOffset { .. })
    }
}

/// How the fiscal-year input was resolved for a local due-date calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProfileCalendarDueBasis {
    /// The entity had a readable `fiscal_year_end`.
    RecordedFiscalYearEnd,
    /// The entity had no `fiscal_year_end`, so the local default was used.
    DefaultFiscalYearEndMissingRecordedValue,
    /// The entity had an unreadable `fiscal_year_end`, so the local default was used.
    DefaultFiscalYearEndUnreadableRecordedValue,
}

impl ProfileCalendarDueBasis {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ProfileCalendarDueBasis::RecordedFiscalYearEnd => "recorded_fiscal_year_end",
            ProfileCalendarDueBasis::DefaultFiscalYearEndMissingRecordedValue => {
                "default_fiscal_year_end_missing_recorded_value"
            }
            ProfileCalendarDueBasis::DefaultFiscalYearEndUnreadableRecordedValue => {
                "default_fiscal_year_end_unreadable_recorded_value"
            }
        }
    }

    #[must_use]
    pub const fn reason_fragment(self) -> &'static str {
        match self {
            ProfileCalendarDueBasis::RecordedFiscalYearEnd => {
                "using the entity's recorded fiscal_year_end"
            }
            ProfileCalendarDueBasis::DefaultFiscalYearEndMissingRecordedValue => {
                "using the default Dec 31 fiscal-year end because no fiscal_year_end is recorded"
            }
            ProfileCalendarDueBasis::DefaultFiscalYearEndUnreadableRecordedValue => {
                "using the default Dec 31 fiscal-year end because the recorded fiscal_year_end could not be read"
            }
        }
    }
}

/// Inputs the local profile-calendar rule engine needs from the API/storage layer.
#[derive(Debug, Clone, Copy)]
pub struct ProfileCalendarEvaluationContext<'a> {
    pub today: Date,
    pub recorded_fiscal_year_end: Option<&'a str>,
    pub constitution_date: Option<Date>,
}

/// A supported local advisory due-date result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileCalendarScheduledRule {
    pub due_date: Date,
    pub fiscal_year_end: FiscalYearEnd,
    pub months_after_fiscal_year_end: u8,
    pub due_basis: ProfileCalendarDueBasis,
}

/// An unsupported preset surfaced as a no-date advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileCalendarUnsupportedRule {
    pub reason: ProfileCalendarUnsupportedReason,
}

/// A rule suppressed because local context shows no advisory should be emitted yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileCalendarSuppressedRule {
    pub reason: ProfileCalendarSuppressionReason,
}

/// Local suppression reasons for profile-calendar evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileCalendarSuppressionReason {
    /// The dashboard date is still inside the entity's first fiscal year.
    FirstFiscalYear,
    /// The computed local due date is before the first applicable annual due date.
    BeforeFirstApplicableAnnualDue,
}

/// Result of evaluating one profile-calendar rule against local entity context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileCalendarRuleEvaluation {
    Scheduled(ProfileCalendarScheduledRule),
    Unsupported(ProfileCalendarUnsupportedRule),
    Suppressed(ProfileCalendarSuppressedRule),
}

/// A calendar preset seed (ENT-02(e)) plus local advisory profile-calendar rule metadata.
///
/// The metadata is a local planning aid only. It does not claim legal-calendar authority,
/// legal compliance, external delivery/sync, provider effects, DRE verification, or
/// certification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CalendarPreset {
    /// Stable preset id (e.g. `"csc-art376-annual"`).
    pub id: &'static str,
    /// Human label.
    pub label: &'static str,
    /// Months after fiscal-year end by which the meeting must be held, when applicable.
    pub months_after_fiscal_year_end: Option<u8>,
    /// Typed local rule kind.
    pub rule_kind: ProfileCalendarRuleKind,
    /// Whether a local due-date rule is encoded.
    pub support_status: ProfileCalendarRuleSupportStatus,
    /// Local metadata/source review status.
    pub review_status: ProfileCalendarReviewStatus,
    /// Local due-date rule shape.
    pub due_rule: ProfileCalendarDueRule,
    /// Source status for the calendar preset itself.
    pub source_status: ProfileCalendarSourceStatus,
    /// Pending/unverified law references, when a structural reference is encoded.
    pub law_refs: &'static [ProfileCalendarLawReference],
    /// Explicit no-claim guardrails.
    pub no_claims: ProfileCalendarNoClaimFlags,
}

impl CalendarPreset {
    #[must_use]
    pub const fn local_due_date_rule_configured(self) -> bool {
        self.due_rule.local_due_date_rule_configured()
    }
}

/// The typed local advisory profile-calendar plan for one entity kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileCalendarPlan {
    pub family: EntityFamily,
    pub template_family: &'static str,
    pub rules: Vec<CalendarPreset>,
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
            vec![fiscal_year_end_calendar_preset(
                "csc-art376-annual",
                "Assembleia geral anual (CSC art. 376.º)",
                ProfileCalendarRuleKind::CommercialCompanyAnnualGeneralMeeting,
                3,
                &CSC_ART_376_REF,
            )],
        ),
        EntityFamily::Condominium => (
            CondominioRulePack::ID,
            SignaturePolicyHint::QualifiedOrHandwritten,
            "condominio-dl268",
            vec![unsupported_calendar_preset(
                "condominio-annual",
                "Assembleia ordinária anual de condóminos (DL 268/94)",
                ProfileCalendarRuleKind::CondominiumAnnualAssembly,
            )],
        ),
        EntityFamily::Association => (
            AssociacaoRulePack::ID,
            SignaturePolicyHint::ManualAttested,
            "assoc-cc",
            vec![fiscal_year_end_calendar_preset(
                "assoc-annual",
                "Assembleia geral ordinária anual (Código Civil)",
                ProfileCalendarRuleKind::AssociationAnnualGeneralMeeting,
                3,
                &CC_ART_173_REF,
            )],
        ),
        EntityFamily::Foundation => (
            FundacaoRulePack::ID,
            SignaturePolicyHint::ManualAttested,
            "fundacao-cc",
            vec![fiscal_year_end_calendar_preset(
                "fundacao-annual",
                "Reunião anual do conselho de administração (Lei 24/2012)",
                ProfileCalendarRuleKind::FoundationAnnualGovernanceReview,
                3,
                &EMPTY_CALENDAR_REFS,
            )],
        ),
        EntityFamily::Cooperative => (
            CooperativaRulePack::ID,
            SignaturePolicyHint::ManualAttested,
            "cooperativa-ccoop",
            vec![fiscal_year_end_calendar_preset(
                "cooperativa-annual",
                "Assembleia geral anual (Código Cooperativo)",
                ProfileCalendarRuleKind::CooperativeAnnualGeneralMeeting,
                3,
                &COOP_ART_33_REF,
            )],
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

fn fiscal_year_end_calendar_preset(
    id: &'static str,
    label: &'static str,
    rule_kind: ProfileCalendarRuleKind,
    months_after_fiscal_year_end: u8,
    law_refs: &'static [ProfileCalendarLawReference],
) -> CalendarPreset {
    CalendarPreset {
        id,
        label,
        months_after_fiscal_year_end: Some(months_after_fiscal_year_end),
        rule_kind,
        support_status: ProfileCalendarRuleSupportStatus::Supported,
        review_status: ProfileCalendarReviewStatus::PendingSourceReview,
        due_rule: ProfileCalendarDueRule::FiscalYearEndOffset {
            months_after_fiscal_year_end,
            default_fiscal_year_end: DEFAULT_PROFILE_CALENDAR_FISCAL_YEAR_END,
        },
        source_status: ProfileCalendarSourceStatus::PendingUnverified,
        law_refs,
        no_claims: ProfileCalendarNoClaimFlags::local_advisory(),
    }
}

fn unsupported_calendar_preset(
    id: &'static str,
    label: &'static str,
    rule_kind: ProfileCalendarRuleKind,
) -> CalendarPreset {
    CalendarPreset {
        id,
        label,
        months_after_fiscal_year_end: None,
        rule_kind,
        support_status: ProfileCalendarRuleSupportStatus::Unsupported,
        review_status: ProfileCalendarReviewStatus::PendingSourceReview,
        due_rule: ProfileCalendarDueRule::NotEncoded {
            reason: ProfileCalendarUnsupportedReason::MissingLocalDueDateRule,
        },
        source_status: ProfileCalendarSourceStatus::PendingUnverified,
        law_refs: &EMPTY_CALENDAR_REFS,
        no_claims: ProfileCalendarNoClaimFlags::local_advisory(),
    }
}

/// Build the typed local advisory profile-calendar plan for a legal type.
#[must_use]
pub fn profile_calendar_plan_for(kind: EntityKind) -> ProfileCalendarPlan {
    let profile = profile_for(kind);
    ProfileCalendarPlan {
        family: profile.family,
        template_family: profile.template_family,
        rules: profile.calendar_presets,
    }
}

/// Returns whether profile-calendar reminders are locally supported for this legal type.
///
/// Commercial-company calendar metadata is currently limited to SA/Lda-like entities, matching the
/// locally reviewed dashboard behavior. Other families surface their encoded local advisory preset.
#[must_use]
pub fn supports_profile_calendar_plan(kind: EntityKind) -> bool {
    !matches!(kind.family(), EntityFamily::CommercialCompany) || is_sa_or_lda_like(kind)
}

fn is_sa_or_lda_like(kind: EntityKind) -> bool {
    matches!(
        kind,
        EntityKind::SociedadeAnonima
            | EntityKind::SociedadePorQuotas
            | EntityKind::SociedadeUnipessoalPorQuotas
    )
}

/// Evaluate one local advisory profile-calendar rule against entity context.
#[must_use]
pub fn evaluate_profile_calendar_rule(
    rule: &CalendarPreset,
    context: ProfileCalendarEvaluationContext<'_>,
) -> ProfileCalendarRuleEvaluation {
    let ProfileCalendarDueRule::FiscalYearEndOffset {
        months_after_fiscal_year_end,
        default_fiscal_year_end,
    } = rule.due_rule
    else {
        let reason = match rule.due_rule {
            ProfileCalendarDueRule::NotEncoded { reason } => reason,
            ProfileCalendarDueRule::FiscalYearEndOffset { .. } => unreachable!(),
        };
        return ProfileCalendarRuleEvaluation::Unsupported(ProfileCalendarUnsupportedRule {
            reason,
        });
    };

    let parsed_fiscal_year_end = context
        .recorded_fiscal_year_end
        .and_then(FiscalYearEnd::parse);
    let (fiscal_year_end, due_basis) =
        match (context.recorded_fiscal_year_end, parsed_fiscal_year_end) {
            (Some(_), Some(value)) => (value, ProfileCalendarDueBasis::RecordedFiscalYearEnd),
            (Some(_), None) => (
                default_fiscal_year_end,
                ProfileCalendarDueBasis::DefaultFiscalYearEndUnreadableRecordedValue,
            ),
            (None, _) => (
                default_fiscal_year_end,
                ProfileCalendarDueBasis::DefaultFiscalYearEndMissingRecordedValue,
            ),
        };

    if is_in_first_fiscal_year(context.constitution_date, fiscal_year_end, context.today) {
        return ProfileCalendarRuleEvaluation::Suppressed(ProfileCalendarSuppressedRule {
            reason: ProfileCalendarSuppressionReason::FirstFiscalYear,
        });
    }

    let due_date = profile_calendar_due_date_for_year(
        context.today.year(),
        fiscal_year_end,
        months_after_fiscal_year_end,
    );
    if is_before_first_applicable_annual_due(
        context.constitution_date,
        fiscal_year_end,
        months_after_fiscal_year_end,
        due_date,
    ) {
        return ProfileCalendarRuleEvaluation::Suppressed(ProfileCalendarSuppressedRule {
            reason: ProfileCalendarSuppressionReason::BeforeFirstApplicableAnnualDue,
        });
    }

    ProfileCalendarRuleEvaluation::Scheduled(ProfileCalendarScheduledRule {
        due_date,
        fiscal_year_end,
        months_after_fiscal_year_end,
        due_basis,
    })
}

/// Calculate the local fiscal-year-offset due date that falls in `due_year`.
#[must_use]
pub fn profile_calendar_due_date_for_year(
    due_year: i32,
    fiscal_year_end: FiscalYearEnd,
    months_after_fiscal_year_end: u8,
) -> Date {
    for fiscal_year in [due_year, due_year - 1] {
        let due_date = add_months_clamped(
            fiscal_year_end_date(fiscal_year, fiscal_year_end),
            months_after_fiscal_year_end,
        );
        if due_date.year() == due_year {
            return due_date;
        }
    }
    add_months_clamped(
        fiscal_year_end_date(due_year, fiscal_year_end),
        months_after_fiscal_year_end,
    )
}

fn is_before_first_applicable_annual_due(
    constitution_date: Option<Date>,
    fiscal_year_end: FiscalYearEnd,
    months_after_fiscal_year_end: u8,
    due_date: Date,
) -> bool {
    let Some(constitution_date) = constitution_date else {
        // Conservative fallback: without a constitution/incorporation date, keep the local annual
        // dashboard advisory rather than guessing that the entity is still first-year.
        return false;
    };
    due_date
        < first_applicable_annual_due_date(
            constitution_date,
            fiscal_year_end,
            months_after_fiscal_year_end,
        )
}

fn is_in_first_fiscal_year(
    constitution_date: Option<Date>,
    fiscal_year_end: FiscalYearEnd,
    today: Date,
) -> bool {
    let Some(constitution_date) = constitution_date else {
        return false;
    };
    today <= first_fiscal_year_end(constitution_date, fiscal_year_end)
}

fn first_applicable_annual_due_date(
    constitution_date: Date,
    fiscal_year_end: FiscalYearEnd,
    months_after_fiscal_year_end: u8,
) -> Date {
    add_months_clamped(
        first_fiscal_year_end(constitution_date, fiscal_year_end),
        months_after_fiscal_year_end,
    )
}

fn first_fiscal_year_end(constitution_date: Date, fiscal_year_end: FiscalYearEnd) -> Date {
    let constitution_year_end = fiscal_year_end_date(constitution_date.year(), fiscal_year_end);
    if constitution_year_end >= constitution_date {
        constitution_year_end
    } else {
        fiscal_year_end_date(constitution_date.year() + 1, fiscal_year_end)
    }
}

fn fiscal_year_end_date(year: i32, fiscal_year_end: FiscalYearEnd) -> Date {
    let month = Month::try_from(fiscal_year_end.month).expect("validated fiscal year end month");
    let day = fiscal_year_end
        .day
        .min(days_in_month(year, fiscal_year_end.month));
    Date::from_calendar_date(year, month, day).expect("clamped fiscal year end date is valid")
}

fn add_months_clamped(date: Date, months: u8) -> Date {
    let zero_based_month = date.month() as i32 - 1 + i32::from(months);
    let year = date.year() + zero_based_month.div_euclid(12);
    let month = zero_based_month.rem_euclid(12) as u8 + 1;
    let day = date.day().min(days_in_month(year, month));
    Date::from_calendar_date(
        year,
        Month::try_from(month).expect("computed month is valid"),
        day,
    )
    .expect("clamped due date is valid")
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => unreachable!("month has already been validated"),
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
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
            issues.extend(statute_findings_for_entity(act, entity, statute));
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
    use crate::act::{
        Act, AttendanceWeight, Attendee, DeliberationItem, MeetingChannel, PresenceMode,
        SignatoryCapacity, VoteResult,
    };
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
    fn profile_calendar_plan_carries_typed_pending_no_claim_metadata() {
        let plan = profile_calendar_plan_for(EntityKind::SociedadeAnonima);
        let rule = plan
            .rules
            .iter()
            .find(|rule| rule.id == "csc-art376-annual")
            .expect("commercial calendar rule");

        assert_eq!(
            rule.rule_kind,
            ProfileCalendarRuleKind::CommercialCompanyAnnualGeneralMeeting
        );
        assert_eq!(
            rule.support_status,
            ProfileCalendarRuleSupportStatus::Supported
        );
        assert_eq!(
            rule.review_status,
            ProfileCalendarReviewStatus::PendingSourceReview
        );
        assert_eq!(
            rule.source_status,
            ProfileCalendarSourceStatus::PendingUnverified
        );
        assert!(rule.local_due_date_rule_configured());
        assert_eq!(rule.law_refs.len(), 1);
        assert_eq!(rule.law_refs[0].diploma_id, "csc");
        assert_eq!(
            rule.law_refs[0].source_status,
            ProfileCalendarSourceStatus::PendingUnverified
        );
        assert!(rule.no_claims.local_advisory_only);
        assert!(!rule.no_claims.legal_deadline_authority_claimed);
        assert!(!rule.no_claims.legal_calendar_authority_claimed);
        assert!(!rule.no_claims.legal_compliance_claimed);
        assert!(!rule.no_claims.external_delivery_claimed);
        assert!(!rule.no_claims.workflow_completion_claimed);
        assert!(!rule.no_claims.dre_verification_claimed);
        assert!(!rule.no_claims.certification_claimed);
    }

    #[test]
    fn profile_calendar_engine_uses_default_when_fiscal_year_is_missing() {
        let plan = profile_calendar_plan_for(EntityKind::SociedadePorQuotas);
        let rule = &plan.rules[0];

        let evaluation = evaluate_profile_calendar_rule(
            rule,
            ProfileCalendarEvaluationContext {
                today: date!(2026 - 01 - 15),
                recorded_fiscal_year_end: None,
                constitution_date: None,
            },
        );

        let ProfileCalendarRuleEvaluation::Scheduled(scheduled) = evaluation else {
            panic!("expected scheduled local advisory, got {evaluation:?}");
        };
        assert_eq!(scheduled.due_date, date!(2026 - 03 - 31));
        assert_eq!(
            scheduled.due_basis,
            ProfileCalendarDueBasis::DefaultFiscalYearEndMissingRecordedValue
        );
        assert_eq!(
            scheduled.fiscal_year_end,
            DEFAULT_PROFILE_CALENDAR_FISCAL_YEAR_END
        );
    }

    #[test]
    fn profile_calendar_engine_uses_recorded_fiscal_year_end() {
        let plan = profile_calendar_plan_for(EntityKind::SociedadePorQuotas);
        let rule = &plan.rules[0];

        let evaluation = evaluate_profile_calendar_rule(
            rule,
            ProfileCalendarEvaluationContext {
                today: date!(2026 - 07 - 09),
                recorded_fiscal_year_end: Some("08-31"),
                constitution_date: None,
            },
        );

        let ProfileCalendarRuleEvaluation::Scheduled(scheduled) = evaluation else {
            panic!("expected scheduled local advisory, got {evaluation:?}");
        };
        assert_eq!(scheduled.due_date, date!(2026 - 11 - 30));
        assert_eq!(
            scheduled.due_basis,
            ProfileCalendarDueBasis::RecordedFiscalYearEnd
        );
        assert_eq!(scheduled.fiscal_year_end.format_mm_dd(), "08-31");
    }

    #[test]
    fn profile_calendar_engine_suppresses_first_fiscal_year_until_it_ends() {
        let plan = profile_calendar_plan_for(EntityKind::SociedadePorQuotas);
        let rule = &plan.rules[0];

        for today in [date!(2026 - 07 - 09), date!(2026 - 08 - 31)] {
            let evaluation = evaluate_profile_calendar_rule(
                rule,
                ProfileCalendarEvaluationContext {
                    today,
                    recorded_fiscal_year_end: Some("08-31"),
                    constitution_date: Some(date!(2026 - 01 - 10)),
                },
            );

            assert_eq!(
                evaluation,
                ProfileCalendarRuleEvaluation::Suppressed(ProfileCalendarSuppressedRule {
                    reason: ProfileCalendarSuppressionReason::FirstFiscalYear
                })
            );
        }

        let evaluation = evaluate_profile_calendar_rule(
            rule,
            ProfileCalendarEvaluationContext {
                today: date!(2026 - 09 - 01),
                recorded_fiscal_year_end: Some("08-31"),
                constitution_date: Some(date!(2026 - 01 - 10)),
            },
        );
        assert!(matches!(
            evaluation,
            ProfileCalendarRuleEvaluation::Scheduled(ProfileCalendarScheduledRule {
                due_date,
                ..
            }) if due_date == date!(2026 - 11 - 30)
        ));
    }

    #[test]
    fn unsupported_profile_calendar_rule_surfaces_without_due_date() {
        let plan = profile_calendar_plan_for(EntityKind::Condominio);
        let rule = &plan.rules[0];

        assert_eq!(
            rule.support_status,
            ProfileCalendarRuleSupportStatus::Unsupported
        );
        assert_eq!(rule.months_after_fiscal_year_end, None);
        assert_eq!(
            evaluate_profile_calendar_rule(
                rule,
                ProfileCalendarEvaluationContext {
                    today: date!(2026 - 01 - 15),
                    recorded_fiscal_year_end: None,
                    constitution_date: None,
                },
            ),
            ProfileCalendarRuleEvaluation::Unsupported(ProfileCalendarUnsupportedRule {
                reason: ProfileCalendarUnsupportedReason::MissingLocalDueDateRule
            })
        );
    }

    #[test]
    fn leap_day_fiscal_year_end_is_clamped_deterministically() {
        let fiscal_year_end = FiscalYearEnd { month: 2, day: 29 };

        assert_eq!(
            profile_calendar_due_date_for_year(2024, fiscal_year_end, 3),
            date!(2024 - 05 - 29)
        );
        assert_eq!(
            profile_calendar_due_date_for_year(2025, fiscal_year_end, 3),
            date!(2025 - 05 - 28)
        );
    }

    #[test]
    fn profile_calendar_plan_is_limited_to_reviewed_commercial_shapes() {
        assert!(supports_profile_calendar_plan(EntityKind::SociedadeAnonima));
        assert!(supports_profile_calendar_plan(
            EntityKind::SociedadePorQuotas
        ));
        assert!(!supports_profile_calendar_plan(
            EntityKind::SociedadeEmNomeColetivo
        ));
        assert!(supports_profile_calendar_plan(EntityKind::Associacao));
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
    fn statute_majority_counts_abstentions_in_the_recorded_denominator() {
        let mut e = entity(EntityKind::Associacao);
        e.statute = Some(StatuteOverrides {
            majority: Some(Majority {
                numerator: 2,
                denominator: 3,
            }),
            ..Default::default()
        });
        let mut act = structured_act(VoteResult::Recorded {
            em_favor: 6,
            contra: 2,
            abstencoes: 2,
        });

        let issues = rule_pack_for(&e).check_act(&act, &e);
        assert!(
            issues.iter().any(|i| i.rule_id == "STATUTE/majority"),
            "6/10 including abstentions should miss a 2/3 configured majority: {issues:?}"
        );

        act.deliberation_items[0].vote = Some(VoteResult::Recorded {
            em_favor: 6,
            contra: 2,
            abstencoes: 0,
        });
        let issues = rule_pack_for(&e).check_act(&act, &e);
        assert!(
            !issues.iter().any(|i| i.rule_id == "STATUTE/majority"),
            "6/8 should satisfy the configured 2/3 majority: {issues:?}"
        );
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
    fn statute_quorum_uses_complete_permilage_attendance_for_condo() {
        let mut e = entity(EntityKind::Condominio);
        e.statute = Some(StatuteOverrides {
            quorum: Some(Quorum { min_present: 501 }),
            ..Default::default()
        });
        let mut act = structured_act(VoteResult::Unanimous);
        act.attendees = vec![
            Attendee {
                name: "Fração A".into(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::InPerson,
                represented_by: None,
                weight: Some(AttendanceWeight::Permilage(300)),
            },
            Attendee {
                name: "Fração B".into(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::Represented,
                represented_by: Some("Fração A".into()),
                weight: Some(AttendanceWeight::Permilage(200)),
            },
        ];

        let issues = rule_pack_for(&e).check_act(&act, &e);
        let issue = issues
            .iter()
            .find(|i| i.rule_id == "STATUTE/quorum")
            .expect("500 permilage should miss a configured 501 quorum");
        assert!(
            issue.message.contains("permilagem"),
            "weighted quorum message should identify the unit: {issue:?}"
        );

        if let Some(AttendanceWeight::Permilage(value)) = &mut act.attendees[1].weight {
            *value = 201;
        }
        let issues = rule_pack_for(&e).check_act(&act, &e);
        assert!(
            !issues
                .iter()
                .any(|i| i.rule_id.starts_with("STATUTE/quorum")),
            "501 permilage should satisfy the configured quorum: {issues:?}"
        );
    }

    #[test]
    fn statute_quorum_falls_back_to_unweighted_attendance_when_no_weights_exist() {
        let mut e = entity(EntityKind::Condominio);
        e.statute = Some(StatuteOverrides {
            quorum: Some(Quorum { min_present: 3 }),
            ..Default::default()
        });
        let mut act = structured_act(VoteResult::Unanimous);
        act.attendees = vec![
            Attendee {
                name: "Fração A".into(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::InPerson,
                represented_by: None,
                weight: None,
            },
            Attendee {
                name: "Fração B".into(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::Represented,
                represented_by: Some("Fração A".into()),
                weight: None,
            },
        ];

        let issues = rule_pack_for(&e).check_act(&act, &e);
        assert!(issues.iter().any(|i| i.rule_id == "STATUTE/quorum"));
        assert!(
            !issues.iter().any(|i| i.rule_id.contains("weight")),
            "no weight metadata should keep the unweighted fallback path: {issues:?}"
        );

        act.attendees.push(Attendee {
            name: "Fração C".into(),
            quality: SignatoryCapacity::CondoOwner,
            presence: PresenceMode::InPerson,
            represented_by: None,
            weight: None,
        });
        let issues = rule_pack_for(&e).check_act(&act, &e);
        assert!(
            !issues
                .iter()
                .any(|i| i.rule_id.starts_with("STATUTE/quorum")),
            "three unweighted attendee rows should satisfy the configured count quorum: {issues:?}"
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
