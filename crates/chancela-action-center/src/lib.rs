use std::collections::{BTreeMap, HashMap};

use chancela_authz::Permission;
use chancela_core::{
    Act, ActId, ActState, Book, BookId, BookKind, BookState, CalendarPreset, Entity, EntityFamily,
    EntityId, EntityKind, ProfileCalendarDueRule, ProfileCalendarEvaluationContext,
    ProfileCalendarNoClaimFlags, ProfileCalendarPlan, ProfileCalendarRuleEvaluation,
    ProfileCalendarScheduledRule, ProfileCalendarUnsupportedRule, Severity,
    evaluate_profile_calendar_rule, profile_calendar_plan_for, profile_for, rule_pack_for,
    supports_profile_calendar_plan,
};
use chancela_law::{LawCatalog, Verification};
use chancela_registry::RegistryExtract;
use chancela_store::{
    StoredDocument, StoredFollowUp, StoredFollowUpStatus, StoredGeneratedDocumentDispatchEvidence,
    StoredImportedDocumentMeta, StoredImportedDocumentReviewStatus,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime};

mod documents;
mod privacy;
mod workflow;

pub use privacy::{
    BreachPlaybookId, BreachPlaybookRecord, DpiaRecord, DpiaRecordId, PrivacyAdvisoryReviewStatus,
    PrivacyRecordStatus, TransferControlId, TransferControlRecord,
};
use privacy::{
    breach_playbook_advisory_review, dpia_advisory_review, transfer_control_advisory_review,
};
pub use workflow::{WorkflowReminderSettings, WorkflowReminderSourceSettings};

const REGISTRY_EXPIRY_WARNING_DAYS: i32 = 30;

fn format_date(date: Date) -> String {
    let format = time::macros::format_description!("[year]-[month]-[day]");
    date.format(&format).unwrap_or_default()
}

pub const DEFAULT_BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS: u16 = 90;
pub const DEFAULT_BACKUP_RECOVERY_TARGET_RPO_MINUTES: u32 = 24 * 60;
pub const DEFAULT_BACKUP_RECOVERY_TARGET_RTO_MINUTES: u32 = 4 * 60;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(default)]
pub struct BackupRecoveryPolicySettings {
    pub max_drill_age_days: u16,
    pub target_rpo_minutes: u32,
    pub target_rto_minutes: u32,
}

impl Default for BackupRecoveryPolicySettings {
    fn default() -> Self {
        Self {
            max_drill_age_days: DEFAULT_BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS,
            target_rpo_minutes: DEFAULT_BACKUP_RECOVERY_TARGET_RPO_MINUTES,
            target_rto_minutes: DEFAULT_BACKUP_RECOVERY_TARGET_RTO_MINUTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupRecoveryFreshnessStatus {
    NoReceipt,
    Fresh,
    Stale,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackupRecoveryFreshnessReview {
    pub generated_at: String,
    pub policy: BackupRecoveryPolicySettings,
    pub status: BackupRecoveryFreshnessStatus,
    pub latest_receipt_id: Option<String>,
    pub latest_receipt_at: Option<String>,
    pub latest_receipt_age_days: Option<u32>,
    pub latest_receipt_preflight_ready: Option<bool>,
    pub latest_receipt_isolated_restore_verified: Option<bool>,
    pub restore_performed: bool,
    pub db_swap_performed: bool,
    pub offsite_custody_verified: bool,
    pub rpo_rto_certified: bool,
    pub production_backup_policy_certified: bool,
}

fn compute_expired(valid_until: Option<&str>, today: Date) -> Option<bool> {
    Some(parse_dashboard_date(valid_until?)? < today)
}

/// One actionable dashboard alert. Alerts are routing/review signals only: `label` is intentionally
/// limited to advisory/review-required and messages avoid unsupported legal conclusions.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardAlert {
    pub code: String,
    pub label: String,
    pub severity: String,
    pub category: String,
    pub message: String,
    pub params: BTreeMap<String, String>,
    pub target: DashboardAlertTarget,
    pub source: Option<String>,
    pub law_refs: Vec<DashboardLawReference>,
    pub action: Option<DashboardAction>,
    pub recommended_next_steps: Vec<String>,
    pub i18n: Option<DashboardI18n>,
}

/// Safe target ids for a dashboard alert.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardAlertTarget {
    pub entity_id: Option<String>,
    pub book_id: Option<String>,
    pub act_id: Option<String>,
    pub links: DashboardTargetLinks,
}

/// API links a client can follow for the target, when such a target exists.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardTargetLinks {
    pub entity: Option<String>,
    pub book: Option<String>,
    pub act: Option<String>,
    pub ledger: Option<String>,
}

/// One law-corpus article reference attached to a dashboard actionable.
///
/// `verification` carries the corpus authenticity tier on the wire as `"Verified"` /
/// `"automated_review"` / `"Pending"` (the [`chancela_law::Verification`] serde value). An
/// `"automated_review"` reference is authentic vendored text reviewed by an automated process but
/// **not** human-legally-approved; `review_method` (e.g. `"automated-capture"`) and `review_note`
/// (the standing pt-PT caveat) are populated for that tier so the client can badge it honestly and
/// show the caveat tooltip. Both are `null` for `Verified`/`Pending`/`Missing` references.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardLawReference {
    pub diploma_id: String,
    pub article: String,
    pub label: String,
    pub heading: String,
    pub verification: String,
    pub source_url: Option<String>,
    pub source_complete: bool,
    pub review_method: Option<String>,
    pub review_note: Option<String>,
}

/// Client-facing action metadata for dashboard actionables.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardAction {
    pub kind: String,
    pub label_key: String,
    pub api_href: Option<String>,
    pub route: Option<String>,
}

/// Translation keys for user-facing dashboard actionable text.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardI18n {
    pub title_key: String,
    pub body_key: String,
    pub action_key: Option<String>,
}

/// One bounded dashboard reminder/action item. These are advisory planning signals, not compliance
/// gates; `source_rule` is the calendar/rule seed and `source_profile` is the entity profile facet
/// that produced it.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardReminder {
    pub due_date: String,
    pub severity: String,
    pub status: String,
    pub reason: String,
    pub entity_id: String,
    pub entity_name: String,
    pub source_rule: String,
    pub source_profile: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_calendar_plan: Option<DashboardProfileCalendarPlan>,
    pub law_refs: Vec<DashboardLawReference>,
    pub action: Option<DashboardAction>,
    pub recommended_next_steps: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i18n: Option<DashboardI18n>,
}

/// Typed local advisory profile-calendar metadata attached to profile-calendar reminders.
///
/// This is a local plan surface only. It does not assert legal-calendar authority, legal
/// compliance, source completeness, external delivery/sync, provider effects, or certification.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardProfileCalendarPlan {
    pub preset_id: String,
    pub preset_label: String,
    pub rule_kind: String,
    pub support_status: String,
    pub review_status: String,
    pub source_status: String,
    pub due_rule: DashboardProfileCalendarDueRule,
    pub evaluation: DashboardProfileCalendarEvaluation,
    pub no_claims: DashboardProfileCalendarNoClaimFlags,
}

/// The local due-rule shape for a profile-calendar reminder.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardProfileCalendarDueRule {
    pub kind: String,
    pub months_after_fiscal_year_end: Option<u8>,
    pub default_fiscal_year_end: Option<String>,
    pub annual_fixed_month: Option<u8>,
    pub annual_fixed_day: Option<u8>,
    pub unsupported_reason: Option<String>,
}

/// The local evaluation result rendered on the reminder.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardProfileCalendarEvaluation {
    pub local_due_date_rule_configured: bool,
    pub local_due_date_calculated: bool,
    pub legal_deadline_calculated: bool,
    pub fiscal_year_end: Option<String>,
    pub due_year: Option<i32>,
    pub due_basis: Option<String>,
    pub unsupported_reason: Option<String>,
}

/// Explicit no-claim flags for profile-calendar output.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DashboardProfileCalendarNoClaimFlags {
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
#[derive(Clone, Serialize)]
pub struct DashboardSearchActionable {
    pub id: String,
    pub title: String,
    pub body: String,
    pub status: String,
    pub due_date: Option<String>,
    pub entity_id: Option<String>,
    pub book_id: Option<String>,
    pub act_id: Option<String>,
    pub required_permission: Permission,
}

fn stable_search_actionable_id<T: Serialize>(
    prefix: &str,
    semantic_identity: &T,
) -> Result<String, serde_json::Error> {
    let canonical = serde_json::to_vec(semantic_identity)?;
    let digest: [u8; 32] = Sha256::digest(canonical).into();
    Ok(format!("{prefix}:{}", hex(&digest)))
}

pub fn search_actionables_from_rows(
    mut alerts: Vec<DashboardAlert>,
    mut reminders: Vec<DashboardReminder>,
) -> Result<Vec<DashboardSearchActionable>, serde_json::Error> {
    sort_dashboard_alerts(&mut alerts);
    sort_dashboard_reminders(&mut reminders);
    let mut out = Vec::with_capacity(alerts.len() + reminders.len());
    for alert in alerts {
        let required_permission = if alert.category == "LedgerIntegrity" {
            Permission::LedgerRead
        } else if alert.code.starts_with("backup.") {
            Permission::DataBackup
        } else if alert.target.act_id.is_some() {
            Permission::ActRead
        } else if alert.target.book_id.is_some() {
            Permission::BookRead
        } else if alert.target.entity_id.is_some() {
            Permission::EntityRead
        } else {
            Permission::ActRead
        };
        let body = if matches!(
            required_permission,
            Permission::ActRead | Permission::BookRead | Permission::EntityRead
        ) {
            serde_json::to_string(&serde_json::json!({
                "code": &alert.code,
                "label": &alert.label,
                "severity": &alert.severity,
                "category": &alert.category,
                "source": &alert.source,
                "law_refs": &alert.law_refs,
                "action": &alert.action,
                "i18n": &alert.i18n,
            }))?
        } else {
            serde_json::to_string(&alert)?
        };
        let id = stable_search_actionable_id(
            "alert",
            &(
                &alert.code,
                &alert.target.entity_id,
                &alert.target.book_id,
                &alert.target.act_id,
                &alert.params,
                &alert.source,
            ),
        )?;
        out.push(DashboardSearchActionable {
            id,
            title: alert.code.clone(),
            body,
            status: alert.severity.clone(),
            due_date: None,
            entity_id: alert.target.entity_id.clone(),
            book_id: alert.target.book_id.clone(),
            act_id: alert.target.act_id.clone(),
            required_permission,
        });
    }
    for reminder in reminders {
        let act_id = reminder.params.get("act_id").cloned();
        let book_id = reminder.params.get("book_id").cloned();
        let required_permission = if reminder.source_rule.starts_with("privacy.")
            || reminder.source_rule.contains("dpia")
            || reminder.source_rule.contains("breach")
            || reminder.source_rule.contains("transfer")
        {
            Permission::PrivacyManage
        } else {
            Permission::ActRead
        };
        let (title, body) = if required_permission == Permission::ActRead {
            (
                reminder.source_rule.clone(),
                serde_json::to_string(&serde_json::json!({
                    "due_date": &reminder.due_date,
                    "severity": &reminder.severity,
                    "status": &reminder.status,
                    "source_rule": &reminder.source_rule,
                    "source_profile": &reminder.source_profile,
                    "law_refs": &reminder.law_refs,
                    "action": &reminder.action,
                    "i18n": &reminder.i18n,
                }))?,
            )
        } else {
            (reminder.reason.clone(), serde_json::to_string(&reminder)?)
        };
        let id = stable_search_actionable_id(
            "reminder",
            &(
                &reminder.source_rule,
                &reminder.source_profile,
                &reminder.entity_id,
                &reminder.due_date,
                &reminder.params,
            ),
        )?;
        out.push(DashboardSearchActionable {
            id,
            title,
            body,
            status: reminder.status.clone(),
            due_date: Some(reminder.due_date.clone()),
            entity_id: Some(reminder.entity_id.clone()),
            book_id,
            act_id,
            required_permission,
        });
    }
    Ok(out)
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub fn sort_dashboard_alerts(alerts: &mut [DashboardAlert]) {
    alerts.sort_by(|a, b| {
        a.label
            .cmp(&b.label)
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.code.cmp(&b.code))
            .then_with(|| a.target.entity_id.cmp(&b.target.entity_id))
            .then_with(|| a.target.book_id.cmp(&b.target.book_id))
            .then_with(|| a.target.act_id.cmp(&b.target.act_id))
            .then_with(|| a.params.cmp(&b.params))
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.severity.cmp(&b.severity))
            .then_with(|| a.message.cmp(&b.message))
            .then_with(|| canonical_dashboard_sort_key(a).cmp(&canonical_dashboard_sort_key(b)))
    });
}

fn canonical_dashboard_sort_key<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).expect("dashboard DTO serialization is infallible")
}

pub fn sort_dashboard_reminders(reminders: &mut [DashboardReminder]) {
    reminders.sort_by(|a, b| {
        dashboard_reminder_due_date_sort_key(a)
            .cmp(&dashboard_reminder_due_date_sort_key(b))
            .then_with(|| a.entity_name.cmp(&b.entity_name))
            .then_with(|| a.entity_id.cmp(&b.entity_id))
            .then_with(|| a.source_profile.cmp(&b.source_profile))
            .then_with(|| a.source_rule.cmp(&b.source_rule))
            .then_with(|| a.params.cmp(&b.params))
            .then_with(|| a.status.cmp(&b.status))
            .then_with(|| a.severity.cmp(&b.severity))
            .then_with(|| a.reason.cmp(&b.reason))
            .then_with(|| canonical_dashboard_sort_key(a).cmp(&canonical_dashboard_sort_key(b)))
    });
}
pub fn parse_dashboard_date(value: &str) -> Option<Date> {
    let (year, rest) = value.split_once('-')?;
    let (month, day) = rest.split_once('-')?;
    let year = year.parse::<i32>().ok()?;
    let month = Month::try_from(month.parse::<u8>().ok()?).ok()?;
    let day = day.parse::<u8>().ok()?;
    Date::from_calendar_date(year, month, day).ok()
}

fn dashboard_reminder_due_date_sort_key(reminder: &DashboardReminder) -> (bool, Option<Date>) {
    let due_date = parse_dashboard_date(reminder.due_date.trim());
    (due_date.is_none(), due_date)
}
pub fn dashboard_alerts(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    registry_extracts: &HashMap<EntityId, RegistryExtract>,
    ledger_valid: bool,
    today: Date,
) -> Vec<DashboardAlert> {
    let mut alerts = Vec::new();

    if !ledger_valid {
        alerts.push(DashboardAlert {
            code: "ledger.integrity.review_required".to_owned(),
            label: "ReviewRequired".to_owned(),
            severity: "Error".to_owned(),
            category: "LedgerIntegrity".to_owned(),
            message: "The dashboard could not verify the ledger chain. Review the ledger integrity report before relying on the audit trail.".to_owned(),
            params: dashboard_alert_params([]),
            target: DashboardAlertTarget {
                entity_id: None,
                book_id: None,
                act_id: None,
                links: DashboardTargetLinks {
                    entity: None,
                    book: None,
                    act: None,
                    ledger: Some("/v1/ledger/integrity".to_owned()),
                },
            },
            source: Some("ledger.verify".to_owned()),
            law_refs: Vec::new(),
            action: Some(dashboard_action(
                "open_ledger",
                "notifications.alert.ledger.integrity.action",
                Some("/v1/ledger/integrity".to_owned()),
                Some("/arquivo".to_owned()),
            )),
            recommended_next_steps: vec![
                "Open the ledger integrity report.".to_owned(),
                "Resolve or re-anchor chain breaks before relying on archive evidence.".to_owned(),
            ],
            i18n: Some(alert_i18n(
                "notifications.alert.ledger.integrity.title",
                "notifications.alert.ledger.integrity.body",
                Some("notifications.alert.ledger.integrity.action"),
            )),
        });
    }

    push_lifecycle_alerts(&mut alerts, entities, books, acts, registry_extracts);

    for act in acts.values() {
        if act.state != ActState::Signing {
            continue;
        }
        let Some(book) = books.get(&act.book_id) else {
            continue;
        };
        let Some(entity) = entities.get(&book.entity_id) else {
            continue;
        };
        let pack = rule_pack_for(entity);
        let has_error = pack
            .check_act(act, entity)
            .iter()
            .any(|issue| issue.severity == Severity::Error);
        if has_error {
            alerts.push(DashboardAlert {
                code: "act.compliance.review_required".to_owned(),
                label: "ReviewRequired".to_owned(),
                severity: "Warning".to_owned(),
                category: "Compliance".to_owned(),
                message: format!(
                    "Act {} is in Signing and has review-required compliance findings. Review the compliance report before sealing.",
                    act.id
                ),
                params: dashboard_alert_params([
                    ("act_id", act.id.to_string()),
                    ("book_id", book.id.to_string()),
                    ("entity_id", entity.id.to_string()),
                    ("rule_pack", pack.id().to_owned()),
                ]),
                target: DashboardAlertTarget {
                    entity_id: Some(entity.id.to_string()),
                    book_id: Some(book.id.to_string()),
                    act_id: Some(act.id.to_string()),
                    links: target_links(Some(entity.id), Some(book.id), Some(act.id)),
                },
                source: Some(pack.id().to_owned()),
                law_refs: Vec::new(),
                action: Some(dashboard_action(
                    "open_act",
                    "notifications.alert.act.compliance.action",
                    Some(format!("/v1/acts/{}", act.id)),
                    Some(format!("/atas/{}", act.id)),
                )),
                recommended_next_steps: vec![
                    "Open the minutes compliance report.".to_owned(),
                    "Resolve review-required findings before sealing.".to_owned(),
                ],
                i18n: Some(alert_i18n(
                    "notifications.alert.act.compliance.title",
                    "notifications.alert.act.compliance.body",
                    Some("notifications.alert.act.compliance.action"),
                )),
            });
        } else {
            alerts.push(DashboardAlert {
                code: "act.lifecycle.signing_ready".to_owned(),
                label: "Advisory".to_owned(),
                severity: "Info".to_owned(),
                category: "ActLifecycle".to_owned(),
                message: format!(
                    "Act {} is in Signing and has no review-required compliance findings from rule pack {}. Collect or import the required signatures and seal when ready.",
                    act.id,
                    pack.id()
                ),
                params: dashboard_alert_params([
                    ("act_id", act.id.to_string()),
                    ("book_id", book.id.to_string()),
                    ("entity_id", entity.id.to_string()),
                    ("current_state", format!("{:?}", act.state)),
                    ("rule_pack", pack.id().to_owned()),
                ]),
                target: DashboardAlertTarget {
                    entity_id: Some(entity.id.to_string()),
                    book_id: Some(book.id.to_string()),
                    act_id: Some(act.id.to_string()),
                    links: target_links(Some(entity.id), Some(book.id), Some(act.id)),
                },
                source: Some("acts.state".to_owned()),
                law_refs: Vec::new(),
                action: Some(dashboard_action(
                    "open_act",
                    "notifications.alert.act.signingReady.action",
                    Some(format!("/v1/acts/{}", act.id)),
                    Some(format!("/atas/{}", act.id)),
                )),
                recommended_next_steps: vec![
                    "Collect or import required signatures.".to_owned(),
                    "Seal the minutes when the signing record is complete.".to_owned(),
                ],
                i18n: Some(alert_i18n(
                    "notifications.alert.act.signingReady.title",
                    "notifications.alert.act.signingReady.body",
                    Some("notifications.alert.act.signingReady.action"),
                )),
            });
        }
    }

    for (entity_id, extract) in registry_extracts {
        let Some(valid_until) = extract.provenance.valid_until.as_deref() else {
            continue;
        };
        let Some(valid_until_date) = parse_dashboard_date(valid_until) else {
            continue;
        };
        let days_until = valid_until_date.to_julian_day() - today.to_julian_day();
        let (code, label, message) = if compute_expired(Some(valid_until), today) == Some(true) {
            (
                "registry.provenance.expired",
                "Advisory",
                format!(
                    "Stored registry extract provenance has valid_until {valid_until}, which is before today. Review the registry extract before using it as current evidence."
                ),
            )
        } else if days_until <= REGISTRY_EXPIRY_WARNING_DAYS {
            let timing = match days_until {
                0 => "today".to_owned(),
                1 => "in 1 day".to_owned(),
                n => format!("in {n} days"),
            };
            (
                "registry.provenance.expiring_soon",
                "Advisory",
                format!(
                    "Stored registry extract provenance has valid_until {valid_until}, which expires {timing}. Plan a registry refresh before relying on it as current evidence."
                ),
            )
        } else {
            continue;
        };
        alerts.push(DashboardAlert {
            code: code.to_owned(),
            label: label.to_owned(),
            severity: "Info".to_owned(),
            category: "RegistryProvenance".to_owned(),
            message,
            params: dashboard_alert_params([
                ("entity_id", entity_id.to_string()),
                ("valid_until", valid_until.to_owned()),
                ("days_until", days_until.to_string()),
            ]),
            target: DashboardAlertTarget {
                entity_id: Some(entity_id.to_string()),
                book_id: None,
                act_id: None,
                links: target_links(Some(*entity_id), None, None),
            },
            source: Some("registry_extracts.provenance.valid_until".to_owned()),
            law_refs: Vec::new(),
            action: Some(dashboard_action(
                "open_entity",
                if code == "registry.provenance.expired" {
                    "notifications.alert.registry.expired.action"
                } else {
                    "notifications.alert.registry.expiringSoon.action"
                },
                Some(format!("/v1/entities/{entity_id}")),
                Some(format!("/entidades/{entity_id}")),
            )),
            recommended_next_steps: vec![
                "Open the entity registry evidence.".to_owned(),
                "Refresh the permanent certificate before using it as current evidence.".to_owned(),
            ],
            i18n: Some(if code == "registry.provenance.expired" {
                alert_i18n(
                    "notifications.alert.registry.expired.title",
                    "notifications.alert.registry.expired.body",
                    Some("notifications.alert.registry.expired.action"),
                )
            } else {
                alert_i18n(
                    "notifications.alert.registry.expiringSoon.title",
                    "notifications.alert.registry.expiringSoon.body",
                    Some("notifications.alert.registry.expiringSoon.action"),
                )
            }),
        });
    }

    sort_dashboard_alerts(&mut alerts);
    alerts
}

pub fn backup_recovery_freshness_alert(
    freshness: &BackupRecoveryFreshnessReview,
) -> Option<DashboardAlert> {
    let status = backup_recovery_freshness_status_value(&freshness.status);
    if matches!(freshness.status, BackupRecoveryFreshnessStatus::Fresh) {
        return None;
    }

    let latest_receipt_at = freshness
        .latest_receipt_at
        .clone()
        .unwrap_or_else(|| "not_recorded".to_owned());
    let latest_receipt_age_days = freshness
        .latest_receipt_age_days
        .map(|days| days.to_string())
        .unwrap_or_else(|| "not_recorded".to_owned());
    let latest_receipt_preflight_ready =
        optional_bool_param(freshness.latest_receipt_preflight_ready);
    let latest_receipt_isolated_restore_verified =
        optional_bool_param(freshness.latest_receipt_isolated_restore_verified);

    Some(DashboardAlert {
        code: "backup.recovery.freshness_advisory".to_owned(),
        label: "Advisory".to_owned(),
        severity: "Warning".to_owned(),
        category: "BackupRecoveryFreshness".to_owned(),
        message: format!(
            "Local backup recovery drill freshness is {status}; policy max age is {} days, latest receipt date is {latest_receipt_at}, latest receipt age is {latest_receipt_age_days} days, preflight readiness is {latest_receipt_preflight_ready}, and isolated snapshot verification is {latest_receipt_isolated_restore_verified}. This is a local advisory from stored recovery-drill receipts only; it does not run recovery, inspect archives, restore data, or certify production readiness.",
            freshness.policy.max_drill_age_days
        ),
        params: dashboard_alert_params([
            ("freshness_status", status.to_owned()),
            (
                "policy_max_drill_age_days",
                freshness.policy.max_drill_age_days.to_string(),
            ),
            ("latest_receipt_at", latest_receipt_at),
            ("latest_receipt_age_days", latest_receipt_age_days),
            (
                "latest_receipt_preflight_ready",
                latest_receipt_preflight_ready,
            ),
            (
                "latest_receipt_isolated_restore_verified",
                latest_receipt_isolated_restore_verified,
            ),
        ]),
        target: DashboardAlertTarget {
            entity_id: None,
            book_id: None,
            act_id: None,
            links: DashboardTargetLinks {
                entity: None,
                book: None,
                act: None,
                ledger: None,
            },
        },
        source: Some("backup_recovery.freshness".to_owned()),
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_backup_recovery_policy",
            "notifications.alert.backupRecoveryFreshness.action",
            None,
            Some("/configuracoes?sec=dados".to_owned()),
        )),
        recommended_next_steps: vec![
            "Review the local recovery-drill receipt freshness state in Data Management."
                .to_owned(),
            "Record a new non-destructive recovery drill only when operator evidence exists."
                .to_owned(),
        ],
        i18n: Some(alert_i18n(
            "notifications.alert.backupRecoveryFreshness.title",
            "notifications.alert.backupRecoveryFreshness.body",
            Some("notifications.alert.backupRecoveryFreshness.action"),
        )),
    })
}

fn backup_recovery_freshness_status_value(status: &BackupRecoveryFreshnessStatus) -> &'static str {
    match status {
        BackupRecoveryFreshnessStatus::NoReceipt => "no_receipt",
        BackupRecoveryFreshnessStatus::Fresh => "fresh",
        BackupRecoveryFreshnessStatus::Stale => "stale",
        BackupRecoveryFreshnessStatus::Failed => "failed",
    }
}

fn optional_bool_param(value: Option<bool>) -> String {
    value.unwrap_or(false).to_string()
}

fn push_lifecycle_alerts(
    alerts: &mut Vec<DashboardAlert>,
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    registry_extracts: &HashMap<EntityId, RegistryExtract>,
) {
    for entity in entities.values() {
        let total_books = books
            .values()
            .filter(|book| book.entity_id == entity.id)
            .count();
        let open_books = books
            .values()
            .filter(|book| book.entity_id == entity.id && book.state == BookState::Open)
            .count();
        if open_books == 0 {
            alerts.push(DashboardAlert {
                code: "entity.book.no_open_book".to_owned(),
                label: "Advisory".to_owned(),
                severity: "Info".to_owned(),
                category: "BookLifecycle".to_owned(),
                message: format!(
                    "Entity {} has no open book recorded. Open a book or import an existing book before drafting new atas.",
                    entity.name
                ),
                params: dashboard_alert_params([
                    ("entity_id", entity.id.to_string()),
                    ("entity_name", entity.name.clone()),
                    ("total_books", total_books.to_string()),
                    ("open_books", open_books.to_string()),
                    ("recommended_actions", "open_book,import_book".to_owned()),
                ]),
                target: DashboardAlertTarget {
                    entity_id: Some(entity.id.to_string()),
                    book_id: None,
                    act_id: None,
                    links: target_links(Some(entity.id), None, None),
                },
                source: Some("entities.books".to_owned()),
                law_refs: law_refs(&[("dl-76-a-2006", "1"), ("dl-76-a-2006", "2")]),
                action: Some(dashboard_action(
                    "open_entity",
                    "notifications.alert.entity.noOpenBook.action",
                    Some(format!("/v1/entities/{}", entity.id)),
                    Some(format!("/entidades/{}", entity.id)),
                )),
                recommended_next_steps: vec![
                    "Open a new digital book for the relevant organ.".to_owned(),
                    "Import an existing paper or external book if the entity already has one.".to_owned(),
                ],
                i18n: Some(alert_i18n(
                    "notifications.alert.entity.noOpenBook.title",
                    "notifications.alert.entity.noOpenBook.body",
                    Some("notifications.alert.entity.noOpenBook.action"),
                )),
            });
        }

        if should_prompt_manager_remuneration(
            entity,
            acts,
            books,
            registry_extracts.get(&entity.id),
        ) {
            let remuneration = remuneration_alert_profile(entity.kind);
            alerts.push(DashboardAlert {
                code: remuneration.code.to_owned(),
                label: "Advisory".to_owned(),
                severity: "Info".to_owned(),
                category: "GovernanceSetup".to_owned(),
                message: format!(
                    "Entity {} has {} officers in the imported registry evidence, but no sealed remuneration or non-remuneration minutes are recorded. Record the remuneration setup when appropriate.",
                    entity.name, remuneration.officer_label
                ),
                params: dashboard_alert_params([
                    ("entity_id", entity.id.to_string()),
                    ("entity_name", entity.name.clone()),
                    ("office", remuneration.officer_label.to_owned()),
                    ("recommended_actions", "record_remuneration,record_non_remuneration".to_owned()),
                ]),
                target: DashboardAlertTarget {
                    entity_id: Some(entity.id.to_string()),
                    book_id: None,
                    act_id: None,
                    links: target_links(Some(entity.id), None, None),
                },
                source: Some("registry_extracts.orgaos".to_owned()),
                law_refs: law_refs(&[("csc", remuneration.article)]),
                action: Some(dashboard_action(
                    "open_entity",
                    remuneration.action_key,
                    Some(format!("/v1/entities/{}", entity.id)),
                    Some(format!("/entidades/{}", entity.id)),
                )),
                recommended_next_steps: vec![
                    "Review the registry officers and statutes.".to_owned(),
                    "Draft minutes for remuneration or explicit non-remuneration if required.".to_owned(),
                ],
                i18n: Some(alert_i18n(
                    remuneration.title_key,
                    remuneration.body_key,
                    Some(remuneration.action_key),
                )),
            });
        }
    }

    for book in books.values().filter(|book| book.state == BookState::Open) {
        let missing_fields = termo_abertura_missing_fields(book);
        if !missing_fields.is_empty() {
            alerts.push(DashboardAlert {
                code: "book.termo_abertura.missing_metadata".to_owned(),
                label: "ReviewRequired".to_owned(),
                severity: "Warning".to_owned(),
                category: "BookLifecycle".to_owned(),
                message: format!(
                    "Open book {} is missing termo de abertura metadata or signatories. Review the book opening record before relying on it as complete evidence.",
                    book.id
                ),
                params: dashboard_alert_params([
                    ("book_id", book.id.to_string()),
                    ("entity_id", book.entity_id.to_string()),
                    ("book_kind", format!("{:?}", book.kind)),
                    ("missing_fields", missing_fields.join(",")),
                ]),
                target: DashboardAlertTarget {
                    entity_id: Some(book.entity_id.to_string()),
                    book_id: Some(book.id.to_string()),
                    act_id: None,
                    links: target_links(Some(book.entity_id), Some(book.id), None),
                },
                source: Some("books.termo_abertura".to_owned()),
                law_refs: law_refs(&[("dl-76-a-2006", "1"), ("dl-76-a-2006", "2")]),
                action: Some(dashboard_action(
                    "open_book",
                    "notifications.alert.book.missingTermo.action",
                    Some(format!("/v1/books/{}", book.id)),
                    Some(format!("/livros/{}", book.id)),
                )),
                recommended_next_steps: vec![
                    "Complete the opening term identification and purpose metadata.".to_owned(),
                    "Record the required signatories for the book opening.".to_owned(),
                ],
                i18n: Some(alert_i18n(
                    "notifications.alert.book.missingTermo.title",
                    "notifications.alert.book.missingTermo.body",
                    Some("notifications.alert.book.missingTermo.action"),
                )),
            });
        }

        let act_count = acts.values().filter(|act| act.book_id == book.id).count();
        if act_count == 0 {
            alerts.push(DashboardAlert {
                code: "book.acts.none_recorded".to_owned(),
                label: "Advisory".to_owned(),
                severity: "Info".to_owned(),
                category: "BookLifecycle".to_owned(),
                message: format!(
                    "Open book {} has no acts recorded yet. Draft a new ata or import historical minutes when appropriate.",
                    book.id
                ),
                params: dashboard_alert_params([
                    ("book_id", book.id.to_string()),
                    ("entity_id", book.entity_id.to_string()),
                    ("book_kind", format!("{:?}", book.kind)),
                    (
                        "next_ata_number",
                        book.last_ata_number.saturating_add(1).to_string(),
                    ),
                    ("recommended_actions", "draft_ata,import_minutes".to_owned()),
                ]),
                target: DashboardAlertTarget {
                    entity_id: Some(book.entity_id.to_string()),
                    book_id: Some(book.id.to_string()),
                    act_id: None,
                    links: target_links(Some(book.entity_id), Some(book.id), None),
                },
                source: Some("acts.by_book".to_owned()),
                law_refs: law_refs(&[("dl-76-a-2006", "1"), ("dl-76-a-2006", "2")]),
                action: Some(dashboard_action(
                    "open_book",
                    "notifications.alert.book.noActs.action",
                    Some(format!("/v1/books/{}", book.id)),
                    Some(format!("/livros/{}", book.id)),
                )),
                recommended_next_steps: vec![
                    "Draft the next minutes for this book.".to_owned(),
                    "Import historical minutes if this book is being migrated.".to_owned(),
                ],
                i18n: Some(alert_i18n(
                    "notifications.alert.book.noActs.title",
                    "notifications.alert.book.noActs.body",
                    Some("notifications.alert.book.noActs.action"),
                )),
            });
        }
    }

    for book in books.values().filter(|book| book.legal_hold.is_some()) {
        let hold = book.legal_hold.as_ref().expect("filtered legal hold");
        alerts.push(DashboardAlert {
            code: "book.legal_hold.active".to_owned(),
            label: "ReviewRequired".to_owned(),
            severity: "Warning".to_owned(),
            category: "ArchiveRetention".to_owned(),
            message: format!(
                "Book {} has an active legal hold set by {}. Review the hold before archive disposal decisions.",
                book.id, hold.actor
            ),
            params: dashboard_alert_params([
                ("book_id", book.id.to_string()),
                ("entity_id", book.entity_id.to_string()),
                ("book_kind", format!("{:?}", book.kind)),
                ("legal_hold_reason", hold.reason.clone()),
                ("legal_hold_actor", hold.actor.clone()),
                ("legal_hold_set_at", rfc3339(hold.set_at)),
                (
                    "recommended_actions",
                    "review_legal_hold,review_archive_disposal".to_owned(),
                ),
            ]),
            target: DashboardAlertTarget {
                entity_id: Some(book.entity_id.to_string()),
                book_id: Some(book.id.to_string()),
                act_id: None,
                links: target_links(Some(book.entity_id), Some(book.id), None),
            },
            source: Some("books.legal_hold".to_owned()),
            law_refs: Vec::new(),
            action: Some(dashboard_action(
                "open_book_legal_hold",
                "notifications.alert.book.legalHold.action",
                Some(format!("/v1/books/{}/legal-hold", book.id)),
                Some(format!("/livros/{}", book.id)),
            )),
            recommended_next_steps: vec![
                "Open the book legal-hold panel.".to_owned(),
                "Review the hold reason before any archive disposal decision.".to_owned(),
            ],
            i18n: Some(alert_i18n(
                "notifications.alert.book.legalHold.title",
                "notifications.alert.book.legalHold.body",
                Some("notifications.alert.book.legalHold.action"),
            )),
        });
    }

    for act in acts.values() {
        let Some(next_state) = next_act_state(act.state) else {
            continue;
        };
        let Some(book) = books.get(&act.book_id) else {
            continue;
        };
        let entity_id = book.entity_id;
        alerts.push(DashboardAlert {
            code: "act.lifecycle.advance_available".to_owned(),
            label: "Advisory".to_owned(),
            severity: "Info".to_owned(),
            category: "ActLifecycle".to_owned(),
            message: format!(
                "Act {} is in {:?}. Continue the recorded lifecycle and advance to {:?} when the supporting work is ready.",
                act.id, act.state, next_state
            ),
            params: dashboard_alert_params([
                ("act_id", act.id.to_string()),
                ("book_id", book.id.to_string()),
                ("entity_id", entity_id.to_string()),
                ("current_state", format!("{:?}", act.state)),
                ("next_state", format!("{:?}", next_state)),
            ]),
            target: DashboardAlertTarget {
                entity_id: Some(entity_id.to_string()),
                book_id: Some(book.id.to_string()),
                act_id: Some(act.id.to_string()),
                links: target_links(Some(entity_id), Some(book.id), Some(act.id)),
            },
            source: Some("acts.state".to_owned()),
            law_refs: Vec::new(),
            action: Some(dashboard_action(
                "open_act",
                "notifications.alert.act.advanceAvailable.action",
                Some(format!("/v1/acts/{}", act.id)),
                Some(format!("/atas/{}", act.id)),
            )),
            recommended_next_steps: vec![
                "Review the supporting work for the current lifecycle state.".to_owned(),
                "Advance the minutes when the next state is ready.".to_owned(),
            ],
            i18n: Some(alert_i18n(
                "notifications.alert.act.advanceAvailable.title",
                "notifications.alert.act.advanceAvailable.body",
                Some("notifications.alert.act.advanceAvailable.action"),
            )),
        });
    }

    for act in acts
        .values()
        .filter(|act| matches!(act.state, ActState::Sealed))
    {
        let Some(book) = books.get(&act.book_id) else {
            continue;
        };
        let entity_id = book.entity_id;
        alerts.push(DashboardAlert {
            code: "act.archive.pending".to_owned(),
            label: "Advisory".to_owned(),
            severity: "Info".to_owned(),
            category: "ArchiveStatus".to_owned(),
            message: format!(
                "Act {} is sealed but not archived. Archive it when the preservation evidence is ready.",
                act.id
            ),
            params: dashboard_alert_params([
                ("act_id", act.id.to_string()),
                ("book_id", book.id.to_string()),
                ("entity_id", entity_id.to_string()),
                ("act_title", act.title.clone()),
                ("current_state", format!("{:?}", act.state)),
                ("recommended_actions", "archive_act".to_owned()),
            ]),
            target: DashboardAlertTarget {
                entity_id: Some(entity_id.to_string()),
                book_id: Some(book.id.to_string()),
                act_id: Some(act.id.to_string()),
                links: target_links(Some(entity_id), Some(book.id), Some(act.id)),
            },
            source: Some("acts.state".to_owned()),
            law_refs: Vec::new(),
            action: Some(dashboard_action(
                "archive_act",
                "notifications.alert.act.archivePending.action",
                Some(format!("/v1/acts/{}/archive", act.id)),
                Some(format!("/atas/{}", act.id)),
            )),
            recommended_next_steps: vec![
                "Open the sealed act.".to_owned(),
                "Archive it when the preservation evidence is ready.".to_owned(),
            ],
            i18n: Some(alert_i18n(
                "notifications.alert.act.archivePending.title",
                "notifications.alert.act.archivePending.body",
                Some("notifications.alert.act.archivePending.action"),
            )),
        });
    }
}

fn termo_abertura_missing_fields(book: &Book) -> Vec<&'static str> {
    let Some(termo) = book.termo_abertura.as_ref() else {
        return vec!["termo_abertura"];
    };

    let mut missing = Vec::new();
    if termo.entity_name.trim().is_empty() {
        missing.push("entity_name");
    }
    if termo.entity_nipc.trim().is_empty() {
        missing.push("entity_nipc");
    }
    if termo.entity_seat.trim().is_empty() {
        missing.push("entity_seat");
    }
    if termo.purpose.trim().is_empty() {
        missing.push("purpose");
    }
    if termo
        .required_signatories
        .iter()
        .all(|signatory| signatory.trim().is_empty())
    {
        missing.push("required_signatories");
    }
    missing
}

fn next_act_state(state: ActState) -> Option<ActState> {
    match state {
        ActState::Draft => Some(ActState::Review),
        ActState::Review => Some(ActState::Convened),
        ActState::Convened => Some(ActState::Deliberated),
        ActState::Deliberated => Some(ActState::TextApproved),
        ActState::TextApproved => Some(ActState::Signing),
        ActState::Signing | ActState::Sealed | ActState::Archived => None,
    }
}

fn dashboard_alert_params<const N: usize>(
    entries: [(&str, String); N],
) -> BTreeMap<String, String> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn alert_i18n(title_key: &str, body_key: &str, action_key: Option<&str>) -> DashboardI18n {
    DashboardI18n {
        title_key: title_key.to_owned(),
        body_key: body_key.to_owned(),
        action_key: action_key.map(str::to_owned),
    }
}

fn dashboard_action(
    kind: &str,
    label_key: &str,
    api_href: Option<String>,
    route: Option<String>,
) -> DashboardAction {
    DashboardAction {
        kind: kind.to_owned(),
        label_key: label_key.to_owned(),
        api_href,
        route,
    }
}

/// The corpus authenticity tier as its stable wire string, matching the [`Verification`] serde
/// value: `"Verified"` (human-approved) / `"automated_review"` (vendored + auto-reviewed, NOT
/// human-approved) / `"Pending"` (no text). Kept in lockstep with the enum's serde so the dashboard
/// contract and the `/v1/law` corpus surface agree on the badge value.
fn law_verification_wire(v: Verification) -> &'static str {
    match v {
        Verification::Verified => "Verified",
        Verification::AutomatedReview => "automated_review",
        Verification::Pending => "Pending",
    }
}

fn law_refs(refs: &[(&str, &str)]) -> Vec<DashboardLawReference> {
    let catalog = LawCatalog::embedded();
    refs.iter()
        .map(|(diploma_id, article_number)| {
            catalog
                .article(diploma_id, article_number)
                .map(|article| DashboardLawReference {
                    diploma_id: article.diploma_id.clone(),
                    article: article.number.clone(),
                    label: article.label.clone(),
                    heading: article.heading.clone(),
                    verification: law_verification_wire(article.verification).to_owned(),
                    source_url: article.source.url.clone(),
                    source_complete: article.source.is_complete(),
                    // Only automated-review articles carry these; verified/pending leave them null.
                    review_method: article.source.review_method.clone(),
                    review_note: article.source.review_note.clone(),
                })
                .unwrap_or_else(|| DashboardLawReference {
                    diploma_id: (*diploma_id).to_owned(),
                    article: (*article_number).to_owned(),
                    label: format!("Artigo {article_number}"),
                    heading: String::new(),
                    verification: "Missing".to_owned(),
                    source_url: None,
                    source_complete: false,
                    review_method: None,
                    review_note: None,
                })
        })
        .collect()
}

struct RemunerationAlertProfile {
    code: &'static str,
    officer_label: &'static str,
    article: &'static str,
    title_key: &'static str,
    body_key: &'static str,
    action_key: &'static str,
}

fn remuneration_alert_profile(kind: EntityKind) -> RemunerationAlertProfile {
    if matches!(kind, EntityKind::SociedadeAnonima) {
        RemunerationAlertProfile {
            code: "entity.administrator_remuneration.setup_recommended",
            officer_label: "administration",
            article: "399",
            title_key: "notifications.alert.entity.administratorRemuneration.title",
            body_key: "notifications.alert.entity.administratorRemuneration.body",
            action_key: "notifications.alert.entity.administratorRemuneration.action",
        }
    } else {
        RemunerationAlertProfile {
            code: "entity.manager_remuneration.setup_recommended",
            officer_label: "management",
            article: "255",
            title_key: "notifications.alert.entity.managerRemuneration.title",
            body_key: "notifications.alert.entity.managerRemuneration.body",
            action_key: "notifications.alert.entity.managerRemuneration.action",
        }
    }
}

fn should_prompt_manager_remuneration(
    entity: &Entity,
    acts: &HashMap<ActId, Act>,
    books: &HashMap<BookId, Book>,
    registry_extract: Option<&RegistryExtract>,
) -> bool {
    if !matches!(entity.family, EntityFamily::CommercialCompany) || !is_sa_or_lda_like(entity.kind)
    {
        return false;
    }
    let Some(extract) = registry_extract else {
        return false;
    };
    if !extract.orgaos.iter().any(|officer| {
        officer.cessation_date.is_none()
            && officer
                .role
                .as_deref()
                .map(fold_ascii)
                .is_some_and(|role| role.contains("gerente") || role.contains("administrador"))
    }) {
        return false;
    }

    !acts.values().any(|act| {
        matches!(act.state, ActState::Sealed | ActState::Archived)
            && books
                .get(&act.book_id)
                .is_some_and(|book| book.entity_id == entity.id)
            && act_mentions_remuneration(act)
    })
}

fn is_sa_or_lda_like(kind: EntityKind) -> bool {
    matches!(
        kind,
        EntityKind::SociedadeAnonima
            | EntityKind::SociedadePorQuotas
            | EntityKind::SociedadeUnipessoalPorQuotas
    )
}

fn act_mentions_remuneration(act: &Act) -> bool {
    let haystack = fold_ascii(&format!("{} {}", act.title, act.deliberations));
    haystack.contains("remuneracao") || haystack.contains("nao remuneracao")
}

fn fold_ascii(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            'á' | 'à' | 'â' | 'ã' | 'ä' | 'Á' | 'À' | 'Â' | 'Ã' | 'Ä' => 'a',
            'é' | 'è' | 'ê' | 'ë' | 'É' | 'È' | 'Ê' | 'Ë' => 'e',
            'í' | 'ì' | 'î' | 'ï' | 'Í' | 'Ì' | 'Î' | 'Ï' => 'i',
            'ó' | 'ò' | 'ô' | 'õ' | 'ö' | 'Ó' | 'Ò' | 'Ô' | 'Õ' | 'Ö' => 'o',
            'ú' | 'ù' | 'û' | 'ü' | 'Ú' | 'Ù' | 'Û' | 'Ü' => 'u',
            'ç' | 'Ç' => 'c',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

fn rfc3339(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_default()
}

fn target_links(
    entity_id: Option<EntityId>,
    book_id: Option<BookId>,
    act_id: Option<ActId>,
) -> DashboardTargetLinks {
    DashboardTargetLinks {
        entity: entity_id.map(|id| format!("/v1/entities/{id}")),
        book: book_id.map(|id| format!("/v1/books/{id}")),
        act: act_id.map(|id| format!("/v1/acts/{id}")),
        ledger: ledger_link(entity_id, book_id, act_id),
    }
}

fn ledger_link(
    entity_id: Option<EntityId>,
    book_id: Option<BookId>,
    act_id: Option<ActId>,
) -> Option<String> {
    if let Some(act_id) = act_id {
        return Some(format!("/v1/ledger/events?scope=act:{act_id}"));
    }
    if let Some(book_id) = book_id {
        return Some(format!("/v1/ledger/events?chain=book:{book_id}"));
    }
    entity_id.map(|id| format!("/v1/ledger/events?chain=company:{id}"))
}
#[derive(Clone)]
pub struct GeneratedDispatchEvidenceSnapshot {
    pub document: StoredDocument,
    pub evidence: Vec<StoredGeneratedDocumentDispatchEvidence>,
}
pub struct ReminderInputs<'a> {
    pub entities: &'a HashMap<EntityId, Entity>,
    pub books: &'a HashMap<BookId, Book>,
    pub acts: &'a HashMap<ActId, Act>,
    pub follow_ups: &'a HashMap<String, StoredFollowUp>,
    pub generated_dispatch_evidence: &'a [GeneratedDispatchEvidenceSnapshot],
    pub imported_documents: &'a [StoredImportedDocumentMeta],
    pub registry_extracts: &'a HashMap<EntityId, RegistryExtract>,
    pub dpia_records: &'a HashMap<DpiaRecordId, DpiaRecord>,
    pub breach_playbooks: &'a HashMap<BreachPlaybookId, BreachPlaybookRecord>,
    pub transfer_controls: &'a HashMap<TransferControlId, TransferControlRecord>,
}

pub fn dashboard_reminders_with_generated_dispatch_evidence(
    inputs: ReminderInputs<'_>,
    today: Date,
    policy: &WorkflowReminderSettings,
) -> Vec<DashboardReminder> {
    let ReminderInputs {
        entities,
        books,
        acts,
        follow_ups,
        generated_dispatch_evidence,
        imported_documents,
        registry_extracts,
        dpia_records,
        breach_playbooks,
        transfer_controls,
    } = inputs;
    if !policy.enabled {
        return Vec::new();
    }

    let mut reminders = Vec::new();
    if policy.sources.act_follow_ups {
        reminders.extend(follow_up_reminders(
            entities,
            books,
            acts,
            follow_ups,
            today,
            policy.due_soon_days,
        ));
    }
    if policy.sources.attendance_hygiene {
        reminders.extend(open_act_attendance_reminders(
            entities,
            books,
            acts,
            today,
            policy.attendance_lookahead_days,
            policy.due_soon_days,
        ));
    }
    reminders.extend(open_act_convocation_notice_reminders(
        entities,
        books,
        acts,
        today,
        policy.due_soon_days,
    ));
    reminders.extend(absent_owner_dispatch_evidence_reminders(
        entities,
        books,
        acts,
        generated_dispatch_evidence,
    ));
    reminders.extend(generated_convening_dispatch_evidence_reminders(
        entities,
        books,
        acts,
        generated_dispatch_evidence,
    ));
    reminders.extend(imported_document_review_reminders(
        entities,
        books,
        acts,
        imported_documents,
    ));
    if policy.sources.privacy_control_reviews {
        reminders.extend(privacy_control_review_reminders(
            dpia_records,
            breach_playbooks,
            transfer_controls,
            today,
            policy.due_soon_days,
        ));
    }
    if policy.sources.profile_calendar {
        reminders.extend(
            entities
                .values()
                .flat_map(|entity| {
                    let context = ProfileCalendarReminderContext {
                        books,
                        acts,
                        registry_extract: registry_extracts.get(&entity.id),
                        today,
                        due_soon_days: policy.due_soon_days,
                    };
                    annual_general_meeting_reminders(entity, &context)
                })
                .collect::<Vec<_>>(),
        );
    }

    sort_dashboard_reminders(&mut reminders);
    reminders.truncate(policy.dashboard_limit as usize);
    reminders
}

fn follow_up_reminders(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    follow_ups: &HashMap<String, StoredFollowUp>,
    today: Date,
    due_soon_days: u16,
) -> Vec<DashboardReminder> {
    follow_ups
        .values()
        .filter(|follow_up| follow_up.status == StoredFollowUpStatus::Open)
        .filter_map(|follow_up| {
            let due_date = follow_up.due_date?;
            let act = acts.get(&follow_up.act_id)?;
            let book = books.get(&act.book_id)?;
            let entity = entities.get(&book.entity_id)?;
            Some(follow_up_reminder(
                entity,
                book,
                act,
                follow_up,
                due_date,
                today,
                due_soon_days,
            ))
        })
        .collect()
}

fn open_act_attendance_reminders(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    today: Date,
    attendance_lookahead_days: u16,
    due_soon_days: u16,
) -> Vec<DashboardReminder> {
    acts.values()
        .filter_map(|act| {
            let book = books.get(&act.book_id)?;
            if book.state != BookState::Open || !is_pre_signing_work_queue_state(act.state) {
                return None;
            }
            let entity = entities.get(&book.entity_id)?;
            if !entity.is_consistent() {
                return None;
            }
            act_attendance_reminder(
                entity,
                book,
                act,
                today,
                attendance_lookahead_days,
                due_soon_days,
            )
        })
        .collect()
}

fn act_attendance_reminder(
    entity: &Entity,
    book: &Book,
    act: &Act,
    today: Date,
    attendance_lookahead_days: u16,
    due_soon_days: u16,
) -> Option<DashboardReminder> {
    let due_date = act.meeting_date?;
    let days_until = due_date.to_julian_day() - today.to_julian_day();
    if days_until > i32::from(attendance_lookahead_days) {
        return None;
    }

    let missing_fields = missing_attendance_fields(act);
    if missing_fields.is_empty() {
        return None;
    }

    let due_date_text = format_date(due_date);
    let status = reminder_status(today, due_date, due_soon_days).to_owned();
    let severity = if status == "Overdue" {
        "Warning"
    } else {
        "Info"
    }
    .to_owned();
    let missing_fields_text = missing_fields.join(",");
    let profile = profile_for(entity.kind);

    Some(DashboardReminder {
        due_date: due_date_text.clone(),
        severity,
        status,
        reason: format!(
            "Act \"{}\" is dated for {} but is missing attendance capture ({}). \
             Record the attendance reference and either presence counts or structured attendees before advancing it.",
            act.title, due_date_text, missing_fields_text
        ),
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: "act-attendance-missing".to_owned(),
        source_profile: profile.template_family.to_owned(),
        params: dashboard_alert_params([
            ("act_id", act.id.to_string()),
            ("act_title", act.title.clone()),
            ("book_id", book.id.to_string()),
            ("entity_id", entity.id.to_string()),
            ("entity_name", entity.name.clone()),
            ("meeting_date", due_date_text),
            ("act_state", format!("{:?}", act.state)),
            ("missing_fields", missing_fields_text),
            (
                "days_until",
                (due_date.to_julian_day() - today.to_julian_day()).to_string(),
            ),
        ]),
        profile_calendar_plan: None,
        law_refs: act_attendance_law_refs(entity.family),
        action: Some(dashboard_action(
            "open_act_attendance",
            "notifications.reminder.act.attendance.action",
            Some(format!("/v1/acts/{}", act.id)),
            Some(format!("/atas/{}", act.id)),
        )),
        recommended_next_steps: vec![
            "Open the act.".to_owned(),
            "Record the attendance reference and presence counts or structured attendee rows."
                .to_owned(),
        ],
        i18n: Some(alert_i18n(
            "notifications.reminder.act.attendance.title",
            "notifications.reminder.act.attendance.body",
            Some("notifications.reminder.act.attendance.action"),
        )),
    })
}

fn is_pre_signing_work_queue_state(state: ActState) -> bool {
    matches!(
        state,
        ActState::Draft
            | ActState::Review
            | ActState::Convened
            | ActState::Deliberated
            | ActState::TextApproved
    )
}

fn missing_attendance_fields(act: &Act) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if act
        .attendance_reference
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        missing.push("attendance_reference");
    }
    if act.members_present.is_none()
        && act.members_represented.is_none()
        && act.attendees.is_empty()
    {
        missing.push("presence_counts_or_attendees");
    }
    missing
}

fn act_attendance_law_refs(family: EntityFamily) -> Vec<DashboardLawReference> {
    match family {
        EntityFamily::CommercialCompany => law_refs(&[("csc", "63")]),
        _ => Vec::new(),
    }
}

fn open_act_convocation_notice_reminders(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    today: Date,
    due_soon_days: u16,
) -> Vec<DashboardReminder> {
    acts.values()
        .filter_map(|act| {
            let book = books.get(&act.book_id)?;
            if book.state != BookState::Open || !is_pre_signing_work_queue_state(act.state) {
                return None;
            }
            let entity = entities.get(&book.entity_id)?;
            if !entity.is_consistent() {
                return None;
            }
            act_convocation_notice_reminder(entity, book, act, today, due_soon_days)
        })
        .collect()
}

fn act_convocation_notice_reminder(
    entity: &Entity,
    book: &Book,
    act: &Act,
    today: Date,
    due_soon_days: u16,
) -> Option<DashboardReminder> {
    let required_days = entity.statute.as_ref()?.convocation_notice_days?;
    let dispatch_date = act
        .convening
        .as_ref()
        .and_then(|convening| convening.dispatch_date);
    let antecedence_days = act_convocation_notice_antecedence_days(act);
    let Some(meeting_date) = act.meeting_date else {
        return Some(act_convocation_notice_missing_meeting_date_reminder(
            entity,
            book,
            act,
            required_days,
            dispatch_date,
            antecedence_days,
        ));
    };
    let notice_due_date =
        Date::from_julian_day(meeting_date.to_julian_day() - i32::from(required_days)).ok()?;

    if antecedence_days
        .map(|actual| actual >= i32::from(required_days))
        .unwrap_or(false)
    {
        return None;
    }

    let meeting_date_text = format_date(meeting_date);
    let notice_due_date_text = format_date(notice_due_date);
    let dispatch_date_text = dispatch_date.map(format_date).unwrap_or_default();
    let antecedence_days_text = antecedence_days
        .map(|days| days.to_string())
        .unwrap_or_default();
    let evidence_status = if antecedence_days.is_some() {
        "short_dispatch_evidence"
    } else {
        "missing_or_unverifiable_dispatch_evidence"
    };
    let profile = profile_for(entity.kind);

    Some(DashboardReminder {
        due_date: notice_due_date_text.clone(),
        severity: "Warning".to_owned(),
        status: reminder_status(today, notice_due_date, due_soon_days).to_owned(),
        reason: format!(
            "Act \"{}\" has a local statute convocation-notice advisory of {} days for meeting date {}. \
             Recorded convening dispatch evidence is {} and does not demonstrate the configured notice period. \
             This is a local advisory over recorded statute/convening metadata only; no legal sufficiency, \
             external delivery, or workflow completion is claimed.",
            act.title, required_days, meeting_date_text, evidence_status
        ),
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: "act-convening-notice".to_owned(),
        source_profile: profile.template_family.to_owned(),
        params: dashboard_alert_params([
            ("act_id", act.id.to_string()),
            ("act_title", act.title.clone()),
            ("book_id", book.id.to_string()),
            ("entity_id", entity.id.to_string()),
            ("entity_name", entity.name.clone()),
            ("required_notice_days", required_days.to_string()),
            ("meeting_date", meeting_date_text),
            ("notice_due_date", notice_due_date_text),
            ("dispatch_date", dispatch_date_text),
            ("antecedence_days", antecedence_days_text),
            ("evidence_status", evidence_status.to_owned()),
            ("act_state", format!("{:?}", act.state)),
            ("local_advisory_only", "true".to_owned()),
            ("legal_sufficiency_claimed", "false".to_owned()),
            ("external_delivery_claimed", "false".to_owned()),
            ("workflow_completion_claimed", "false".to_owned()),
        ]),
        profile_calendar_plan: None,
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_act_convening_notice",
            "notifications.reminder.act.conveningNotice.action",
            Some(format!("/v1/acts/{}", act.id)),
            Some(format!("/atas/{}", act.id)),
        )),
        recommended_next_steps: vec![
            "Open the act.".to_owned(),
            "Review the recorded convening dispatch date and actual antecedence metadata."
                .to_owned(),
        ],
        i18n: Some(alert_i18n(
            "notifications.reminder.act.conveningNotice.title",
            "notifications.reminder.act.conveningNotice.body",
            Some("notifications.reminder.act.conveningNotice.action"),
        )),
    })
}

fn act_convocation_notice_missing_meeting_date_reminder(
    entity: &Entity,
    book: &Book,
    act: &Act,
    required_days: u16,
    dispatch_date: Option<Date>,
    antecedence_days: Option<i32>,
) -> DashboardReminder {
    let dispatch_date_text = dispatch_date.map(format_date).unwrap_or_default();
    let antecedence_days_text = antecedence_days
        .map(|days| days.to_string())
        .unwrap_or_default();
    let profile = profile_for(entity.kind);

    DashboardReminder {
        due_date: String::new(),
        severity: "Warning".to_owned(),
        status: "Pending".to_owned(),
        reason: format!(
            "Act \"{}\" has a local configured convocation-notice advisory of {} days, but no \
             meeting date is recorded. The local notice due date cannot be computed until the \
             meeting date is recorded. Review the act metadata and recorded convening dispatch \
             evidence before advancing it. This is a local advisory over recorded \
             statute/convening metadata only; no legal sufficiency is claimed, and no legal \
             deadline computation, external delivery, workflow completion, registry/DRE \
             acceptance, or provider acceptance is claimed.",
            act.title, required_days
        ),
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: "act-convening-notice".to_owned(),
        source_profile: profile.template_family.to_owned(),
        params: dashboard_alert_params([
            ("act_id", act.id.to_string()),
            ("act_title", act.title.clone()),
            ("book_id", book.id.to_string()),
            ("entity_id", entity.id.to_string()),
            ("entity_name", entity.name.clone()),
            ("required_notice_days", required_days.to_string()),
            ("meeting_date", String::new()),
            ("notice_due_date", String::new()),
            ("dispatch_date", dispatch_date_text),
            ("antecedence_days", antecedence_days_text),
            ("evidence_status", "missing_meeting_date".to_owned()),
            ("notice_due_date_computable", "false".to_owned()),
            (
                "notice_due_date_blocked_by",
                "missing_meeting_date".to_owned(),
            ),
            ("local_deadline_computed", "false".to_owned()),
            ("local_advisory_only", "true".to_owned()),
            ("legal_sufficiency_claimed", "false".to_owned()),
            ("legal_deadline_computation_claimed", "false".to_owned()),
            ("external_delivery_claimed", "false".to_owned()),
            ("workflow_completion_claimed", "false".to_owned()),
            ("registry_acceptance_claimed", "false".to_owned()),
            ("dre_acceptance_claimed", "false".to_owned()),
            ("provider_acceptance_claimed", "false".to_owned()),
        ]),
        profile_calendar_plan: None,
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_act_convening_notice",
            "notifications.reminder.act.conveningNotice.action",
            Some(format!("/v1/acts/{}", act.id)),
            Some(format!("/atas/{}", act.id)),
        )),
        recommended_next_steps: vec![
            "Open the act.".to_owned(),
            "Record the meeting date before computing the local notice due date.".to_owned(),
            "Review the recorded convening dispatch evidence after the meeting date is known."
                .to_owned(),
        ],
        i18n: Some(alert_i18n(
            "notifications.reminder.act.conveningNotice.title",
            "notifications.reminder.act.conveningNotice.missingMeetingDate.body",
            Some("notifications.reminder.act.conveningNotice.action"),
        )),
    }
}

fn act_convocation_notice_antecedence_days(act: &Act) -> Option<i32> {
    let convening = act.convening.as_ref()?;
    if let Some(days) = convening.antecedence_days {
        return Some(i32::from(days));
    }

    let dispatch_date = convening.dispatch_date?;
    let meeting_date = act.meeting_date?;
    Some(meeting_date.to_julian_day() - dispatch_date.to_julian_day())
}

fn imported_document_review_reminders(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    imported_documents: &[StoredImportedDocumentMeta],
) -> Vec<DashboardReminder> {
    imported_documents
        .iter()
        .filter(|document| {
            imported_document_status_requires_review(document.operator_review_status)
        })
        .filter_map(|document| {
            let act_id = document.act_id?;
            let act = acts.get(&act_id)?;
            let book = books.get(&act.book_id)?;
            let entity = entities.get(&book.entity_id)?;
            Some(imported_document_review_reminder(
                entity, book, act, document,
            ))
        })
        .collect()
}

fn imported_document_status_requires_review(status: StoredImportedDocumentReviewStatus) -> bool {
    matches!(
        status,
        StoredImportedDocumentReviewStatus::OperatorReviewRequired
            | StoredImportedDocumentReviewStatus::OcrReviewRequired
            | StoredImportedDocumentReviewStatus::CanonicalConversionReviewRequired
    )
}

fn imported_document_review_reminder(
    entity: &Entity,
    book: &Book,
    act: &Act,
    document: &StoredImportedDocumentMeta,
) -> DashboardReminder {
    let review_status = document.operator_review_status.as_str().to_owned();
    DashboardReminder {
        due_date: String::new(),
        severity: "Advisory".to_owned(),
        status: "Pending".to_owned(),
        reason: format!(
            "Imported document {} for act \"{}\" still requires operator review ({review_status}).",
            document.id, act.title
        ),
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: "imported-document-review-required".to_owned(),
        source_profile: format!("imported-document-review:{}", document.id),
        params: dashboard_alert_params([
            ("act_id", act.id.to_string()),
            ("act_title", act.title.clone()),
            ("book_id", book.id.to_string()),
            ("entity_id", entity.id.to_string()),
            ("entity_name", entity.name.clone()),
            ("imported_document_id", document.id.clone()),
            ("operator_review_status", review_status.clone()),
        ]),
        profile_calendar_plan: None,
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_imported_document_review",
            "notifications.reminder.importedDocumentReview.action",
            Some(format!("/v1/documents/imported/{}", document.id)),
            Some(format!(
                "/atas/{}?imported_document_id={}&focus=import-review#imported-documents",
                act.id, document.id
            )),
        )),
        recommended_next_steps: vec![
            "Open the act imported-document panel.".to_owned(),
            "Use the existing imported-document review form to record an operator workflow decision."
                .to_owned(),
        ],
        i18n: Some(alert_i18n(
            "notifications.reminder.importedDocumentReview.title",
            "notifications.reminder.importedDocumentReview.body",
            Some("notifications.reminder.importedDocumentReview.action"),
        )),
    }
}

fn absent_owner_dispatch_evidence_reminders(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    generated_dispatch_evidence: &[GeneratedDispatchEvidenceSnapshot],
) -> Vec<DashboardReminder> {
    generated_dispatch_evidence
        .iter()
        .filter_map(|snapshot| {
            absent_owner_dispatch_evidence_reminder(entities, books, acts, snapshot)
        })
        .collect()
}

fn absent_owner_dispatch_evidence_reminder(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    snapshot: &GeneratedDispatchEvidenceSnapshot,
) -> Option<DashboardReminder> {
    let document = &snapshot.document;
    if document.template_id != crate::documents::CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID
    {
        return None;
    }
    let act = acts.get(&document.act_id)?;
    if act.state != ActState::Sealed || act.ata_number.is_none() {
        return None;
    }
    let book = books.get(&act.book_id)?;
    let entity = entities.get(&book.entity_id)?;
    if entity.family != EntityFamily::Condominium {
        return None;
    }

    let required_recipients = crate::documents::absent_owner_recipient_names(act);
    if required_recipients.is_empty() {
        return None;
    }
    let recorded_recipients = snapshot
        .evidence
        .iter()
        .filter(|row| {
            row.document_id == document.id
                && row.act_id == document.act_id
                && row.template_id == document.template_id
        })
        .flat_map(|row| row.recipients.iter().cloned())
        .collect::<Vec<_>>();
    let dispatch_status = crate::documents::dispatch_evidence_status_for_template(
        &document.template_id,
        &required_recipients,
        &recorded_recipients,
    )?;
    if !matches!(
        dispatch_status.status.as_str(),
        "required_pending" | "operator_evidence_partial"
    ) {
        return None;
    }

    Some(absent_owner_dispatch_evidence_dashboard_reminder(
        entity,
        book,
        act,
        document,
        &dispatch_status,
        snapshot.evidence.len(),
    ))
}

fn absent_owner_dispatch_evidence_dashboard_reminder(
    entity: &Entity,
    book: &Book,
    act: &Act,
    document: &StoredDocument,
    dispatch_status: &crate::documents::DispatchEvidenceStatusView,
    evidence_row_count: usize,
) -> DashboardReminder {
    let required_count = dispatch_status.required_recipients.len();
    let recorded_count = dispatch_status.recorded_recipients.len();
    let missing_count = dispatch_status.missing_recipients.len();
    let missing_recipients = dispatch_status.missing_recipients.join(", ");

    DashboardReminder {
        due_date: String::new(),
        severity: "Advisory".to_owned(),
        status: "Pending".to_owned(),
        reason: format!(
            "Generated absent-owner communication document {} for act \"{}\" has dispatch \
             evidence status {}. This dashboard reminder is advisory only and does not claim \
             sending, delivery, legal notice completion, or legal sufficiency.",
            document.id, act.title, dispatch_status.status
        ),
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: "absent-owner-dispatch-evidence".to_owned(),
        source_profile: "condominium-generated-communication".to_owned(),
        params: dashboard_alert_params([
            ("act_id", act.id.to_string()),
            ("act_title", act.title.clone()),
            ("book_id", book.id.to_string()),
            ("entity_id", entity.id.to_string()),
            ("entity_name", entity.name.clone()),
            ("document_id", document.id.clone()),
            ("template_id", document.template_id.clone()),
            ("dispatch_evidence_status", dispatch_status.status.clone()),
            ("required_recipient_count", required_count.to_string()),
            ("recorded_recipient_count", recorded_count.to_string()),
            ("missing_recipient_count", missing_count.to_string()),
            (
                "required_recipients",
                dispatch_status.required_recipients.join(", "),
            ),
            (
                "recorded_recipients",
                dispatch_status.recorded_recipients.join(", "),
            ),
            ("missing_recipients", missing_recipients),
            ("evidence_row_count", evidence_row_count.to_string()),
        ]),
        profile_calendar_plan: None,
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_absent_owner_dispatch_evidence",
            "notifications.reminder.absentOwnerDispatch.action",
            Some(format!(
                "/v1/documents/generated/{}/dispatch-evidence",
                document.id
            )),
            Some(format!("/atas/{}", act.id)),
        )),
        recommended_next_steps: vec![
            "Open the sealed act's generated communication workflow.".to_owned(),
            "Record operator dispatch evidence for the missing absent recipients when available."
                .to_owned(),
        ],
        i18n: Some(alert_i18n(
            "notifications.reminder.absentOwnerDispatch.title",
            "notifications.reminder.absentOwnerDispatch.body",
            Some("notifications.reminder.absentOwnerDispatch.action"),
        )),
    }
}

fn generated_convening_dispatch_evidence_reminders(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    generated_dispatch_evidence: &[GeneratedDispatchEvidenceSnapshot],
) -> Vec<DashboardReminder> {
    generated_dispatch_evidence
        .iter()
        .filter_map(|snapshot| {
            generated_convening_dispatch_evidence_reminder(entities, books, acts, snapshot)
        })
        .collect()
}

fn generated_convening_dispatch_evidence_reminder(
    entities: &HashMap<EntityId, Entity>,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    snapshot: &GeneratedDispatchEvidenceSnapshot,
) -> Option<DashboardReminder> {
    let document = &snapshot.document;
    if !matches!(
        crate::documents::generated_dispatch_evidence_profile_for_template(&document.template_id),
        Some(crate::documents::GeneratedDispatchEvidenceProfile::GeneratedConveningNotice)
    ) {
        return None;
    }
    let act = acts.get(&document.act_id)?;
    let book = books.get(&act.book_id)?;
    let entity = entities.get(&book.entity_id)?;
    let required_recipients =
        crate::documents::generated_dispatch_required_recipient_names(act, &document.template_id)?;
    if required_recipients.is_empty() {
        return None;
    }
    let recorded_recipients = snapshot
        .evidence
        .iter()
        .filter(|row| {
            row.document_id == document.id
                && row.act_id == document.act_id
                && row.template_id == document.template_id
        })
        .flat_map(|row| row.recipients.iter().cloned())
        .collect::<Vec<_>>();
    let dispatch_status = crate::documents::dispatch_evidence_status_for_template(
        &document.template_id,
        &required_recipients,
        &recorded_recipients,
    )?;
    if !matches!(
        dispatch_status.status.as_str(),
        "required_pending" | "operator_evidence_partial"
    ) {
        return None;
    }

    Some(generated_convening_dispatch_evidence_dashboard_reminder(
        entity,
        book,
        act,
        document,
        &dispatch_status,
        snapshot.evidence.len(),
    ))
}

fn generated_convening_dispatch_evidence_dashboard_reminder(
    entity: &Entity,
    book: &Book,
    act: &Act,
    document: &StoredDocument,
    dispatch_status: &crate::documents::DispatchEvidenceStatusView,
    evidence_row_count: usize,
) -> DashboardReminder {
    let required_count = dispatch_status.required_recipients.len();
    let recorded_count = dispatch_status.recorded_recipients.len();
    let missing_count = dispatch_status.missing_recipients.len();
    let missing_recipients = dispatch_status.missing_recipients.join(", ");

    DashboardReminder {
        due_date: String::new(),
        severity: "Advisory".to_owned(),
        status: "Pending".to_owned(),
        reason: format!(
            "Generated convening notice document {} for act \"{}\" has dispatch evidence status \
             {}. This dashboard reminder is advisory only and records operator metadata for \
             selected required recipients; it does not claim sending, delivery, legal notice \
             completion, or legal sufficiency.",
            document.id, act.title, dispatch_status.status
        ),
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: "generated-convening-dispatch-evidence".to_owned(),
        source_profile: "generated-convening-notice".to_owned(),
        params: dashboard_alert_params([
            ("act_id", act.id.to_string()),
            ("act_title", act.title.clone()),
            ("book_id", book.id.to_string()),
            ("entity_id", entity.id.to_string()),
            ("entity_name", entity.name.clone()),
            ("document_id", document.id.clone()),
            ("generated_document_id", document.id.clone()),
            ("template_id", document.template_id.clone()),
            ("dispatch_evidence_status", dispatch_status.status.clone()),
            ("required_recipient_count", required_count.to_string()),
            ("recorded_recipient_count", recorded_count.to_string()),
            ("missing_recipient_count", missing_count.to_string()),
            (
                "required_recipients",
                dispatch_status.required_recipients.join(", "),
            ),
            (
                "recorded_recipients",
                dispatch_status.recorded_recipients.join(", "),
            ),
            ("missing_recipients", missing_recipients),
            ("evidence_row_count", evidence_row_count.to_string()),
            ("dispatch_completed", "false".to_owned()),
            ("completion_basis", "none".to_owned()),
            ("sending_performed_by_chancela", "false".to_owned()),
            ("delivery_confirmed", "false".to_owned()),
            ("legal_notice_completion_claimed", "false".to_owned()),
            ("legal_sufficiency_claimed", "false".to_owned()),
        ]),
        profile_calendar_plan: None,
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_generated_convening_dispatch_evidence",
            "notifications.reminder.absentOwnerDispatch.action",
            Some(format!(
                "/v1/documents/generated/{}/dispatch-evidence",
                document.id
            )),
            Some(format!(
                "/atas/{}?generated_document_id={}&focus=dispatch-evidence#generated-dispatch-evidence",
                act.id, document.id
            )),
        )),
        recommended_next_steps: vec![
            "Open the generated convening notice dispatch evidence workflow.".to_owned(),
            "Record operator dispatch evidence for the missing required recipients when available."
                .to_owned(),
        ],
        i18n: None,
    }
}

fn privacy_control_review_reminders(
    dpia_records: &HashMap<DpiaRecordId, DpiaRecord>,
    breach_playbooks: &HashMap<BreachPlaybookId, BreachPlaybookRecord>,
    transfer_controls: &HashMap<TransferControlId, TransferControlRecord>,
    today: Date,
    due_soon_days: u16,
) -> Vec<DashboardReminder> {
    let dpia_reminders = dpia_records.values().filter_map(|record| {
        if record.status == PrivacyRecordStatus::Retired {
            return None;
        }
        let summary = dpia_advisory_review(record, today, due_soon_days);
        let review = &summary.review;
        privacy_review_reminder_from_summary(
            "privacy-dpia-review",
            "privacy-dpia",
            &record.id.to_string(),
            &record.title,
            record.status,
            &review.status,
            review.next_review_due_at.as_deref(),
            review.last_reviewed_at.as_deref(),
            review.last_drill_at.as_deref(),
            review.days_until_due,
            review.review_receipt_count,
            review.drill_receipt_count,
            review.receipt_count,
            &[
                (
                    "authority_filing_claimed",
                    summary.authority_filing_claimed.to_string(),
                ),
                (
                    "legal_acceptance_claimed",
                    summary.legal_acceptance_claimed.to_string(),
                ),
                (
                    "legal_certification_claimed",
                    summary.legal_certification_claimed.to_string(),
                ),
                (
                    "external_delivery_claimed",
                    summary.external_delivery_claimed.to_string(),
                ),
                ("completion_claimed", summary.completion_claimed.to_string()),
                (
                    "compliance_certification_claimed",
                    summary.compliance_certification_claimed.to_string(),
                ),
            ],
        )
    });
    let breach_reminders = breach_playbooks.values().filter_map(|record| {
        if record.status == PrivacyRecordStatus::Retired {
            return None;
        }
        let review = breach_playbook_advisory_review(record, today, due_soon_days);
        privacy_review_reminder_from_summary(
            "privacy-breach-playbook-review",
            "privacy-breach-playbook",
            &record.id.to_string(),
            &record.title,
            record.status,
            &review.status,
            review.next_review_due_at.as_deref(),
            review.last_reviewed_at.as_deref(),
            review.last_drill_at.as_deref(),
            review.days_until_due,
            review.review_receipt_count,
            review.drill_receipt_count,
            review.receipt_count,
            &[],
        )
    });
    let transfer_reminders = transfer_controls.values().filter_map(|record| {
        if record.status == PrivacyRecordStatus::Retired {
            return None;
        }
        let review = transfer_control_advisory_review(record, today, due_soon_days);
        privacy_review_reminder_from_summary(
            "privacy-transfer-control-review",
            "privacy-transfer-control",
            &record.id.to_string(),
            &record.name,
            record.status,
            &review.status,
            review.next_review_due_at.as_deref(),
            review.last_reviewed_at.as_deref(),
            None,
            review.days_until_due,
            review.review_receipt_count,
            review.drill_receipt_count,
            review.receipt_count,
            &[],
        )
    });

    dpia_reminders
        .chain(breach_reminders)
        .chain(transfer_reminders)
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn privacy_review_reminder_from_summary(
    source_rule: &str,
    source_profile: &str,
    record_id: &str,
    record_label: &str,
    record_status: PrivacyRecordStatus,
    review_status: &PrivacyAdvisoryReviewStatus,
    next_review_due_at: Option<&str>,
    last_reviewed_at: Option<&str>,
    last_drill_at: Option<&str>,
    days_until_due: Option<i32>,
    review_receipt_count: usize,
    drill_receipt_count: usize,
    receipt_count: usize,
    extra_params: &[(&str, String)],
) -> Option<DashboardReminder> {
    let (dashboard_status, severity, reason_prefix) = match review_status {
        PrivacyAdvisoryReviewStatus::NoReceipt => (
            "Pending",
            "Advisory",
            "has no local review or drill receipt recorded",
        ),
        PrivacyAdvisoryReviewStatus::DueSoon => {
            ("DueSoon", "Info", "has a local advisory review due soon")
        }
        PrivacyAdvisoryReviewStatus::Overdue => {
            ("Overdue", "Warning", "has an overdue local advisory review")
        }
        PrivacyAdvisoryReviewStatus::UnderReview => ("Pending", "Info", "is marked under review"),
        PrivacyAdvisoryReviewStatus::Current => return None,
    };
    let next_due_text = next_review_due_at.unwrap_or("");
    let due_phrase = if next_due_text.is_empty() {
        "No next review date is derived because no local review cadence anchor exists.".to_owned()
    } else {
        format!("Next derived local review date is {next_due_text}.")
    };
    let last_activity = last_reviewed_at
        .or(last_drill_at)
        .unwrap_or("no local review/drill receipt");

    let mut params = dashboard_alert_params([
        ("record_id", record_id.to_owned()),
        ("record_label", record_label.to_owned()),
        ("record_status", format!("{record_status:?}")),
        ("review_status", format!("{review_status:?}")),
        ("next_review_due_at", next_due_text.to_owned()),
        ("last_local_activity_at", last_activity.to_owned()),
        (
            "last_reviewed_at",
            last_reviewed_at.unwrap_or_default().to_owned(),
        ),
        (
            "last_drill_at",
            last_drill_at.unwrap_or_default().to_owned(),
        ),
        (
            "days_until_due",
            days_until_due
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ),
        ("receipt_count", receipt_count.to_string()),
        ("review_receipt_count", review_receipt_count.to_string()),
        ("drill_receipt_count", drill_receipt_count.to_string()),
        ("local_advisory_only", "true".to_owned()),
        ("authority_notification_claimed", "false".to_owned()),
        ("subject_notification_claimed", "false".to_owned()),
        ("transfer_approval_claimed", "false".to_owned()),
        ("transfer_execution_claimed", "false".to_owned()),
        ("external_delivery_configured", "false".to_owned()),
        ("legal_completion_claimed", "false".to_owned()),
    ]);
    for (key, value) in extra_params {
        params.insert((*key).to_owned(), value.clone());
    }

    Some(DashboardReminder {
        due_date: next_due_text.to_owned(),
        severity: severity.to_owned(),
        status: dashboard_status.to_owned(),
        reason: format!(
            "Privacy register item \"{record_label}\" {reason_prefix}. {due_phrase} \
             This dashboard reminder is local and advisory only; it does not notify authorities \
             or subjects, file with authorities, approve or execute transfers, approve or complete \
             DPIAs, perform external delivery, certify adequacy or compliance, claim production \
             privacy compliance, or claim legal completion."
        ),
        entity_id: "privacy".to_owned(),
        entity_name: "Privacidade".to_owned(),
        source_rule: source_rule.to_owned(),
        source_profile: source_profile.to_owned(),
        params,
        profile_calendar_plan: None,
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_privacy_review",
            "notifications.reminder.privacy.review.action",
            Some(
                match source_profile {
                    "privacy-dpia" => "/v1/privacy/dpias",
                    "privacy-breach-playbook" => "/v1/privacy/breach-playbooks",
                    "privacy-transfer-control" => "/v1/privacy/transfer-controls",
                    _ => "/v1/privacy",
                }
                .to_owned(),
            ),
            Some("/configuracoes?sec=privacidade".to_owned()),
        )),
        recommended_next_steps: vec![
            "Open the privacy register item.".to_owned(),
            "Record a local review or drill receipt when operator evidence exists.".to_owned(),
        ],
        i18n: Some(alert_i18n(
            "notifications.reminder.privacy.review.title",
            "notifications.reminder.privacy.review.body",
            Some("notifications.reminder.privacy.review.action"),
        )),
    })
}

/// An operator-entered string, or `None` when nothing usable was recorded.
///
/// Blank is absent. A field holding only whitespace carries no more information than an absent
/// one, and every site in this crate that reads operator text says so: it must never out-rank a
/// populated fallback, and it must never render as a value the operator can read as a fact.
fn trimmed_non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn follow_up_reminder(
    entity: &Entity,
    book: &Book,
    act: &Act,
    follow_up: &StoredFollowUp,
    due_date: Date,
    today: Date,
    due_soon_days: u16,
) -> DashboardReminder {
    let due_date_text = format_date(due_date);
    let status = reminder_status(today, due_date, due_soon_days).to_owned();
    let severity = match status.as_str() {
        "Overdue" => "Warning",
        "DueSoon" => "Info",
        _ => "Advisory",
    }
    .to_owned();
    let detail = trimmed_non_empty(follow_up.detail.as_deref());
    // Trim and discard the blank BEFORE falling back, not after: a display label of "   " is an
    // absent label, and an operator shown an empty assignee where one is recorded is being shown
    // something false. This is the order `detail` above and `privacy_receipt_sort_key` already use.
    let assignee_display = trimmed_non_empty(follow_up.assignee_display.as_deref())
        .or_else(|| trimmed_non_empty(follow_up.assignee.as_deref()))
        .unwrap_or("");
    let body_key = if detail.is_some() {
        "notifications.reminder.followUp.body"
    } else {
        "notifications.reminder.followUp.bodyNoDetail"
    };
    let reason = match detail {
        Some(detail) => format!(
            "Follow-up \"{}\" for act \"{}\" is due on {}. {}",
            follow_up.title, act.title, due_date_text, detail
        ),
        None => format!(
            "Follow-up \"{}\" for act \"{}\" is due on {}.",
            follow_up.title, act.title, due_date_text
        ),
    };

    DashboardReminder {
        due_date: due_date_text.clone(),
        severity,
        status,
        reason,
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: "act-follow-up".to_owned(),
        source_profile: format!("follow-up:{}", follow_up.id),
        params: dashboard_alert_params([
            ("follow_up_id", follow_up.id.clone()),
            ("follow_up_title", follow_up.title.clone()),
            (
                "follow_up_detail",
                detail.map(str::to_owned).unwrap_or_default(),
            ),
            ("act_id", act.id.to_string()),
            ("act_title", act.title.clone()),
            ("book_id", book.id.to_string()),
            ("entity_id", entity.id.to_string()),
            ("entity_name", entity.name.clone()),
            ("due_date", due_date_text),
            ("assignee", follow_up.assignee.clone().unwrap_or_default()),
            ("assignee_display", assignee_display.to_owned()),
            (
                "agenda_number",
                follow_up
                    .agenda_number
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            ),
            (
                "deliberation_index",
                follow_up
                    .deliberation_index
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            ),
        ]),
        profile_calendar_plan: None,
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_act_follow_up",
            "notifications.reminder.followUp.action",
            Some(format!("/v1/acts/{}/follow-ups", act.id)),
            Some(format!("/atas/{}", act.id)),
        )),
        recommended_next_steps: vec![
            "Open the act follow-up list.".to_owned(),
            "Complete the follow-up row when the task is done.".to_owned(),
        ],
        i18n: Some(alert_i18n(
            "notifications.reminder.followUp.title",
            body_key,
            Some("notifications.reminder.followUp.action"),
        )),
    }
}

fn annual_general_meeting_reminders(
    entity: &Entity,
    context: &ProfileCalendarReminderContext<'_>,
) -> Vec<DashboardReminder> {
    if !entity.is_consistent() || !supports_profile_calendar_plan(entity.kind) {
        return Vec::new();
    }

    let plan = profile_calendar_plan_for(entity.kind);
    plan.rules
        .iter()
        .filter_map(|preset| profile_calendar_reminder(entity, &plan, preset, context))
        .collect()
}

struct ProfileCalendarReminderContext<'a> {
    books: &'a HashMap<BookId, Book>,
    acts: &'a HashMap<ActId, Act>,
    registry_extract: Option<&'a RegistryExtract>,
    today: Date,
    due_soon_days: u16,
}

fn profile_calendar_reminder(
    entity: &Entity,
    plan: &ProfileCalendarPlan,
    preset: &CalendarPreset,
    context: &ProfileCalendarReminderContext<'_>,
) -> Option<DashboardReminder> {
    let evaluation = evaluate_profile_calendar_rule(
        preset,
        ProfileCalendarEvaluationContext {
            today: context.today,
            recorded_fiscal_year_end: entity.fiscal_year_end.as_deref(),
            constitution_date: registry_constitution_date(context.registry_extract),
        },
    );

    match evaluation {
        ProfileCalendarRuleEvaluation::Scheduled(scheduled) => {
            if has_recent_calendar_signal(
                entity,
                context.books,
                context.acts,
                scheduled.due_date.year(),
            ) {
                return None;
            }
            Some(supported_profile_calendar_advisory(
                entity, plan, preset, scheduled, context,
            ))
        }
        ProfileCalendarRuleEvaluation::Unsupported(unsupported) => Some(
            unsupported_profile_calendar_advisory(entity, plan, preset, unsupported),
        ),
        ProfileCalendarRuleEvaluation::Suppressed(_) => None,
    }
}

fn supported_profile_calendar_advisory(
    entity: &Entity,
    plan: &ProfileCalendarPlan,
    preset: &CalendarPreset,
    scheduled: ProfileCalendarScheduledRule,
    context: &ProfileCalendarReminderContext<'_>,
) -> DashboardReminder {
    let due_date = scheduled.due_date;
    let params = supported_profile_calendar_params(preset, scheduled);
    DashboardReminder {
        due_date: format_date(due_date),
        severity: "Advisory".to_owned(),
        status: reminder_status(context.today, due_date, context.due_soon_days).to_owned(),
        reason: format!(
            "The {} calendar preset \"{}\" produces a local advisory date of {} \
             ({}). \
             No sealed or archived {} act dated {} is recorded for this entity. \
             Chancela does not claim a legal deadline, legal calendar authority, or legal \
             compliance from this local plan.",
            family_calendar_label(plan.family),
            preset.label,
            format_date(due_date),
            scheduled.due_basis.reason_fragment(),
            calendar_signal_label(plan.family),
            due_date.year()
        ),
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: preset.id.to_owned(),
        source_profile: plan.template_family.to_owned(),
        params,
        profile_calendar_plan: Some(supported_profile_calendar_plan_view(preset, scheduled)),
        law_refs: calendar_law_refs(preset),
        action: Some(dashboard_action(
            "open_entity",
            "notifications.reminder.annual.action",
            Some(format!("/v1/entities/{}", entity.id)),
            Some(format!("/entidades/{}", entity.id)),
        )),
        recommended_next_steps: calendar_next_steps(plan.family),
        i18n: None,
    }
}

fn unsupported_profile_calendar_advisory(
    entity: &Entity,
    plan: &ProfileCalendarPlan,
    preset: &CalendarPreset,
    unsupported: ProfileCalendarUnsupportedRule,
) -> DashboardReminder {
    let params = unsupported_profile_calendar_params(preset, unsupported);

    DashboardReminder {
        due_date: String::new(),
        severity: "Advisory".to_owned(),
        status: "Pending".to_owned(),
        reason: format!(
            "The {} calendar preset \"{}\" is encoded in the entity profile, but no local \
             due-date rule or fiscal-year offset is configured/encoded for it. Chancela does \
             not calculate a legal deadline for this preset; this advisory only makes the \
             unsupported preset visible.",
            family_calendar_label(plan.family),
            preset.label
        ),
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        source_rule: preset.id.to_owned(),
        source_profile: plan.template_family.to_owned(),
        params,
        profile_calendar_plan: Some(unsupported_profile_calendar_plan_view(preset, unsupported)),
        law_refs: Vec::new(),
        action: Some(dashboard_action(
            "open_entity",
            "notifications.reminder.annual.action",
            Some(format!("/v1/entities/{}", entity.id)),
            Some(format!("/entidades/{}", entity.id)),
        )),
        recommended_next_steps: vec![
            "Review the encoded profile calendar preset manually.".to_owned(),
            "Add a local due-date rule only after the calendar rule is verified and encoded."
                .to_owned(),
        ],
        i18n: None,
    }
}

fn supported_profile_calendar_params(
    preset: &CalendarPreset,
    scheduled: ProfileCalendarScheduledRule,
) -> BTreeMap<String, String> {
    let mut params = profile_calendar_preset_params(preset, true, true, false);
    if let Some(months_after_fiscal_year_end) = scheduled.months_after_fiscal_year_end {
        params.insert(
            "months_after_fiscal_year_end".to_owned(),
            months_after_fiscal_year_end.to_string(),
        );
    }
    if let Some(fiscal_year_end) = scheduled.fiscal_year_end {
        params.insert("fiscal_year_end".to_owned(), fiscal_year_end.format_mm_dd());
    }
    if let Some(annual_fixed_date) = scheduled.annual_fixed_date {
        params.insert(
            "annual_fixed_month".to_owned(),
            annual_fixed_date.month.to_string(),
        );
        params.insert(
            "annual_fixed_day".to_owned(),
            annual_fixed_date.day.to_string(),
        );
    }
    params.insert("due_year".to_owned(), scheduled.due_date.year().to_string());
    params.insert(
        "due_basis".to_owned(),
        scheduled.due_basis.as_str().to_owned(),
    );
    params
}

fn unsupported_profile_calendar_params(
    preset: &CalendarPreset,
    unsupported: ProfileCalendarUnsupportedRule,
) -> BTreeMap<String, String> {
    let mut params = profile_calendar_preset_params(preset, false, false, false);
    params.insert(
        "unsupported_reason".to_owned(),
        unsupported.reason.as_str().to_owned(),
    );
    params
}

fn profile_calendar_preset_params(
    preset: &CalendarPreset,
    local_due_date_rule_configured: bool,
    local_due_date_calculated: bool,
    legal_deadline_calculated: bool,
) -> BTreeMap<String, String> {
    let mut params = BTreeMap::new();
    params.insert(
        "calendar_preset_support".to_owned(),
        preset.support_status.as_str().to_owned(),
    );
    params.insert("preset_id".to_owned(), preset.id.to_owned());
    params.insert("preset_label".to_owned(), preset.label.to_owned());
    params.insert("rule_kind".to_owned(), preset.rule_kind.as_str().to_owned());
    params.insert(
        "review_status".to_owned(),
        preset.review_status.as_str().to_owned(),
    );
    params.insert(
        "source_status".to_owned(),
        preset.source_status.as_str().to_owned(),
    );
    params.insert(
        "local_due_date_rule_configured".to_owned(),
        local_due_date_rule_configured.to_string(),
    );
    params.insert(
        "local_due_date_calculated".to_owned(),
        local_due_date_calculated.to_string(),
    );
    params.insert(
        "legal_deadline_calculated".to_owned(),
        legal_deadline_calculated.to_string(),
    );
    insert_profile_calendar_no_claim_params(&mut params, preset.no_claims);
    params
}

fn insert_profile_calendar_no_claim_params(
    params: &mut BTreeMap<String, String>,
    no_claims: ProfileCalendarNoClaimFlags,
) {
    params.insert(
        "local_advisory_only".to_owned(),
        no_claims.local_advisory_only.to_string(),
    );
    params.insert(
        "legal_deadline_authority_claimed".to_owned(),
        no_claims.legal_deadline_authority_claimed.to_string(),
    );
    params.insert(
        "legal_calendar_authority_claimed".to_owned(),
        no_claims.legal_calendar_authority_claimed.to_string(),
    );
    params.insert(
        "legal_compliance_claimed".to_owned(),
        no_claims.legal_compliance_claimed.to_string(),
    );
    params.insert(
        "compliance_status_claimed".to_owned(),
        no_claims.compliance_status_claimed.to_string(),
    );
    params.insert(
        "workflow_completion_claimed".to_owned(),
        no_claims.workflow_completion_claimed.to_string(),
    );
    params.insert(
        "external_delivery_claimed".to_owned(),
        no_claims.external_delivery_claimed.to_string(),
    );
    params.insert(
        "external_calendar_sync_claimed".to_owned(),
        no_claims.external_calendar_sync_claimed.to_string(),
    );
    params.insert(
        "webhook_delivery_claimed".to_owned(),
        no_claims.webhook_delivery_claimed.to_string(),
    );
    params.insert(
        "legal_review_claimed".to_owned(),
        no_claims.legal_review_claimed.to_string(),
    );
    params.insert(
        "dre_verification_claimed".to_owned(),
        no_claims.dre_verification_claimed.to_string(),
    );
    params.insert(
        "provider_effect_claimed".to_owned(),
        no_claims.provider_effect_claimed.to_string(),
    );
    params.insert(
        "certification_claimed".to_owned(),
        no_claims.certification_claimed.to_string(),
    );
}

fn supported_profile_calendar_plan_view(
    preset: &CalendarPreset,
    scheduled: ProfileCalendarScheduledRule,
) -> DashboardProfileCalendarPlan {
    profile_calendar_plan_view(
        preset,
        DashboardProfileCalendarEvaluation {
            local_due_date_rule_configured: true,
            local_due_date_calculated: true,
            legal_deadline_calculated: false,
            fiscal_year_end: scheduled
                .fiscal_year_end
                .map(|fiscal_year_end| fiscal_year_end.format_mm_dd()),
            due_year: Some(scheduled.due_date.year()),
            due_basis: Some(scheduled.due_basis.as_str().to_owned()),
            unsupported_reason: None,
        },
    )
}

fn unsupported_profile_calendar_plan_view(
    preset: &CalendarPreset,
    unsupported: ProfileCalendarUnsupportedRule,
) -> DashboardProfileCalendarPlan {
    profile_calendar_plan_view(
        preset,
        DashboardProfileCalendarEvaluation {
            local_due_date_rule_configured: false,
            local_due_date_calculated: false,
            legal_deadline_calculated: false,
            fiscal_year_end: None,
            due_year: None,
            due_basis: None,
            unsupported_reason: Some(unsupported.reason.as_str().to_owned()),
        },
    )
}

fn profile_calendar_plan_view(
    preset: &CalendarPreset,
    evaluation: DashboardProfileCalendarEvaluation,
) -> DashboardProfileCalendarPlan {
    DashboardProfileCalendarPlan {
        preset_id: preset.id.to_owned(),
        preset_label: preset.label.to_owned(),
        rule_kind: preset.rule_kind.as_str().to_owned(),
        support_status: preset.support_status.as_str().to_owned(),
        review_status: preset.review_status.as_str().to_owned(),
        source_status: preset.source_status.as_str().to_owned(),
        due_rule: profile_calendar_due_rule_view(preset),
        evaluation,
        no_claims: dashboard_profile_calendar_no_claims(preset.no_claims),
    }
}

fn profile_calendar_due_rule_view(preset: &CalendarPreset) -> DashboardProfileCalendarDueRule {
    match preset.due_rule {
        ProfileCalendarDueRule::FiscalYearEndOffset {
            months_after_fiscal_year_end,
            default_fiscal_year_end,
        } => DashboardProfileCalendarDueRule {
            kind: preset.due_rule.kind().to_owned(),
            months_after_fiscal_year_end: Some(months_after_fiscal_year_end),
            default_fiscal_year_end: Some(default_fiscal_year_end.format_mm_dd()),
            annual_fixed_month: None,
            annual_fixed_day: None,
            unsupported_reason: None,
        },
        ProfileCalendarDueRule::AnnualFixedDate { month, day } => DashboardProfileCalendarDueRule {
            kind: preset.due_rule.kind().to_owned(),
            months_after_fiscal_year_end: None,
            default_fiscal_year_end: None,
            annual_fixed_month: Some(month),
            annual_fixed_day: Some(day),
            unsupported_reason: None,
        },
        ProfileCalendarDueRule::NotEncoded { reason } => DashboardProfileCalendarDueRule {
            kind: preset.due_rule.kind().to_owned(),
            months_after_fiscal_year_end: None,
            default_fiscal_year_end: None,
            annual_fixed_month: None,
            annual_fixed_day: None,
            unsupported_reason: Some(reason.as_str().to_owned()),
        },
    }
}

fn dashboard_profile_calendar_no_claims(
    no_claims: ProfileCalendarNoClaimFlags,
) -> DashboardProfileCalendarNoClaimFlags {
    DashboardProfileCalendarNoClaimFlags {
        local_advisory_only: no_claims.local_advisory_only,
        legal_deadline_authority_claimed: no_claims.legal_deadline_authority_claimed,
        legal_calendar_authority_claimed: no_claims.legal_calendar_authority_claimed,
        legal_compliance_claimed: no_claims.legal_compliance_claimed,
        compliance_status_claimed: no_claims.compliance_status_claimed,
        workflow_completion_claimed: no_claims.workflow_completion_claimed,
        external_delivery_claimed: no_claims.external_delivery_claimed,
        external_calendar_sync_claimed: no_claims.external_calendar_sync_claimed,
        webhook_delivery_claimed: no_claims.webhook_delivery_claimed,
        legal_review_claimed: no_claims.legal_review_claimed,
        dre_verification_claimed: no_claims.dre_verification_claimed,
        provider_effect_claimed: no_claims.provider_effect_claimed,
        certification_claimed: no_claims.certification_claimed,
    }
}

fn calendar_law_refs(preset: &CalendarPreset) -> Vec<DashboardLawReference> {
    preset
        .law_refs
        .iter()
        .map(|law_ref| DashboardLawReference {
            diploma_id: law_ref.diploma_id.to_owned(),
            article: law_ref.article.to_owned(),
            label: law_ref.label.to_owned(),
            heading: String::new(),
            verification: law_ref.source_status.dashboard_verification().to_owned(),
            source_url: None,
            source_complete: false,
            // Calendar-preset refs carry only their preset source-status, never corpus provenance.
            review_method: None,
            review_note: None,
        })
        .collect()
}

fn calendar_next_steps(family: EntityFamily) -> Vec<String> {
    match family {
        EntityFamily::CommercialCompany => vec![
            "Prepare annual accounts approval minutes if the meeting has not occurred.".to_owned(),
            "Seal or archive the annual general meeting minutes once approved.".to_owned(),
        ],
        EntityFamily::Association | EntityFamily::Cooperative => vec![
            "Prepare the annual general meeting record if the meeting has not occurred.".to_owned(),
            "Seal or archive the annual minutes once approved.".to_owned(),
        ],
        EntityFamily::Foundation => vec![
            "Review the annual foundation governance record.".to_owned(),
            "Seal or archive the relevant annual act once approved.".to_owned(),
        ],
        EntityFamily::Condominium => vec![
            "Review the annual condominium assembly record.".to_owned(),
            "Seal or archive the assembly minutes once approved.".to_owned(),
        ],
    }
}

fn family_calendar_label(family: EntityFamily) -> &'static str {
    match family {
        EntityFamily::CommercialCompany => "commercial-company",
        EntityFamily::Condominium => "condominium",
        EntityFamily::Association => "association",
        EntityFamily::Foundation => "foundation",
        EntityFamily::Cooperative => "cooperative",
    }
}

fn calendar_signal_label(family: EntityFamily) -> &'static str {
    match family {
        EntityFamily::CommercialCompany | EntityFamily::Association | EntityFamily::Cooperative => {
            "Assembleia Geral"
        }
        EntityFamily::Condominium => "condominium assembly",
        EntityFamily::Foundation => "administration/assembly",
    }
}

fn registry_constitution_date(registry_extract: Option<&RegistryExtract>) -> Option<Date> {
    let constitution_date = registry_extract?.effective_data_constituicao()?;
    parse_dashboard_date(&constitution_date)
}

fn reminder_status(today: Date, due_date: Date, due_soon_days: u16) -> &'static str {
    if today > due_date {
        return "Overdue";
    }
    let days_until = due_date.to_julian_day() - today.to_julian_day();
    if days_until <= i32::from(due_soon_days) {
        "DueSoon"
    } else {
        "Upcoming"
    }
}

fn has_recent_calendar_signal(
    entity: &Entity,
    books: &HashMap<BookId, Book>,
    acts: &HashMap<ActId, Act>,
    due_year: i32,
) -> bool {
    let signal_book_kinds = calendar_signal_book_kinds(entity.family);
    acts.values().any(|act| {
        let Some(book) = books.get(&act.book_id) else {
            return false;
        };
        book.entity_id == entity.id
            && signal_book_kinds.contains(&book.kind)
            && matches!(act.state, ActState::Sealed | ActState::Archived)
            && act
                .meeting_date
                .is_some_and(|meeting_date| meeting_date.year() == due_year)
    })
}

fn calendar_signal_book_kinds(family: EntityFamily) -> &'static [BookKind] {
    match family {
        EntityFamily::CommercialCompany | EntityFamily::Association | EntityFamily::Cooperative => {
            &[BookKind::AssembleiaGeral]
        }
        EntityFamily::Condominium => &[BookKind::Condominio],
        // Foundation templates model the annual board spine, while legacy/test data may still use
        // the general-assembly book as the shared family ata container.
        EntityFamily::Foundation => &[BookKind::GerenciaAdministracao, BookKind::AssembleiaGeral],
    }
}
