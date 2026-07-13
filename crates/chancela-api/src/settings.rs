//! Application settings (contract §2.8): a typed, versioned configuration document plus its
//! `GET`/`PUT` endpoints and optional file persistence.
//!
//! The settings document is the single place where operator-facing configuration lives —
//! organization identity, document defaults, signing preferences, AI/MCP controls, and appearance. It is
//! **whole-document** on the wire: `PUT` replaces the entire [`Settings`] (simpler than a
//! PATCH merge, and the Configurações UI always holds the full form). Every field carries a
//! serde default so a partial or empty stored document still deserializes cleanly, which is
//! what makes a hand-edited or older `settings.json` safe to load.
//!
//! ## Persistence
//!
//! When [`AppState`](crate::AppState) is built with a data directory (see
//! [`AppState::with_data_dir`](crate::AppState::with_data_dir) /
//! [`AppState::from_env`](crate::AppState::from_env)), `settings.json` in that directory is
//! read at startup and rewritten atomically (temp file + rename) on every successful `PUT`.
//! Without a data directory the settings live purely in memory and reset on restart, exactly
//! like the rest of the scaffold state.
//!
//! Each successful `PUT` also appends a `settings.updated` event to the audit ledger (DAT-10),
//! so a configuration change is as auditable as any domain mutation.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Query, State};
use chancela_cae::{CaeSourceFormat, PreferredOfficialSource};
use chancela_core::NumberingScheme;
use chancela_csc::CscSecrets;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use chancela_authz::{Permission, Scope};

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::require_permission;
use crate::error::ApiError;

/// The current schema version of the settings document. Bumped only on a breaking shape
/// change; a stored document with an older/newer value still loads (unknown fields ignored,
/// missing fields defaulted) but this lets a future migration recognise what it is reading.
pub const SETTINGS_SCHEMA_VERSION: u32 = 1;

// --- The settings document ----------------------------------------------------------------

/// The full, versioned settings document (contract §2.8).
///
/// `#[serde(default)]` on the container means any missing section falls back to its default,
/// so both an empty `{}` and a partial document deserialize into a complete, valid value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Schema version discriminator (always [`SETTINGS_SCHEMA_VERSION`] when written here).
    pub schema_version: u32,
    /// Who the books belong to, and the default audit actor.
    pub organization: OrganizationSettings,
    /// Document-production defaults (locale, numbering).
    pub documents: DocumentSettings,
    /// Catalog-management sources (currently the CAE auto-update dataset URL).
    pub catalog: CatalogSettings,
    /// Signing preferences and trust-service endpoints.
    pub signing: SigningSettings,
    /// Backend commercial-registry auto-update scheduling. Defaults disabled and non-invasive.
    #[serde(
        default,
        skip_serializing_if = "RegistryAutoUpdateSettings::is_default"
    )]
    pub registry_auto_update: RegistryAutoUpdateSettings,
    /// Local workflow policy for advisory dashboard behavior.
    pub workflow: WorkflowSettings,
    /// Local data-management policy defaults. Does not authorize legal retention/disposal work.
    pub data_management: DataManagementSettings,
    /// Tenant-level AI/MCP controls. Defaults off so older settings documents do not enable AI.
    pub ai: AiSettings,
    /// Platform operations controls: service desired state, logging levels, and audit metadata.
    pub platform: PlatformSettings,
    /// Purely cosmetic front-end preferences (theme, leather texture).
    pub appearance: AppearanceSettings,
    /// Front-end layout preferences that are safe to persist server-side.
    pub ui: UiSettings,
    /// First-use onboarding state (plan t29 §4.1): the authoritative "is the app set up?" signal.
    pub onboarding: OnboardingSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            schema_version: SETTINGS_SCHEMA_VERSION,
            organization: OrganizationSettings::default(),
            documents: DocumentSettings::default(),
            catalog: CatalogSettings::default(),
            signing: SigningSettings::default(),
            registry_auto_update: RegistryAutoUpdateSettings::default(),
            workflow: WorkflowSettings::default(),
            data_management: DataManagementSettings::default(),
            ai: AiSettings::default(),
            platform: PlatformSettings::default(),
            appearance: AppearanceSettings::default(),
            ui: UiSettings::default(),
            onboarding: OnboardingSettings::default(),
        }
    }
}

/// Commercial-registry auto-update controls.
///
/// This is only scheduling/state policy. The full certidao access code is still not stored in
/// settings or registry provenance, so a worker can plan due records safely but cannot invent a
/// live refresh without a future secure code source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RegistryAutoUpdateSettings {
    /// Master switch. Default `false`: no background or worker-triggered update is due.
    pub enabled: bool,
    /// Simple backend cadence. It is advisory for the worker scheduler; handlers still re-check
    /// stale/backoff state before accepting work.
    pub cadence: RegistryAutoUpdateCadence,
    /// How old an imported extract may be before it is considered stale.
    pub stale_threshold_hours: u16,
    /// First retry/backoff window after a failed or manual-required attempt.
    pub min_backoff_minutes: u16,
    /// Maximum retry/backoff window.
    pub max_backoff_minutes: u16,
    /// Hard cap for a single due-plan slice.
    pub max_attempts_per_run: u16,
    /// Defaults applied to entities that do not yet have a per-entity override.
    pub entity_defaults: RegistryAutoUpdateEntityDefaults,
}

impl Default for RegistryAutoUpdateSettings {
    fn default() -> Self {
        RegistryAutoUpdateSettings {
            enabled: false,
            cadence: RegistryAutoUpdateCadence::default(),
            stale_threshold_hours: 24 * 30,
            min_backoff_minutes: 60,
            max_backoff_minutes: 24 * 60,
            max_attempts_per_run: 10,
            entity_defaults: RegistryAutoUpdateEntityDefaults::default(),
        }
    }
}

impl RegistryAutoUpdateSettings {
    pub(crate) fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        self.cadence.validate()?;
        if !(1..=24 * 365).contains(&self.stale_threshold_hours) {
            return Err(ApiError::Unprocessable(format!(
                "registry_auto_update.stale_threshold_hours must be between 1 and 8760, got {}",
                self.stale_threshold_hours
            )));
        }
        if !(1..=7 * 24 * 60).contains(&self.min_backoff_minutes) {
            return Err(ApiError::Unprocessable(format!(
                "registry_auto_update.min_backoff_minutes must be between 1 and 10080, got {}",
                self.min_backoff_minutes
            )));
        }
        if !(1..=7 * 24 * 60).contains(&self.max_backoff_minutes) {
            return Err(ApiError::Unprocessable(format!(
                "registry_auto_update.max_backoff_minutes must be between 1 and 10080, got {}",
                self.max_backoff_minutes
            )));
        }
        if self.min_backoff_minutes > self.max_backoff_minutes {
            return Err(ApiError::Unprocessable(
                "registry_auto_update.min_backoff_minutes must be <= max_backoff_minutes"
                    .to_owned(),
            ));
        }
        if !(1..=100).contains(&self.max_attempts_per_run) {
            return Err(ApiError::Unprocessable(format!(
                "registry_auto_update.max_attempts_per_run must be between 1 and 100, got {}",
                self.max_attempts_per_run
            )));
        }
        for (i, profile) in self.entity_defaults.enabled_profiles.iter().enumerate() {
            let trimmed = profile.trim();
            if trimmed.is_empty() || trimmed.len() > 64 || trimmed.chars().any(char::is_control) {
                return Err(ApiError::Unprocessable(format!(
                    "registry_auto_update.entity_defaults.enabled_profiles[{i}] must be a non-empty profile name up to 64 non-control characters"
                )));
            }
        }
        Ok(())
    }
}

pub const DEFAULT_WORKFLOW_REMINDER_DASHBOARD_LIMIT: u16 = 5;
pub const DEFAULT_WORKFLOW_REMINDER_DUE_SOON_DAYS: u16 = 45;
pub const DEFAULT_WORKFLOW_REMINDER_ATTENDANCE_LOOKAHEAD_DAYS: u16 = 45;
pub const DEFAULT_RETAINED_EXPORT_CLEANUP_MINIMUM_AGE_DAYS: u16 = 30;
pub const DEFAULT_RETAINED_EXPORT_CLEANUP_KEEP_LATEST: u16 = 5;
pub const DEFAULT_BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS: u16 = 90;
pub const DEFAULT_BACKUP_RECOVERY_TARGET_RPO_MINUTES: u32 = 24 * 60;
pub const DEFAULT_BACKUP_RECOVERY_TARGET_RTO_MINUTES: u32 = 4 * 60;

const MAX_WORKFLOW_REMINDER_DASHBOARD_LIMIT: u16 = 50;
const MAX_WORKFLOW_REMINDER_DAYS: u16 = 365;
const MAX_RETAINED_EXPORT_CLEANUP_MINIMUM_AGE_DAYS: u16 = 3650;
const MAX_RETAINED_EXPORT_CLEANUP_KEEP_LATEST: u16 = 100;
const MAX_BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS: u16 = 3650;
const MAX_BACKUP_RECOVERY_TARGET_MINUTES: u32 = 60 * 24 * 365;

/// Local workflow controls. These are advisory settings for in-app surfaces only; they do not
/// create legal-calendar authority, external delivery guarantees, or workflow-completion gates.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkflowSettings {
    /// Dashboard reminder generation policy.
    pub reminders: WorkflowReminderSettings,
}

impl WorkflowSettings {
    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        self.reminders.validate()
    }
}

/// Advisory dashboard reminder policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkflowReminderSettings {
    /// Master switch for local dashboard reminder cards/feed entries.
    pub enabled: bool,
    /// Maximum number of local reminders returned by the dashboard.
    pub dashboard_limit: u16,
    /// Due dates within this many days are labelled `DueSoon`.
    pub due_soon_days: u16,
    /// Future meeting dates within this many days are scanned for attendance hygiene reminders.
    pub attendance_lookahead_days: u16,
    /// Per-family source switches for the existing local reminder generators.
    pub sources: WorkflowReminderSourceSettings,
}

impl Default for WorkflowReminderSettings {
    fn default() -> Self {
        WorkflowReminderSettings {
            enabled: true,
            dashboard_limit: DEFAULT_WORKFLOW_REMINDER_DASHBOARD_LIMIT,
            due_soon_days: DEFAULT_WORKFLOW_REMINDER_DUE_SOON_DAYS,
            attendance_lookahead_days: DEFAULT_WORKFLOW_REMINDER_ATTENDANCE_LOOKAHEAD_DAYS,
            sources: WorkflowReminderSourceSettings::default(),
        }
    }
}

impl WorkflowReminderSettings {
    fn validate(&self) -> Result<(), ApiError> {
        if self.dashboard_limit > MAX_WORKFLOW_REMINDER_DASHBOARD_LIMIT {
            return Err(ApiError::Unprocessable(format!(
                "workflow.reminders.dashboard_limit must be between 0 and {}, got {}",
                MAX_WORKFLOW_REMINDER_DASHBOARD_LIMIT, self.dashboard_limit
            )));
        }
        if self.due_soon_days > MAX_WORKFLOW_REMINDER_DAYS {
            return Err(ApiError::Unprocessable(format!(
                "workflow.reminders.due_soon_days must be between 0 and {}, got {}",
                MAX_WORKFLOW_REMINDER_DAYS, self.due_soon_days
            )));
        }
        if self.attendance_lookahead_days > MAX_WORKFLOW_REMINDER_DAYS {
            return Err(ApiError::Unprocessable(format!(
                "workflow.reminders.attendance_lookahead_days must be between 0 and {}, got {}",
                MAX_WORKFLOW_REMINDER_DAYS, self.attendance_lookahead_days
            )));
        }
        Ok(())
    }
}

/// Per-family switches for local dashboard reminder generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkflowReminderSourceSettings {
    /// Annual/profile calendar advisory reminders.
    pub profile_calendar: bool,
    /// Open act follow-up reminders.
    pub act_follow_ups: bool,
    /// Draft/review act attendance hygiene reminders.
    pub attendance_hygiene: bool,
    /// Local privacy breach/transfer review-depth reminders.
    pub privacy_control_reviews: bool,
}

impl Default for WorkflowReminderSourceSettings {
    fn default() -> Self {
        WorkflowReminderSourceSettings {
            profile_calendar: true,
            act_follow_ups: true,
            attendance_hygiene: true,
            privacy_control_reviews: true,
        }
    }
}

/// Local data-management policy defaults. These values only seed the retained-export cleanup
/// preview/execution request; they do not create legal-retention, archive-disposal, or erasure
/// authority.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DataManagementSettings {
    /// Default policy for retained local export-file cleanup previews.
    pub retained_export_cleanup: RetainedExportCleanupSettings,
    /// Operator-declared local backup recovery review policy. It only drives local freshness
    /// warnings; it does not execute restore, prove custody, or certify production DR targets.
    pub backup_recovery: BackupRecoveryPolicySettings,
}

impl DataManagementSettings {
    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        self.retained_export_cleanup.validate()?;
        self.backup_recovery.validate()
    }
}

/// Defaults for `POST /v1/data/cleanup` when the target is `exports`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RetainedExportCleanupSettings {
    /// Minimum file age, in days, before an export can be previewed as cleanup-eligible.
    pub minimum_age_days: u16,
    /// Number of newest retained export files to keep even when they meet the age rule.
    pub keep_latest: u16,
}

impl Default for RetainedExportCleanupSettings {
    fn default() -> Self {
        RetainedExportCleanupSettings {
            minimum_age_days: DEFAULT_RETAINED_EXPORT_CLEANUP_MINIMUM_AGE_DAYS,
            keep_latest: DEFAULT_RETAINED_EXPORT_CLEANUP_KEEP_LATEST,
        }
    }
}

impl RetainedExportCleanupSettings {
    fn validate(&self) -> Result<(), ApiError> {
        if self.minimum_age_days > MAX_RETAINED_EXPORT_CLEANUP_MINIMUM_AGE_DAYS {
            return Err(ApiError::Unprocessable(format!(
                "data_management.retained_export_cleanup.minimum_age_days must be between 0 and {}, got {}",
                MAX_RETAINED_EXPORT_CLEANUP_MINIMUM_AGE_DAYS, self.minimum_age_days
            )));
        }
        if self.keep_latest > MAX_RETAINED_EXPORT_CLEANUP_KEEP_LATEST {
            return Err(ApiError::Unprocessable(format!(
                "data_management.retained_export_cleanup.keep_latest must be between 0 and {}, got {}",
                MAX_RETAINED_EXPORT_CLEANUP_KEEP_LATEST, self.keep_latest
            )));
        }
        Ok(())
    }
}

/// Local policy used to review recovery-drill freshness. These are operator targets only: the
/// application derives warning metadata from receipts but does not certify RPO/RTO compliance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BackupRecoveryPolicySettings {
    /// Maximum age, in days, before the latest successful local drill receipt is considered stale.
    pub max_drill_age_days: u16,
    /// Operator-declared target recovery point objective in minutes.
    pub target_rpo_minutes: u32,
    /// Operator-declared target recovery time objective in minutes.
    pub target_rto_minutes: u32,
}

impl Default for BackupRecoveryPolicySettings {
    fn default() -> Self {
        BackupRecoveryPolicySettings {
            max_drill_age_days: DEFAULT_BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS,
            target_rpo_minutes: DEFAULT_BACKUP_RECOVERY_TARGET_RPO_MINUTES,
            target_rto_minutes: DEFAULT_BACKUP_RECOVERY_TARGET_RTO_MINUTES,
        }
    }
}

impl BackupRecoveryPolicySettings {
    fn validate(&self) -> Result<(), ApiError> {
        if self.max_drill_age_days == 0
            || self.max_drill_age_days > MAX_BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS
        {
            return Err(ApiError::Unprocessable(format!(
                "data_management.backup_recovery.max_drill_age_days must be between 1 and {}, got {}",
                MAX_BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS, self.max_drill_age_days
            )));
        }
        if self.target_rpo_minutes == 0
            || self.target_rpo_minutes > MAX_BACKUP_RECOVERY_TARGET_MINUTES
        {
            return Err(ApiError::Unprocessable(format!(
                "data_management.backup_recovery.target_rpo_minutes must be between 1 and {}, got {}",
                MAX_BACKUP_RECOVERY_TARGET_MINUTES, self.target_rpo_minutes
            )));
        }
        if self.target_rto_minutes == 0
            || self.target_rto_minutes > MAX_BACKUP_RECOVERY_TARGET_MINUTES
        {
            return Err(ApiError::Unprocessable(format!(
                "data_management.backup_recovery.target_rto_minutes must be between 1 and {}, got {}",
                MAX_BACKUP_RECOVERY_TARGET_MINUTES, self.target_rto_minutes
            )));
        }
        Ok(())
    }
}

/// Simple cadence options, intentionally much smaller than cron.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RegistryAutoUpdateCadence {
    /// Run at most once per N hours.
    IntervalHours { hours: u16 },
    /// Run once per UTC day near `hour_utc`.
    Daily { hour_utc: u8 },
    /// Run once per UTC week near `weekday` + `hour_utc`.
    Weekly {
        weekday: RegistryAutoUpdateWeekday,
        hour_utc: u8,
    },
}

impl Default for RegistryAutoUpdateCadence {
    fn default() -> Self {
        RegistryAutoUpdateCadence::IntervalHours { hours: 24 }
    }
}

impl RegistryAutoUpdateCadence {
    fn validate(&self) -> Result<(), ApiError> {
        match self {
            RegistryAutoUpdateCadence::IntervalHours { hours } => {
                if !(1..=24 * 30).contains(hours) {
                    return Err(ApiError::Unprocessable(format!(
                        "registry_auto_update.cadence.hours must be between 1 and 720, got {hours}"
                    )));
                }
            }
            RegistryAutoUpdateCadence::Daily { hour_utc }
            | RegistryAutoUpdateCadence::Weekly { hour_utc, .. } => {
                if *hour_utc > 23 {
                    return Err(ApiError::Unprocessable(format!(
                        "registry_auto_update.cadence.hour_utc must be between 0 and 23, got {hour_utc}"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Weekday for the weekly registry auto-update cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistryAutoUpdateWeekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

/// Defaults applied when an entity has no explicit worker state override.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RegistryAutoUpdateEntityDefaults {
    /// Whether entities are auto-update candidates by default. Default `false`.
    pub enabled: bool,
    /// Optional entity-profile allow-list. Empty means every entity profile is eligible when
    /// `enabled` is true. The current backend profile is the entity kind name.
    pub enabled_profiles: Vec<String>,
}

/// Tenant-level AI/MCP controls.
///
/// Additive and serde-defaulted: an older `settings.json` that omits this section deserializes with
/// AI disabled. This is the operator-facing tenant switch; MCP's stdio process remains separately
/// gated by its local environment config and does not read live settings over the network.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AiSettings {
    /// Whether tenant-level AI/MCP functionality is enabled. Default `false`.
    pub enabled: bool,
}

/// Stable platform-service id for the currently running API process.
pub const PLATFORM_API_SERVICE_ID: &str = "api";
/// Stable platform-service id for the external stdio MCP process.
pub const PLATFORM_MCP_STDIO_SERVICE_ID: &str = "mcp_stdio";
/// Stable logging id for the application shell as a whole.
pub const PLATFORM_APP_SERVICE_ID: &str = "app";

const PLATFORM_AUDIT_LIMIT: usize = 100;

/// Platform operations settings.
///
/// This is intentionally desired-state metadata only. It does not grant the API process an OS
/// supervisor, spawn processes, or store secrets. External launchers/supervisors may read this
/// section and decide how to reconcile it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PlatformSettings {
    /// Logging levels by platform area and service override.
    pub logging: PlatformLoggingSettings,
    /// Desired state for the API server represented by the current process.
    pub api_server: PlatformServiceControlSettings,
    /// Desired state for the external stdio MCP server.
    pub mcp_stdio_server: PlatformServiceControlSettings,
    /// Settings-backed audit tail for platform operations controls.
    pub audit: Vec<PlatformAuditEvent>,
}

impl Default for PlatformSettings {
    fn default() -> Self {
        Self {
            logging: PlatformLoggingSettings::default(),
            api_server: PlatformServiceControlSettings {
                enabled: true,
                desired_state: PlatformServiceDesiredState::Running,
                last_action: None,
            },
            mcp_stdio_server: PlatformServiceControlSettings::default(),
            audit: Vec::new(),
        }
    }
}

impl PlatformSettings {
    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        self.logging.validate()?;
        for event in &self.audit {
            validate_platform_service_id(&event.service_id)?;
            if event.requested_by.trim().is_empty() {
                return Err(ApiError::Unprocessable(
                    "platform.audit[].requested_by must not be blank".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn control_settings_mut(
        &mut self,
        service_id: &str,
    ) -> Result<&mut PlatformServiceControlSettings, ApiError> {
        match service_id {
            PLATFORM_API_SERVICE_ID => Ok(&mut self.api_server),
            PLATFORM_MCP_STDIO_SERVICE_ID => Ok(&mut self.mcp_stdio_server),
            _ => Err(ApiError::Unprocessable(format!(
                "unknown platform service id {service_id:?}"
            ))),
        }
    }

    pub(crate) fn append_audit(&mut self, event: PlatformAuditEvent) {
        self.audit.push(event);
        let overflow = self.audit.len().saturating_sub(PLATFORM_AUDIT_LIMIT);
        if overflow > 0 {
            self.audit.drain(0..overflow);
        }
    }
}

/// Logging level controls. The service overrides are keyed by stable service id: `app`, `api`,
/// and `mcp_stdio`.
///
/// `global = off` is a platform-wide kill switch. Otherwise a service override is absolute for
/// that service; services without an override use the stricter global/area threshold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PlatformLoggingSettings {
    pub global: PlatformLogLevel,
    pub app: PlatformLogLevel,
    pub api: PlatformLogLevel,
    pub mcp: PlatformLogLevel,
    pub service_overrides: BTreeMap<String, PlatformLogLevel>,
}

impl Default for PlatformLoggingSettings {
    fn default() -> Self {
        Self {
            global: PlatformLogLevel::Info,
            app: PlatformLogLevel::Info,
            api: PlatformLogLevel::Info,
            mcp: PlatformLogLevel::Info,
            service_overrides: BTreeMap::new(),
        }
    }
}

impl PlatformLoggingSettings {
    fn validate(&self) -> Result<(), ApiError> {
        for service_id in self.service_overrides.keys() {
            validate_platform_service_id(service_id)?;
        }
        Ok(())
    }

    pub(crate) fn effective_for(&self, service_id: &str) -> PlatformLogLevel {
        if self.global == PlatformLogLevel::Off {
            return PlatformLogLevel::Off;
        }
        if let Some(level) = self.service_overrides.get(service_id) {
            return *level;
        }
        let area = match service_id {
            PLATFORM_APP_SERVICE_ID => self.app,
            PLATFORM_API_SERVICE_ID => self.api,
            PLATFORM_MCP_STDIO_SERVICE_ID => self.mcp,
            _ => self.global,
        };
        self.global.stricter(area)
    }
}

/// Strict logging levels accepted by the platform settings wire shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformLogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    Off,
}

impl PlatformLogLevel {
    pub(crate) fn allows(self, emitted: PlatformLogLevel) -> bool {
        self != PlatformLogLevel::Off && emitted.rank() >= self.rank()
    }

    fn stricter(self, other: PlatformLogLevel) -> PlatformLogLevel {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    fn rank(self) -> u8 {
        match self {
            PlatformLogLevel::Trace => 0,
            PlatformLogLevel::Debug => 1,
            PlatformLogLevel::Info => 2,
            PlatformLogLevel::Warn => 3,
            PlatformLogLevel::Error => 4,
            PlatformLogLevel::Off => 5,
        }
    }
}

/// Desired-state controls for one platform service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PlatformServiceControlSettings {
    pub enabled: bool,
    pub desired_state: PlatformServiceDesiredState,
    pub last_action: Option<PlatformServiceLastAction>,
}

impl Default for PlatformServiceControlSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            desired_state: PlatformServiceDesiredState::Stopped,
            last_action: None,
        }
    }
}

/// Desired service state stored in settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformServiceDesiredState {
    Running,
    #[default]
    Stopped,
}

/// Operator action stored in service-control metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformServiceAction {
    Start,
    Stop,
    Restart,
}

/// Outcome kind for a platform control action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformControlOutcomeKind {
    Unsupported,
    RestartRequired,
    SupervisorRequired,
}

/// Last control action recorded for a platform service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformServiceLastAction {
    pub action: PlatformServiceAction,
    pub requested_at: String,
    pub requested_by: String,
    pub outcome: PlatformControlOutcomeKind,
    pub message: String,
}

/// Settings-backed audit record for platform operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformAuditEvent {
    pub service_id: String,
    pub action: PlatformServiceAction,
    pub requested_at: String,
    pub requested_by: String,
    pub outcome: PlatformControlOutcomeKind,
    pub desired_state: PlatformServiceDesiredState,
    pub message: String,
}

pub(crate) fn validate_platform_service_id(service_id: &str) -> Result<(), ApiError> {
    if service_id.trim().is_empty() {
        return Err(ApiError::Unprocessable(
            "platform service id must not be blank".to_owned(),
        ));
    }
    if !is_known_platform_service_id(service_id) {
        return Err(ApiError::Unprocessable(format!(
            "unknown platform service id {service_id:?}; expected app, api, or mcp_stdio"
        )));
    }
    Ok(())
}

pub(crate) fn is_known_platform_service_id(service_id: &str) -> bool {
    matches!(
        service_id,
        PLATFORM_APP_SERVICE_ID | PLATFORM_API_SERVICE_ID | PLATFORM_MCP_STDIO_SERVICE_ID
    )
}

/// First-use onboarding flag (plan t29 §4.1). Additive, serde-defaulted, no `schema_version`
/// bump. The web first-run guard treats `completed == false` **and** an empty `GET /v1/users` as
/// "fresh install"; the wizard sets `completed = true` (and stamps `completed_at`) on finish.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OnboardingSettings {
    /// Whether first-use onboarding has been completed.
    pub completed: bool,
    /// When onboarding was completed (RFC 3339), or `null`.
    pub completed_at: Option<String>,
}

/// Front-end layout preferences. Additive and serde-defaulted so older settings documents keep the
/// product defaults without a migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UiSettings {
    /// Visible columns on the registered entities list, in display order.
    pub registered_entity_columns: Vec<RegisteredEntityColumn>,
}

impl Default for UiSettings {
    fn default() -> Self {
        UiSettings {
            registered_entity_columns: default_registered_entity_columns(),
        }
    }
}

fn default_registered_entity_columns() -> Vec<RegisteredEntityColumn> {
    vec![
        RegisteredEntityColumn::Name,
        RegisteredEntityColumn::Nipc,
        RegisteredEntityColumn::Type,
        RegisteredEntityColumn::LastActivity,
        RegisteredEntityColumn::Actions,
    ]
}

/// Configurable columns for the registered entities table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegisteredEntityColumn {
    Name,
    Nipc,
    Seat,
    Type,
    Matricula,
    Constitution,
    Capital,
    Cae,
    Registry,
    LastRegistryChange,
    FiscalYearEnd,
    LastBook,
    LastActivity,
    Actions,
}

/// Organization identity and the default actor recorded on ledger events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OrganizationSettings {
    /// Display name of the organization, or `null` if not set.
    pub name: Option<String>,
    /// Default actor attributed to audit events when a request does not name one.
    pub default_actor: String,
}

impl Default for OrganizationSettings {
    fn default() -> Self {
        OrganizationSettings {
            name: None,
            default_actor: "api".to_owned(),
        }
    }
}

/// Document-production defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DocumentSettings {
    /// UI / document locale.
    pub locale: Locale,
    /// Default numbering scheme proposed when opening a new book.
    pub numbering_scheme_default: NumberingScheme,
}

impl Default for DocumentSettings {
    fn default() -> Self {
        DocumentSettings {
            locale: Locale::default(),
            numbering_scheme_default: NumberingScheme::Sequential,
        }
    }
}

/// Catalog-management configuration (§catalog-v2).
///
/// `POST /v1/cae/refresh` builds an **ordered source chain** from these fields and tries each in
/// turn, the first that fetches, parses, and supersedes the active catalog winning (plan t23 §2.7):
///
/// 1. the built-in official Diário da República diploma pair, prepended when
///    [`cae_official_source`](Self::cae_official_source) is `true`;
/// 2. every entry in [`cae_sources`](Self::cae_sources), in order (each a URL + declared/auto
///    format + optional sha256 pin);
/// 3. the legacy single [`cae_update_url`](Self::cae_update_url) as a trailing `Auto` mirror entry;
/// 4. the `CHANCELA_CAE_URL` environment variable as a final trailing `Auto` mirror entry.
///
/// `cae_update_url` is kept for backward compatibility (t19-e1b): a config that only sets it keeps
/// working unchanged, as the last-but-one chain entry. When **nothing** is configured the refresh
/// runs the built-in official chain ([`chancela_cae::official_chain_for`], ordered by
/// [`preferred_official_source`](Self::preferred_official_source)) rather than erroring — so the
/// catalog is always obtainable from the official gov source (§catalog-v3).
///
/// **The built-in official source ordering (§catalog-v3, user directive t37: "default is ine").**
/// Wherever the built-in official source enters the chain — the [`cae_official_source`] prepend and the
/// no-config default — it is expanded per [`preferred_official_source`](Self::preferred_official_source):
/// INE first (the default) then the Diário da República pair, or the DR pair alone. INE publishes no
/// downloadable bulk CAE artifact (investigation t37), so the INE entry fails honestly and the DR pair
/// (always present) fulfils the refresh: the outcome `failures` show "INE indisponível → Diário da
/// República", never a silent substitution, and the reliable default never regresses.
///
/// **Defaults:** `cae_update_url: null`, `cae_sources: []`, `cae_official_source: false` (no official
/// machine-readable CAE *feed* exists and the DR obtain is heavy, so mirror/official opt-ins are
/// explicit); `preferred_official_source: Ine` (the user's stated default preference).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CatalogSettings {
    /// URL of the CAE dataset for `POST /v1/cae/refresh`; `null` (default) leaves it unset. Kept as
    /// the trailing fallback chain entry for backward compatibility.
    pub cae_update_url: Option<String>,
    /// Ordered fallback chain of CAE update sources, each auto-detected or format-pinned. Empty by
    /// default; tried in order after the optional official pair and before `cae_update_url`.
    pub cae_sources: Vec<CaeSourceEntry>,
    /// When `true`, prepend the built-in official source(s) to the chain — expanded per
    /// [`preferred_official_source`](Self::preferred_official_source) (a complete both-revision catalog
    /// obtained + parsed in-app). Default `false`.
    pub cae_official_source: bool,
    /// Which built-in official government source leads when the chain obtains from the official source
    /// (the `cae_official_source` prepend and the no-config default). `Ine` (default) → INE first then
    /// the Diário da República pair; `DiarioRepublica` → the DR pair directly. The DR pair is always
    /// present as the reliable fallback (§catalog-v3, user directive t37).
    pub preferred_official_source: PreferredOfficialSource,
}

/// One entry in the ordered CAE source chain ([`CatalogSettings::cae_sources`]).
///
/// A mirror URL plus its declared [`format`](Self::format) (`Auto` sniffs the bytes) and an optional
/// `digest` — a lowercase-hex sha256 pin of the fetched artifact, refused on mismatch. Maps to a
/// [`chancela_cae::MirrorArtifactSource`] at refresh time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaeSourceEntry {
    /// The mirror URL (validated http(s) on `PUT`).
    pub url: String,
    /// The declared artifact format; `Auto` (default) sniffs `%PDF` / `{` / `[`.
    #[serde(default)]
    pub format: CaeSourceFormat,
    /// Optional lowercase-hex sha256 pin of the fetched artifact (`null` = unpinned).
    #[serde(default)]
    pub digest: Option<String>,
}

/// Default RFC 3161 timestamping authority: AMA's Cartão de Cidadão qualified timestamp service
/// (Entidade de Validação Cronológica do CC), the Portuguese state's free public endpoint.
///
/// Sourced from the official autenticacao.gov / Cartão de Cidadão trust services — an
/// admin-configurable default, not a hard dependency. Notes:
/// - **Plain `http://` is correct here and MUST NOT be "upgraded" to https.** RFC 3161 tokens
///   are cryptographically signed, so integrity does not rely on TLS; there is no https listener
///   and switching the scheme would break it. [`is_http_url`] already accepts `http://`.
/// - **Rate-limited: ~20 requests / 20-minute window; exceeding it blocks the caller for 24h.**
///   This matters only for live use, which stays network-gated (the app never contacts the TSA
///   at rest — see [`SigningSettings`]). A test endpoint exists at
///   `http://ts.teste.cartaodecidadao.pt/`; we deliberately do not default to it.
pub const DEFAULT_PT_TSA_URL: &str = "http://ts.cartaodecidadao.pt/tsa/server";

/// Default Portuguese Trusted List (TSL) location, published by the Gabinete Nacional de
/// Segurança (GNS). Mirror of `chancela_tsl::DEFAULT_PT_TSL_URL` (kept in sync by hand rather
/// than depending on the whole TSL crate for one string). Verified live 2026-07-07; GNS renames
/// the published asset from time to time, so this is an admin-configurable default with the
/// `CHANCELA_TSL_URL` env override / the settings field as escape hatches.
pub const DEFAULT_PT_TSL_URL: &str = "https://www.gns.gov.pt/media/TSLPT.xml";

/// European Commission List of Trusted Lists (LOTL). Kept disabled by default because the current
/// trust engine only consumes a single TSL URL; this is configuration plumbing for the future
/// multi-source resolver.
pub const DEFAULT_EU_LOTL_URL: &str = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";

const DEFAULT_TRUST_TIMEOUT_SECONDS: u16 = 30;
const DEFAULT_TSL_MAX_BYTES: u64 = 25 * 1024 * 1024;
const DEFAULT_TSA_MAX_BYTES: u64 = 1024 * 1024;
const MAX_TSL_BYTES: u64 = 100 * 1024 * 1024;
const MAX_TSA_BYTES: u64 = 10 * 1024 * 1024;

/// Signing preferences and trust-service endpoints.
///
/// `tsa_url`/`tsl_url` default to the official Portuguese trust services
/// ([`DEFAULT_PT_TSA_URL`] / [`DEFAULT_PT_TSL_URL`]) so a fresh install is pre-wired to real,
/// free state endpoints. **Pre-filling a URL does not change runtime behaviour**: the app never
/// contacts the TSA/TSL at rest; live use stays network-gated (feature-gated, operator-initiated)
/// exactly as before. An admin may override or clear either URL in Configurações → Assinaturas.
///
/// Null-vs-default policy (backward-compatible, no schema bump — the container `#[serde(default)]`
/// drives it): a stored document that **omits** `tsa_url`/`tsl_url` inherits the official default;
/// one that stores an explicit `null` keeps `null` (`None`) — the operator's recorded choice wins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SigningSettings {
    /// Preferred qualified-signature family offered first in the UI.
    pub preferred_family: SignatureFamily,
    /// RFC 3161 timestamping authority URL. Defaults to [`DEFAULT_PT_TSA_URL`]; `null` clears it.
    pub tsa_url: Option<String>,
    /// Trusted-list (TSL) URL used for qualified-status checks. Defaults to
    /// [`DEFAULT_PT_TSL_URL`]; `null` clears it.
    pub tsl_url: Option<String>,
    /// Additive multi-source Trusted List configuration. Enabled entries are considered before the
    /// legacy [`tsl_url`](Self::tsl_url) compatibility field in trust refresh and qualified-signing
    /// trust-policy selection.
    pub tsl_sources: Vec<TslSourceSettings>,
    /// Additive RFC 3161 timestamp provider configuration. The enabled default provider is
    /// considered before the legacy [`tsa_url`](Self::tsa_url) compatibility field in timestamping.
    pub tsa_providers: Vec<TsaProviderSettings>,
    /// When true, an act cannot reach the finalized-**qualified** status until a valid qualified
    /// signature is present (t57 ruling 6 / deliverable D). This gates the STATUS, **not** the seal:
    /// sealing still succeeds and the unsigned PDF/A still exists; the async OTP signing flow is a
    /// distinct post-seal step. With it `false`, the non-qualified finalized path stays fully usable.
    pub require_qualified_for_seal: bool,
    /// Chave Móvel Digital signing configuration (t57 Slice 1). Non-secret selectors only — the AMA
    /// ApplicationId secret material and the field-encryption certificate PEM come from the
    /// environment (`CHANCELA_CMD_*`), never this echoed settings document.
    pub cmd: SigningCmdSettings,
    /// Read-only provider-mode metadata for the settings UI. This is stamped server-side from
    /// non-secret config on GET/PUT; missing or stale client values are ignored.
    #[serde(default = "default_signing_provider_metadata")]
    pub providers: Vec<SigningProviderMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeTrustLocation {
    Url(String),
    Path(String),
}

impl RuntimeTrustLocation {
    pub(crate) fn url(&self) -> Option<&str> {
        match self {
            RuntimeTrustLocation::Url(url) => Some(url),
            RuntimeTrustLocation::Path(_) => None,
        }
    }

    pub(crate) fn path(&self) -> Option<&str> {
        match self {
            RuntimeTrustLocation::Url(_) => None,
            RuntimeTrustLocation::Path(path) => Some(path),
        }
    }

    pub(crate) fn kind(&self) -> &'static str {
        match self {
            RuntimeTrustLocation::Url(_) => "url",
            RuntimeTrustLocation::Path(_) => "path",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeTslSource {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) location: RuntimeTrustLocation,
    pub(crate) timeout_seconds: u16,
    pub(crate) max_bytes: u64,
    pub(crate) configured_index: Option<usize>,
    pub(crate) legacy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeTslSelection {
    pub(crate) selected: Option<RuntimeTslSource>,
    pub(crate) configured_count: usize,
    pub(crate) enabled_count: usize,
    pub(crate) disabled_count: usize,
    pub(crate) selection_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeTsaProvider {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) location: RuntimeTrustLocation,
    pub(crate) policy: Option<String>,
    pub(crate) digest: String,
    pub(crate) timeout_seconds: u16,
    pub(crate) max_bytes: u64,
    pub(crate) configured_index: Option<usize>,
    pub(crate) legacy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeTsaSelection {
    pub(crate) selected: Option<RuntimeTsaProvider>,
    pub(crate) configured_count: usize,
    pub(crate) enabled_count: usize,
    pub(crate) disabled_count: usize,
    pub(crate) enabled_default_count: usize,
    pub(crate) selection_error: Option<String>,
}

impl SigningSettings {
    pub(crate) fn runtime_tsl_selection(&self) -> RuntimeTslSelection {
        let mut selected = None;
        let mut enabled_count = 0usize;
        let mut disabled_count = 0usize;

        for (index, entry) in self.tsl_sources.iter().enumerate() {
            if !entry.enabled {
                disabled_count += 1;
                continue;
            }
            enabled_count += 1;
            if selected.is_none() {
                selected = runtime_tsl_location(entry).map(|location| RuntimeTslSource {
                    id: entry.id.clone(),
                    name: entry.name.clone(),
                    location,
                    timeout_seconds: entry.timeout_seconds,
                    max_bytes: entry.max_bytes,
                    configured_index: Some(index),
                    legacy: false,
                });
            }
        }

        let selection_error = if selected.is_none() && enabled_count > 0 {
            Some("enabled TSL sources contain no usable URL or path".to_owned())
        } else {
            None
        };

        if selected.is_none() && enabled_count == 0 {
            selected = trimmed_setting(self.tsl_url.as_deref()).map(|url| RuntimeTslSource {
                id: "legacy-tsl-url".to_owned(),
                name: "Legacy signing.tsl_url".to_owned(),
                location: RuntimeTrustLocation::Url(url),
                timeout_seconds: DEFAULT_TRUST_TIMEOUT_SECONDS,
                max_bytes: DEFAULT_TSL_MAX_BYTES,
                configured_index: None,
                legacy: true,
            });
        }

        RuntimeTslSelection {
            selected,
            configured_count: self.tsl_sources.len(),
            enabled_count,
            disabled_count,
            selection_error,
        }
    }

    pub(crate) fn runtime_tsa_selection(&self) -> RuntimeTsaSelection {
        let mut selected = None;
        let mut enabled_count = 0usize;
        let mut disabled_count = 0usize;
        let mut enabled_default_count = 0usize;

        for (index, entry) in self.tsa_providers.iter().enumerate() {
            if !entry.enabled {
                disabled_count += 1;
                continue;
            }
            enabled_count += 1;
            if entry.r#default {
                enabled_default_count += 1;
                if selected.is_none() {
                    selected = runtime_tsa_location(entry).map(|location| RuntimeTsaProvider {
                        id: entry.id.clone(),
                        name: entry.name.clone(),
                        location,
                        policy: entry.policy.clone(),
                        digest: entry.digest.clone(),
                        timeout_seconds: entry.timeout_seconds,
                        max_bytes: entry.max_bytes,
                        configured_index: Some(index),
                        legacy: false,
                    });
                }
            }
        }

        let selection_error = if enabled_count > 0 && enabled_default_count != 1 {
            Some(format!(
                "enabled TSA providers require exactly one default provider, found {enabled_default_count}"
            ))
        } else if selected.is_none() && enabled_count > 0 {
            Some("enabled default TSA provider contains no usable URL or path".to_owned())
        } else {
            None
        };

        if selected.is_none() && enabled_count == 0 {
            selected = trimmed_setting(self.tsa_url.as_deref()).map(|url| RuntimeTsaProvider {
                id: "legacy-tsa-url".to_owned(),
                name: "Legacy signing.tsa_url".to_owned(),
                location: RuntimeTrustLocation::Url(url),
                policy: None,
                digest: "sha256".to_owned(),
                timeout_seconds: DEFAULT_TRUST_TIMEOUT_SECONDS,
                max_bytes: DEFAULT_TSA_MAX_BYTES,
                configured_index: None,
                legacy: true,
            });
        }

        RuntimeTsaSelection {
            selected,
            configured_count: self.tsa_providers.len(),
            enabled_count,
            disabled_count,
            enabled_default_count,
            selection_error,
        }
    }
}

impl Default for SigningSettings {
    fn default() -> Self {
        SigningSettings {
            preferred_family: SignatureFamily::default(),
            tsa_url: Some(DEFAULT_PT_TSA_URL.to_owned()),
            tsl_url: Some(DEFAULT_PT_TSL_URL.to_owned()),
            tsl_sources: default_tsl_sources(),
            tsa_providers: default_tsa_providers(),
            require_qualified_for_seal: false,
            cmd: SigningCmdSettings::default(),
            providers: default_signing_provider_metadata(),
        }
    }
}

/// One configured Trusted List source. This is source metadata and fetch policy only; it does not
/// make a legal-validity claim and is not yet wired into the signing trust decision engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TslSourceSettings {
    /// Stable operator-facing id, unique within `signing.tsl_sources`.
    pub id: String,
    /// Human-readable source name.
    pub name: String,
    /// Disabled sources are stored and validated but ignored by future refresh/resolution work.
    pub enabled: bool,
    /// Remote TSL/LOTL URL, or `null` when the source is file-backed.
    pub url: Option<String>,
    /// Local TSL/LOTL path, or `null` when the source is URL-backed.
    pub path: Option<String>,
    /// ISO-like territory marker such as `PT` or `EU`.
    pub country: Option<String>,
    /// Scheme label such as `eidas`, `lotl`, or an operator-defined value.
    pub scheme: Option<String>,
    /// Optional lowercase-hex sha256 pin for the source bytes.
    pub digest: Option<String>,
    /// Fetch/read timeout in seconds.
    pub timeout_seconds: u16,
    /// Maximum accepted source size in bytes.
    pub max_bytes: u64,
    /// Optional refresh policy metadata for schedulers.
    pub refresh: TrustRefreshSettings,
}

impl Default for TslSourceSettings {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            enabled: false,
            url: None,
            path: None,
            country: None,
            scheme: None,
            digest: None,
            timeout_seconds: DEFAULT_TRUST_TIMEOUT_SECONDS,
            max_bytes: DEFAULT_TSL_MAX_BYTES,
            refresh: TrustRefreshSettings::default(),
        }
    }
}

/// One configured RFC 3161 TSA provider. Secrets, credentials, and trust decisions are out of
/// scope for this settings slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TsaProviderSettings {
    /// Stable operator-facing id, unique within `signing.tsa_providers`.
    pub id: String,
    /// Human-readable provider name.
    pub name: String,
    /// Disabled providers are stored and validated but ignored by future provider selection.
    pub enabled: bool,
    /// Remote RFC 3161 endpoint URL, or `null` when the provider is file-backed/offline.
    pub url: Option<String>,
    /// Local path for an offline/mock provider, or `null` for normal HTTP RFC 3161.
    pub path: Option<String>,
    /// Whether this enabled provider is the default. Exactly one enabled provider must be default
    /// when any TSA providers are configured.
    pub r#default: bool,
    /// Optional accepted timestamp policy OID.
    pub policy: Option<String>,
    /// Request digest algorithm label, e.g. `sha256`.
    pub digest: String,
    /// Request timeout in seconds.
    pub timeout_seconds: u16,
    /// Maximum accepted response size in bytes.
    pub max_bytes: u64,
}

impl Default for TsaProviderSettings {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            enabled: false,
            url: None,
            path: None,
            r#default: false,
            policy: None,
            digest: "sha256".to_owned(),
            timeout_seconds: DEFAULT_TRUST_TIMEOUT_SECONDS,
            max_bytes: DEFAULT_TSA_MAX_BYTES,
        }
    }
}

/// Refresh policy metadata shared by trust-source settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TrustRefreshSettings {
    pub enabled: bool,
    pub cadence: TrustRefreshCadence,
}

impl Default for TrustRefreshSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            cadence: TrustRefreshCadence::Manual,
        }
    }
}

/// Small, scheduler-friendly refresh cadence shape. No cron parser is introduced for this slice.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TrustRefreshCadence {
    #[default]
    Manual,
    IntervalHours {
        hours: u16,
    },
    Daily {
        hour_utc: u8,
    },
}

fn default_tsl_sources() -> Vec<TslSourceSettings> {
    vec![
        TslSourceSettings {
            id: "pt-gns".to_owned(),
            name: "Portugal GNS Trusted List".to_owned(),
            enabled: true,
            url: Some(DEFAULT_PT_TSL_URL.to_owned()),
            path: None,
            country: Some("PT".to_owned()),
            scheme: Some("eidas".to_owned()),
            digest: None,
            timeout_seconds: DEFAULT_TRUST_TIMEOUT_SECONDS,
            max_bytes: DEFAULT_TSL_MAX_BYTES,
            refresh: TrustRefreshSettings {
                enabled: false,
                cadence: TrustRefreshCadence::Daily { hour_utc: 3 },
            },
        },
        TslSourceSettings {
            id: "eu-lotl".to_owned(),
            name: "EU List of Trusted Lists".to_owned(),
            enabled: false,
            url: Some(DEFAULT_EU_LOTL_URL.to_owned()),
            path: None,
            country: Some("EU".to_owned()),
            scheme: Some("lotl".to_owned()),
            digest: None,
            timeout_seconds: DEFAULT_TRUST_TIMEOUT_SECONDS,
            max_bytes: DEFAULT_TSL_MAX_BYTES,
            refresh: TrustRefreshSettings {
                enabled: false,
                cadence: TrustRefreshCadence::Daily { hour_utc: 2 },
            },
        },
    ]
}

fn default_tsa_providers() -> Vec<TsaProviderSettings> {
    vec![TsaProviderSettings {
        id: "pt-cc".to_owned(),
        name: "Portugal Cartao de Cidadao TSA".to_owned(),
        enabled: true,
        url: Some(DEFAULT_PT_TSA_URL.to_owned()),
        path: None,
        r#default: true,
        policy: None,
        digest: "sha256".to_owned(),
        timeout_seconds: DEFAULT_TRUST_TIMEOUT_SECONDS,
        max_bytes: DEFAULT_TSA_MAX_BYTES,
    }]
}

fn runtime_tsl_location(entry: &TslSourceSettings) -> Option<RuntimeTrustLocation> {
    // A path-backed TSL is an operator-pinned local copy and should win over a URL if both are
    // present. This keeps catalog/trust checks deterministic and avoids an avoidable network fetch.
    trimmed_setting(entry.path.as_deref())
        .map(RuntimeTrustLocation::Path)
        .or_else(|| trimmed_setting(entry.url.as_deref()).map(RuntimeTrustLocation::Url))
}

fn runtime_tsa_location(entry: &TsaProviderSettings) -> Option<RuntimeTrustLocation> {
    // Live timestamping is implemented for HTTP RFC 3161 providers. A path-only provider remains a
    // deterministic blocker in the signing flow rather than being silently ignored.
    trimmed_setting(entry.url.as_deref())
        .map(RuntimeTrustLocation::Url)
        .or_else(|| trimmed_setting(entry.path.as_deref()).map(RuntimeTrustLocation::Path))
}

fn trimmed_setting(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// Non-secret provider-mode status surfaced in Settings -> Assinaturas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningProviderMetadata {
    /// Stable mode/provider id (`cmd`, `cc`, `csc_qtsp`, `soft_pkcs12`, or a CSC provider id).
    pub id: String,
    /// Broad provider mode (`CMD`, `CC`, `CSC_QTSP`, `LOCAL_PKCS12`).
    pub mode: SigningProviderMode,
    /// Human-readable label.
    pub label: String,
    /// Whether non-secret configuration/capability is present.
    pub configured: bool,
    /// Whether this mode is blocked for production use with the current configuration.
    pub production_blocked: bool,
    /// Whether this mode only works with a local desktop/API process.
    pub local_only: bool,
    /// Non-secret operational note for settings screens.
    pub note: String,
}

/// Signing-provider mode names. Kept screaming-snake to read as metadata, not domain enum variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SigningProviderMode {
    Cmd,
    Cc,
    CscQtsp,
    LocalPkcs12,
}

fn default_signing_provider_metadata() -> Vec<SigningProviderMetadata> {
    vec![
        SigningProviderMetadata {
            id: "cmd".to_owned(),
            mode: SigningProviderMode::Cmd,
            label: "Chave Móvel Digital (CMD/SCMD)".to_owned(),
            configured: false,
            production_blocked: true,
            local_only: false,
            note: "Missing AMA ApplicationId/certificate; defaults to pre-production.".to_owned(),
        },
        SigningProviderMetadata {
            id: "cc".to_owned(),
            mode: SigningProviderMode::Cc,
            label: "Cartão de Cidadão".to_owned(),
            configured: false,
            production_blocked: false,
            local_only: true,
            note: "Requires a co-located desktop process and card reader; no PIN is stored.".to_owned(),
        },
        SigningProviderMetadata {
            id: "csc_qtsp".to_owned(),
            mode: SigningProviderMode::CscQtsp,
            label: "CSC/QTSP remote provider".to_owned(),
            configured: false,
            production_blocked: true,
            local_only: false,
            note: "No CSC/QTSP provider is configured in the environment.".to_owned(),
        },
        SigningProviderMetadata {
            id: "soft_pkcs12".to_owned(),
            mode: SigningProviderMode::LocalPkcs12,
            label: "Local soft certificate (PKCS#12/PFX)".to_owned(),
            configured: false,
            production_blocked: true,
            local_only: true,
            note: "Local-only test/operator material; private key and passphrase are never captured in settings.".to_owned(),
        },
    ]
}

/// Chave Móvel Digital signing configuration surfaced in the settings document (t57 F1).
///
/// **Secrets never live here.** The AMA field-encryption certificate PEM and HTTP BasicAuth
/// credentials are read from the environment (`CHANCELA_CMD_AMA_CERT_PEM`,
/// `CHANCELA_CMD_HTTP_BASIC_USERNAME`, `CHANCELA_CMD_HTTP_BASIC_PASSWORD`) by
/// `chancela_cmd::CmdConfig::from_env`. This sub-object carries only the non-secret selectors an
/// operator sees: which environment, the (non-secret) ApplicationId echo, and a read-only "is the
/// AMA cert configured?" indicator.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SigningCmdSettings {
    /// Which AMA SCMD environment to talk to. Defaults to `Preprod` (t57 ruling 5): ship pointing at
    /// pre-production until real prod credentials + AMA onboarding are in place.
    pub env: CmdEnvSetting,
    /// The AMA-assigned ApplicationId, or `null` if not set. Non-secret opaque identifier; required
    /// (from env in production) before a signature can be started.
    pub application_id: Option<String>,
    /// Read-only surface: whether the AMA field-encryption certificate is configured (the PEM itself
    /// comes from `CHANCELA_CMD_AMA_CERT_PEM`, never this document). PROD requires it.
    pub ama_cert_configured: bool,
}

/// The AMA SCMD environment selector (mirrors `chancela_cmd::CmdEnv`, serialized lowercase).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CmdEnvSetting {
    /// AMA pre-production — the default (cleartext fields allowed).
    #[default]
    Preprod,
    /// AMA production (field encryption required).
    Prod,
}

/// Cosmetic front-end preferences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppearanceSettings {
    /// Light/dark/system theme selection.
    pub theme: ThemeMode,
    /// Whether the procedural leather-texture background is rendered.
    pub leather_texture: bool,
    /// Texture strength, `0..=100` (validated on `PUT`).
    pub texture_intensity: u8,
    /// Whether the subtle leather grain is applied to buttons. Additive and defaults to `true`,
    /// so an older stored document that omits it keeps the textured buttons.
    pub button_texture: bool,
}

impl Default for AppearanceSettings {
    fn default() -> Self {
        AppearanceSettings {
            theme: ThemeMode::default(),
            leather_texture: true,
            texture_intensity: 60,
            button_texture: true,
        }
    }
}

// --- Enums (serde encodings pinned by the contract) ---------------------------------------

/// Document/UI locale. Serialized as the BCP-47 tag the front-end expects (language subtag
/// lowercase, region subtag UPPERCASE). The set is additive: the pre-existing `pt-PT`/`en-US`
/// tags keep their exact encodings, so older stored documents remain valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Locale {
    /// Portuguese (Portugal) — the default.
    #[default]
    #[serde(rename = "pt-PT")]
    PtPt,
    /// Portuguese (Brazil).
    #[serde(rename = "pt-BR")]
    PtBr,
    /// Danish (Denmark).
    #[serde(rename = "da-DK")]
    DaDk,
    /// German (Germany).
    #[serde(rename = "de-DE")]
    DeDe,
    /// French (France).
    #[serde(rename = "fr-FR")]
    FrFr,
    /// Finnish (Finland).
    #[serde(rename = "fi-FI")]
    FiFi,
    /// Swedish (Finland) — Finland-Swedish, distinct from `sv-SE`.
    #[serde(rename = "sv-FI")]
    SvFi,
    /// Italian (Italy).
    #[serde(rename = "it-IT")]
    ItIt,
    /// Dutch (Netherlands).
    #[serde(rename = "nl-NL")]
    NlNl,
    /// Polish (Poland).
    #[serde(rename = "pl-PL")]
    PlPl,
    /// English (United Kingdom).
    #[serde(rename = "en-GB")]
    EnGb,
    /// English (United States).
    #[serde(rename = "en-US")]
    EnUs,
    /// Swedish (Sweden).
    #[serde(rename = "sv-SE")]
    SvSe,
    /// Spanish (Spain).
    #[serde(rename = "es-ES")]
    EsEs,
}

/// Preferred qualified-signature family. Variant names match the domain vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SignatureFamily {
    /// Cartão de Cidadão (smart card).
    CartaoCidadao,
    /// Chave Móvel Digital (remote qualified signing) — the default (t57 Slice 1). CMD is the
    /// family the product wires end-to-end (two-phase OTP flow); it needs no local card reader, so
    /// it is the sensible default offered first in the UI.
    #[default]
    ChaveMovelDigital,
    /// Any other qualified certificate.
    OtherQualified,
    /// Manual (wet-ink / out-of-band) signature.
    Manual,
}

/// Theme selection. Lowercase to match the CSS/theme tokens the web app uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    /// Follow the operating-system preference — the default.
    #[default]
    System,
    /// Force the light theme.
    Light,
    /// Force the dark theme.
    Dark,
}

// --- Validation ---------------------------------------------------------------------------

impl Settings {
    /// Validate the ranges and URL shapes serde cannot express on its own. Enum and locale
    /// values are already validated by deserialization; this covers `texture_intensity`'s
    /// numeric range and the trust-service URLs. Returns `422` on any violation.
    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        if self.appearance.texture_intensity > 100 {
            return Err(ApiError::Unprocessable(format!(
                "appearance.texture_intensity must be between 0 and 100, got {}",
                self.appearance.texture_intensity
            )));
        }
        for (field, url) in [
            ("signing.tsa_url", &self.signing.tsa_url),
            ("signing.tsl_url", &self.signing.tsl_url),
            ("catalog.cae_update_url", &self.catalog.cae_update_url),
        ] {
            if let Some(raw) = url {
                let trimmed = raw.trim();
                // A present-but-empty string is treated as "unset"; anything non-empty must
                // look like an http(s) URL (plain string check, no URL-parsing dependency).
                if !trimmed.is_empty() && !is_http_url(trimmed) {
                    return Err(ApiError::Unprocessable(format!(
                        "{field} must be an http(s) URL, got {raw:?}"
                    )));
                }
                if !trimmed.is_empty() && field.starts_with("signing.") {
                    validate_outbound_url_setting(field, trimmed)?;
                }
            }
        }
        // Each ordered CAE source entry: a required http(s) URL and, when present, a 64-char
        // sha256-hex digest pin. A bad entry is a client-actionable `422`.
        for (i, entry) in self.catalog.cae_sources.iter().enumerate() {
            let trimmed = entry.url.trim();
            if trimmed.is_empty() || !is_http_url(trimmed) {
                return Err(ApiError::Unprocessable(format!(
                    "catalog.cae_sources[{i}].url must be an http(s) URL, got {:?}",
                    entry.url
                )));
            }
            if let Some(digest) = &entry.digest {
                let digest = digest.trim();
                if !digest.is_empty()
                    && (digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()))
                {
                    return Err(ApiError::Unprocessable(format!(
                        "catalog.cae_sources[{i}].digest must be a 64-character sha256 hex, got {:?}",
                        entry.digest
                    )));
                }
            }
        }
        validate_tsl_sources(&self.signing.tsl_sources)?;
        validate_tsa_providers(&self.signing.tsa_providers)?;
        self.registry_auto_update.validate()?;
        self.workflow.validate()?;
        self.data_management.validate()?;
        self.platform.validate()?;
        Ok(())
    }
}

fn validate_tsl_sources(entries: &[TslSourceSettings]) -> Result<(), ApiError> {
    let mut ids = BTreeSet::new();
    for (i, entry) in entries.iter().enumerate() {
        validate_config_id(&format!("signing.tsl_sources[{i}].id"), &entry.id)?;
        if !ids.insert(entry.id.as_str()) {
            return Err(ApiError::Unprocessable(format!(
                "signing.tsl_sources[{i}].id duplicates {:?}",
                entry.id
            )));
        }
        validate_non_blank_label(&format!("signing.tsl_sources[{i}].name"), &entry.name)?;
        validate_url_or_path(
            &format!("signing.tsl_sources[{i}]"),
            entry.url.as_deref(),
            entry.path.as_deref(),
        )?;
        if let Some(url) = entry.url.as_deref() {
            let trimmed = url.trim();
            if !trimmed.is_empty() && !is_http_url(trimmed) {
                return Err(ApiError::Unprocessable(format!(
                    "signing.tsl_sources[{i}].url must be an http(s) URL, got {url:?}"
                )));
            }
            if !trimmed.is_empty() {
                validate_outbound_url_setting(&format!("signing.tsl_sources[{i}].url"), trimmed)?;
            }
        }
        if let Some(digest) = entry.digest.as_deref() {
            validate_optional_sha256_hex(&format!("signing.tsl_sources[{i}].digest"), digest)?;
        }
        validate_timeout(
            &format!("signing.tsl_sources[{i}].timeout_seconds"),
            entry.timeout_seconds,
        )?;
        validate_max_bytes(
            &format!("signing.tsl_sources[{i}].max_bytes"),
            entry.max_bytes,
            MAX_TSL_BYTES,
        )?;
        validate_refresh(&format!("signing.tsl_sources[{i}].refresh"), &entry.refresh)?;
        validate_optional_token(
            &format!("signing.tsl_sources[{i}].country"),
            &entry.country,
            16,
        )?;
        validate_optional_token(
            &format!("signing.tsl_sources[{i}].scheme"),
            &entry.scheme,
            64,
        )?;
    }
    Ok(())
}

fn validate_tsa_providers(entries: &[TsaProviderSettings]) -> Result<(), ApiError> {
    let mut ids = BTreeSet::new();
    let mut enabled = 0usize;
    let mut enabled_defaults = 0usize;
    for (i, entry) in entries.iter().enumerate() {
        validate_config_id(&format!("signing.tsa_providers[{i}].id"), &entry.id)?;
        if !ids.insert(entry.id.as_str()) {
            return Err(ApiError::Unprocessable(format!(
                "signing.tsa_providers[{i}].id duplicates {:?}",
                entry.id
            )));
        }
        validate_non_blank_label(&format!("signing.tsa_providers[{i}].name"), &entry.name)?;
        validate_url_or_path(
            &format!("signing.tsa_providers[{i}]"),
            entry.url.as_deref(),
            entry.path.as_deref(),
        )?;
        if let Some(url) = entry.url.as_deref() {
            let trimmed = url.trim();
            if !trimmed.is_empty() && !is_http_url(trimmed) {
                return Err(ApiError::Unprocessable(format!(
                    "signing.tsa_providers[{i}].url must be an http(s) URL, got {url:?}"
                )));
            }
            if !trimmed.is_empty() {
                validate_outbound_url_setting(&format!("signing.tsa_providers[{i}].url"), trimmed)?;
            }
        }
        validate_non_blank_label(&format!("signing.tsa_providers[{i}].digest"), &entry.digest)?;
        validate_timeout(
            &format!("signing.tsa_providers[{i}].timeout_seconds"),
            entry.timeout_seconds,
        )?;
        validate_max_bytes(
            &format!("signing.tsa_providers[{i}].max_bytes"),
            entry.max_bytes,
            MAX_TSA_BYTES,
        )?;
        validate_optional_token(
            &format!("signing.tsa_providers[{i}].policy"),
            &entry.policy,
            128,
        )?;
        if entry.enabled {
            enabled += 1;
            if entry.r#default {
                enabled_defaults += 1;
            }
        }
    }
    if enabled > 0 && enabled_defaults != 1 {
        return Err(ApiError::Unprocessable(format!(
            "signing.tsa_providers must contain exactly one enabled default provider, found {enabled_defaults}"
        )));
    }
    Ok(())
}

fn validate_config_id(field: &str, id: &str) -> Result<(), ApiError> {
    let trimmed = id.trim();
    if trimmed.is_empty()
        || trimmed != id
        || trimmed.len() > 64
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))
        || !trimmed
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be a stable lowercase id up to 64 chars using a-z, 0-9, '-', '_' or '.', got {id:?}"
        )));
    }
    Ok(())
}

fn validate_non_blank_label(field: &str, value: &str) -> Result<(), ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 160 || trimmed.chars().any(char::is_control) {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be non-empty text up to 160 non-control characters"
        )));
    }
    Ok(())
}

fn validate_url_or_path(
    field: &str,
    url: Option<&str>,
    path: Option<&str>,
) -> Result<(), ApiError> {
    let has_url = url.is_some_and(|value| !value.trim().is_empty());
    let has_path = path.is_some_and(|value| !value.trim().is_empty());
    if !has_url && !has_path {
        return Err(ApiError::Unprocessable(format!(
            "{field} must provide either url or path"
        )));
    }
    if let Some(path) = path {
        let trimmed = path.trim();
        if trimmed.is_empty() || trimmed.len() > 1024 || trimmed.chars().any(char::is_control) {
            return Err(ApiError::Unprocessable(format!(
                "{field}.path must be non-empty path text up to 1024 non-control characters"
            )));
        }
    }
    Ok(())
}

fn validate_outbound_url_setting(field: &str, url: &str) -> Result<(), ApiError> {
    crate::trust::validate_outbound_http_url_metadata(url).map_err(|e| {
        ApiError::Unprocessable(format!("{field} rejected by outbound URL policy: {e}"))
    })?;
    Ok(())
}

fn validate_optional_sha256_hex(field: &str, digest: &str) -> Result<(), ApiError> {
    let trimmed = digest.trim();
    if !trimmed.is_empty()
        && (trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be a 64-character sha256 hex, got {digest:?}"
        )));
    }
    Ok(())
}

fn validate_timeout(field: &str, timeout_seconds: u16) -> Result<(), ApiError> {
    if !(1..=300).contains(&timeout_seconds) {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be between 1 and 300, got {timeout_seconds}"
        )));
    }
    Ok(())
}

fn validate_max_bytes(field: &str, max_bytes: u64, upper: u64) -> Result<(), ApiError> {
    if !(1024..=upper).contains(&max_bytes) {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be between 1024 and {upper}, got {max_bytes}"
        )));
    }
    Ok(())
}

fn validate_refresh(field: &str, refresh: &TrustRefreshSettings) -> Result<(), ApiError> {
    match refresh.cadence {
        TrustRefreshCadence::Manual => Ok(()),
        TrustRefreshCadence::IntervalHours { hours } => {
            if !(1..=24 * 30).contains(&hours) {
                return Err(ApiError::Unprocessable(format!(
                    "{field}.cadence.hours must be between 1 and 720, got {hours}"
                )));
            }
            Ok(())
        }
        TrustRefreshCadence::Daily { hour_utc } => {
            if hour_utc > 23 {
                return Err(ApiError::Unprocessable(format!(
                    "{field}.cadence.hour_utc must be between 0 and 23, got {hour_utc}"
                )));
            }
            Ok(())
        }
    }
}

fn validate_optional_token(
    field: &str,
    value: &Option<String>,
    max_len: usize,
) -> Result<(), ApiError> {
    let Some(value) = value else {
        return Ok(());
    };
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > max_len
        || trimmed
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\'' | '<' | '>'))
    {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be non-empty token text up to {max_len} characters"
        )));
    }
    Ok(())
}

/// Minimal http(s) URL shape check: an `http://` or `https://` scheme with a non-empty
/// authority following it. Deliberately not a full RFC 3986 parse — just enough to reject
/// obviously wrong values (empty, `ftp://…`, a bare hostname) without adding a dependency.
fn is_http_url(s: &str) -> bool {
    match s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
    {
        Some(rest) => !rest.is_empty(),
        None => false,
    }
}

fn stamp_signing_provider_metadata(state: &AppState, settings: &mut Settings) {
    let cmd_configured = settings
        .signing
        .cmd
        .application_id
        .as_deref()
        .is_some_and(|id| !id.trim().is_empty());
    let cmd_prod = settings.signing.cmd.env == CmdEnvSetting::Prod;
    let cmd_production_blocked =
        !cmd_configured || !cmd_prod || !settings.signing.cmd.ama_cert_configured;

    let mut providers = vec![
        SigningProviderMetadata {
            id: "cmd".to_owned(),
            mode: SigningProviderMode::Cmd,
            label: "Chave Móvel Digital (CMD/SCMD)".to_owned(),
            configured: cmd_configured,
            production_blocked: cmd_production_blocked,
            local_only: false,
            note: if cmd_configured {
                if cmd_production_blocked {
                    "Configured for non-production or missing the AMA production certificate."
                        .to_owned()
                } else {
                    "Configured for AMA production. PIN/OTP are never stored.".to_owned()
                }
            } else {
                "Missing AMA ApplicationId/certificate; defaults to pre-production.".to_owned()
            },
        },
        SigningProviderMetadata {
            id: "cc".to_owned(),
            mode: SigningProviderMode::Cc,
            label: "Cartão de Cidadão".to_owned(),
            configured: state.local_signing,
            production_blocked: false,
            local_only: true,
            note: if state.local_signing {
                "Local desktop signing is available; PIN entry stays at the card reader.".to_owned()
            } else {
                "Requires a co-located desktop process and card reader; no PIN is stored."
                    .to_owned()
            },
        },
    ];

    if state.csc_providers.is_empty() {
        providers.push(SigningProviderMetadata {
            id: "csc_qtsp".to_owned(),
            mode: SigningProviderMode::CscQtsp,
            label: "CSC/QTSP remote provider".to_owned(),
            configured: false,
            production_blocked: true,
            local_only: false,
            note: "No CSC/QTSP provider is configured in the environment.".to_owned(),
        });
    } else {
        let injected_transport = state.csc_transport.is_some();
        for cfg in state.csc_providers.iter() {
            let configured = injected_transport || CscSecrets::is_configured(&cfg.provider_id);
            providers.push(SigningProviderMetadata {
                id: cfg.provider_id.clone(),
                mode: SigningProviderMode::CscQtsp,
                label: cfg.display_name.clone(),
                configured,
                production_blocked: !configured || cfg.sandbox,
                local_only: false,
                note: if configured {
                    if cfg.sandbox {
                        "CSC/QTSP provider is configured in sandbox mode.".to_owned()
                    } else {
                        "CSC/QTSP provider is configured; secrets stay in the environment."
                            .to_owned()
                    }
                } else {
                    "CSC/QTSP provider metadata exists, but runtime credentials are missing."
                        .to_owned()
                },
            });
        }
    }

    providers.push(SigningProviderMetadata {
        id: "soft_pkcs12".to_owned(),
        mode: SigningProviderMode::LocalPkcs12,
        label: "Local soft certificate (PKCS#12/PFX)".to_owned(),
        configured: false,
        production_blocked: true,
        local_only: true,
        note: "Local-only test/operator material; private key and passphrase are never captured in settings."
            .to_owned(),
    });

    settings.signing.providers = providers;
}

// --- Persistence --------------------------------------------------------------------------

/// The file name holding the settings document inside the data directory.
pub const SETTINGS_FILE: &str = "settings.json";

/// Read `settings.json` from `path`, returning `None` if it is absent or unreadable, and
/// falling back to defaults (with a warning) if it is present but malformed. A corrupt file
/// must never stop the server from starting.
pub(crate) fn load_settings(path: &Path) -> Option<Settings> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice(&bytes) {
        Ok(settings) => Some(settings),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid settings document ({e}); using defaults",
                path.display()
            );
            None
        }
    }
}

/// Atomically write `settings` to `path`: serialize to a uniquely-named temp file in the same
/// directory, then rename it over the destination (an atomic replace on both Windows and
/// Unix). The parent directory is created if missing.
pub(crate) fn write_settings_atomic(path: &Path, settings: &Settings) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_vec_pretty(settings).map_err(std::io::Error::other)?;
    let tmp = tmp_path(path);
    std::fs::write(&tmp, &json)?;
    // rename over the destination is atomic and, on Windows, replaces an existing file.
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Best-effort cleanup so a failed rename does not leave a stray temp file behind.
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// A sibling temp path for the atomic write, made unique so two concurrent `PUT`s never race
/// on the same temp file before their renames.
fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| SETTINGS_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

// --- Handlers -----------------------------------------------------------------------------

/// Query for `PUT /v1/settings`: an optional actor override for the audit event.
#[derive(Deserialize)]
pub struct SettingsActorQuery {
    /// Actor to attribute the `settings.updated` event to; falls back to the document's
    /// `organization.default_actor` when absent or blank.
    pub actor: Option<String>,
}

/// `GET /v1/settings` — the current settings document (defaults if never set).
pub async fn get_settings(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Settings>, ApiError> {
    // RBAC (t64-E3): reading settings is `settings.read` at Global.
    require_permission(&state, &actor, Permission::SettingsRead, Scope::Global).await?;
    let mut settings = state.settings.read().await.clone();
    stamp_signing_provider_metadata(&state, &mut settings);
    Ok(Json(settings))
}

/// `PUT /v1/settings` — replace the whole settings document.
///
/// The body is the entire [`Settings`] document. It is parsed leniently (missing fields
/// default), then validated (`texture_intensity` range, trust-service URL shapes). On success
/// the document is persisted (atomically, if the state is file-backed), a `settings.updated`
/// ledger event is appended, the in-memory copy is replaced, and the stored document is
/// echoed back. Any validation failure returns `422` with the standard `{"error": …}` body.
pub async fn put_settings(
    State(state): State<AppState>,
    Query(query): Query<SettingsActorQuery>,
    current_actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Bytes,
) -> Result<Json<Settings>, ApiError> {
    // RBAC (t64-E3): replacing settings is `settings.manage` at Global.
    require_permission(
        &state,
        &current_actor,
        Permission::SettingsManage,
        Scope::Global,
    )
    .await?;
    // Parse by hand (rather than via the `Json` extractor) so every rejection — malformed
    // JSON, a bad enum, a bad locale — renders through `ApiError` as the standard body.
    let mut settings: Settings = serde_json::from_slice(&body)
        .map_err(|e| ApiError::Unprocessable(format!("invalid settings document: {e}")))?;
    // Always stamp the current schema version regardless of what the client sent.
    settings.schema_version = SETTINGS_SCHEMA_VERSION;
    stamp_signing_provider_metadata(&state, &mut settings);
    settings.validate()?;

    // Persist before we acknowledge success, so we never report a write we did not make.
    if let Some(path) = &state.persist_path {
        write_settings_atomic(path, &settings)
            .map_err(|e| ApiError::Internal(format!("failed to persist settings: {e}")))?;
    }

    // Actor precedence (contract §2.8): a valid session wins; else the `?actor=` override; else
    // the document's own default actor.
    let request_actor = query
        .actor
        .filter(|a| !a.trim().is_empty())
        .unwrap_or_else(|| settings.organization.default_actor.clone());
    let actor = current_actor.resolve(&request_actor);

    let payload = serde_json::to_vec(&settings)?;
    {
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &actor,
            "settings",
            "settings.updated",
            Some("settings updated"),
            &payload,
        );
        // Persist the audit event; the settings document itself is durable via `settings.json`.
        state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
        state.attest_latest(&attestor, &ledger).await;
    }

    *state.settings.write().await = settings.clone();
    Ok(Json(settings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_default_includes_retained_export_cleanup_policy() {
        let settings = Settings::default();

        assert_eq!(
            settings
                .data_management
                .retained_export_cleanup
                .minimum_age_days,
            DEFAULT_RETAINED_EXPORT_CLEANUP_MINIMUM_AGE_DAYS
        );
        assert_eq!(
            settings.data_management.retained_export_cleanup.keep_latest,
            DEFAULT_RETAINED_EXPORT_CLEANUP_KEEP_LATEST
        );
        settings
            .validate()
            .expect("default settings should validate");
    }

    #[test]
    fn settings_default_includes_backup_recovery_policy() {
        let settings = Settings::default();

        assert_eq!(
            settings.data_management.backup_recovery.max_drill_age_days,
            DEFAULT_BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS
        );
        assert_eq!(
            settings.data_management.backup_recovery.target_rpo_minutes,
            DEFAULT_BACKUP_RECOVERY_TARGET_RPO_MINUTES
        );
        assert_eq!(
            settings.data_management.backup_recovery.target_rto_minutes,
            DEFAULT_BACKUP_RECOVERY_TARGET_RTO_MINUTES
        );
        settings
            .validate()
            .expect("default settings should validate");
    }

    #[test]
    fn legacy_settings_json_defaults_retained_export_cleanup_policy() {
        let settings: Settings =
            serde_json::from_str(r#"{"schema_version":1}"#).expect("legacy settings");

        assert_eq!(
            settings
                .data_management
                .retained_export_cleanup
                .minimum_age_days,
            DEFAULT_RETAINED_EXPORT_CLEANUP_MINIMUM_AGE_DAYS
        );
        assert_eq!(
            settings.data_management.retained_export_cleanup.keep_latest,
            DEFAULT_RETAINED_EXPORT_CLEANUP_KEEP_LATEST
        );
    }

    #[test]
    fn legacy_settings_json_defaults_backup_recovery_policy() {
        let settings: Settings =
            serde_json::from_str(r#"{"schema_version":1}"#).expect("legacy settings");

        assert_eq!(
            settings.data_management.backup_recovery.max_drill_age_days,
            DEFAULT_BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS
        );
        assert_eq!(
            settings.data_management.backup_recovery.target_rpo_minutes,
            DEFAULT_BACKUP_RECOVERY_TARGET_RPO_MINUTES
        );
        assert_eq!(
            settings.data_management.backup_recovery.target_rto_minutes,
            DEFAULT_BACKUP_RECOVERY_TARGET_RTO_MINUTES
        );
    }

    #[test]
    fn retained_export_cleanup_policy_rejects_out_of_range_values() {
        let mut settings = Settings::default();
        settings
            .data_management
            .retained_export_cleanup
            .minimum_age_days = MAX_RETAINED_EXPORT_CLEANUP_MINIMUM_AGE_DAYS + 1;

        let err = settings
            .validate()
            .expect_err("minimum age above policy bound should fail");
        match err {
            ApiError::Unprocessable(message) => {
                assert!(
                    message.contains("data_management.retained_export_cleanup.minimum_age_days")
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let mut settings = Settings::default();
        settings.data_management.retained_export_cleanup.keep_latest =
            MAX_RETAINED_EXPORT_CLEANUP_KEEP_LATEST + 1;
        let err = settings
            .validate()
            .expect_err("keep latest above policy bound should fail");
        match err {
            ApiError::Unprocessable(message) => {
                assert!(message.contains("data_management.retained_export_cleanup.keep_latest"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn backup_recovery_policy_rejects_out_of_range_values() {
        let mut settings = Settings::default();
        settings.data_management.backup_recovery.max_drill_age_days = 0;

        let err = settings.validate().expect_err("zero drill age should fail");
        match err {
            ApiError::Unprocessable(message) => {
                assert!(message.contains("data_management.backup_recovery.max_drill_age_days"));
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let mut settings = Settings::default();
        settings.data_management.backup_recovery.target_rpo_minutes =
            MAX_BACKUP_RECOVERY_TARGET_MINUTES + 1;
        let err = settings.validate().expect_err("oversized RPO should fail");
        match err {
            ApiError::Unprocessable(message) => {
                assert!(message.contains("data_management.backup_recovery.target_rpo_minutes"));
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let mut settings = Settings::default();
        settings.data_management.backup_recovery.target_rto_minutes = 0;
        let err = settings.validate().expect_err("zero RTO should fail");
        match err {
            ApiError::Unprocessable(message) => {
                assert!(message.contains("data_management.backup_recovery.target_rto_minutes"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
