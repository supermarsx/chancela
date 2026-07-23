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
use chancela_cmd::{CmdBasicAuth, CmdConfig, CmdEnv};
use chancela_connectors::{
    ALLOWED_HOSTS_ENV, MAX_RUNTIME_ALLOWLIST_ENTRIES, NetworkPolicy, RuntimeAllowlist,
};
use chancela_core::NumberingScheme;
use chancela_csc::{CscAuthorization, CscConfig, CscSecrets};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use chancela_authz::{Permission, Scope};

use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::require_permission;
use crate::error::ApiError;
use crate::secretstore_persist::{
    FIELD_ACCESS_TOKEN, FIELD_AMA_CERT_PEM, FIELD_APPLICATION_ID, FIELD_CLIENT_ID,
    FIELD_CLIENT_SECRET, FIELD_HTTP_BASIC_PASSWORD, FIELD_HTTP_BASIC_USERNAME,
};
use crate::smtp::SmtpEncryption;
use crate::{AppState, CredentialMode, DecryptedCredentialRecord};

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
    /// Connector outbound-egress boundary. Empty by default so an older document never widens it.
    #[serde(default, skip_serializing_if = "ConnectorSettings::is_default")]
    pub connectors: ConnectorSettings,
    /// Outbound email (SMTP) relay configuration (t23). Non-secret only — the relay password lives
    /// in the credential store, never here. Disabled by default.
    pub email: EmailSettings,
    /// Authentication, self-signup and second-factor policy (t95). Every field fails closed, and
    /// the whole slice is skipped on the wire while it is at its defaults, so an existing
    /// `settings.json` — and `contracts/settings.json` — are unchanged by its arrival.
    #[serde(default, skip_serializing_if = "AuthSettings::is_default")]
    pub auth: AuthSettings,
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
            connectors: ConnectorSettings::default(),
            email: EmailSettings::default(),
            auth: AuthSettings::default(),
            ai: AiSettings::default(),
            platform: PlatformSettings::default(),
            appearance: AppearanceSettings::default(),
            ui: UiSettings::default(),
            onboarding: OnboardingSettings::default(),
        }
    }
}

/// Connector outbound-egress controls: the runtime half of the connector allowlist.
///
/// This is a containment boundary, not a preference. It decides which hosts a connector may ship
/// minute-book bytes to, so it is deliberately the *narrowing* half of a two-source policy: when
/// `CHANCELA_CONNECTOR_ALLOWED_HOSTS` is set, the deployment owns a ceiling that nothing saved
/// here can exceed. See [`chancela_connectors::NetworkPolicy`] for the resolution rule and for the
/// stricter validation applied to entries that arrive through this path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectorSettings {
    /// Exact hostnames and IP/CIDR entries. Empty means "no runtime allowlist configured", which
    /// leaves the deployment ceiling (if any) in force — it never means "allow everything".
    pub allowed_hosts: Vec<String>,
    /// Read-only mirror of `CHANCELA_CONNECTOR_ALLOWED_HOSTS`, stamped on `GET` so the UI can
    /// state the precedence rule with the actual ceiling rather than in the abstract. Never
    /// persisted and never trusted from a `PUT`: the handler clears whatever the client sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_ceiling: Option<Vec<String>>,
}

impl ConnectorSettings {
    pub(crate) fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// Normalized entries: trimmed, lowercased, blank-free, order-preserving, duplicate-free.
    pub(crate) fn normalized(&self) -> Vec<String> {
        let mut seen = BTreeSet::new();
        self.allowed_hosts
            .iter()
            .map(|entry| entry.trim().to_ascii_lowercase())
            .filter(|entry| !entry.is_empty())
            .filter(|entry| seen.insert(entry.clone()))
            .collect()
    }

    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        if self.allowed_hosts.len() > MAX_RUNTIME_ALLOWLIST_ENTRIES {
            return Err(ApiError::Unprocessable(format!(
                "connectors.allowed_hosts accepts at most {MAX_RUNTIME_ALLOWLIST_ENTRIES} entries"
            )));
        }
        let entries = self.normalized();
        if entries.is_empty() {
            return Ok(());
        }
        // Parse with the strict administrative rules, then prove the result cannot exceed the
        // deployment ceiling. Both failures are the operator's to fix, so both are a 422.
        let policy = NetworkPolicy::parse_administrative(&entries).map_err(|error| {
            ApiError::Unprocessable(format!("connectors.allowed_hosts: {error}"))
        })?;
        if let Some(ceiling) = environment_ceiling() {
            let ceiling = NetworkPolicy::parse(&ceiling).map_err(|error| {
                ApiError::Unprocessable(format!(
                    "the deployment connector allowlist is itself invalid: {error}"
                ))
            })?;
            policy.require_within(&ceiling).map_err(|error| {
                ApiError::Unprocessable(format!("connectors.allowed_hosts: {error}"))
            })?;
        }
        Ok(())
    }
}

/// The deployment ceiling as configured, or `None` when unset/blank.
pub(crate) fn environment_ceiling() -> Option<String> {
    std::env::var(ALLOWED_HOSTS_ENV)
        .ok()
        .filter(|raw| !raw.trim().is_empty())
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
    /// Operator declaration of the shared-mounted zero-knowledge object root, equivalent to
    /// `CHANCELA_ZK_SHARED_OBJECT_ROOT` (which wins when both are set).
    ///
    /// This is a **fail-closed safety interlock, not a preference**. On PostgreSQL/HA the ZK
    /// repository routes refuse to serve until this names the shared mount, because a node-local
    /// root would split object storage silently across the cluster — each node holding objects the
    /// others cannot see, with no error anywhere. Absent by default, so an older settings document
    /// can never open the interlock by omission.
    ///
    /// It is resolved **once at startup**, so writing it here takes effect at the next restart and
    /// the UI says so. Deep validation (absolute, exactly `<data_dir>/zk-repositories`, exists,
    /// writable) happens in `put_settings`, which has the data directory; see
    /// [`crate::zk_repository::validate_shared_object_root`] for what a single node can and cannot
    /// check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zk_shared_object_root: Option<String>,
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

/// The default submission port. 587 + STARTTLS is the modern submission norm.
pub const DEFAULT_SMTP_PORT: u16 = 587;

/// Outbound email (SMTP) relay configuration (t23).
///
/// **What is deliberately not here:** the relay password. It is written through
/// `PUT /v1/settings/email/password` into the AEAD-encrypted credential store
/// ([`CredentialMode::Smtp`](crate::CredentialMode::Smtp)) and is never returned by any endpoint —
/// this document only ever carries a `configured` flag on the side. Putting it here would put a live
/// mail credential in `settings.json` in the clear and echo it back on every `GET /v1/settings`.
///
/// Additive and serde-defaulted: an older `settings.json` that omits this section deserializes with
/// mail disabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailSettings {
    /// Whether outbound mail is configured for use. Off by default.
    pub enabled: bool,
    /// Relay hostname. Also the name the TLS certificate must match.
    pub host: Option<String>,
    /// Relay port.
    pub port: u16,
    /// Transport security. Defaults to STARTTLS; see [`allow_insecure`](Self::allow_insecure) for
    /// what it takes to turn it off.
    pub encryption: SmtpEncryption,
    /// SMTP AUTH username, or `null`/empty for a relay that takes no credentials.
    pub username: Option<String>,
    /// Envelope sender and `From:` address for every message the application sends.
    pub from_address: Option<String>,
    /// Optional display name for the `From:` header.
    pub from_name: Option<String>,
    /// The name announced in `EHLO`. Defaults to the `from_address` domain when unset.
    pub helo_name: Option<String>,
    /// The operator's **explicit** acknowledgement that [`encryption`](Self::encryption) is
    /// [`SmtpEncryption::None`] and credentials will therefore cross the network in the clear.
    ///
    /// This is a server-enforced gate, not UI copy: `PUT /v1/settings` rejects `encryption = "none"`
    /// unless this is `true`, so an unencrypted relay can only ever be reached by someone who said
    /// so on purpose. It resets to `false` whenever encryption is re-enabled.
    pub allow_insecure: bool,
}

impl Default for EmailSettings {
    fn default() -> Self {
        EmailSettings {
            enabled: false,
            host: None,
            port: DEFAULT_SMTP_PORT,
            encryption: SmtpEncryption::default(),
            username: None,
            from_address: None,
            from_name: None,
            helo_name: None,
            allow_insecure: false,
        }
    }
}

impl EmailSettings {
    /// The name to announce in `EHLO`: the operator's override, else the sender's domain, else a
    /// literal `localhost` (which some relays reject — hence the override).
    pub fn resolved_helo_name(&self) -> String {
        if let Some(name) = self
            .helo_name
            .as_ref()
            .map(|n| n.trim())
            .filter(|n| !n.is_empty())
        {
            return name.to_owned();
        }
        self.from_address
            .as_deref()
            .and_then(|addr| addr.split_once('@'))
            .map(|(_, domain)| domain.trim().to_owned())
            .filter(|domain| !domain.is_empty())
            .unwrap_or_else(|| "localhost".to_owned())
    }

    fn validate(&self) -> Result<(), ApiError> {
        // A relay reachable in the clear is only allowed as a deliberate, recorded decision.
        if self.encryption == SmtpEncryption::None && !self.allow_insecure {
            return Err(ApiError::Unprocessable(
                "email.encryption \"none\" sends the relay password and message content in the \
                 clear; set email.allow_insecure to true to confirm that is intended"
                    .to_owned(),
            ));
        }
        if self.port == 0 {
            return Err(ApiError::Unprocessable(
                "email.port must be between 1 and 65535".to_owned(),
            ));
        }
        for (field, value) in [
            ("email.host", &self.host),
            ("email.helo_name", &self.helo_name),
        ] {
            if let Some(raw) = value {
                let trimmed = raw.trim();
                if !trimmed.is_empty() && trimmed.chars().any(char::is_whitespace) {
                    return Err(ApiError::Unprocessable(format!(
                        "{field} must not contain whitespace, got {raw:?}"
                    )));
                }
            }
        }
        // Addresses go into SMTP command lines, so a CR/LF would be command injection. The email
        // validator already rejects whitespace, but the sender is checked explicitly here because it
        // is the one field that reaches `MAIL FROM`.
        if let Some(from) = &self.from_address {
            crate::email::normalize_optional_email(Some(from.clone()), "email.from_address")?;
        }
        if let Some(username) = &self.username
            && username.contains(['\r', '\n'])
        {
            return Err(ApiError::Unprocessable(
                "email.username must not contain line breaks".to_owned(),
            ));
        }
        // Only demand a complete configuration once the operator switches it on, so a half-filled
        // form can still be saved while it is being set up.
        if self.enabled {
            let host_set = self
                .host
                .as_deref()
                .map(str::trim)
                .is_some_and(|h| !h.is_empty());
            if !host_set {
                return Err(ApiError::Unprocessable(
                    "email.host is required when email.enabled is true".to_owned(),
                ));
            }
            let from_set = self
                .from_address
                .as_deref()
                .map(str::trim)
                .is_some_and(|a| !a.is_empty());
            if !from_set {
                return Err(ApiError::Unprocessable(
                    "email.from_address is required when email.enabled is true".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

// --- Authentication & signup (t95 P0-1) ---------------------------------------------------------

/// Authentication, self-signup and second-factor policy (t95 §3).
///
/// **Every field fails closed.** `#[serde(default)]` on the container means a `settings.json`
/// written before this slice existed deserializes with signup `Disabled`, no recovery links and no
/// second factor — which is the difference between "we shipped a feature" and "we opened every
/// existing instance to strangers on upgrade".
///
/// The slice carries **no behaviour** in P0: nothing reads it yet. It exists so that the handlers
/// that will read it (P1) are written against a shape whose invariants — above all the §2.6
/// default-role ceiling — are already enforced at the door.
///
/// No secret ever enters this document. TOTP secrets live AEAD-encrypted in the credential store
/// and token verifiers live in [`crate::auth_token`], exactly as the SMTP password does.
///
/// Magic link is deliberately absent: it was dropped from the tranche by explicit ruling, because a
/// passwordless session cannot unwrap the user's attestation key and would produce silently
/// unattested acts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthSettings {
    /// Who, if anyone, may create their own account.
    pub signup: SignupSettings,
    /// Email-based account recovery.
    pub password_recovery: PasswordRecoverySettings,
    /// Second-factor policy.
    pub two_factor: TwoFactorSettings,
}

/// Who may create an account without an administrator doing it for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignupMode {
    /// Nobody. Accounts are created by an administrator through `POST /v1/users`. **Default**, and
    /// what every pre-t95 settings document deserializes to.
    #[default]
    Disabled,
    /// Only the holder of a valid invitation (`user.invite` issued it).
    InviteOnly,
    /// Anyone with an address at one of [`SignupSettings::allowed_domains`].
    DomainAllowlist,
    /// Anyone at all.
    Public,
}

impl SignupMode {
    /// The stable id (matches the serde representation).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            SignupMode::Disabled => "disabled",
            SignupMode::InviteOnly => "invite_only",
            SignupMode::DomainAllowlist => "domain_allowlist",
            SignupMode::Public => "public",
        }
    }
}

impl std::fmt::Display for SignupMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Self-signup policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SignupSettings {
    /// Who may sign themselves up. [`SignupMode::Disabled`] by default.
    pub mode: SignupMode,
    /// Exact, lowercased mail domains accepted when `mode` is
    /// [`SignupMode::DomainAllowlist`].
    ///
    /// **No wildcards.** `*.example.pt` looks convenient and is a subdomain-takeover signup
    /// vector: anyone who gets `abandoned-staging.example.pt` gets accounts on this instance. An
    /// entry containing `*` is refused, not silently ignored, so an operator who tries it finds out
    /// at the moment they try rather than the moment it is abused.
    pub allowed_domains: Vec<String>,
    /// The single role a self-signed-up account receives. Guest by default, and ceiling-checked —
    /// see [`AuthSettings::validate_default_role_against`].
    pub default_role: chancela_authz::RoleId,
    /// Whether a self-signed-up account must prove control of its address before it can be used.
    /// Defaults **on**: the safe direction, and the one that makes the address in the account real.
    pub require_email_verification: bool,
    /// How long an invitation stays redeemable. Clamped 1 hour … 30 days.
    pub invite_ttl_hours: u32,
}

impl Default for SignupSettings {
    fn default() -> Self {
        SignupSettings {
            mode: SignupMode::Disabled,
            allowed_domains: Vec::new(),
            default_role: chancela_authz::GUEST_ROLE_ID,
            require_email_verification: true,
            invite_ttl_hours: 168,
        }
    }
}

impl SignupSettings {
    /// The allow-list, trimmed, lowercased, de-duplicated and ordered. Stored normalized (the
    /// [`ConnectorSettings::normalized`] precedent) so a match is a byte comparison and the
    /// audit diff shows a boundary change rather than a whitespace change.
    #[must_use]
    pub fn normalized_domains(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .allowed_domains
            .iter()
            .map(|d| d.trim().to_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

/// Email-based account recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordRecoverySettings {
    /// Whether "forgot my password" issues an emailed reset link. Off by default.
    ///
    /// Turning this on has a consequence that must reach the user before they commit: the reset
    /// happens without the old password, so the attestation key cannot be re-wrapped and is
    /// **retired**, exactly as a recovery-phrase reset already does.
    pub email_link_enabled: bool,
    /// Whether "I forgot my username" mails the matching username(s) to the address. Off by
    /// default. It answers only into the mailbox — never over HTTP, which would be an enumeration
    /// oracle no rate limit repairs.
    pub username_by_email: bool,
    /// Reset-link lifetime in minutes. Clamped 5 … 60.
    pub link_ttl_minutes: u32,
}

impl Default for PasswordRecoverySettings {
    fn default() -> Self {
        PasswordRecoverySettings {
            email_link_enabled: false,
            username_by_email: false,
            link_ttl_minutes: 15,
        }
    }
}

/// Second-factor policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TwoFactorSettings {
    /// Authenticator-app second factor (RFC 6238). Off by default.
    pub totp_enabled: bool,
    /// Emailed second factor. Off by default, and see
    /// [`acknowledge_single_channel_risk`](Self::acknowledge_single_channel_risk) before turning it
    /// on.
    pub email_enabled: bool,
    /// Whether a second factor is required instance-wide. Off by default, and refused unless
    /// [`totp_enabled`](Self::totp_enabled) is on — a requirement that can only be satisfied over
    /// the mail relay is a lockout waiting for the relay to have a bad day.
    pub required: bool,
    /// The operator's **explicit** acknowledgement that email is about to be both the second factor
    /// and the recovery channel — that is one factor wearing two hats, and an attacker with the
    /// mailbox then has everything, password included.
    ///
    /// A server-enforced gate in the [`EmailSettings::allow_insecure`] mould, not UI copy: the
    /// combination is refused outright without it.
    pub acknowledge_single_channel_risk: bool,
}

impl AuthSettings {
    /// Whether the slice is entirely at its (closed) defaults. Drives `skip_serializing_if`, so a
    /// `GET /v1/settings` on an instance that has never touched authentication is byte-identical to
    /// one from before this slice existed.
    pub(crate) fn is_default(&self) -> bool {
        self == &AuthSettings::default()
    }

    /// Whether any enabled feature needs to put a **link to this instance** in an email, and
    /// therefore needs [`PlatformSettings::public_base_url`] configured.
    #[must_use]
    pub fn requires_instance_base_url(&self) -> bool {
        self.password_recovery.email_link_enabled
            || matches!(self.signup.mode, SignupMode::InviteOnly)
            || (!matches!(self.signup.mode, SignupMode::Disabled)
                && self.signup.require_email_verification)
    }

    /// Whether any enabled feature needs to send mail at all, and therefore needs
    /// [`EmailSettings::enabled`].
    #[must_use]
    pub fn requires_outbound_email(&self) -> bool {
        self.requires_instance_base_url()
            || self.password_recovery.username_by_email
            || self.two_factor.email_enabled
    }

    /// Structural validation — everything that can be decided without resolving the role catalog.
    ///
    /// The default-role **ceiling** is deliberately split: the part that needs no catalog (never
    /// Owner) is here, and the part that needs the role's permission-set is
    /// [`validate_default_role_against`](Self::validate_default_role_against). Both run on every
    /// `PUT /v1/settings`.
    fn validate(&self) -> Result<(), ApiError> {
        // --- §2.6 ceiling, the half that needs no catalog -------------------------------------
        if self.signup.default_role == chancela_authz::OWNER_ROLE_ID {
            return Err(ApiError::Unprocessable(
                "auth.signup.default_role must never be the Owner role — self-signup may not \
                 grant the protected super-role"
                    .to_owned(),
            ));
        }

        // --- Domain allow-list ----------------------------------------------------------------
        for (i, raw) in self.signup.allowed_domains.iter().enumerate() {
            validate_signup_domain(&format!("auth.signup.allowed_domains[{i}]"), raw)?;
        }
        if matches!(self.signup.mode, SignupMode::DomainAllowlist)
            && self.signup.normalized_domains().is_empty()
        {
            return Err(ApiError::Unprocessable(
                "auth.signup.mode \"domain_allowlist\" requires at least one entry in \
                 auth.signup.allowed_domains; an empty list would either admit everyone or nobody, \
                 and neither is what the operator asked for"
                    .to_owned(),
            ));
        }

        // --- Lifetimes ------------------------------------------------------------------------
        if !(1..=720).contains(&self.signup.invite_ttl_hours) {
            return Err(ApiError::Unprocessable(format!(
                "auth.signup.invite_ttl_hours must be between 1 and 720 (30 days), got {}",
                self.signup.invite_ttl_hours
            )));
        }
        if !(5..=60).contains(&self.password_recovery.link_ttl_minutes) {
            return Err(ApiError::Unprocessable(format!(
                "auth.password_recovery.link_ttl_minutes must be between 5 and 60, got {}",
                self.password_recovery.link_ttl_minutes
            )));
        }

        // --- §2.4: email must not be both the second factor and the recovery channel ----------
        if self.two_factor.email_enabled
            && !self.two_factor.totp_enabled
            && self.password_recovery.email_link_enabled
            && !self.two_factor.acknowledge_single_channel_risk
        {
            return Err(ApiError::Unprocessable(
                "auth.two_factor.email_enabled as the only second factor together with \
                 auth.password_recovery.email_link_enabled makes the mailbox both the second factor \
                 and the reset channel, so an attacker holding it does not need the password at \
                 all; enable auth.two_factor.totp_enabled, or set \
                 auth.two_factor.acknowledge_single_channel_risk to true to confirm that is intended"
                    .to_owned(),
            ));
        }

        // --- §5 #9: a requirement that only mail can satisfy is a lockout ---------------------
        if self.two_factor.required && !self.two_factor.totp_enabled {
            return Err(ApiError::Unprocessable(
                "auth.two_factor.required needs auth.two_factor.totp_enabled: a second factor that \
                 can only arrive over the mail relay locks every user out — including the last \
                 Owner — the first time the relay is unavailable"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// The half of the §2.6 ceiling that needs the role catalog: the configured default role must
    /// exist, must not be protected, and must hold none of
    /// [`Permission::SELF_SIGNUP_FORBIDDEN`](chancela_authz::Permission::SELF_SIGNUP_FORBIDDEN).
    ///
    /// An unresolvable role is a refusal, not a shrug: "the default role does not exist" would
    /// otherwise be discovered at the moment a stranger signs up, which is the worst possible time
    /// to find out what happens next.
    ///
    /// **This is one of two call sites the ceiling needs.** The other is role *edit* time — a role
    /// that is eligible today can be edited tomorrow to hold `settings.manage` while remaining the
    /// configured signup default, and checking only here would leave that bypass wide open. Both
    /// sites share [`Role::signup_default_refusal`](chancela_authz::Role::signup_default_refusal)
    /// so they cannot drift apart. Wiring the role-edit site belongs to P1.
    pub(crate) fn validate_default_role_against(
        &self,
        roles: &chancela_authz::RoleCatalog,
    ) -> Result<(), ApiError> {
        let id = self.signup.default_role;
        let Some(role) = roles.get(id) else {
            return Err(ApiError::Unprocessable(format!(
                "auth.signup.default_role {id} does not name a role in the catalog"
            )));
        };
        if let Some(refusal) = role.signup_default_refusal() {
            return Err(ApiError::Unprocessable(format!(
                "auth.signup.default_role {:?} cannot be the self-signup default role because \
                 {refusal}",
                role.name
            )));
        }
        Ok(())
    }
}

/// The instance's public base URL (t95 P0-3): absolute, `https://`, no credentials, no query, no
/// fragment.
///
/// Deliberately strict. This string becomes the origin of a URL carrying a single-use credential
/// into someone's mailbox, and every rejection below corresponds to a way that URL could point
/// somewhere other than where the operator thinks it points:
///
/// - **`http://`** — a recovery token travelling in the clear.
/// - **userinfo (`https://livros.example.pt@evil.example/`)** — reads as the real host to a human
///   skimming a mail client's status bar, resolves to the attacker's.
/// - **a query or fragment** — appended to by the link builder, producing a URL nobody wrote.
/// - **whitespace or control characters** — header and body injection into the outgoing message.
/// - **`..` in the path** — a link that traverses out of the deployment's subpath.
fn validate_public_base_url(field: &str, raw: &str) -> Result<(), ApiError> {
    let value = raw.trim();
    let refuse = |why: &str| {
        Err(ApiError::Unprocessable(format!(
            "{field} must be the absolute https:// URL this instance is reached at, because every \
             emailed link is built from it and it is never inferred from a request header: {why} \
             (got {raw:?})"
        )))
    };
    if value.len() > 512 {
        return refuse("it is longer than 512 characters");
    }
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return refuse("it contains whitespace or control characters");
    }
    let Some(rest) = value.strip_prefix("https://") else {
        return refuse(
            "it does not start with \"https://\" — plain http would put a single-use recovery \
             credential on the wire in the clear",
        );
    };
    if value.contains(['?', '#']) {
        return refuse("it carries a query string or fragment, which the link builder appends to");
    }
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, path),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return refuse("it has no host");
    }
    if authority.contains('@') {
        return refuse(
            "it embeds credentials before the host, which renders as the real host in a mail \
             client while resolving somewhere else",
        );
    }
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    if host.is_empty()
        || host.starts_with(['.', '-'])
        || host.ends_with(['.', '-'])
        || host.contains("..")
    {
        return refuse("its host is not a well-formed name");
    }
    if path.contains("..") {
        return refuse("its path traverses upwards");
    }
    Ok(())
}

/// One entry of [`SignupSettings::allowed_domains`]: an **exact** mail domain.
fn validate_signup_domain(field: &str, raw: &str) -> Result<(), ApiError> {
    let value = raw.trim().to_lowercase();
    // Named separately from the generic shape error, because "wildcards are not supported" and
    // "that is not a domain" send an operator to two different places.
    if value.contains('*') {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be an exact domain: wildcards such as {raw:?} are refused because a \
             subdomain that is later abandoned or taken over would grant signup on this instance"
        )));
    }
    let looks_like_a_domain = !value.is_empty()
        && value.len() <= 253
        && value.contains('.')
        && !value.starts_with(['.', '-'])
        && !value.ends_with(['.', '-'])
        && !value.contains("..")
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    if !looks_like_a_domain {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be a bare mail domain such as \"example.pt\" — no scheme, no \"@\", no \
             path, no wildcard — got {raw:?}"
        )));
    }
    Ok(())
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
    /// **The instance's own public base URL** — the origin every emailed link is built from
    /// (t95 P0-3). `null` until an operator sets it, and there is no fallback.
    ///
    /// ## It must never be derived from the request
    ///
    /// The obvious shortcut is to read the `Host` (or `X-Forwarded-Host`) header of whatever
    /// request is issuing the link. **That is host-header injection**, and on this surface it is
    /// the single most dangerous line in the tranche: `POST /v1/auth/recover` is unauthenticated,
    /// so an attacker sends it with `Host: evil.example` naming *someone else's* account, and the
    /// victim receives a genuine, correctly-addressed, correctly-signed password-recovery mail
    /// whose link points at the attacker's server. The victim clicks their own reset link and
    /// hands over a live single-use credential. No amount of TTL, single-use or rate limiting helps
    /// — the token is valid and the victim delivered it themselves.
    ///
    /// So the value is **configured or absent**, never inferred, and never guessed from a
    /// certificate, a bind address or an `Origin`. `smtp_settings.rs` already refused to guess one
    /// for the welcome mail; this is that same refusal, made configurable rather than reversed.
    ///
    /// ## When it is absent
    ///
    /// Every link-issuing feature is **unavailable and says so**. Settings validation refuses to
    /// enable one (`422`, naming this field), and the welcome mail omits its sign-in link rather
    /// than inventing one. Nothing silently falls back to a plausible-looking origin.
    ///
    /// Must be an absolute `https://` URL. Plain `http` is refused: a recovery link is a bearer
    /// credential in a URL, and putting one on the wire in the clear defeats the rest of this
    /// design.
    pub public_base_url: Option<String>,
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
            public_base_url: None,
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
    /// The configured public base URL with trailing slashes removed, ready to have `"/reset"` and
    /// friends appended — or `None` when it is unset or blank.
    ///
    /// **This is the only source of a link origin.** There is no request-derived variant of this
    /// function and there must never be one; see [`PlatformSettings::public_base_url`].
    #[must_use]
    pub fn resolved_public_base_url(&self) -> Option<String> {
        self.public_base_url
            .as_deref()
            .map(str::trim)
            .filter(|raw| !raw.is_empty())
            .map(|raw| raw.trim_end_matches('/').to_owned())
            .filter(|raw| !raw.is_empty())
    }

    pub(crate) fn validate(&self) -> Result<(), ApiError> {
        if let Some(raw) = self.public_base_url.as_deref()
            && !raw.trim().is_empty()
        {
            validate_public_base_url("platform.public_base_url", raw)?;
        }
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
    /// PEM-encoded trust-anchor certificate(s) pinning the EU LOTL / national-scheme XML-DSig
    /// **signing certificate** used to authenticate the Trusted List itself (SIG-11). Each entry is
    /// one or more `-----BEGIN CERTIFICATE-----` blocks (or a single raw-DER cert). This is the
    /// application-config surface for the same anchor otherwise loaded from
    /// [`CHANCELA_TSL_TRUST_ANCHOR`](chancela_tsl::ENV_TSL_TRUST_ANCHOR); at runtime the settings
    /// anchors are **unioned** with the environment ones. **Defaults to empty (fail-closed):** no
    /// default anchor is ever baked in — an unconfigured install trusts no list. Configure several
    /// to cover key rotation. Omitted from the serialized document when empty (the common,
    /// fail-closed default) so the on-the-wire shape is unchanged for installs that never set one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tsl_trust_anchor_certs: Vec<String>,
    /// Hex SHA-256 fingerprint(s) (over the DER encoding of the signer certificate) pinning the same
    /// Trusted-List signing anchor as [`tsl_trust_anchor_certs`](Self::tsl_trust_anchor_certs),
    /// as an alternative to shipping the certificate bytes — the settings analogue of
    /// [`CHANCELA_TSL_TRUST_ANCHOR_SHA256`](chancela_tsl::ENV_TSL_TRUST_ANCHOR_SHA256). Each entry is
    /// a 64-character sha256 hex string. Unioned with the certificate anchors and the environment
    /// anchors; **defaults to empty (fail-closed)**. Omitted from the serialized document when empty
    /// so the on-the-wire shape is unchanged for installs that never set one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tsl_trust_anchor_sha256: Vec<String>,
    /// Additive RFC 3161 timestamp provider configuration. The enabled default provider is
    /// considered before the legacy [`tsa_url`](Self::tsa_url) compatibility field in timestamping.
    pub tsa_providers: Vec<TsaProviderSettings>,
    /// When true, an act cannot reach the finalized-**qualified** status until a valid qualified
    /// signature is present (t57 ruling 6 / deliverable D). This gates the STATUS, **not** the seal:
    /// sealing still succeeds and the unsigned PDF/A still exists; the async OTP signing flow is a
    /// distinct post-seal step. With it `false`, the non-qualified finalized path stays fully usable.
    pub require_qualified_for_seal: bool,
    /// Chave Móvel Digital signing configuration (t57 Slice 1). Non-secret selectors only — runtime
    /// credentials and the field-encryption certificate PEM come from protected storage or
    /// `CHANCELA_CMD_*`, never this echoed settings document.
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
            // Fail-closed: no trust anchor is provisioned by default. A default anchor is NEVER
            // baked in — an operator must supply the public LOTL signing cert here or via env.
            tsl_trust_anchor_certs: Vec::new(),
            tsl_trust_anchor_sha256: Vec::new(),
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
            note: "No CSC/QTSP provider is configured in protected storage or environment."
                .to_owned(),
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
/// credentials are read from protected storage or the environment (`CHANCELA_CMD_AMA_CERT_PEM`,
/// `CHANCELA_CMD_HTTP_BASIC_USERNAME`, `CHANCELA_CMD_HTTP_BASIC_PASSWORD`) by the runtime resolver.
/// This sub-object carries only the non-secret selectors an operator sees: which environment, the
/// optional ApplicationId echo, and a read-only "is the AMA cert configured?" indicator.
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

impl Locale {
    /// The BCP 47 tag — the same string serde reads and writes.
    ///
    /// Added for the server-side email templates (t70), which pick a copy catalog by tag and are
    /// not going through serde to get there. `locale_as_str_matches_serde` pins the two together so
    /// they cannot drift, which is the same trap `SmtpEncryption::StartTls` fell into.
    pub fn as_str(self) -> &'static str {
        match self {
            Locale::PtPt => "pt-PT",
            Locale::PtBr => "pt-BR",
            Locale::DaDk => "da-DK",
            Locale::DeDe => "de-DE",
            Locale::FrFr => "fr-FR",
            Locale::FiFi => "fi-FI",
            Locale::SvFi => "sv-FI",
            Locale::ItIt => "it-IT",
            Locale::NlNl => "nl-NL",
            Locale::PlPl => "pl-PL",
            Locale::EnGb => "en-GB",
            Locale::EnUs => "en-US",
            Locale::SvSe => "sv-SE",
            Locale::EsEs => "es-ES",
        }
    }
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
        validate_tsl_trust_anchors(
            &self.signing.tsl_trust_anchor_certs,
            &self.signing.tsl_trust_anchor_sha256,
        )?;
        validate_tsa_providers(&self.signing.tsa_providers)?;
        self.registry_auto_update.validate()?;
        self.workflow.validate()?;
        self.data_management.validate()?;
        self.connectors.validate()?;
        self.email.validate()?;
        self.platform.validate()?;
        self.auth.validate()?;
        self.validate_auth_prerequisites()?;
        Ok(())
    }

    /// The cross-slice half of the t95 rules: a feature that mails a link to this instance cannot
    /// be enabled while the instance has no configured origin to link to, and a feature that mails
    /// anything cannot be enabled while the relay is off.
    ///
    /// Refusing here — rather than enabling the toggle and discovering at send time that there is
    /// no URL — is what "unavailable and says so" means in practice. The alternative is an operator
    /// who believes recovery is on, and users who find out it is not while locked out.
    fn validate_auth_prerequisites(&self) -> Result<(), ApiError> {
        if self.auth.requires_instance_base_url()
            && self.platform.resolved_public_base_url().is_none()
        {
            return Err(ApiError::Unprocessable(
                "this authentication setting emails a link back to this instance, so \
                 platform.public_base_url must be configured first; it is never inferred from the \
                 request's Host header, because an attacker could then aim a live recovery link at \
                 their own domain"
                    .to_owned(),
            ));
        }
        if self.auth.requires_outbound_email() && !self.email.enabled {
            return Err(ApiError::Unprocessable(
                "this authentication setting sends mail, so email.enabled must be on and the relay \
                 configured first"
                    .to_owned(),
            ));
        }
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

/// Validate the operator-provisioned Trusted-List trust anchors (SIG-11). Each certificate entry
/// must parse as PEM (one or more `CERTIFICATE` blocks) or raw DER via the same
/// [`chancela_tsl::parse_anchor_certs`] used by the environment loader; each fingerprint entry must
/// be a 64-character sha256 hex string (reusing [`validate_optional_sha256_hex`]). Both lists
/// default to empty (fail-closed) — an empty configuration is valid and simply trusts no list.
/// Malformed PEM or malformed hex is a client-actionable `422`.
fn validate_tsl_trust_anchors(certs: &[String], fingerprints: &[String]) -> Result<(), ApiError> {
    for (i, pem) in certs.iter().enumerate() {
        let field = format!("signing.tsl_trust_anchor_certs[{i}]");
        if pem.trim().is_empty() {
            return Err(ApiError::Unprocessable(format!(
                "{field} must be a non-empty PEM or DER certificate"
            )));
        }
        chancela_tsl::parse_anchor_certs(pem.as_bytes()).map_err(|e| {
            ApiError::Unprocessable(format!(
                "{field} must be a valid PEM/DER trust-anchor certificate: {e}"
            ))
        })?;
    }
    for (i, fingerprint) in fingerprints.iter().enumerate() {
        let field = format!("signing.tsl_trust_anchor_sha256[{i}]");
        if fingerprint.trim().is_empty() {
            return Err(ApiError::Unprocessable(format!(
                "{field} must be a 64-character sha256 hex fingerprint"
            )));
        }
        // Reuse the shared hex validator; unlike the env form, settings fingerprints are plain
        // 64-hex (no `:` separators), which this rejects.
        validate_optional_sha256_hex(&field, fingerprint)?;
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
    let settings_cmd_configured = settings
        .signing
        .cmd
        .application_id
        .as_deref()
        .is_some_and(|id| !id.trim().is_empty());
    let stored_cmd = stored_cmd_metadata_credential_state(state, &settings.signing.cmd);
    let cmd_configured = match stored_cmd.state {
        MetadataCredentialState::Complete => true,
        MetadataCredentialState::Incomplete | MetadataCredentialState::Unavailable => false,
        MetadataCredentialState::Missing => settings_cmd_configured,
    };
    let cmd_prod = settings.signing.cmd.env == CmdEnvSetting::Prod;
    settings.signing.cmd.ama_cert_configured |= stored_cmd.ama_cert_configured;
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
            note: "No CSC/QTSP provider is configured in protected storage or environment."
                .to_owned(),
        });
    } else {
        let injected_transport = state.csc_transport.is_some();
        for cfg in state.csc_providers.iter() {
            let configured = csc_metadata_credentials_configured(state, cfg, injected_transport);
            providers.push(SigningProviderMetadata {
                id: cfg.provider_id.clone(),
                mode: SigningProviderMode::CscQtsp,
                label: cfg.display_name.clone(),
                configured,
                production_blocked: !configured || cfg.sandbox,
                local_only: false,
                note: if configured {
                    if cfg.sandbox {
                        "CSC/QTSP provider is configured in sandbox mode; runtime credentials stay in protected storage or environment.".to_owned()
                    } else {
                        "CSC/QTSP provider is configured; runtime credentials stay in protected storage or environment and are not returned."
                            .to_owned()
                    }
                } else {
                    "CSC/QTSP provider metadata exists, but authorization-matching runtime credentials are missing or unavailable."
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataCredentialState {
    Missing,
    Complete,
    Incomplete,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CmdMetadataCredentialState {
    state: MetadataCredentialState,
    ama_cert_configured: bool,
}

fn stored_cmd_metadata_credential_state(
    state: &AppState,
    cmd: &SigningCmdSettings,
) -> CmdMetadataCredentialState {
    match state
        .provider_credentials
        .read_runtime(CredentialMode::Cmd, "")
    {
        Ok(Some(record)) => {
            let ama_cert_configured = credential_field_nonblank(&record, FIELD_AMA_CERT_PEM);
            let state = if cmd_stored_metadata_config(cmd, &record)
                .is_some_and(|cfg| cfg.field_encryptor().is_ok())
            {
                MetadataCredentialState::Complete
            } else {
                MetadataCredentialState::Incomplete
            };
            CmdMetadataCredentialState {
                state,
                ama_cert_configured,
            }
        }
        Ok(None) => CmdMetadataCredentialState {
            state: MetadataCredentialState::Missing,
            ama_cert_configured: false,
        },
        Err(_) => CmdMetadataCredentialState {
            state: MetadataCredentialState::Unavailable,
            ama_cert_configured: false,
        },
    }
}

fn cmd_stored_metadata_config(
    cmd: &SigningCmdSettings,
    record: &DecryptedCredentialRecord,
) -> Option<CmdConfig> {
    if !cmd_stored_missing_fields(cmd, record).is_empty() {
        return None;
    }
    let application_id = record.fields.get(FIELD_APPLICATION_ID)?.as_str().to_owned();
    let basic_auth = if credential_field_nonblank(record, FIELD_HTTP_BASIC_USERNAME)
        && credential_field_nonblank(record, FIELD_HTTP_BASIC_PASSWORD)
    {
        Some(CmdBasicAuth::new(
            record
                .fields
                .get(FIELD_HTTP_BASIC_USERNAME)?
                .as_str()
                .to_owned(),
            record
                .fields
                .get(FIELD_HTTP_BASIC_PASSWORD)?
                .as_str()
                .to_owned(),
        ))
    } else {
        None
    };
    Some(CmdConfig {
        env: cmd_env_for_metadata(cmd.env),
        application_id,
        basic_auth,
        ama_cert_pem: record
            .fields
            .get(FIELD_AMA_CERT_PEM)
            .filter(|pem| !pem.trim().is_empty())
            .map(|pem| pem.as_str().to_owned()),
    })
}

fn cmd_stored_missing_fields(
    cmd: &SigningCmdSettings,
    record: &DecryptedCredentialRecord,
) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if !credential_field_nonblank(record, FIELD_APPLICATION_ID) {
        missing.push(FIELD_APPLICATION_ID);
    }

    let has_username = credential_field_nonblank(record, FIELD_HTTP_BASIC_USERNAME);
    let has_password = credential_field_nonblank(record, FIELD_HTTP_BASIC_PASSWORD);
    match (has_username, has_password) {
        (true, false) => missing.push(FIELD_HTTP_BASIC_PASSWORD),
        (false, true) => missing.push(FIELD_HTTP_BASIC_USERNAME),
        _ => {}
    }

    if matches!(cmd.env, CmdEnvSetting::Prod)
        && !credential_field_nonblank(record, FIELD_AMA_CERT_PEM)
    {
        missing.push(FIELD_AMA_CERT_PEM);
    }
    missing
}

fn cmd_env_for_metadata(env: CmdEnvSetting) -> CmdEnv {
    match env {
        CmdEnvSetting::Preprod => CmdEnv::Preprod,
        CmdEnvSetting::Prod => CmdEnv::Prod,
    }
}

fn csc_metadata_credentials_configured(
    state: &AppState,
    cfg: &CscConfig,
    injected_transport: bool,
) -> bool {
    match stored_csc_metadata_credential_state(state, cfg) {
        MetadataCredentialState::Complete => true,
        MetadataCredentialState::Incomplete | MetadataCredentialState::Unavailable => false,
        MetadataCredentialState::Missing => {
            csc_env_configured_for_authorization(cfg) || injected_transport
        }
    }
}

fn stored_csc_metadata_credential_state(
    state: &AppState,
    cfg: &CscConfig,
) -> MetadataCredentialState {
    match state
        .provider_credentials
        .read_runtime(CredentialMode::CscQtsp, &cfg.provider_id)
    {
        Ok(Some(record)) => {
            if csc_stored_missing_fields(cfg.authorization, &record).is_empty() {
                MetadataCredentialState::Complete
            } else {
                MetadataCredentialState::Incomplete
            }
        }
        Ok(None) => MetadataCredentialState::Missing,
        Err(_) => MetadataCredentialState::Unavailable,
    }
}

fn csc_env_configured_for_authorization(cfg: &CscConfig) -> bool {
    let Ok(secrets) = CscSecrets::from_env(&cfg.provider_id) else {
        return false;
    };
    match cfg.authorization {
        CscAuthorization::Service => {
            !secrets.client_id.trim().is_empty() && !secrets.client_secret.trim().is_empty()
        }
        CscAuthorization::User => secrets
            .access_token
            .as_ref()
            .is_some_and(|token| !token.trim().is_empty()),
        _ => false,
    }
}

fn csc_stored_missing_fields(
    authorization: CscAuthorization,
    record: &DecryptedCredentialRecord,
) -> Vec<&'static str> {
    csc_authorization_missing_fields(
        authorization,
        credential_field_nonblank(record, FIELD_CLIENT_ID),
        credential_field_nonblank(record, FIELD_CLIENT_SECRET),
        credential_field_nonblank(record, FIELD_ACCESS_TOKEN),
    )
}

fn credential_field_nonblank(record: &DecryptedCredentialRecord, field: &str) -> bool {
    record
        .fields
        .get(field)
        .is_some_and(|value| !value.trim().is_empty())
}

fn csc_authorization_missing_fields(
    authorization: CscAuthorization,
    has_client_id: bool,
    has_client_secret: bool,
    has_access_token: bool,
) -> Vec<&'static str> {
    match authorization {
        CscAuthorization::Service => {
            let mut missing = Vec::new();
            if !has_client_id {
                missing.push(FIELD_CLIENT_ID);
            }
            if !has_client_secret {
                missing.push(FIELD_CLIENT_SECRET);
            }
            missing
        }
        CscAuthorization::User => {
            if has_access_token {
                Vec::new()
            } else {
                vec![FIELD_ACCESS_TOKEN]
            }
        }
        _ => vec![FIELD_CLIENT_ID, FIELD_CLIENT_SECRET, FIELD_ACCESS_TOKEN],
    }
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
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
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

/// The connector egress policy currently in force, resolved from live state.
///
/// The API resolves from its own in-memory settings rather than re-reading the sidecar, so a
/// target is always checked against exactly the boundary the operator last saved — never against a
/// file the worker has not observed yet.
pub(crate) async fn effective_network_policy(
    state: &AppState,
) -> Result<NetworkPolicy, chancela_connectors::ConnectorError> {
    let entries = state.settings.read().await.connectors.normalized();
    let runtime =
        (!entries.is_empty()).then(|| RuntimeAllowlist::new(entries, String::new(), String::new()));
    NetworkPolicy::resolve(environment_ceiling().as_deref(), runtime.as_ref())
}

/// Entries present in `left` but not in `right`.
fn difference(left: &[String], right: &[String]) -> Vec<String> {
    let right: BTreeSet<&String> = right.iter().collect();
    left.iter()
        .filter(|entry| !right.contains(entry))
        .cloned()
        .collect()
}

/// The human-readable before/after carried in the ledger event's `justification`.
///
/// The ledger commits to a payload by **digest** and does not retain its bytes, so a change that
/// must be reconstructable from the chain alone has to say what it was in a stored field. This is
/// that field; the JSON payload remains as a digest commitment to the exact lists.
fn allowlist_change_summary(previous: &[String], next: &[String], ceiling: Option<&str>) -> String {
    let added = difference(next, previous);
    let removed = difference(previous, next);
    let mut summary = String::from("connector egress allowlist");
    if !added.is_empty() {
        summary.push_str(&format!(" +[{}]", added.join(" ")));
    }
    if !removed.is_empty() {
        summary.push_str(&format!(" -[{}]", removed.join(" ")));
    }
    summary.push_str(&format!(
        " · now [{}] · deployment ceiling {}",
        next.join(" "),
        match ceiling {
            Some(ceiling) => format!("[{}]", ceiling.trim()),
            None => "unset".to_owned(),
        }
    ));
    summary
}

/// Write the runtime allowlist sidecar the connector stack enforces from.
///
/// The document lives in the shared data directory precisely because the connector *worker* is a
/// separate process: it re-resolves the policy per job, so publishing the file is what makes a
/// saved change effective without restarting anything. Without a data directory the API is a
/// purely in-memory scaffold with no worker to inform, so there is nothing to publish.
async fn publish_runtime_allowlist(
    state: &AppState,
    settings: &Settings,
    actor: &str,
) -> Result<(), ApiError> {
    let Some(data_dir) = state.data_dir() else {
        return Ok(());
    };
    let path = RuntimeAllowlist::path_in(&data_dir);
    if settings.connectors.allowed_hosts.is_empty() {
        // Removing the last entry restores the deployment ceiling as the sole boundary; it must
        // never leave a stale file behind that keeps enforcing a boundary nobody can see.
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ApiError::Internal(format!(
                "unable to clear the connector allowlist: {error}"
            ))),
        };
    }
    let document = RuntimeAllowlist::new(
        settings.connectors.allowed_hosts.clone(),
        time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
        actor.to_owned(),
    );
    let bytes = serde_json::to_vec_pretty(&document)?;
    let temporary = tmp_path(&path);
    std::fs::write(&temporary, &bytes).map_err(|error| {
        ApiError::Internal(format!("unable to stage the connector allowlist: {error}"))
    })?;
    std::fs::rename(&temporary, &path).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        ApiError::Internal(format!(
            "unable to publish the connector allowlist: {error}"
        ))
    })
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
    // Show the deployment ceiling next to the setting it constrains, so the precedence rule is
    // visible where the change is made rather than only in the documentation.
    settings.connectors.environment_ceiling = environment_ceiling().map(|raw| {
        raw.split(',')
            .map(|entry| entry.trim().to_ascii_lowercase())
            .filter(|entry| !entry.is_empty())
            .collect()
    });
    Ok(Json(settings))
}

/// Whether the operator-authored signing **policy** differs between two slices, ignoring the
/// server-owned [`SigningSettings::providers`] metadata — that list is re-stamped from live
/// credential/env state on every GET/PUT ([`stamp_signing_provider_metadata`]), so it can differ
/// between two saves the operator never touched and must not, on its own, trip the `signing.configure`
/// gate. Everything an operator actually authors — preferred family, the seal-status rule, the
/// TSA/TSL sources and anchors, and the CMD selectors — is compared.
fn signing_policy_changed(previous: &SigningSettings, next: &SigningSettings) -> bool {
    let policy = |s: &SigningSettings| {
        let mut s = s.clone();
        s.providers = Vec::new();
        s
    };
    policy(previous) != policy(next)
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
    // JSON, a bad enum, a bad locale — renders through `ApiError` as the standard body. The
    // intermediate `Value` is kept because the carry-forward below needs to tell "the client sent
    // this key" from "serde defaulted it", which the typed document can no longer express.
    let raw: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| ApiError::Unprocessable(format!("invalid settings document: {e}")))?;
    let mut settings: Settings = serde_json::from_value(raw.clone())
        .map_err(|e| ApiError::Unprocessable(format!("invalid settings document: {e}")))?;

    let previous = state.settings.read().await.clone();

    // `PUT` is a whole-document replace, and `#[serde(default)]` means an omitted section arrives
    // as its default rather than as "unchanged". For a section a client has simply never heard of
    // — the t95 `auth` slice, or `platform.public_base_url` — that turns "save the appearance tab
    // from a tab opened before the upgrade" into "silently switch password recovery off and blank
    // the link origin". So an *absent* key carries the stored value forward. An explicitly sent
    // one, including an explicit `null`, still replaces it: this restores intent, it does not make
    // the field unwritable.
    if raw.get("auth").is_none() {
        settings.auth = previous.auth.clone();
    }
    if raw
        .get("platform")
        .and_then(|platform| platform.get("public_base_url"))
        .is_none()
    {
        settings.platform.public_base_url = previous.platform.public_base_url.clone();
    }

    // Always stamp the current schema version regardless of what the client sent.
    settings.schema_version = SETTINGS_SCHEMA_VERSION;
    stamp_signing_provider_metadata(&state, &mut settings);

    // t50: the signature-policy slice is gated on the dedicated `signing.configure` verb — a finer
    // authority than the document-wide `settings.manage` this PUT already required. A caller may
    // replace every other slice with `settings.manage` alone, but CHANGING the signing policy
    // (preferred family, the seal-status rule, TSL/TSA sources and trust anchors, CMD config)
    // additionally requires `signing.configure`. Only a real change is gated, so a `settings.manage`
    // holder saving an unrelated tab (the web always PUTs the whole document) is never blocked; and
    // grandfathering grants `signing.configure` to every current `settings.manage` holder, so this
    // narrows only future custom roles. The server-owned `providers` metadata is excluded from the
    // diff because it is re-stamped from live credential/env state on every save.
    if signing_policy_changed(&previous.signing, &settings.signing) {
        require_permission(
            &state,
            &current_actor,
            Permission::SigningConfigure,
            Scope::Global,
        )
        .await?;
    }
    // Store the egress allowlist normalized, so the ledger diff below compares boundaries rather
    // than whitespace and casing. The stamped ceiling is server-owned: drop whatever came back.
    settings.connectors.allowed_hosts = settings.connectors.normalized();
    settings.connectors.environment_ceiling = None;
    // Same reasoning for the signup allow-list: a domain match must be a byte comparison, so it is
    // stored trimmed, lowercased and de-duplicated rather than compared that way at every signup.
    settings.auth.signup.allowed_domains = settings.auth.signup.normalized_domains();
    settings.validate()?;
    // The §2.6 ceiling's catalog-dependent half. It runs here rather than inside `validate()`
    // because the role catalog is state, not part of the document — and it must run on the same
    // request that stores the document, or the ceiling is advisory.
    settings
        .auth
        .validate_default_role_against(&*state.roles.read().await)?;

    // The zero-knowledge object root is checked here, not in `validate()`, for the same reason as
    // the line above: the answer depends on state (the data directory and the real filesystem),
    // not on the document. Refusing at save time is the whole point — this value's failure mode is
    // that a wrong path looks fine until the next restart, or worse, quietly gives each node its
    // own object storage. Only a *changed* value is checked, so an instance whose directory has
    // since become unwritable can still save an unrelated tab rather than being locked out of
    // settings entirely.
    if settings.data_management.zk_shared_object_root
        != previous.data_management.zk_shared_object_root
        && let Some(candidate) = settings.data_management.zk_shared_object_root.as_deref()
    {
        let data_dir = state.data_dir().ok_or_else(|| {
            ApiError::Unprocessable(
                "data_management.zk_shared_object_root requires CHANCELA_DATA_DIR persistence"
                    .to_owned(),
            )
        })?;
        crate::zk_repository::validate_shared_object_root(&data_dir, candidate).map_err(
            |reason| {
                ApiError::Unprocessable(format!(
                    "data_management.zk_shared_object_root is invalid: {reason}"
                ))
            },
        )?;
    }

    let previous_allowed_hosts = previous.connectors.normalized();
    let allowlist_changed = previous_allowed_hosts != settings.connectors.allowed_hosts;

    // Persist before we acknowledge success, so we never report a write we did not make. wp16 P3b:
    // routes to the active source (Postgres `settings` row, else `settings.json`). File behaviour on
    // SQLite/single-node is unchanged.
    crate::sidecar_store::persist_settings(&state, &settings).await?;

    // Actor precedence (contract §2.8): a valid session wins; else the `?actor=` override; else
    // the document's own default actor.
    let request_actor = query
        .actor
        .filter(|a| !a.trim().is_empty())
        .unwrap_or_else(|| settings.organization.default_actor.clone());
    let actor = current_actor.resolve(&request_actor);

    // The egress boundary is enforced from a sidecar the worker process also reads, so publish it
    // before acknowledging. A failure here is a failure of the whole PUT: reporting success while
    // the enforced boundary still differs from the stored one would be the worst outcome.
    if allowlist_changed {
        publish_runtime_allowlist(&state, &settings, &actor).await?;
    }

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
        // A dedicated event for the egress boundary. `settings.updated` already carries the whole
        // document, but reconstructing "who opened which host, and when" from a sequence of full
        // documents is exactly the reconstruction we do not want to depend on after an incident.
        if allowlist_changed {
            let ceiling = environment_ceiling();
            let summary = allowlist_change_summary(
                &previous_allowed_hosts,
                &settings.connectors.allowed_hosts,
                ceiling.as_deref(),
            );
            let diff = serde_json::to_vec(&serde_json::json!({
                "previous_allowed_hosts": previous_allowed_hosts,
                "allowed_hosts": settings.connectors.allowed_hosts,
                "added": difference(&settings.connectors.allowed_hosts, &previous_allowed_hosts),
                "removed": difference(&previous_allowed_hosts, &settings.connectors.allowed_hosts),
                "environment_ceiling_configured": ceiling.is_some(),
                "environment_ceiling": ceiling,
            }))?;
            ledger.append(
                &actor,
                "settings",
                "connector.allowlist.updated",
                Some(&summary),
                &diff,
            );
        }
        // Persist the audit event(s); the settings document itself is durable via `settings.json`.
        let event_count = if allowlist_changed { 2 } else { 1 };
        state
            .persist_write_through(&mut ledger, event_count, |_tx| Ok(()))
            .await?;
        state.attest_latest(&attestor, &ledger).await;
    }

    *state.settings.write().await = settings.clone();
    Ok(Json(settings))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`Locale::as_str`] and serde must agree, in both directions, for every variant.
    ///
    /// This is the trap `SmtpEncryption::StartTls` fell into during t23: `rename_all` rendered it
    /// `start_tls` while `as_str` said `starttls`, and the two disagreed silently until a fixture
    /// caught it downstream. `as_str` now picks the email copy catalog server-side while serde
    /// writes the settings document and the TypeScript union, so a drift between them would send a
    /// user mail in the wrong language — or fall back to Portuguese — with nothing failing.
    ///
    /// The round-trip half matters as much as the forward half: it is what catches a *duplicated*
    /// tag, where two variants both claim `"pt-PT"` and `as_str` looks correct in isolation.
    #[test]
    fn locale_as_str_matches_serde() {
        // Every variant, listed explicitly. A new locale added to the enum but not here is caught
        // by the exhaustiveness assertion at the end rather than silently skipped.
        let all = [
            Locale::PtPt,
            Locale::PtBr,
            Locale::DaDk,
            Locale::DeDe,
            Locale::FrFr,
            Locale::FiFi,
            Locale::SvFi,
            Locale::ItIt,
            Locale::NlNl,
            Locale::PlPl,
            Locale::EnGb,
            Locale::EnUs,
            Locale::SvSe,
            Locale::EsEs,
        ];

        for locale in all {
            // Forward: serializing must produce exactly `as_str`.
            assert_eq!(
                serde_json::to_value(locale).expect("serialize"),
                serde_json::Value::String(locale.as_str().to_owned()),
                "{locale:?} serializes differently from its as_str form"
            );
            // Back: `as_str` must deserialize to the same variant, so no tag is a dead end.
            let round_tripped: Locale =
                serde_json::from_value(serde_json::Value::String(locale.as_str().to_owned()))
                    .unwrap_or_else(|e| panic!("{:?} does not deserialize: {e}", locale.as_str()));
            assert_eq!(round_tripped, locale, "{locale:?} did not round-trip");
        }

        // No two variants may claim the same tag — that would make `as_str` look right while the
        // round-trip above silently resolved to whichever variant serde saw first.
        let mut tags: Vec<&str> = all.iter().map(|l| l.as_str()).collect();
        tags.sort_unstable();
        let count = tags.len();
        tags.dedup();
        assert_eq!(tags.len(), count, "two locales share a BCP 47 tag");

        // The list above is the whole enum. `Locale` is `#[serde(...)]`-tagged with no catch-all, so
        // a variant missing here would still deserialize — this pins the count so adding one to the
        // enum without adding it to the email catalogs fails here rather than at runtime.
        assert_eq!(
            count, 14,
            "the shipped locale set changed; update the email catalogs too"
        );
    }

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

    // A syntactically valid PEM `CERTIFICATE` block (the base64 body need only decode; anchoring is
    // by fingerprint, so real X.509 structure is not required for shape validation).
    const SAMPLE_ANCHOR_PEM: &str =
        "-----BEGIN CERTIFICATE-----\naGVsbG8gdHJ1c3QgYW5jaG9y\n-----END CERTIFICATE-----";

    #[test]
    fn tsl_trust_anchors_default_is_empty_and_fail_closed() {
        // No default anchor is ever baked in: a fresh install trusts no list.
        let settings = Settings::default();
        assert!(
            settings.signing.tsl_trust_anchor_certs.is_empty(),
            "default cert anchors must be empty (fail-closed)"
        );
        assert!(
            settings.signing.tsl_trust_anchor_sha256.is_empty(),
            "default fingerprint anchors must be empty (fail-closed)"
        );
        settings
            .validate()
            .expect("empty anchor configuration is valid (trusts nothing)");
    }

    #[test]
    fn tsl_trust_anchor_valid_pem_is_accepted() {
        let mut settings = Settings::default();
        settings.signing.tsl_trust_anchor_certs = vec![SAMPLE_ANCHOR_PEM.to_owned()];
        settings
            .validate()
            .expect("a valid PEM trust anchor should validate");
    }

    #[test]
    fn tsl_trust_anchor_valid_sha256_is_accepted() {
        let mut settings = Settings::default();
        settings.signing.tsl_trust_anchor_sha256 = vec!["a".repeat(64)];
        settings
            .validate()
            .expect("a 64-char sha256 hex fingerprint should validate");
    }

    #[test]
    fn tsl_trust_anchor_invalid_sha256_is_rejected() {
        // Wrong length.
        let mut settings = Settings::default();
        settings.signing.tsl_trust_anchor_sha256 = vec!["abc123".to_owned()];
        match settings
            .validate()
            .expect_err("short fingerprint should fail")
        {
            ApiError::Unprocessable(message) => {
                assert!(
                    message.contains("signing.tsl_trust_anchor_sha256[0]"),
                    "{message}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }

        // Right length, non-hex character.
        let mut settings = Settings::default();
        settings.signing.tsl_trust_anchor_sha256 = vec!["z".repeat(64)];
        match settings
            .validate()
            .expect_err("non-hex fingerprint should fail")
        {
            ApiError::Unprocessable(message) => {
                assert!(
                    message.contains("signing.tsl_trust_anchor_sha256[0]"),
                    "{message}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn tsl_trust_anchor_invalid_pem_is_rejected() {
        let mut settings = Settings::default();
        // BEGIN with no END marker: malformed PEM.
        settings.signing.tsl_trust_anchor_certs =
            vec!["-----BEGIN CERTIFICATE-----\nAAAA".to_owned()];
        match settings.validate().expect_err("malformed PEM should fail") {
            ApiError::Unprocessable(message) => {
                assert!(
                    message.contains("signing.tsl_trust_anchor_certs[0]"),
                    "{message}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn tsl_trust_anchor_blank_entries_are_rejected() {
        let mut settings = Settings::default();
        settings.signing.tsl_trust_anchor_certs = vec!["   ".to_owned()];
        match settings
            .validate()
            .expect_err("blank cert entry should fail")
        {
            ApiError::Unprocessable(message) => {
                assert!(
                    message.contains("signing.tsl_trust_anchor_certs[0]"),
                    "{message}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let mut settings = Settings::default();
        settings.signing.tsl_trust_anchor_sha256 = vec![String::new()];
        match settings
            .validate()
            .expect_err("blank fingerprint entry should fail")
        {
            ApiError::Unprocessable(message) => {
                assert!(
                    message.contains("signing.tsl_trust_anchor_sha256[0]"),
                    "{message}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // --- t95 P0-1 / P0-3: authentication slice + instance base URL ----------------------------

    /// A settings document with the relay and base URL already configured, so a test can turn one
    /// auth toggle on without tripping the unrelated prerequisites.
    fn settings_ready_for_links() -> Settings {
        let mut settings = Settings::default();
        settings.email.enabled = true;
        settings.email.host = Some("smtp.example.pt".to_owned());
        settings.email.from_address = Some("sistema@example.pt".to_owned());
        settings.platform.public_base_url = Some("https://livros.example.pt".to_owned());
        settings
    }

    fn refusal(result: Result<(), ApiError>) -> String {
        match result.expect_err("expected a 422") {
            ApiError::Unprocessable(message) => message,
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// **The upgrade test.** A `settings.json` written before t95 has no `auth` key at all. If it
    /// deserialized into anything other than "signup off, no recovery links, no second factor",
    /// upgrading a live instance would open it to strangers — the one outcome in this tranche that
    /// cannot be walked back, because the accounts would already exist.
    ///
    /// The fixture below is a real pre-t95 document (the shape `contracts/settings.json` had), not
    /// a `Settings::default()` re-serialized, so it also proves the missing sections are genuinely
    /// missing rather than round-tripped.
    #[test]
    fn a_pre_t95_settings_document_loads_with_signup_disabled_and_everything_else_off() {
        let pre_t95 = serde_json::json!({
            "schema_version": 1,
            "organization": { "name": "Encosto Estratégico, S.A.", "default_actor": "amelia.marques" },
            "documents": { "locale": "pt-PT", "numbering_scheme_default": "Sequential" },
            "email": {
                "enabled": true,
                "host": "smtp.encosto-estrategico.pt",
                "port": 587,
                "encryption": "starttls",
                "from_address": "sistema@encosto-estrategico.pt"
            },
            "ai": { "enabled": false },
            "platform": { "logging": { "global": "info" } },
            "appearance": { "theme": "system" },
            "onboarding": { "completed": true }
        });

        let settings: Settings =
            serde_json::from_value(pre_t95).expect("a pre-t95 document still deserializes");

        // The headline: signup is OFF on a document that has never heard of signup.
        assert_eq!(settings.auth.signup.mode, SignupMode::Disabled);
        // And every other new switch is closed too.
        assert_eq!(settings.auth, AuthSettings::default());
        assert!(!settings.auth.password_recovery.email_link_enabled);
        assert!(!settings.auth.password_recovery.username_by_email);
        assert!(!settings.auth.two_factor.totp_enabled);
        assert!(!settings.auth.two_factor.email_enabled);
        assert!(!settings.auth.two_factor.required);
        assert!(!settings.auth.two_factor.acknowledge_single_channel_risk);
        assert!(settings.auth.signup.allowed_domains.is_empty());
        assert_eq!(
            settings.auth.signup.default_role,
            chancela_authz::GUEST_ROLE_ID
        );
        // P0-3: no base URL, so no link-issuing feature can be live either.
        assert_eq!(settings.platform.public_base_url, None);
        assert_eq!(settings.platform.resolved_public_base_url(), None);
        assert!(!settings.auth.requires_instance_base_url());
        // It is a document the server would accept unchanged — the upgrade is not a validation
        // failure on first save.
        settings.validate().expect("a pre-t95 document stays valid");
    }

    /// The whole slice is skipped while it is at its defaults, so the on-the-wire document — and
    /// therefore `contracts/settings.json` and every stored `settings.json` — is unchanged by the
    /// arrival of this feature. `connectors` and `registry_auto_update` set this precedent.
    #[test]
    fn the_auth_slice_is_absent_from_the_wire_until_it_is_configured() {
        let mut settings = Settings::default();
        let wire = serde_json::to_value(&settings).expect("serializes");
        assert!(
            wire.get("auth").is_none(),
            "a default auth slice must not appear on the wire: {wire}"
        );

        settings.auth.signup.mode = SignupMode::InviteOnly;
        let wire = serde_json::to_value(&settings).expect("serializes");
        assert_eq!(wire["auth"]["signup"]["mode"], "invite_only");
    }

    #[test]
    fn signup_mode_ids_are_stable_in_both_directions() {
        for (mode, id) in [
            (SignupMode::Disabled, "disabled"),
            (SignupMode::InviteOnly, "invite_only"),
            (SignupMode::DomainAllowlist, "domain_allowlist"),
            (SignupMode::Public, "public"),
        ] {
            assert_eq!(mode.as_str(), id);
            assert_eq!(serde_json::to_value(mode).unwrap(), serde_json::json!(id));
            assert_eq!(
                serde_json::from_value::<SignupMode>(serde_json::json!(id)).unwrap(),
                mode
            );
        }
        // Magic link was dropped from the tranche; nothing here should resurrect it by accident.
        assert!(serde_json::from_value::<SignupMode>(serde_json::json!("magic_link")).is_err());
    }

    /// §2.6, the half that needs no role catalog.
    #[test]
    fn the_signup_default_role_may_never_be_owner() {
        let mut settings = Settings::default();
        settings.auth.signup.default_role = chancela_authz::OWNER_ROLE_ID;
        let message = refusal(settings.validate());
        assert!(message.contains("auth.signup.default_role"), "{message}");
        assert!(message.contains("Owner"), "{message}");
    }

    /// §2.6, the half that needs the catalog — including the bypass it exists to close: a role that
    /// is eligible today, edited tomorrow, must stop being an acceptable signup default.
    #[test]
    fn the_signup_default_role_ceiling_is_enforced_against_the_role_catalog() {
        use chancela_authz::{Permission, Role, RoleCatalog};

        let catalog = RoleCatalog::seeded_defaults();
        let settings = Settings::default();
        settings
            .auth
            .validate_default_role_against(&catalog)
            .expect("Guest is an acceptable default");

        // A role that does not exist is a refusal, not a shrug — otherwise the discovery happens
        // when a stranger signs up.
        let mut settings = Settings::default();
        settings.auth.signup.default_role =
            chancela_authz::RoleId(uuid::Uuid::from_u128(0xdead_beef));
        let message = refusal(settings.auth.validate_default_role_against(&catalog));
        assert!(message.contains("does not name a role"), "{message}");

        // A privileged seeded role is refused outright.
        let mut settings = Settings::default();
        settings.auth.signup.default_role = chancela_authz::PLATFORM_ADMIN_ROLE_ID;
        let message = refusal(settings.auth.validate_default_role_against(&catalog));
        assert!(message.contains("Platform Administrator"), "{message}");

        // THE BYPASS: keep Guest as the default and edit Guest to hold `settings.manage`. Checking
        // the ceiling only when the default role is *chosen* would let this through.
        let mut edited = RoleCatalog::seeded_defaults();
        let mut guest = Role::guest();
        guest.permission_set.insert(Permission::SettingsManage);
        edited.insert(guest);
        let message = refusal(
            Settings::default()
                .auth
                .validate_default_role_against(&edited),
        );
        assert!(message.contains("settings.manage"), "{message}");
    }

    /// Wildcards are refused by name, not silently ignored: `*.example.pt` invites
    /// subdomain-takeover signup, and an operator who tries it must find out immediately.
    #[test]
    fn the_signup_domain_allowlist_takes_exact_domains_only() {
        for bad in [
            "*.example.pt",
            "example.*",
            "https://example.pt",
            "ana@example.pt",
            "example.pt/signup",
            "localhost",
            ".example.pt",
            "example..pt",
            "example.pt-",
        ] {
            let mut settings = Settings::default();
            settings.auth.signup.allowed_domains = vec![bad.to_owned()];
            let message = refusal(settings.validate());
            assert!(
                message.contains("auth.signup.allowed_domains[0]"),
                "{bad:?} was accepted or misreported: {message}"
            );
            if bad.contains('*') {
                assert!(
                    message.contains("wildcard"),
                    "a wildcard must be refused by name: {message}"
                );
            }
        }

        let mut settings = Settings::default();
        settings.auth.signup.allowed_domains = vec![
            " Example.PT ".to_owned(),
            "example.pt".to_owned(),
            "b.example.pt".to_owned(),
        ];
        settings.validate().expect("valid domains");
        assert_eq!(
            settings.auth.signup.normalized_domains(),
            vec!["b.example.pt".to_owned(), "example.pt".to_owned()],
            "domains are stored lowercased, trimmed and de-duplicated"
        );
    }

    #[test]
    fn domain_allowlist_mode_requires_at_least_one_domain() {
        let mut settings = settings_ready_for_links();
        settings.auth.signup.mode = SignupMode::DomainAllowlist;
        settings.auth.signup.require_email_verification = false;
        let message = refusal(settings.validate());
        assert!(message.contains("auth.signup.allowed_domains"), "{message}");

        settings.auth.signup.allowed_domains = vec!["example.pt".to_owned()];
        settings.validate().expect("one domain is enough");
    }

    #[test]
    fn token_lifetimes_are_bounded() {
        for (hours, ok) in [
            (0, false),
            (1, true),
            (168, true),
            (720, true),
            (721, false),
        ] {
            let mut settings = Settings::default();
            settings.auth.signup.invite_ttl_hours = hours;
            assert_eq!(settings.validate().is_ok(), ok, "invite_ttl_hours {hours}");
        }
        for (minutes, ok) in [(4, false), (5, true), (15, true), (60, true), (61, false)] {
            let mut settings = Settings::default();
            settings.auth.password_recovery.link_ttl_minutes = minutes;
            assert_eq!(
                settings.validate().is_ok(),
                ok,
                "link_ttl_minutes {minutes}"
            );
        }
    }

    /// §2.4. Email as the only second factor *and* the recovery channel is one factor wearing two
    /// hats: whoever holds the mailbox does not need the password. Refused unless the operator says
    /// so explicitly, in the `email.allow_insecure` mould.
    #[test]
    fn email_cannot_be_both_the_only_second_factor_and_the_recovery_channel() {
        let mut settings = settings_ready_for_links();
        settings.auth.two_factor.email_enabled = true;
        settings.auth.password_recovery.email_link_enabled = true;
        let message = refusal(settings.validate());
        assert!(
            message.contains("acknowledge_single_channel_risk"),
            "{message}"
        );

        // TOTP alongside it removes the objection: the mailbox is no longer the whole model.
        let mut with_totp = settings.clone();
        with_totp.auth.two_factor.totp_enabled = true;
        with_totp
            .validate()
            .expect("TOTP resolves the single-channel risk");

        // Or the operator acknowledges it on purpose.
        let mut acknowledged = settings.clone();
        acknowledged.auth.two_factor.acknowledge_single_channel_risk = true;
        acknowledged
            .validate()
            .expect("an explicit acknowledgement is accepted");
    }

    /// §5 #9. A required second factor that only the mail relay can deliver locks every user out —
    /// the last Owner included — the first time the relay has a bad day.
    #[test]
    fn a_required_second_factor_must_be_satisfiable_without_the_mail_relay() {
        let mut settings = settings_ready_for_links();
        settings.auth.two_factor.required = true;
        settings.auth.two_factor.email_enabled = true;
        let message = refusal(settings.validate());
        assert!(message.contains("totp_enabled"), "{message}");

        settings.auth.two_factor.totp_enabled = true;
        settings
            .validate()
            .expect("TOTP makes the requirement satisfiable");
    }

    /// P0-3. The base URL is the origin of every emailed link, so the shapes that could aim one
    /// somewhere other than this instance are all refused.
    #[test]
    fn the_public_base_url_must_be_an_absolute_https_origin() {
        for bad in [
            "http://livros.example.pt",
            "livros.example.pt",
            "//livros.example.pt",
            "https://",
            "https://livros.example.pt@evil.example",
            "https://livros.example.pt/?next=x",
            "https://livros.example.pt/#/reset",
            "https://livros.example.pt/app/../../evil",
            "https://livros.example.pt/ x",
            "ftp://livros.example.pt",
            "https://.example.pt",
        ] {
            let mut settings = Settings::default();
            settings.platform.public_base_url = Some(bad.to_owned());
            let message = refusal(settings.validate());
            assert!(
                message.contains("platform.public_base_url"),
                "{bad:?} was accepted or misreported: {message}"
            );
            assert!(
                message.contains("never inferred from a request header"),
                "the refusal must carry the reason the field exists: {message}"
            );
        }

        for good in [
            "https://livros.example.pt",
            "https://livros.example.pt/",
            "https://livros.example.pt:8443/livros/",
            "https://livros.example.pt/livros",
        ] {
            let mut settings = Settings::default();
            settings.platform.public_base_url = Some(good.to_owned());
            settings
                .validate()
                .unwrap_or_else(|e| panic!("{good:?}: {e:?}"));
        }

        // Resolution strips trailing slashes so the link builder can append a path unconditionally.
        let mut settings = Settings::default();
        settings.platform.public_base_url = Some("  https://livros.example.pt///  ".to_owned());
        assert_eq!(
            settings.platform.resolved_public_base_url().as_deref(),
            Some("https://livros.example.pt")
        );
        // Blank is "unset", not "the empty origin".
        settings.platform.public_base_url = Some("   ".to_owned());
        assert_eq!(settings.platform.resolved_public_base_url(), None);
        settings
            .validate()
            .expect("a blank value is treated as unset");
    }

    /// P0-3's other half: with no configured origin, a feature that emails a link cannot be turned
    /// on at all. "Unavailable and says so" — not enabled-then-broken, and never a guessed origin.
    #[test]
    fn a_link_issuing_feature_cannot_be_enabled_without_a_configured_base_url() {
        let link_issuing: [(&str, fn(&mut Settings)); 3] = [
            ("recovery link", |s| {
                s.auth.password_recovery.email_link_enabled = true
            }),
            ("invite-only signup", |s| {
                s.auth.signup.mode = SignupMode::InviteOnly
            }),
            ("signup with email verification", |s| {
                s.auth.signup.mode = SignupMode::Public;
                s.auth.signup.require_email_verification = true;
            }),
        ];

        for (label, enable) in link_issuing {
            let mut settings = settings_ready_for_links();
            settings.platform.public_base_url = None;
            enable(&mut settings);
            let message = refusal(settings.validate());
            assert!(
                message.contains("platform.public_base_url"),
                "{label} was allowed with no base URL: {message}"
            );
            assert!(message.contains("Host header"), "{label}: {message}");

            // With an origin configured it is accepted.
            let mut settings = settings_ready_for_links();
            enable(&mut settings);
            settings
                .validate()
                .unwrap_or_else(|e| panic!("{label} with a base URL: {e:?}"));
        }
    }

    /// A feature that sends mail at all needs the relay on. `username_by_email` needs no link, so
    /// it is the case that separates the two prerequisites.
    #[test]
    fn a_mail_sending_feature_cannot_be_enabled_without_the_relay() {
        let mut settings = Settings::default();
        settings.platform.public_base_url = Some("https://livros.example.pt".to_owned());
        settings.auth.password_recovery.username_by_email = true;
        assert!(!settings.auth.requires_instance_base_url());
        let message = refusal(settings.validate());
        assert!(message.contains("email.enabled"), "{message}");

        let mut settings = settings_ready_for_links();
        settings.auth.password_recovery.username_by_email = true;
        settings
            .validate()
            .expect("with the relay on it is accepted");
    }
}
