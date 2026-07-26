use serde::{Deserialize, Serialize};

pub const DEFAULT_WORKFLOW_REMINDER_DASHBOARD_LIMIT: u16 = 5;
pub const DEFAULT_WORKFLOW_REMINDER_DUE_SOON_DAYS: u16 = 45;
pub const DEFAULT_WORKFLOW_REMINDER_ATTENDANCE_LOOKAHEAD_DAYS: u16 = 45;

/// Advisory dashboard reminder policy consumed by the shared Action Center projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkflowReminderSettings {
    pub enabled: bool,
    pub dashboard_limit: u16,
    pub due_soon_days: u16,
    pub attendance_lookahead_days: u16,
    pub sources: WorkflowReminderSourceSettings,
}

impl Default for WorkflowReminderSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            dashboard_limit: DEFAULT_WORKFLOW_REMINDER_DASHBOARD_LIMIT,
            due_soon_days: DEFAULT_WORKFLOW_REMINDER_DUE_SOON_DAYS,
            attendance_lookahead_days: DEFAULT_WORKFLOW_REMINDER_ATTENDANCE_LOOKAHEAD_DAYS,
            sources: WorkflowReminderSourceSettings::default(),
        }
    }
}

/// Per-family switches for local dashboard reminder generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkflowReminderSourceSettings {
    pub profile_calendar: bool,
    pub act_follow_ups: bool,
    pub attendance_hygiene: bool,
    pub privacy_control_reviews: bool,
}

impl Default for WorkflowReminderSourceSettings {
    fn default() -> Self {
        Self {
            profile_calendar: true,
            act_follow_ups: true,
            attendance_hygiene: true,
            privacy_control_reviews: true,
        }
    }
}
