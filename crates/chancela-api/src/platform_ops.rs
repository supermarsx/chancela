//! Platform operations endpoints.
//!
//! These handlers deliberately do not manage OS processes. They expose the API process and the
//! external stdio MCP process as settings-backed desired state plus honest runtime observations, so a
//! future supervisor can reconcile them without the API pretending to have that authority.

use axum::Json;
use axum::extract::{Path, State};
use chancela_authz::{Permission, Scope};
use serde::Serialize;
use time::format_description::well_known::Rfc3339;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::require_permission;
use crate::error::ApiError;
use crate::settings::{
    PLATFORM_API_SERVICE_ID, PLATFORM_MCP_STDIO_SERVICE_ID, PlatformAuditEvent,
    PlatformControlOutcomeKind, PlatformLogLevel, PlatformServiceAction,
    PlatformServiceDesiredState, PlatformServiceLastAction, Settings, validate_platform_service_id,
    write_settings_atomic,
};

#[derive(Debug, Clone, Serialize)]
pub struct PlatformServicesResponse {
    pub services: Vec<PlatformServiceStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformServiceStatus {
    pub id: String,
    pub kind: PlatformServiceKind,
    pub label: String,
    pub configured: bool,
    pub enabled: bool,
    pub desired_state: PlatformServiceDesiredState,
    pub actual_runtime_status: PlatformRuntimeStatus,
    pub controllable_actions: Vec<PlatformActionCapability>,
    pub logging_level: PlatformLogLevel,
    pub last_action: Option<PlatformServiceLastAction>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformServiceKind {
    Api,
    Mcp,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformRuntimeStatus {
    Running,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformActionCapability {
    pub action: PlatformServiceAction,
    pub supported: bool,
    pub outcome: PlatformControlOutcomeKind,
    pub limitation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformControlResponse {
    pub service: PlatformServiceStatus,
    pub action: PlatformServiceAction,
    pub result: PlatformControlResult,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformControlResult {
    pub kind: PlatformControlOutcomeKind,
    pub supported: bool,
    pub applied_to_settings: bool,
    pub desired_state: PlatformServiceDesiredState,
    pub actual_runtime_status: PlatformRuntimeStatus,
    pub message: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PlatformControlAuditPayload {
    service_id: String,
    action: PlatformServiceAction,
    requested_at: String,
    requested_by: String,
    desired_state: PlatformServiceDesiredState,
    outcome: PlatformControlOutcomeKind,
    message: String,
    limitations: Vec<String>,
}

/// `GET /v1/platform/services` — read-only platform service status.
pub async fn list_services(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<PlatformServicesResponse>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsRead, Scope::Global).await?;
    let settings = state.settings.read().await.clone();
    Ok(Json(status_response(&settings)))
}

/// `POST /v1/platform/services/{id}/actions/{action}` — record desired service control state.
pub async fn control_service(
    State(state): State<AppState>,
    Path((service_id, action)): Path<(String, String)>,
    current_actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<PlatformControlResponse>, ApiError> {
    require_permission(
        &state,
        &current_actor,
        Permission::SettingsManage,
        Scope::Global,
    )
    .await?;

    validate_controllable_service_id(&service_id)?;
    let action = parse_action(&action)?;
    let requested_by = current_actor.resolve("api");
    let requested_at = time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
    let desired_state = desired_state_for(action);
    let outcome = outcome_for(&service_id, action);
    let message = outcome_message(&service_id, action, outcome).to_owned();

    let mut settings = state.settings.read().await.clone();
    {
        let control = settings.platform.control_settings_mut(&service_id)?;
        control.enabled = matches!(desired_state, PlatformServiceDesiredState::Running);
        control.desired_state = desired_state;
        control.last_action = Some(PlatformServiceLastAction {
            action,
            requested_at: requested_at.clone(),
            requested_by: requested_by.clone(),
            outcome,
            message: message.clone(),
        });
    }
    settings.platform.append_audit(PlatformAuditEvent {
        service_id: service_id.clone(),
        action,
        requested_at: requested_at.clone(),
        requested_by: requested_by.clone(),
        outcome,
        desired_state,
        message: message.clone(),
    });
    settings.validate()?;

    if let Some(path) = &state.persist_path {
        write_settings_atomic(path, &settings)
            .map_err(|e| ApiError::Internal(format!("failed to persist settings: {e}")))?;
    }

    let limitations = limitations_for(&settings, &service_id);
    let payload = PlatformControlAuditPayload {
        service_id: service_id.clone(),
        action,
        requested_at,
        requested_by,
        desired_state,
        outcome,
        message: message.clone(),
        limitations: limitations.clone(),
    };
    let payload_bytes = serde_json::to_vec(&payload)?;
    {
        let mut ledger = state.ledger.write().await;
        ledger.append(
            &payload.requested_by,
            "platform",
            "platform.service.control",
            Some("platform service control requested"),
            &payload_bytes,
        );
        state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
        state.attest_latest(&attestor, &ledger).await;
    }

    *state.settings.write().await = settings.clone();
    let service = service_status(&settings, &service_id)?;
    Ok(Json(PlatformControlResponse {
        service,
        action,
        result: PlatformControlResult {
            kind: outcome,
            supported: false,
            applied_to_settings: true,
            desired_state,
            actual_runtime_status: actual_runtime_status(&service_id),
            message,
            limitations,
        },
    }))
}

fn status_response(settings: &Settings) -> PlatformServicesResponse {
    PlatformServicesResponse {
        services: vec![
            service_status(settings, PLATFORM_API_SERVICE_ID).expect("api service is known"),
            service_status(settings, PLATFORM_MCP_STDIO_SERVICE_ID).expect("mcp service is known"),
        ],
    }
}

fn service_status(
    settings: &Settings,
    service_id: &str,
) -> Result<PlatformServiceStatus, ApiError> {
    validate_controllable_service_id(service_id)?;
    match service_id {
        PLATFORM_API_SERVICE_ID => Ok(PlatformServiceStatus {
            id: PLATFORM_API_SERVICE_ID.to_owned(),
            kind: PlatformServiceKind::Api,
            label: "Chancela API server".to_owned(),
            configured: true,
            enabled: settings.platform.api_server.enabled,
            desired_state: settings.platform.api_server.desired_state,
            actual_runtime_status: PlatformRuntimeStatus::Running,
            controllable_actions: api_action_capabilities(),
            logging_level: settings
                .platform
                .logging
                .effective_for(PLATFORM_API_SERVICE_ID),
            last_action: settings.platform.api_server.last_action.clone(),
            limitations: limitations_for(settings, PLATFORM_API_SERVICE_ID),
        }),
        PLATFORM_MCP_STDIO_SERVICE_ID => Ok(PlatformServiceStatus {
            id: PLATFORM_MCP_STDIO_SERVICE_ID.to_owned(),
            kind: PlatformServiceKind::Mcp,
            label: "Chancela MCP stdio server".to_owned(),
            configured: env_truthy("CHANCELA_MCP_ENABLED"),
            enabled: settings.platform.mcp_stdio_server.enabled,
            desired_state: settings.platform.mcp_stdio_server.desired_state,
            actual_runtime_status: PlatformRuntimeStatus::Unknown,
            controllable_actions: mcp_action_capabilities(),
            logging_level: settings
                .platform
                .logging
                .effective_for(PLATFORM_MCP_STDIO_SERVICE_ID),
            last_action: settings.platform.mcp_stdio_server.last_action.clone(),
            limitations: limitations_for(settings, PLATFORM_MCP_STDIO_SERVICE_ID),
        }),
        _ => unreachable!("validated controllable service id"),
    }
}

fn api_action_capabilities() -> Vec<PlatformActionCapability> {
    vec![
        PlatformActionCapability {
            action: PlatformServiceAction::Start,
            supported: false,
            outcome: PlatformControlOutcomeKind::Unsupported,
            limitation: "The current API process cannot start another copy of itself.".to_owned(),
        },
        PlatformActionCapability {
            action: PlatformServiceAction::Stop,
            supported: false,
            outcome: PlatformControlOutcomeKind::Unsupported,
            limitation: "The current API process cannot stop itself through this request."
                .to_owned(),
        },
        PlatformActionCapability {
            action: PlatformServiceAction::Restart,
            supported: false,
            outcome: PlatformControlOutcomeKind::RestartRequired,
            limitation: "Restart requires an external supervisor or process relaunch.".to_owned(),
        },
    ]
}

fn mcp_action_capabilities() -> Vec<PlatformActionCapability> {
    [
        PlatformServiceAction::Start,
        PlatformServiceAction::Stop,
        PlatformServiceAction::Restart,
    ]
    .into_iter()
    .map(|action| PlatformActionCapability {
        action,
        supported: false,
        outcome: PlatformControlOutcomeKind::SupervisorRequired,
        limitation:
            "The stdio MCP server is launched externally; the API can only record desired state."
                .to_owned(),
    })
    .collect()
}

fn parse_action(raw: &str) -> Result<PlatformServiceAction, ApiError> {
    match raw {
        "start" => Ok(PlatformServiceAction::Start),
        "stop" => Ok(PlatformServiceAction::Stop),
        "restart" => Ok(PlatformServiceAction::Restart),
        _ => Err(ApiError::Unprocessable(format!(
            "unknown platform service action {raw:?}; expected start, stop, or restart"
        ))),
    }
}

fn validate_controllable_service_id(service_id: &str) -> Result<(), ApiError> {
    validate_platform_service_id(service_id)?;
    if service_id == PLATFORM_API_SERVICE_ID || service_id == PLATFORM_MCP_STDIO_SERVICE_ID {
        Ok(())
    } else {
        Err(ApiError::Unprocessable(format!(
            "platform service id {service_id:?} is not controllable"
        )))
    }
}

fn desired_state_for(action: PlatformServiceAction) -> PlatformServiceDesiredState {
    match action {
        PlatformServiceAction::Start | PlatformServiceAction::Restart => {
            PlatformServiceDesiredState::Running
        }
        PlatformServiceAction::Stop => PlatformServiceDesiredState::Stopped,
    }
}

fn outcome_for(service_id: &str, action: PlatformServiceAction) -> PlatformControlOutcomeKind {
    match (service_id, action) {
        (PLATFORM_API_SERVICE_ID, PlatformServiceAction::Restart) => {
            PlatformControlOutcomeKind::RestartRequired
        }
        (PLATFORM_API_SERVICE_ID, _) => PlatformControlOutcomeKind::Unsupported,
        (PLATFORM_MCP_STDIO_SERVICE_ID, _) => PlatformControlOutcomeKind::SupervisorRequired,
        _ => PlatformControlOutcomeKind::Unsupported,
    }
}

fn outcome_message(
    service_id: &str,
    action: PlatformServiceAction,
    outcome: PlatformControlOutcomeKind,
) -> &'static str {
    match (service_id, action, outcome) {
        (PLATFORM_API_SERVICE_ID, PlatformServiceAction::Restart, _) => {
            "API restart desired state was recorded; an external supervisor must restart the process."
        }
        (PLATFORM_API_SERVICE_ID, PlatformServiceAction::Start, _) => {
            "API start desired state was recorded, but this already-running process cannot start itself."
        }
        (PLATFORM_API_SERVICE_ID, PlatformServiceAction::Stop, _) => {
            "API stop desired state was recorded, but this process cannot terminate itself safely through the API."
        }
        (PLATFORM_MCP_STDIO_SERVICE_ID, PlatformServiceAction::Start, _) => {
            "MCP start desired state was recorded; relaunch the external MCP client or supervisor."
        }
        (PLATFORM_MCP_STDIO_SERVICE_ID, PlatformServiceAction::Stop, _) => {
            "MCP stop desired state was recorded; stop or relaunch the external MCP client or supervisor."
        }
        (PLATFORM_MCP_STDIO_SERVICE_ID, PlatformServiceAction::Restart, _) => {
            "MCP restart desired state was recorded; relaunch the external MCP client or supervisor."
        }
        _ => "Platform service control desired state was recorded.",
    }
}

fn limitations_for(settings: &Settings, service_id: &str) -> Vec<String> {
    match service_id {
        PLATFORM_API_SERVICE_ID => vec![
            "The API can observe this process as running only because it is serving this request."
                .to_owned(),
            "Start, stop, and restart require an external supervisor or process relaunch."
                .to_owned(),
        ],
        PLATFORM_MCP_STDIO_SERVICE_ID => {
            let mut limitations = vec![
                "The stdio MCP server is launched by an external client or supervisor; the API cannot observe or spawn that process.".to_owned(),
                "No MCP API key or other secret is exposed through this status surface.".to_owned(),
            ];
            if !settings.ai.enabled {
                limitations.push(
                    "Tenant AI/MCP gate settings.ai.enabled is false; a launcher must mirror it before MCP can serve."
                        .to_owned(),
                );
            }
            limitations
        }
        _ => Vec::new(),
    }
}

fn actual_runtime_status(service_id: &str) -> PlatformRuntimeStatus {
    match service_id {
        PLATFORM_API_SERVICE_ID => PlatformRuntimeStatus::Running,
        PLATFORM_MCP_STDIO_SERVICE_ID => PlatformRuntimeStatus::Unknown,
        _ => PlatformRuntimeStatus::Unknown,
    }
}

fn env_truthy(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}
