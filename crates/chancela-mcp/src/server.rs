//! The MCP server: JSON-RPC dispatch over the tool registry + the stdio serve loop.
//!
//! **Off by default is enforced structurally**: [`McpServer::from_config`] returns
//! [`McpError::Disabled`] unless both the MCP process switch and tenant AI/MCP gate are enabled, and
//! [`serve_stdio`] returns early (serving nothing, touching no I/O) before it ever reads stdin. There
//! is no way to serve a disabled server — "off" is genuinely zero surface, not a soft flag.
//!
//! Dispatch handles the MCP subset needed for a tool server: `initialize`, `notifications/*`,
//! `ping`, `tools/list`, `tools/call`, bounded prompt discovery, and read-only local resources
//! such as `chancela://mcp/status`.
//! `tools/call` resolves the tool to an `/api/v1` request via [`crate::registry::resolve_call`] and
//! forwards it through the [`ApiBridge`] with the configured key. Authorization is entirely
//! server-side (the key's principal); this layer never re-checks it.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Write};

use serde_json::{Value, json};

use crate::bridge::{ApiBridge, ApiOutcome, BridgeError, HttpTransport, ReqwestTransport};
use crate::config::{EnabledTools, McpConfig, McpTransport};
use crate::error::McpError;
use crate::jsonrpc::{JsonRpcRequest, JsonRpcResponse, codes};
use crate::registry::{McpTool, ResolvedCall, ToolAccess, ToolError, catalog, resolve_call};

/// The MCP protocol version this server implements.
pub const PROTOCOL_VERSION: &str = "2025-06-18";
/// Advertised server name.
pub const SERVER_NAME: &str = "chancela-mcp";
/// Read-only MCP resource URI for local server operability state.
pub const MCP_STATUS_RESOURCE_URI: &str = "chancela://mcp/status";
/// Read-only MCP resource URI for local spec 09 MCP coverage boundaries.
pub const MCP_SPEC_09_COVERAGE_RESOURCE_URI: &str = "chancela://mcp/spec-09-coverage";
/// Read-only MCP resource URI for static workflow provenance review guidance.
pub const MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI: &str =
    "chancela://mcp/workflow-provenance-review";
/// Read-only MCP resource URI for static draft-vs-signed comparison review guidance.
pub const MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI: &str =
    "chancela://mcp/draft-signed-comparison-review";
/// Read-only MCP resource URI for local chronology review summaries.
pub const MCP_CHRONOLOGY_REVIEW_SUMMARY_RESOURCE_URI: &str =
    "chancela://mcp/chronology-review-summary";
/// Read-only MCP resource URI for local privacy-control review summaries.
pub const MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI: &str =
    "chancela://mcp/privacy-control-review-summary";
/// Read-only MCP resource URI for local document/archive review summaries.
pub const MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI: &str =
    "chancela://mcp/document-archive-review-summary";
/// Read-only MCP resource URI for local meeting metadata extraction review.
pub const MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI: &str =
    "chancela://mcp/meeting-metadata-extraction-review";

const DRAFT_MINUTES_REVIEW_PROMPT_NAME: &str = "draft_minutes_human_review_checklist";
const DRAFT_MINUTES_REVIEW_PROMPT_TITLE: &str = "Draft Minutes Human Review Checklist";
const DRAFT_MINUTES_REVIEW_PROMPT_DESCRIPTION: &str = "Human-review checklist for draft minutes. Guidance only; no legal validity, signing, or hidden provider call.";
const COMPLIANCE_PACK_GAP_REVIEW_PROMPT_NAME: &str = "compliance_pack_gap_review";
const COMPLIANCE_PACK_GAP_REVIEW_PROMPT_TITLE: &str = "Compliance Pack Gap Review";
const COMPLIANCE_PACK_GAP_REVIEW_PROMPT_DESCRIPTION: &str = "Human-review prompt for DSR, retention, and archive evidence gaps. Guidance only; no legal-validity or provider claims.";
const PAPER_BOOK_OCR_REVIEW_PROMPT_NAME: &str = "paper_book_ocr_canonical_review";
const PAPER_BOOK_OCR_REVIEW_PROMPT_TITLE: &str = "Paper Book OCR Canonical Review";
const PAPER_BOOK_OCR_REVIEW_PROMPT_DESCRIPTION: &str = "Human-review prompt for paper-book OCR and canonical-conversion evidence. Guidance only; no legal-validity, signing, or provider claims.";
const WORKFLOW_PROVENANCE_REVIEW_PROMPT_NAME: &str = "workflow_provenance_review_checklist";
const WORKFLOW_PROVENANCE_REVIEW_PROMPT_TITLE: &str = "Workflow Provenance Review Checklist";
const WORKFLOW_PROVENANCE_REVIEW_PROMPT_DESCRIPTION: &str = "Static human-review prompt for workflow provenance evidence. Guidance only; no legal-validity, source-certification, provider, or trust claims.";
const DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_NAME: &str = "draft_signed_comparison_review_checklist";
const DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_TITLE: &str =
    "Draft-Signed Comparison Review Checklist";
const DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_DESCRIPTION: &str = "Static human-review prompt for comparing draft identifiers with signed artifacts. Guidance only; no legal-validity, source-certification, external-validation, signature-qualification, provider, or trust claims.";

const HUMAN_VERIFICATION_PENDING: &str = "pending_human_verification";
const HUMAN_VERIFICATION_ACCEPTED: &str = "accepted_by_human";
const HUMAN_VERIFICATION_REJECTED: &str = "rejected_by_human";
const HUMAN_VERIFICATION_AUTHORITY: &str = "human_review_workflow_only";
const HUMAN_VERIFICATION_ACCEPTANCE_CLAIM: &str = "human_review_only_not_legal_certification";
const AI_DRAFT_LEGAL_EFFECT: &str = "none_until_human_verification_and_seal";

#[derive(Debug, Clone, Copy)]
struct McpPrompt {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    text: fn() -> &'static str,
}

const PROMPT_CATALOG: &[McpPrompt] = &[
    McpPrompt {
        name: DRAFT_MINUTES_REVIEW_PROMPT_NAME,
        title: DRAFT_MINUTES_REVIEW_PROMPT_TITLE,
        description: DRAFT_MINUTES_REVIEW_PROMPT_DESCRIPTION,
        text: draft_minutes_review_prompt_text,
    },
    McpPrompt {
        name: COMPLIANCE_PACK_GAP_REVIEW_PROMPT_NAME,
        title: COMPLIANCE_PACK_GAP_REVIEW_PROMPT_TITLE,
        description: COMPLIANCE_PACK_GAP_REVIEW_PROMPT_DESCRIPTION,
        text: compliance_pack_gap_review_prompt_text,
    },
    McpPrompt {
        name: PAPER_BOOK_OCR_REVIEW_PROMPT_NAME,
        title: PAPER_BOOK_OCR_REVIEW_PROMPT_TITLE,
        description: PAPER_BOOK_OCR_REVIEW_PROMPT_DESCRIPTION,
        text: paper_book_ocr_review_prompt_text,
    },
    McpPrompt {
        name: WORKFLOW_PROVENANCE_REVIEW_PROMPT_NAME,
        title: WORKFLOW_PROVENANCE_REVIEW_PROMPT_TITLE,
        description: WORKFLOW_PROVENANCE_REVIEW_PROMPT_DESCRIPTION,
        text: workflow_provenance_review_prompt_text,
    },
    McpPrompt {
        name: DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_NAME,
        title: DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_TITLE,
        description: DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_DESCRIPTION,
        text: draft_signed_comparison_review_prompt_text,
    },
];

/// The running MCP server: the enabled tool subset + the api-key bridge.
pub struct McpServer<T: HttpTransport> {
    tools: Vec<McpTool>,
    bridge: ApiBridge<T>,
    runtime: RuntimeStatus,
}

#[derive(Debug, Clone)]
struct RuntimeStatus {
    transport: McpTransport,
    base_url: String,
    base_path: String,
    catalog_tool_count: usize,
}

impl<T: HttpTransport> McpServer<T> {
    /// Build a server from config + a transport. **Refuses an unserved config**
    /// (`McpError::Disabled`) — off by default means not served. Both `CHANCELA_MCP_ENABLED` and the
    /// tenant AI/MCP gate must be enabled by the resolved config. The enabled-tools policy filters
    /// the catalog here, so a disabled tool is absent from `tools/list` and unreachable via
    /// `tools/call`.
    pub fn from_config(config: &McpConfig, transport: T) -> Result<Self, McpError> {
        if !config.served() {
            return Err(McpError::Disabled);
        }
        config.validate()?;
        let all_tools = catalog();
        let catalog_tool_count = all_tools.len();
        let tools = all_tools
            .into_iter()
            .filter(|t| config.enabled_tools.allows(t.name))
            .collect();
        Ok(Self {
            runtime: RuntimeStatus {
                transport: config.transport,
                base_url: config.base_url.clone(),
                base_path: config.base_path.clone(),
                catalog_tool_count,
            },
            tools,
            bridge: ApiBridge::new(config, transport),
        })
    }

    /// The enabled tools (for tests/inspection).
    pub fn tools(&self) -> &[McpTool] {
        &self.tools
    }

    /// Dispatch one JSON-RPC message. Returns `None` for notifications (no reply is sent).
    pub fn handle(&self, req: &JsonRpcRequest) -> Option<JsonRpcResponse> {
        if req.is_notification() {
            // `notifications/initialized` and friends: acknowledge silently.
            return None;
        }
        let id = req.id.clone().unwrap_or(Value::Null);
        let resp = match req.method.as_str() {
            "initialize" => JsonRpcResponse::success(id, self.initialize_result()),
            "ping" => JsonRpcResponse::success(id, json!({})),
            "prompts/list" => self.prompts_list(id, req.params.as_ref()),
            "prompts/get" => self.prompts_get(id, req.params.as_ref()),
            "resources/list" => JsonRpcResponse::success(id, self.resources_list_result()),
            "resources/read" => self.resources_read(id, req.params.as_ref()),
            "tools/list" => JsonRpcResponse::success(id, self.tools_list_result()),
            "tools/call" => self.tools_call(id, req.params.as_ref()),
            other => JsonRpcResponse::error(
                id,
                codes::METHOD_NOT_FOUND,
                format!("method not found: {other}"),
            ),
        };
        Some(resp)
    }

    fn initialize_result(&self) -> Value {
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "prompts": { "listChanged": false },
                "tools": { "listChanged": false },
                "resources": { "listChanged": false },
            },
            "serverInfo": { "name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION") },
            "instructions": "Chancela platform operations as permission-gated MCP tools. Every tool call is authorized server-side by the configured API key's RBAC principal. Prompts are static guidance only; they do not create legal validity, sign documents, or call hidden providers.",
        })
    }

    fn prompts_list(&self, id: Value, params: Option<&Value>) -> JsonRpcResponse {
        if !params_are_absent_or_object(params) {
            return JsonRpcResponse::error(
                id,
                codes::INVALID_PARAMS,
                "prompts/list requires object params when params are provided",
            );
        }

        let prompts: Vec<Value> = PROMPT_CATALOG
            .iter()
            .map(|p| {
                json!({
                    "name": p.name,
                    "title": p.title,
                    "description": p.description,
                    "arguments": [],
                })
            })
            .collect();
        JsonRpcResponse::success(id, json!({ "prompts": prompts }))
    }

    fn prompts_get(&self, id: Value, params: Option<&Value>) -> JsonRpcResponse {
        let params = match params.and_then(Value::as_object) {
            Some(params) => params,
            None => {
                return JsonRpcResponse::error(
                    id,
                    codes::INVALID_PARAMS,
                    "prompts/get requires object params",
                );
            }
        };
        let name = match params.get("name").and_then(Value::as_str) {
            Some(name) => name,
            None => {
                return JsonRpcResponse::error(
                    id,
                    codes::INVALID_PARAMS,
                    "prompts/get requires a string name",
                );
            }
        };
        let prompt = match PROMPT_CATALOG.iter().find(|prompt| prompt.name == name) {
            Some(prompt) => prompt,
            None => {
                return JsonRpcResponse::error(
                    id,
                    codes::INVALID_PARAMS,
                    format!("invalid prompt name: {name}"),
                );
            }
        };
        if let Some(arguments) = params.get("arguments") {
            match arguments.as_object() {
                Some(arguments) if arguments.is_empty() => {}
                Some(_) => {
                    return JsonRpcResponse::error(
                        id,
                        codes::INVALID_PARAMS,
                        format!("{name} does not accept arguments"),
                    );
                }
                None => {
                    return JsonRpcResponse::error(
                        id,
                        codes::INVALID_PARAMS,
                        "prompts/get arguments must be an object when provided",
                    );
                }
            }
        }

        JsonRpcResponse::success(
            id,
            json!({
                "description": prompt.description,
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": (prompt.text)(),
                        },
                    }
                ],
            }),
        )
    }

    fn tools_list_result(&self) -> Value {
        let tools: Vec<Value> = self
            .tools
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "title": t.title,
                    "description": t.description,
                    "inputSchema": t.input_schema,
                    "annotations": {
                        "title": t.title,
                        "readOnlyHint": t.access.read_only_hint(),
                    },
                })
            })
            .collect();
        json!({ "tools": tools })
    }

    fn resources_list_result(&self) -> Value {
        json!({
            "resources": [
                {
                    "uri": MCP_STATUS_RESOURCE_URI,
                    "name": "mcp_status",
                    "title": "MCP Status",
                    "description": "Read-only Chancela MCP server operability snapshot. Contains no API key material and does not probe the integration API.",
                    "mimeType": "application/json",
                    "annotations": {
                        "audience": ["user", "assistant"],
                        "priority": 0.8,
                    },
                },
                {
                    "uri": MCP_SPEC_09_COVERAGE_RESOURCE_URI,
                    "name": "mcp_spec_09_coverage",
                    "title": "MCP Spec 09 Coverage",
                    "description": "Read-only local summary of MCP coverage for spec 09 AI-10/11/12 and the boundaries that still require human or API-side review. Contains no secrets and performs no provider calls.",
                    "mimeType": "application/json",
                    "annotations": {
                        "audience": ["user", "assistant"],
                        "priority": 0.7,
                    },
                },
                {
                    "uri": MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI,
                    "name": "workflow_provenance_review",
                    "title": "Workflow Provenance Review",
                    "description": "Read-only workflow provenance review resource. Without arguments it returns static guidance; with workflow_evidence JSON or text it returns deterministic aggregate local counts only. Contains no secrets, performs no bridge, API, AI, or provider calls, and makes no legal-validity, source-certification, workflow-completion, provider-assurance, trust, external-validation, signature-qualification, or extraction-accuracy claims.",
                    "mimeType": "application/json",
                    "annotations": {
                        "audience": ["user", "assistant"],
                        "priority": 0.65,
                    },
                },
                {
                    "uri": MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI,
                    "name": "draft_signed_comparison_review",
                    "title": "Draft-Signed Comparison Review",
                    "description": "Read-only draft-vs-signed comparison review resource. Without arguments it returns static guidance; with draft/signed arguments it returns a deterministic local comparison report. Contains no secrets, performs no bridge, API, AI, or provider calls, and makes no legal-validity, source-certification, external-validation, signature-qualification, provider, or trust claims.",
                    "mimeType": "application/json",
                    "annotations": {
                        "audience": ["user", "assistant"],
                        "priority": 0.65,
                    },
                },
                {
                    "uri": MCP_CHRONOLOGY_REVIEW_SUMMARY_RESOURCE_URI,
                    "name": "chronology_review_summary",
                    "title": "Chronology Review Summary",
                    "description": "Read-only local chronology review summary resource. Without arguments it returns static guidance; with chronology JSON it returns deterministic aggregate counts, date-range metadata, evidence-marker counts, and caveats. Contains no secrets, performs no bridge, API, AI, registry, legal-service, or provider calls, and makes no legal-validity, ownership, registry-certification, AI-completion, source-certification, provider, or trust claims.",
                    "mimeType": "application/json",
                    "annotations": {
                        "audience": ["user", "assistant"],
                        "priority": 0.65,
                    },
                },
                {
                    "uri": MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI,
                    "name": "privacy_control_review_summary",
                    "title": "Privacy Control Review Summary",
                    "description": "Read-only local privacy-control review summary resource. Without arguments it returns static input guidance and no-claim boundaries; with privacy_controls JSON it returns deterministic aggregate counts only. Contains no secrets, performs no bridge, API, AI, legal-service, or provider calls, and makes no legal, notification, transfer, DPIA, compliance, deletion, redaction, anonymization, disposal, erasure, provider, or completion claims.",
                    "mimeType": "application/json",
                    "annotations": {
                        "audience": ["user", "assistant"],
                        "priority": 0.65,
                    },
                },
                {
                    "uri": MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI,
                    "name": "document_archive_review_summary",
                    "title": "Document/Archive Review Summary",
                    "description": "Read-only local document-bundle/archive evidence summary resource. Without arguments it returns static input guidance; with document_archive JSON it returns deterministic aggregate counts, technical evidence flags, PDF accessibility v12 summary fields, archive path counts, and missing-evidence blockers. Contains no secrets, performs no bridge, API, AI, legal-service, HTTP/SSE, or provider calls, does not expose raw reports, and makes no PDF/UA, DGLAB, legal-validity, signature-validity, archive-certification, provider-validation, external-validator-success, or legal-review claims.",
                    "mimeType": "application/json",
                    "annotations": {
                        "audience": ["user", "assistant"],
                        "priority": 0.65,
                    },
                },
                {
                    "uri": MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI,
                    "name": "meeting_metadata_extraction_review",
                    "title": "Meeting Metadata Extraction Review",
                    "description": "Read-only local meeting metadata extraction review resource. Without arguments it returns static guidance; with meeting_document JSON or text metadata it returns deterministic candidate counts, bounded channel classification, evidence markers, blockers, warnings, and no-claim flags. Contains no secrets, performs no bridge, API, AI, legal-service, HTTP/SSE, or provider calls, does not echo raw document text, names, contacts, emails, phone numbers, access codes, credentials, secrets, or uploaded bytes, and makes no legal-validity, source-certification, or workflow-completion claims.",
                    "mimeType": "application/json",
                    "annotations": {
                        "audience": ["user", "assistant"],
                        "priority": 0.65,
                    },
                }
            ]
        })
    }

    fn resources_read(&self, id: Value, params: Option<&Value>) -> JsonRpcResponse {
        let params = match params.and_then(Value::as_object) {
            Some(params) => params,
            None => {
                return JsonRpcResponse::error(
                    id,
                    codes::INVALID_PARAMS,
                    "resources/read requires object params",
                );
            }
        };
        let uri = match params.get("uri").and_then(Value::as_str) {
            Some(uri) => uri,
            None => {
                return JsonRpcResponse::error(
                    id,
                    codes::INVALID_PARAMS,
                    "resources/read requires a string uri",
                );
            }
        };
        let workflow_arguments = if uri == MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI {
            if params.keys().any(|key| key != "uri" && key != "arguments") {
                return JsonRpcResponse::error(
                    id,
                    codes::INVALID_PARAMS,
                    "workflow provenance review resource accepts only uri or uri plus arguments",
                );
            }
            params.get("arguments")
        } else {
            None
        };
        let draft_signed_arguments = if uri == MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI {
            if params.keys().any(|key| key != "uri" && key != "arguments") {
                return JsonRpcResponse::error(
                    id,
                    codes::INVALID_PARAMS,
                    "draft-signed comparison resource accepts only uri or uri plus arguments",
                );
            }
            params.get("arguments")
        } else {
            None
        };
        let chronology_arguments = if uri == MCP_CHRONOLOGY_REVIEW_SUMMARY_RESOURCE_URI {
            if params.keys().any(|key| key != "uri" && key != "arguments") {
                return JsonRpcResponse::error(
                    id,
                    codes::INVALID_PARAMS,
                    "chronology review summary resource accepts only uri or uri plus arguments",
                );
            }
            params.get("arguments")
        } else {
            None
        };
        let privacy_control_arguments = if uri == MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI {
            if params.keys().any(|key| key != "uri" && key != "arguments") {
                return JsonRpcResponse::error(
                    id,
                    codes::INVALID_PARAMS,
                    "privacy-control review summary resource accepts only uri or uri plus arguments",
                );
            }
            params.get("arguments")
        } else {
            None
        };
        let document_archive_arguments = if uri == MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI
        {
            if params.keys().any(|key| key != "uri" && key != "arguments") {
                return JsonRpcResponse::error(
                    id,
                    codes::INVALID_PARAMS,
                    "document/archive review summary resource accepts only uri or uri plus arguments",
                );
            }
            params.get("arguments")
        } else {
            None
        };
        let meeting_metadata_arguments = if uri
            == MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI
        {
            if params.keys().any(|key| key != "uri" && key != "arguments") {
                return JsonRpcResponse::error(
                    id,
                    codes::INVALID_PARAMS,
                    "meeting metadata extraction review resource accepts only uri or uri plus arguments",
                );
            }
            params.get("arguments")
        } else {
            None
        };
        let payload = match uri {
            MCP_STATUS_RESOURCE_URI => self.status_resource_payload(),
            MCP_SPEC_09_COVERAGE_RESOURCE_URI => self.spec_09_coverage_resource_payload(),
            MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI => match workflow_arguments {
                Some(arguments) => match workflow_provenance_review_report_payload(arguments) {
                    Ok(payload) => payload,
                    Err(message) => {
                        return JsonRpcResponse::error(
                            id,
                            codes::INVALID_PARAMS,
                            format!("invalid workflow provenance review arguments: {message}"),
                        );
                    }
                },
                None => self.workflow_provenance_review_resource_payload(),
            },
            MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI => match draft_signed_arguments {
                Some(arguments) => match draft_signed_comparison_report_payload(arguments) {
                    Ok(payload) => payload,
                    Err(message) => {
                        return JsonRpcResponse::error(
                            id,
                            codes::INVALID_PARAMS,
                            format!("invalid draft-signed comparison arguments: {message}"),
                        );
                    }
                },
                None => self.draft_signed_comparison_review_resource_payload(),
            },
            MCP_CHRONOLOGY_REVIEW_SUMMARY_RESOURCE_URI => match chronology_arguments {
                Some(arguments) => match chronology_review_summary_report_payload(arguments) {
                    Ok(payload) => payload,
                    Err(message) => {
                        return JsonRpcResponse::error(
                            id,
                            codes::INVALID_PARAMS,
                            format!("invalid chronology review summary arguments: {message}"),
                        );
                    }
                },
                None => self.chronology_review_summary_resource_payload(),
            },
            MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI => match privacy_control_arguments {
                Some(arguments) => match privacy_control_review_summary_report_payload(arguments) {
                    Ok(payload) => payload,
                    Err(message) => {
                        return JsonRpcResponse::error(
                            id,
                            codes::INVALID_PARAMS,
                            format!("invalid privacy-control review summary arguments: {message}"),
                        );
                    }
                },
                None => self.privacy_control_review_summary_resource_payload(),
            },
            MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI => match document_archive_arguments {
                Some(arguments) => {
                    match document_archive_review_summary_report_payload(arguments) {
                        Ok(payload) => payload,
                        Err(message) => {
                            return JsonRpcResponse::error(
                                id,
                                codes::INVALID_PARAMS,
                                format!(
                                    "invalid document/archive review summary arguments: {message}"
                                ),
                            );
                        }
                    }
                }
                None => self.document_archive_review_summary_resource_payload(),
            },
            MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI => match meeting_metadata_arguments
            {
                Some(arguments) => {
                    match meeting_metadata_extraction_review_report_payload(arguments) {
                        Ok(payload) => payload,
                        Err(message) => {
                            return JsonRpcResponse::error(
                                id,
                                codes::INVALID_PARAMS,
                                format!(
                                    "invalid meeting metadata extraction review arguments: {message}"
                                ),
                            );
                        }
                    }
                }
                None => self.meeting_metadata_extraction_review_resource_payload(),
            },
            _ => {
                return JsonRpcResponse::error_with_data(
                    id,
                    codes::RESOURCE_NOT_FOUND,
                    "Resource not found",
                    json!({ "uri": uri }),
                );
            }
        };

        let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string());
        JsonRpcResponse::success(
            id,
            json!({
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": text,
                    }
                ]
            }),
        )
    }

    fn status_resource_payload(&self) -> Value {
        json!({
            "kind": "chancela_mcp_status",
            "status": "serving",
            "server": {
                "name": SERVER_NAME,
                "version": env!("CARGO_PKG_VERSION"),
                "protocol_version": PROTOCOL_VERSION,
            },
            "transport": {
                "active": transport_name(self.runtime.transport),
                "supported": ["stdio"],
                "reserved_not_served": ["http-sse"],
                "non_stdio_served": false,
            },
            "gates": {
                "mcp_enabled": true,
                "tenant_ai_enabled": true,
                "api_key_configured": true,
                "api_key_exposed": false,
            },
            "integration_api": {
                "base_url": self.runtime.base_url.as_str(),
                "base_path": self.runtime.base_path.as_str(),
                "health_probe": "not_performed",
            },
            "tools": {
                "enabled": self.tools.len(),
                "catalog": self.runtime.catalog_tool_count,
            },
            "security": {
                "authorization_forwarded_server_side": true,
                "rbac_reimplemented_in_mcp": false,
                "secrets_in_resource": false,
            },
            "limitations": [
                "stdio_transport_only",
                "http_sse_reserved_not_served",
                "integration_api_health_not_probed",
                "no_stdout_stderr_log_tail",
            ],
        })
    }

    fn spec_09_coverage_resource_payload(&self) -> Value {
        let tools_by_access = |access: ToolAccess| -> Vec<Value> {
            self.tools
                .iter()
                .filter(|tool| tool.access == access)
                .map(|tool| {
                    json!({
                        "name": tool.name,
                        "permission": tool.permission,
                    })
                })
                .collect()
        };
        let prompt_names = PROMPT_CATALOG
            .iter()
            .map(|prompt| prompt.name)
            .collect::<Vec<_>>();

        json!({
            "kind": "chancela_mcp_spec_09_coverage",
            "schema_version": 1,
            "source": "local_mcp_registry_and_static_server_metadata",
            "offline": true,
            "spec": {
                "id": "09-ai-mcp",
                "title": "AI, MCP, and Integrations",
                "covered_here": ["AI-10", "AI-11", "AI-12"],
                "not_assessed_here": ["AI-01..AI-04", "AI-20..AI-22", "AI-30..AI-31"],
            },
            "coverage": {
                "AI-10": {
                    "status": "partial",
                    "requirement": "MCP discovery for tools, resources, and prompts",
                    "covered_locally": {
                        "tools": true,
                        "resources": [
                            MCP_STATUS_RESOURCE_URI,
                            MCP_SPEC_09_COVERAGE_RESOURCE_URI,
                            MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI,
                            MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI,
                            MCP_CHRONOLOGY_REVIEW_SUMMARY_RESOURCE_URI,
                            MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI,
                            MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI,
                            MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI,
                        ],
                        "prompts": prompt_names,
                    },
                    "boundaries": [
                        "stdio_transport_only",
                        "resource_payloads_are_local_snapshots",
                        "no_external_provider_or_api_probe",
                    ],
                },
                "AI-11": {
                    "status": "partial",
                    "requirement": "read-only and write-controlled tool split honoring permission scopes",
                    "read_only_tools": tools_by_access(ToolAccess::ReadOnly),
                    "write_controlled_tools": tools_by_access(ToolAccess::WriteControlled),
                    "tool_counts": {
                        "enabled": self.tools.len(),
                        "catalog": self.runtime.catalog_tool_count,
                    },
                    "permission_source": "documented_server_side_rbac_gate_for_forwarded_api_key",
                    "mcp_reimplements_rbac": false,
                },
                "AI-12": {
                    "status": "partial",
                    "requirement": "authenticated API Client role with the same audit-ledger path",
                    "authentication": "configured_bearer_api_key_forwarded_to_integration_api",
                    "authorization_forwarded_server_side": true,
                    "audit_source": "integration_api_and_ledger",
                    "mcp_emits_independent_audit_events": false,
                    "limitations": [
                        "resource_read_does_not_call_the_api",
                        "audit_ledger_state_not_probed",
                    ],
                },
            },
            "mcp_review_aids": {
                "resources": [
                    MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI,
                    MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI,
                    MCP_CHRONOLOGY_REVIEW_SUMMARY_RESOURCE_URI,
                    MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI,
                    MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI,
                    MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI,
                ],
                "prompts": [
                    WORKFLOW_PROVENANCE_REVIEW_PROMPT_NAME,
                    DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_NAME,
                ],
                "purpose": "offline_human_review_guidance_plus_deterministic_local_draft_signed_chronology_privacy_control_document_archive_and_meeting_metadata_summaries",
                "ai_01_claimed": false,
                "ai_02_claimed": false,
                "full_ai_mcp_completion_claimed": false,
            },
            "review_boundaries": {
                "hidden_provider_calls": false,
                "additional_credentials_required": false,
                "resource_read_forwards_api_key": false,
                "secrets_in_resource": false,
                "legal_validity_claimed": false,
                "source_certification_claimed": false,
                "trust_claimed": false,
                "external_validation_claimed": false,
                "archive_certification_claimed": false,
                "signature_qualification_claimed": false,
            },
            "operator_review_next_steps": [
                "Compare enabled tools against the tenant policy and API-key grant before use.",
                "Use explicit tools or API records to verify DSR, retention, archive, and audit evidence.",
                "Treat all prompt output as review assistance only; human review and normal platform gates remain required.",
            ],
        })
    }

    fn workflow_provenance_review_resource_payload(&self) -> Value {
        json!({
            "kind": "chancela_mcp_workflow_provenance_review",
            "schema_version": 1,
            "source": "static_mcp_review_aid",
            "offline": true,
            "static": true,
            "arguments": [],
            "bridge_calls": false,
            "api_calls": false,
            "provider_calls": false,
            "secrets_in_resource": false,
            "claims": {
                "legal_validity": false,
                "source_certification": false,
                "provider": false,
                "trust": false,
                "external": false,
                "archive_certification": false,
                "signature_qualification": false,
            },
            "review_categories": [
                {
                    "id": "act_lifecycle",
                    "title": "Act lifecycle",
                    "checkpoints": [
                        "Identify draft, review, approval, signature, sealing, archive, and correction states recorded for the act.",
                        "Check timestamps, actors, transitions, and unresolved lifecycle gaps against supplied platform evidence.",
                        "Separate recorded lifecycle facts from reviewer assumptions and proposed next actions.",
                    ],
                },
                {
                    "id": "book_chain",
                    "title": "Book chain",
                    "checkpoints": [
                        "Check book id, entity id, act sequence, page or folio references, prior and next act links, and any gap markers.",
                        "Compare chain references with ledger evidence or manifests supplied for review.",
                        "Flag duplicate, missing, reordered, or unexplained chain entries for human review.",
                    ],
                },
                {
                    "id": "source_records",
                    "title": "Source records",
                    "checkpoints": [
                        "List source record ids, filenames, checksums, capture timestamps, import actors, and stated source type.",
                        "Check whether every provenance statement points to a supplied source record.",
                        "Flag missing, ambiguous, or inconsistent source records without treating the source as certified.",
                    ],
                },
                {
                    "id": "ledger_events",
                    "title": "Ledger events",
                    "checkpoints": [
                        "List ledger event ids, event types, actor references, timestamps, object ids, and digests supplied for review.",
                        "Compare event order with act lifecycle and book chain evidence.",
                        "Treat ledger evidence as technical evidence to review, not a legal-validity or external trust claim.",
                    ],
                },
                {
                    "id": "imported_evidence",
                    "title": "Imported evidence",
                    "checkpoints": [
                        "Review imported paper-book, OCR, canonical conversion, external report, and manifest references supplied by the operator.",
                        "Check provenance fields for source capture, import job, human correction, checksum, and ledger anchoring.",
                        "Flag imports whose evidence is incomplete, mismatched, or unclear before downstream archive or signature workflows.",
                    ],
                },
                {
                    "id": "signature_archive_technical_evidence",
                    "title": "Signature/archive technical evidence",
                    "checkpoints": [
                        "Review signature bundle ids, validator report ids, archive package ids, manifests, timestamps, digests, and preservation metadata supplied for review.",
                        "Keep signature and archive observations limited to technical evidence fields.",
                        "Do not infer legal validity, signature qualification, archive certification, provider assurance, or trust status.",
                    ],
                },
                {
                    "id": "operator_review_notes",
                    "title": "Operator review notes",
                    "checkpoints": [
                        "Record human review questions, missing evidence, conflicting identifiers, and follow-up owners.",
                        "Label suggested corrections as suggestions only until the responsible operator verifies them.",
                        "Preserve a concise boundary note: static offline review aid, no bridge calls, no secrets, no legal or provider claims.",
                    ],
                },
            ],
            "operator_boundaries": [
                "Use only evidence supplied by the operator or explicitly retrieved through Chancela tools.",
                "Do not claim legal validity, source certification, provider assurance, trust status, external verification, archive certification, or signature qualification.",
                "Do not include credentials, API keys, secrets, or personal data that is not needed for the review.",
                "Normal platform permissions, lifecycle gates, and human review remain required.",
            ],
        })
    }

    fn chronology_review_summary_resource_payload(&self) -> Value {
        json!({
            "kind": "chancela_mcp_chronology_review_summary",
            "schema_version": 1,
            "source": "static_mcp_review_aid",
            "offline": true,
            "static": true,
            "local_json_only": true,
            "arguments": [],
            "optional_arguments": [
                {
                    "name": "chronology",
                    "description": "Caller-supplied chronology JSON object with an events array, or an events array directly. The resource only returns aggregate local counts/classifications.",
                }
            ],
            "bridge_calls": false,
            "api_calls": false,
            "provider_calls": false,
            "ai_provider_calls": false,
            "registry_calls": false,
            "legal_service_calls": false,
            "secrets_in_resource": false,
            "claims": {
                "legal_validity": false,
                "ownership_determination": false,
                "registry_certification": false,
                "ai_completion": false,
                "source_certification": false,
                "provider": false,
                "trust": false,
                "external_validation": false,
                "archive_certification": false,
                "signature_qualification": false,
            },
            "summary_categories": [
                {
                    "id": "event_counts",
                    "title": "Event counts",
                    "checkpoints": [
                        "Count total caller-supplied events and classify event kinds and statuses using common chronology fields.",
                        "Treat missing, empty, or unknown event kind/status values as local classification gaps only.",
                    ],
                },
                {
                    "id": "date_range",
                    "title": "Date range",
                    "checkpoints": [
                        "Extract non-empty date/timestamp strings from common chronology fields and report the local lexical range.",
                        "Treat missing or unparseable dates as review caveats; do not certify chronological correctness.",
                    ],
                },
                {
                    "id": "evidence_markers",
                    "title": "Evidence markers",
                    "checkpoints": [
                        "Count events with recognized evidence/source/digest markers and events lacking those markers.",
                        "Count explicit missing-evidence flags when supplied by the caller.",
                    ],
                },
                {
                    "id": "review_caveats",
                    "title": "Review caveats",
                    "checkpoints": [
                        "Keep output advisory and local to the supplied JSON.",
                        "Do not infer legal validity, ownership, registry certification, AI completion, source certification, trust, external validation, or provider assurance.",
                    ],
                },
            ],
            "operator_boundaries": [
                "Use only chronology JSON supplied in resources/read arguments.",
                "Do not include credentials, API keys, secrets, or unnecessary personal data in chronology JSON.",
                "Use the summary as advisory local review assistance only.",
                "Normal platform permissions, lifecycle gates, source review, and human verification remain required.",
            ],
        })
    }

    fn privacy_control_review_summary_resource_payload(&self) -> Value {
        json!({
            "kind": "chancela_mcp_privacy_control_review_summary",
            "schema_version": 1,
            "source": "static_mcp_review_aid",
            "offline": true,
            "static": true,
            "local_json_only": true,
            "arguments": [],
            "optional_arguments": [
                {
                    "name": "privacy_controls",
                    "description": "Caller-supplied local JSON object containing optional arrays named processors, dpias, breach_playbooks, transfer_controls, retention_policies, retention_executions, dsr_requests, retention_candidate_resolutions, plus an optional retention_due_candidates report object. The resource returns aggregate counts only and does not echo record names, ids, notes, legal bases, recipients, subjects, data categories, raw evidence text, or secrets.",
                }
            ],
            "expected_input_shape": {
                "resources_read_params": {
                    "uri": MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI,
                    "arguments": {
                        "privacy_controls": {
                            "processors": "array of local processor register objects",
                            "dpias": "array of local DPIA register objects",
                            "breach_playbooks": "array of local breach-playbook objects",
                            "transfer_controls": "array of local transfer-control objects",
                            "retention_policies": "array of local retention-policy objects",
                            "retention_executions": "array of local retention-execution objects",
                            "dsr_requests": "array of local DSR request objects",
                            "retention_due_candidates": "optional local RetentionDueCandidatesReport object",
                            "retention_candidate_resolutions": "optional array of local RetentionCandidateResolutionRecord objects"
                        }
                    }
                }
            },
            "privacy_control_categories": [
                "processors",
                "dpias",
                "breach_playbooks",
                "transfer_controls",
                "retention_policies",
                "retention_executions",
                "dsr_requests",
                "retention_due_candidates",
                "retention_candidate_resolutions"
            ],
            "summary_categories": [
                {
                    "id": "record_counts",
                    "title": "Record counts",
                    "checkpoints": [
                        "Count caller-supplied local JSON records by known privacy-control category.",
                        "Ignore unknown top-level privacy_controls keys without echoing their values."
                    ],
                },
                {
                    "id": "risk_status_counts",
                    "title": "Risk/status counts",
                    "checkpoints": [
                        "Classify recognized risk/status labels into bounded buckets.",
                        "Bucket unrecognized values as other so caller text is not echoed."
                    ],
                },
                {
                    "id": "advisory_review_counts",
                    "title": "Advisory review counts",
                    "checkpoints": [
                        "Count advisory-review status buckets and missing advisory-review status markers.",
                        "Count review and drill receipt markers without including receipt notes or actors."
                    ],
                },
                {
                    "id": "retention_execution_counts",
                    "title": "Retention execution counts",
                    "checkpoints": [
                        "Count retention execution status, outcome, and evidence-state buckets.",
                        "Keep destructive disposal and full-erasure completion claims false."
                    ],
                },
                {
                    "id": "retention_due_candidate_counts",
                    "title": "Retention due-candidate counts",
                    "checkpoints": [
                        "Count caller-supplied due-candidate status, outcome, evidence-state, bounded suppression, latest-resolution, blocker, and approval buckets.",
                        "Bucket unrecognized candidate labels as other and never echo candidate ids, names, notes, legal bases, raw evidence, or schedule text."
                    ],
                },
                {
                    "id": "retention_candidate_resolution_counts",
                    "title": "Retention candidate-resolution counts",
                    "checkpoints": [
                        "Count caller-supplied evidence-only resolution dispositions, candidate-snapshot blocker and approval presence, and no-claim observations.",
                        "Treat disposal, deletion, redaction, erasure, legal-completion, legal-hold, and retention-policy mutation fields as caveat counts only."
                    ],
                },
                {
                    "id": "dsr_counts",
                    "title": "DSR counts",
                    "checkpoints": [
                        "Count DSR request type, status, and outcome buckets.",
                        "Do not echo subject identifiers, reasons, execution notes, affected collections, or legal-basis review text."
                    ],
                },
                {
                    "id": "false_claim_flags",
                    "title": "False-claim flag counts",
                    "checkpoints": [
                        "Aggregate explicit false/truthy observations for fields that must not be treated as approvals, notifications, filings, certifications, compliance completion, disposal, deletion, anonymization, redaction, or erasure.",
                        "Treat truthy caller-supplied observations as caveats only; this resource never upgrades them into completion claims."
                    ],
                }
            ],
            "bridge_calls": false,
            "api_calls": false,
            "provider_calls": false,
            "ai_provider_calls": false,
            "legal_service_calls": false,
            "secrets_in_resource": false,
            "claims": {
                "legal_approval": false,
                "legal_completion": false,
                "authority_notification": false,
                "data_subject_notification": false,
                "transfer_approval": false,
                "transfer_execution": false,
                "dpia_authority_filing": false,
                "dpia_completion": false,
                "compliance_certification": false,
                "privacy_compliance_completion": false,
                "gdpr_compliance_completion": false,
                "destructive_disposal": false,
                "deletion_completion": false,
                "anonymization_completion": false,
                "redaction_completion": false,
                "full_erasure": false,
                "erasure_completion": false,
                "legal_hold_mutation": false,
                "retention_policy_mutation": false,
                "provider": false,
                "legal_service": false
            },
            "operator_boundaries": [
                "Use only privacy_controls JSON supplied in resources/read arguments.",
                "Do not include credentials, API keys, secrets, raw subject identifiers, raw recipients, legal bases, notes, or data categories in caller JSON.",
                "Use this summary as advisory local review assistance only.",
                "No bridge, API, AI-provider, legal-service, provider, notification, transfer, filing, certification, disposal, deletion, anonymization, redaction, or erasure action is performed.",
                "Normal platform permissions, privacy workflow gates, legal review, and human verification remain required."
            ],
        })
    }

    fn document_archive_review_summary_resource_payload(&self) -> Value {
        json!({
            "kind": "chancela_mcp_document_archive_review_summary",
            "schema_version": 1,
            "source": "static_mcp_review_aid",
            "offline": true,
            "static": true,
            "local_json_only": true,
            "arguments": [],
            "optional_arguments": [
                {
                    "name": "document_archive",
                    "description": "Caller-supplied local JSON object containing document_bundle, archive_package, evidence_index, validation_report, pdf_accessibility, signed_document, and external_validator_reports evidence. The resource returns deterministic counts, bounded statuses, no-claim observations, and missing-evidence blockers only; it does not echo raw reports or raw document bytes.",
                }
            ],
            "expected_input_shape": {
                "resources_read_params": {
                    "uri": MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI,
                    "arguments": {
                        "document_archive": {
                            "document_bundle": "optional bundle JSON returned or assembled by the caller",
                            "archive_package": "optional archive/package manifest or evidence-index JSON supplied by the caller",
                            "validation_report": "optional local validation-report object",
                            "pdf_accessibility": "optional chancela-pdf-accessibility-evidence/v1 sidecar or report object",
                            "signed_document": "optional signed-document technical metadata object",
                            "external_validator_reports": "optional metadata attachment summary object or array"
                        }
                    }
                }
            },
            "summary_categories": [
                {
                    "id": "validation_and_fixity",
                    "title": "Validation and fixity",
                    "checkpoints": [
                        "Report whether a validation report/status marker is present using bounded status buckets.",
                        "Count digest/checksum/SHA-256 fields without echoing digest values.",
                        "Flag missing validation or fixity evidence as local review blockers only.",
                    ],
                },
                {
                    "id": "signed_document_state",
                    "title": "Signed document state",
                    "checkpoints": [
                        "Detect signed-document technical metadata and bounded status labels when supplied.",
                        "Count signature metadata and signed-PDF digest presence without validating signatures.",
                        "Keep signature-validity, qualified-signature, and legal-validity claims false.",
                    ],
                },
                {
                    "id": "external_validator_attachments",
                    "title": "External validator attachments",
                    "checkpoints": [
                        "Count caller-supplied external-validator metadata attachment objects and bounded attachment statuses.",
                        "Count raw-report references without exposing raw report bytes, content, or payload fields.",
                        "Do not infer provider validation, external-validator success, trust validation, certification, or legal acceptance.",
                    ],
                },
                {
                    "id": "pdf_accessibility_v12",
                    "title": "PDF accessibility v12",
                    "checkpoints": [
                        "Summarize report-version counts, known PDF/UA blocker codes, and table row/column header counts from supplied local JSON.",
                        "Count explicit false no-claim flags for PDF/UA, DGLAB, legal validity, signature validity, archive certification, provider validation, external-validator success, and legal review.",
                        "Treat truthy no-claim fields as blockers, never as conformance or certification.",
                    ],
                },
                {
                    "id": "archive_paths",
                    "title": "Archive paths",
                    "checkpoints": [
                        "Count evidence-index, archive-evidence, PDF-accessibility, external-validator, canonical-PDF, and signed-PDF path markers without dumping raw reports.",
                        "Keep output local and advisory; normal source review and platform permissions remain required.",
                    ],
                },
            ],
            "bridge_calls": false,
            "api_calls": false,
            "provider_calls": false,
            "ai_provider_calls": false,
            "legal_service_calls": false,
            "http_sse_transport_added": false,
            "raw_reports_exposed": false,
            "raw_document_bytes_exposed": false,
            "secrets_in_resource": false,
            "claims": {
                "pdf_ua_conformance": false,
                "dglab_certification": false,
                "legal_validity": false,
                "signature_validity": false,
                "qualified_signature": false,
                "archive_certification": false,
                "provider_validation": false,
                "external_validator_success": false,
                "trust_validation": false,
                "legal_review": false,
            },
            "operator_boundaries": [
                "Use only document/archive JSON supplied in resources/read arguments.",
                "Do not include credentials, API keys, secrets, raw report bytes, raw PDF bytes, or unnecessary personal data in caller JSON.",
                "Use this summary as advisory local review assistance only.",
                "No bridge, API, HTTP/SSE, AI-provider, legal-service, signature, archive-certification, external-validator, trust-list, DGLAB, or provider calls are made.",
                "No PDF/UA conformance, DGLAB certification, legal validity, signature validity, archive certification, provider validation, external-validator success, trust validation, or legal review is claimed."
            ],
        })
    }

    fn meeting_metadata_extraction_review_resource_payload(&self) -> Value {
        json!({
            "kind": "chancela_mcp_meeting_metadata_extraction_review",
            "schema_version": 1,
            "source": "static_mcp_review_aid",
            "offline": true,
            "static": true,
            "local_json_or_text_metadata_only": true,
            "arguments": [],
            "optional_arguments": [
                {
                    "name": "meeting_document",
                    "description": "Caller-supplied local JSON object metadata, JSON string metadata, or plain text metadata. The resource returns deterministic aggregate candidates, blockers, and warnings only; it does not echo raw document text, names, contacts, emails, phone numbers, secrets, access codes, credentials, or raw uploaded bytes.",
                }
            ],
            "expected_input_shape": {
                "resources_read_params": {
                    "uri": MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI,
                    "arguments": {
                        "meeting_document": {
                            "meeting_date": "optional string date metadata",
                            "meeting_time": "optional string time metadata",
                            "dispatch_date": "optional string date metadata",
                            "channel": "optional bounded meeting channel metadata",
                            "agenda_items": "optional array used only for count metadata",
                            "second_call_present": "optional boolean or marker metadata",
                            "evidence_reference": "optional evidence/source/reference marker metadata"
                        }
                    }
                }
            },
            "summary_categories": [
                {
                    "id": "metadata_candidate_counts",
                    "title": "Metadata candidate counts",
                    "checkpoints": [
                        "Count conservative meeting metadata candidates from recognized local JSON keys or text labels.",
                        "Report presence and ambiguity without echoing the supplied values.",
                        "Treat missing required review fields as blockers, not inferred truth."
                    ],
                },
                {
                    "id": "agenda_and_call_markers",
                    "title": "Agenda and call markers",
                    "checkpoints": [
                        "Count agenda item arrays or explicit agenda_item_count markers when supplied.",
                        "Count second-call markers as present or missing without deciding legal sufficiency.",
                    ],
                },
                {
                    "id": "evidence_and_safety_markers",
                    "title": "Evidence and safety markers",
                    "checkpoints": [
                        "Count evidence/source/reference markers without echoing IDs, paths, text, digests, names, or contacts.",
                        "Flag raw content, contact, credential, access-code, secret, or uploaded-byte markers as review warnings.",
                    ],
                },
                {
                    "id": "human_review_boundaries",
                    "title": "Human review boundaries",
                    "checkpoints": [
                        "Require human verification for every extracted candidate.",
                        "Do not claim legal validity, source certification, workflow completion, provider activity, or API activity."
                    ],
                }
            ],
            "human_verification_required": true,
            "ai_provider_called": false,
            "api_called": false,
            "legal_validity_claimed": false,
            "source_certification_claimed": false,
            "workflow_completion_claimed": false,
            "bridge_calls": false,
            "api_calls": false,
            "provider_calls": false,
            "ai_provider_calls": false,
            "legal_service_calls": false,
            "http_sse_transport_added": false,
            "raw_document_text_echoed": false,
            "raw_document_bytes_echoed": false,
            "names_contacts_emails_phones_echoed": false,
            "secrets_access_codes_credentials_echoed": false,
            "secrets_in_resource": false,
            "claims": {
                "legal_validity": false,
                "source_certification": false,
                "workflow_completion": false,
                "ai_completion": false,
                "provider": false,
                "trust": false,
                "external_validation": false,
                "archive_certification": false,
                "signature_qualification": false
            },
            "operator_boundaries": [
                "Use only caller-supplied local meeting metadata in resources/read arguments.",
                "Do not include raw minutes text, uploaded bytes, names, contacts, emails, phone numbers, access codes, credentials, API keys, secrets, or unnecessary personal data in caller metadata.",
                "Use this summary as advisory local review assistance only.",
                "No bridge, API, AI-provider, legal-service, HTTP/SSE, registry, trust, archive, signature, or provider calls are made.",
                "No legal validity, source certification, workflow completion, provider assurance, or trust status is claimed.",
                "Human verification and normal platform evidence checks remain required."
            ],
        })
    }

    fn draft_signed_comparison_review_resource_payload(&self) -> Value {
        json!({
            "kind": "chancela_mcp_draft_signed_comparison_review",
            "schema_version": 1,
            "source": "static_mcp_review_aid",
            "offline": true,
            "static": true,
            "local_json_only": true,
            "arguments": [],
            "bridge_calls": false,
            "api_calls": false,
            "provider_calls": false,
            "secrets_in_resource": false,
            "claims": {
                "legal_validity": false,
                "source_certification": false,
                "provider": false,
                "trust": false,
                "external_validation": false,
                "archive_certification": false,
                "signature_qualification": false,
            },
            "comparison_categories": [
                {
                    "id": "draft_identifiers",
                    "title": "Draft identifiers",
                    "checkpoints": [
                        "Record draft act id, entity id, book id, draft version, template id, source record ids, author or generator, created timestamp, and draft digest when supplied.",
                        "Check that each draft identifier is tied to supplied platform evidence, a manifest entry, or an explicit reviewer note.",
                        "Flag missing, ambiguous, duplicate, or conflicting draft identifiers before comparing content.",
                    ],
                },
                {
                    "id": "signed_artifact_identifiers",
                    "title": "Signed artifact identifiers",
                    "checkpoints": [
                        "Record signed document id, artifact id or URI, signature bundle id, seal id, signed version, signature event id, manifest id, and signed artifact digest when supplied.",
                        "Check that signed artifact identifiers point to the intended act, entity, book, and lifecycle event in the supplied evidence.",
                        "Flag artifacts that cannot be tied back to the draft or approved version under review.",
                    ],
                },
                {
                    "id": "digest_comparison",
                    "title": "Digest comparison",
                    "checkpoints": [
                        "Compare draft digest, canonical text digest, rendered artifact digest, signed artifact digest, manifest member digest, and ledger digest when supplied.",
                        "Separate exact digest matches from expected rendering changes, missing digest evidence, and unresolved digest mismatches.",
                        "Treat digest matches or mismatches as technical review signals only, not external validation or signature qualification.",
                    ],
                },
                {
                    "id": "text_comparison",
                    "title": "Text comparison",
                    "checkpoints": [
                        "Compare normalized draft text with signed text for names, capacities, dates, amounts, article references, resolutions, tables, attachments, footnotes, and annex references.",
                        "Classify differences as formatting only, expected rendering change, authorized content edit, uncertain change, or substantive mismatch.",
                        "Preserve reviewer uncertainty when OCR, rendering, extraction, whitespace, or layout changes prevent a confident comparison.",
                    ],
                },
                {
                    "id": "version_lifecycle_comparison",
                    "title": "Version and lifecycle comparison",
                    "checkpoints": [
                        "Compare draft version, approved version, rendered version, signed version, event ids, actors, timestamps, and lifecycle states from the supplied evidence.",
                        "Check whether every content change after the draft has an explicit approval or correction record supplied for review.",
                        "Flag skipped, reordered, duplicated, or unclear lifecycle transitions for human follow-up.",
                    ],
                },
                {
                    "id": "mismatch_triage",
                    "title": "Mismatch triage",
                    "checkpoints": [
                        "Classify each mismatch as exact match, expected formatting change, authorized edit, unresolved mismatch, or blocking mismatch.",
                        "Record the evidence references, affected field, reviewer rationale, owner, and next action for every unresolved or blocking mismatch.",
                        "Do not advance a legal-validity, source-certification, trust, external-validation, or signature-qualification conclusion from this review aid.",
                    ],
                },
                {
                    "id": "human_review_notes",
                    "title": "Human review notes",
                    "checkpoints": [
                        "Separate recorded facts from assumptions, suggested corrections, unresolved questions, and follow-up owners.",
                        "Label suggested wording or correction notes as suggestions only until a responsible human verifies them through normal platform gates.",
                        "Preserve a concise boundary note: static local JSON review aid, no arguments, no bridge calls, no API calls, no provider calls, no secrets, and no legal or trust claims.",
                    ],
                },
            ],
            "mismatch_triage": {
                "labels": [
                    "exact_match",
                    "expected_formatting_change",
                    "authorized_content_edit",
                    "unresolved_mismatch",
                    "blocking_mismatch",
                ],
                "required_notes": [
                    "evidence_reference",
                    "affected_identifier_or_text",
                    "reviewer_rationale",
                    "follow_up_owner",
                    "next_action",
                ],
            },
            "operator_boundaries": [
                "Use only evidence supplied by the operator or explicitly retrieved through Chancela tools.",
                "Do not include credentials, API keys, secrets, or personal data that is not needed for the review.",
                "Do not claim legal validity, source certification, provider assurance, trust status, external validation, archive certification, or signature qualification.",
                "Normal platform permissions, lifecycle gates, and human review remain required.",
            ],
        })
    }

    fn tools_call(&self, id: Value, params: Option<&Value>) -> JsonRpcResponse {
        let params = match params {
            Some(p) => p,
            None => return JsonRpcResponse::error(id, codes::INVALID_PARAMS, "missing params"),
        };
        let name = match params.get("name").and_then(Value::as_str) {
            Some(n) => n,
            None => return JsonRpcResponse::error(id, codes::INVALID_PARAMS, "missing tool name"),
        };
        let tool = match self.tools.iter().find(|t| t.name == name) {
            Some(t) => t,
            // Unknown OR not-enabled ⇒ tool error result (honest; a disabled tool is not callable).
            None => {
                return JsonRpcResponse::success(
                    id,
                    tool_error_result(&format!("unknown or disabled tool: {name}")),
                );
            }
        };
        let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

        let mut resolved = match resolve_call(tool, &arguments) {
            Ok(r) => r,
            Err(e) => {
                return JsonRpcResponse::success(id, tool_error_result(&tool_error_message(&e)));
            }
        };
        let mermaid_kind = if tool.name == "generate_mermaid_graph" {
            match mermaid_graph_kind_from_arguments(&arguments) {
                Ok(kind) => Some(kind),
                Err(message) => {
                    return JsonRpcResponse::success(
                        id,
                        tool_error_result(&format!("invalid tool arguments: {message}")),
                    );
                }
            }
        } else {
            None
        };
        attach_ai_draft_statement_sources(tool, &mut resolved, &arguments);

        match self.bridge.execute(
            resolved.method,
            &resolved.path,
            &resolved.query,
            resolved.body.as_ref(),
        ) {
            Ok(outcome) if outcome.is_success() => {
                let text = match mermaid_kind {
                    Some(kind) => match mermaid_graph_success_text(&outcome, kind) {
                        Ok(text) => text,
                        Err(message) => {
                            return JsonRpcResponse::success(id, tool_error_result(&message));
                        }
                    },
                    None if is_ai_draft_tool(tool.name) => {
                        match ai_draft_success_text(&outcome, tool, &resolved, &arguments) {
                            Ok(text) => text,
                            Err(message) => {
                                return JsonRpcResponse::success(id, tool_error_result(&message));
                            }
                        }
                    }
                    None if is_signature_bundle_validation_tool(tool.name) => {
                        match signature_bundle_validation_success_text(
                            &outcome, &resolved, &arguments,
                        ) {
                            Ok(text) => text,
                            Err(message) => {
                                return JsonRpcResponse::success(id, tool_error_result(&message));
                            }
                        }
                    }
                    None => tool_success_text(&outcome),
                };
                JsonRpcResponse::success(id, tool_text_result(&text, false))
            }
            // Non-2xx (that isn't 401/403/429) — surface the status honestly as a tool error.
            Ok(outcome) => JsonRpcResponse::success(
                id,
                tool_error_result(&format!(
                    "the integration API returned HTTP {}: {}",
                    outcome.status,
                    truncate(&outcome.raw, 500)
                )),
            ),
            Err(e) => JsonRpcResponse::success(id, tool_error_result(&bridge_error_message(&e))),
        }
    }

    /// Run the newline-delimited JSON-RPC stdio loop until EOF.
    pub fn run<R: BufRead, W: Write>(&self, reader: R, mut writer: W) -> std::io::Result<()> {
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<JsonRpcRequest>(&line) {
                Ok(req) => self.handle(&req),
                Err(e) => Some(JsonRpcResponse::error(
                    Value::Null,
                    codes::PARSE_ERROR,
                    format!("parse error: {e}"),
                )),
            };
            if let Some(resp) = response {
                let encoded = serde_json::to_string(&resp).unwrap_or_else(|_| {
                    r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error"}}"#.to_string()
                });
                writer.write_all(encoded.as_bytes())?;
                writer.write_all(b"\n")?;
                writer.flush()?;
            }
        }
        Ok(())
    }
}

/// Build a server from config and serve it over stdio. **Off by default**: a disabled config returns
/// `Ok(())` immediately, serving nothing and reading no input. A non-stdio transport is refused
/// (only stdio ships in v1).
pub fn serve_stdio(config: &McpConfig) -> Result<(), McpError> {
    if !config.served() {
        // Off = not served. Zero surface: no transport is built, stdin is never read.
        return Ok(());
    }
    if config.transport != McpTransport::Stdio {
        return Err(McpError::UnsupportedTransport(
            "only 'stdio' is supported in this build; 'http-sse' is reserved for a later opt-in release".to_string(),
        ));
    }
    let transport = ReqwestTransport::new().map_err(|e| McpError::Config(e.to_string()))?;
    let server = McpServer::from_config(config, transport)?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    server.run(stdin.lock(), stdout.lock())?;
    Ok(())
}

/// Number of tools that would be served under `config` (0 when disabled) — for the launcher banner.
pub fn enabled_tool_count(config: &McpConfig) -> usize {
    if !config.served() {
        return 0;
    }
    match &config.enabled_tools {
        EnabledTools::All => catalog().len(),
        EnabledTools::List(_) => catalog()
            .into_iter()
            .filter(|t| config.enabled_tools.allows(t.name))
            .count(),
    }
}

fn transport_name(transport: McpTransport) -> &'static str {
    match transport {
        McpTransport::Stdio => "stdio",
        McpTransport::HttpSse => "http-sse",
    }
}

fn params_are_absent_or_object(params: Option<&Value>) -> bool {
    matches!(params, None | Some(Value::Null) | Some(Value::Object(_)))
}

fn draft_minutes_review_prompt_text() -> &'static str {
    r#"You are helping a human reviewer check draft minutes in Chancela.

Use this checklist as guidance only. It has no legal validity, does not sign or seal anything, and does not call any hidden AI, signature, trust, registry, or legal provider. Do not claim that a draft is legally valid, final, signed, sealed, or ready for signature. The human reviewer must verify every fact against source documents and the platform record.

Review checklist:
1. Identify the entity, book, meeting or written-resolution type, date, place or channel, chair, secretary, attendees, quorum, agenda, and voting requirements.
2. Compare every statement in the draft against the source materials available to the reviewer. Mark missing sources, uncertain facts, and assumptions.
3. Check whether the draft distinguishes factual minutes from suggestions, commentary, or AI-proposed wording.
4. Flag any decision that appears outside the stated agenda, quorum, authority, or represented capacity.
5. Confirm that names, capacities, shareholdings or voting rights, document references, dates, and numbers are internally consistent.
6. List open questions for the responsible human reviewer before any lifecycle advance, document generation, signature, or sealing workflow.

Return a concise review with these sections:
- Missing or uncertain source facts
- Consistency issues
- Authority or agenda concerns
- Suggested wording changes, clearly labelled as suggestions only
- Final human-review reminder: guidance only, no legal validity, no signing, no hidden provider call"#
}

fn compliance_pack_gap_review_prompt_text() -> &'static str {
    r#"You are helping a human operator review gaps in a Chancela compliance pack.

Use this as review guidance only. Use only evidence the operator supplies or explicitly retrieves through Chancela tools. Do not call hidden AI, legal, registry, trust, signature, archive, or privacy providers. Do not claim GDPR compliance, legal validity, lawful deletion, retention correctness, archive certification, qualified-signature status, or production B-LT/B-LTA sufficiency.

Review checklist:
1. Identify the scope: DSR request ids, user ids, retention policy or execution ids, legal-hold state, archive package ids or digests, signature evidence records, and ledger event references.
2. Separate recorded facts from missing evidence, assumptions, recommendations, and legal judgment reserved for the responsible human reviewer.
3. For DSR evidence, check request type, status, actor, timestamps, operator reason, affected record summaries, retention review, legal-basis review, and explicit exclusion of credential secrets.
4. For retention evidence, check policy id and version, dry-run or execution status, outcome, notes, affected records, legal holds, and whether any deletion/anonymization was only proposed rather than performed.
5. For archive evidence, check package manifest, member checksums, ledger references, legal-hold metadata, preservation-level statements, PDF/A or ZIP metadata, and explicit limits on DGLAB or official-certification claims.
6. For signature evidence, check that technical evidence is labelled as technical evidence only and that no unsupported legal or qualified-signature conclusion is inferred.

Return a concise gap review with these sections:
- Evidence reviewed
- Missing records or identifiers
- DSR evidence gaps
- Retention and legal-hold evidence gaps
- Archive and signature evidence gaps
- Follow-up questions for the human reviewer
- Boundary reminder: guidance only, no legal validity, no hidden provider call"#
}

fn paper_book_ocr_review_prompt_text() -> &'static str {
    r#"You are helping a human operator review paper-book OCR and canonical-conversion evidence in Chancela.

Use this as review guidance only. Use only source images, OCR outputs, canonical records, manifests, and ledger evidence the operator supplies or explicitly retrieves through Chancela tools. Do not call hidden OCR, AI, legal, registry, trust, signature, archive, or storage providers. Do not claim legal validity, official certification, signing, sealing, preservation sufficiency, or that the conversion is correct without human verification.

Review checklist:
1. Identify the review scope: book id, page or folio range, source image or PDF references, OCR artifact ids, canonical record ids, manifest ids, ledger event references, and operator notes.
2. Check source-to-OCR traceability: page order, folio numbers, image checksum or digest, OCR engine/version when recorded, confidence data when recorded, timestamps, actor, and whether any page is missing, duplicated, rotated, cropped, blurred, or unreadable.
3. Compare OCR text with the source: names, dates, amounts, article numbers, signatures, stamps, handwritten notes, marginalia, tables, strike-throughs, amendments, abbreviations, and uncertain characters.
4. Check OCR-to-canonical conversion: normalized headings, sections, page anchors, canonical identifiers, extracted dates and parties, table structure, preserved uncertainty markers, and whether editorial cleanup changed meaning.
5. Separate recorded facts from reviewer assumptions, suggested corrections, and unresolved evidence gaps. Treat confidence scores as review signals only, not proof.
6. Flag any missing provenance for source capture, OCR generation, canonical conversion, manual correction, manifest checksums, or ledger anchoring before any later lifecycle, archive, signature, or sealing workflow.

Return a concise review with these sections:
- Evidence reviewed
- Source image or page issues
- OCR transcription issues
- Canonical-conversion issues
- Missing provenance, checksum, or ledger evidence
- Suggested corrections, clearly labelled as suggestions only
- Follow-up questions for the human reviewer
- Boundary reminder: guidance only, no legal validity, no signing, no hidden provider call"#
}

fn workflow_provenance_review_prompt_text() -> &'static str {
    r#"You are helping a human reviewer inspect workflow provenance evidence in Chancela.

Use this checklist as static offline review guidance only. It accepts no arguments, uses only evidence the human reviewer supplies or explicitly retrieves through Chancela tools, and makes no bridge, API, registry, signature, archive, trust, legal, or provider call. There is no hidden provider call. Do not claim legal validity, source certification, official archive status, signature qualification, provider assurance, trust-list status, or external verification.

Review checklist:
1. Act lifecycle: identify draft, review, approval, signature, sealing, archive, correction, cancellation, and re-open states with actors, timestamps, and object ids.
2. Book chain: check entity id, book id, act sequence, page or folio references, prior and next act links, and any chain gaps or reorderings.
3. Source records: list source records, filenames, checksums, capture timestamps, import actors, and source types; mark missing or ambiguous source records for human review.
4. Ledger evidence: compare ledger evidence, event ids, event types, digests, actors, timestamps, and object references against the act lifecycle and book chain.
5. Imported evidence: review paper-book imports, OCR outputs, canonical conversion records, external reports, manifests, human corrections, and checksum links.
6. Signature/archive technical evidence: review validator report ids, signature bundle ids, archive package ids, manifests, timestamps, digests, and preservation metadata as technical evidence only.
7. Operator review notes: separate recorded facts from assumptions, suggested corrections, unresolved questions, and follow-up owners.

Return a concise workflow provenance review with these sections:
- Evidence reviewed
- Act lifecycle gaps
- Book chain gaps
- Source records and imported evidence gaps
- Ledger evidence gaps
- Signature/archive technical evidence gaps
- Human review notes and follow-up questions
- Boundary reminder: human review aid only, no legal validity, no source certification, no hidden provider call"#
}

fn draft_signed_comparison_review_prompt_text() -> &'static str {
    r#"You are helping a human reviewer compare a Chancela draft with a signed artifact.

Use this checklist as static offline review guidance only. It accepts no arguments, uses only evidence the human reviewer supplies or explicitly retrieves through Chancela tools, and makes no bridge, API, registry, signature, archive, trust, legal, external-validation, or provider call. There is no hidden provider call. Do not claim legal validity, source certification, signature qualification, provider assurance, trust-list status, external validation, or that a signed artifact is correct.

Review checklist:
1. Draft identifiers: record draft act id, entity id, book id, draft version, template id, source record ids, author or generator, created timestamp, and draft digest when supplied.
2. Signed artifact identifiers: record signed document id, artifact id or URI, signature bundle id, seal id, signed version, signature event id, manifest id, and signed artifact digest when supplied.
3. Digest comparison: compare draft digest, canonical text digest, rendered artifact digest, signed artifact digest, manifest member digest, and ledger digest. Separate exact matches, expected rendering changes, missing digest evidence, and unresolved digest mismatches.
4. Text comparison: compare names, capacities, dates, amounts, article references, resolutions, tables, attachments, footnotes, annex references, and any content that could change meaning.
5. Version comparison: compare draft, approved, rendered, and signed versions with event ids, actors, timestamps, and lifecycle states.
6. Mismatch triage: classify each difference as exact match, expected formatting change, authorized content edit, unresolved mismatch, or blocking mismatch.
7. Human-review notes: record evidence references, affected fields, reviewer rationale, follow-up owner, next action, and unresolved questions.

Return a concise draft-vs-signed comparison review with these sections:
- Evidence reviewed
- Draft identifiers
- Signed artifact identifiers
- Digest comparison
- Text comparison
- Version and lifecycle comparison
- Mismatch triage
- Human review notes and follow-up questions
- Boundary reminder: human review aid only, no legal validity, no source certification, no external validation, no signature qualification, no hidden provider call"#
}

fn tool_text_result(text: &str, is_error: bool) -> Value {
    json!({ "content": [ { "type": "text", "text": text } ], "isError": is_error })
}

fn tool_error_result(text: &str) -> Value {
    tool_text_result(text, true)
}

fn tool_error_message(e: &ToolError) -> String {
    format!("invalid tool arguments: {e}")
}

fn tool_success_text(outcome: &ApiOutcome) -> String {
    if let Some(value) = &outcome.value {
        return serde_json::to_string_pretty(value).unwrap_or_else(|_| outcome.raw.clone());
    }
    if should_render_as_binary(outcome) {
        return binary_payload_text(outcome);
    }
    outcome.raw.clone()
}

#[derive(Debug, Clone, Copy)]
struct DraftSignedFieldSpec {
    category: &'static str,
    field: &'static str,
    draft_paths: &'static [&'static str],
    signed_paths: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
struct LocatedValue<'a> {
    path: &'static str,
    value: &'a Value,
}

#[derive(Debug, Clone, Copy)]
struct MeetingMetadataCandidateSpec {
    id: &'static str,
    key_names: &'static [&'static str],
}

const MEETING_METADATA_CANDIDATE_SPECS: &[MeetingMetadataCandidateSpec] = &[
    MeetingMetadataCandidateSpec {
        id: "meeting_date",
        key_names: &[
            "meeting_date",
            "meeting_day",
            "assembly_date",
            "session_date",
            "date",
        ],
    },
    MeetingMetadataCandidateSpec {
        id: "meeting_time",
        key_names: &[
            "meeting_time",
            "meeting_hour",
            "assembly_time",
            "session_time",
            "time",
            "hour",
        ],
    },
    MeetingMetadataCandidateSpec {
        id: "dispatch_date",
        key_names: &[
            "dispatch_date",
            "notice_dispatch_date",
            "convocation_dispatch_date",
            "sent_date",
            "notice_sent_date",
            "notice_date",
        ],
    },
    MeetingMetadataCandidateSpec {
        id: "channel",
        key_names: &[
            "channel",
            "meeting_channel",
            "meeting_mode",
            "attendance_channel",
            "location_type",
            "venue_type",
        ],
    },
];
const MEETING_AGENDA_ITEM_COUNT_KEYS: &[&str] = &[
    "agenda_item_count",
    "agenda_items_count",
    "agenda_count",
    "agenda_points_count",
    "order_of_business_count",
];
const MEETING_AGENDA_ARRAY_KEYS: &[&str] = &[
    "agenda",
    "agenda_items",
    "agenda_points",
    "order_of_business",
    "items",
];
const MEETING_SECOND_CALL_KEYS: &[&str] = &[
    "second_call_present",
    "second_call",
    "segunda_convocatoria",
    "second_notice",
    "second_session",
];
const MEETING_EVIDENCE_REFERENCE_KEYS: &[&str] = &[
    "evidence_reference",
    "evidence_references",
    "evidence_ref",
    "source_reference",
    "source_record_id",
    "source_record_ids",
    "ledger_event_id",
    "ledger_event_ids",
    "manifest_id",
    "digest",
    "checksum",
    "sha256",
];
const MEETING_RAW_CONTENT_KEY_MARKERS: &[&str] = &[
    "raw_document",
    "raw_text",
    "document_text",
    "full_text",
    "transcript",
    "body",
    "content",
    "content_base64",
    "bytes",
    "uploaded_bytes",
    "file_bytes",
    "payload_bytes",
];
const MEETING_CONTACT_KEY_MARKERS: &[&str] = &[
    "name",
    "full_name",
    "contact",
    "contacts",
    "email",
    "emails",
    "phone",
    "phones",
    "telephone",
    "mobile",
    "address",
];
const MEETING_SECRET_KEY_MARKERS: &[&str] = &[
    "secret",
    "access_code",
    "access_token",
    "credential",
    "credentials",
    "password",
    "passcode",
    "token",
    "api_key",
    "apikey",
    "bearer",
];
const MEETING_CHANNEL_LABELS: &[&str] = &[
    "in_person",
    "remote",
    "hybrid",
    "written",
    "other",
    "missing",
];

const DRAFT_SIGNED_FIELD_SPECS: &[DraftSignedFieldSpec] = &[
    DraftSignedFieldSpec {
        category: "identifiers",
        field: "act_id",
        draft_paths: &["act_id", "id", "draft.id", "draft_id"],
        signed_paths: &["act_id", "source_act_id", "draft_act_id", "id"],
    },
    DraftSignedFieldSpec {
        category: "identifiers",
        field: "entity_id",
        draft_paths: &["entity_id", "entity.id"],
        signed_paths: &["entity_id", "entity.id"],
    },
    DraftSignedFieldSpec {
        category: "identifiers",
        field: "book_id",
        draft_paths: &["book_id", "book.id"],
        signed_paths: &["book_id", "book.id"],
    },
    DraftSignedFieldSpec {
        category: "identifiers",
        field: "document_id",
        draft_paths: &["document_id", "rendered_document_id", "artifact_id"],
        signed_paths: &["document_id", "signed_document_id", "artifact_id"],
    },
    DraftSignedFieldSpec {
        category: "identifiers",
        field: "signature_bundle_id",
        draft_paths: &["signature_bundle_id"],
        signed_paths: &["signature_bundle_id", "signature.bundle_id"],
    },
    DraftSignedFieldSpec {
        category: "identifiers",
        field: "manifest_id",
        draft_paths: &["manifest_id", "archive_manifest_id"],
        signed_paths: &["manifest_id", "archive_manifest_id"],
    },
    DraftSignedFieldSpec {
        category: "digests",
        field: "content_digest",
        draft_paths: &[
            "content_digest",
            "payload_digest",
            "draft_digest",
            "canonical_text_digest",
        ],
        signed_paths: &[
            "content_digest",
            "payload_digest",
            "signed_content_digest",
            "canonical_text_digest",
        ],
    },
    DraftSignedFieldSpec {
        category: "digests",
        field: "document_digest",
        draft_paths: &[
            "document_digest",
            "rendered_document_digest",
            "artifact_digest",
        ],
        signed_paths: &[
            "document_digest",
            "signed_document_digest",
            "signed_pdf_digest",
            "artifact_digest",
        ],
    },
    DraftSignedFieldSpec {
        category: "digests",
        field: "manifest_digest",
        draft_paths: &["manifest_digest", "manifest_sha256"],
        signed_paths: &["manifest_digest", "manifest_sha256"],
    },
    DraftSignedFieldSpec {
        category: "lifecycle",
        field: "status",
        draft_paths: &["status", "state", "lifecycle_status"],
        signed_paths: &["status", "state", "lifecycle_status", "signature_status"],
    },
    DraftSignedFieldSpec {
        category: "lifecycle",
        field: "version",
        draft_paths: &["version", "draft_version"],
        signed_paths: &["version", "signed_version"],
    },
    DraftSignedFieldSpec {
        category: "timestamps",
        field: "created_at",
        draft_paths: &["created_at", "draft_created_at"],
        signed_paths: &["created_at", "draft_created_at"],
    },
    DraftSignedFieldSpec {
        category: "timestamps",
        field: "approved_at",
        draft_paths: &["approved_at"],
        signed_paths: &["approved_at"],
    },
    DraftSignedFieldSpec {
        category: "timestamps",
        field: "rendered_at",
        draft_paths: &["rendered_at"],
        signed_paths: &["rendered_at"],
    },
    DraftSignedFieldSpec {
        category: "timestamps",
        field: "signed_at",
        draft_paths: &["signed_at"],
        signed_paths: &["signed_at", "signing_time"],
    },
    DraftSignedFieldSpec {
        category: "artifact_references",
        field: "artifact_ref",
        draft_paths: &["artifact_ref", "artifact_uri", "document_uri", "download"],
        signed_paths: &[
            "artifact_ref",
            "artifact_uri",
            "signed_artifact_uri",
            "download",
        ],
    },
    DraftSignedFieldSpec {
        category: "provenance",
        field: "source_record_id",
        draft_paths: &["source_record_id", "source.id"],
        signed_paths: &["source_record_id", "source.id"],
    },
    DraftSignedFieldSpec {
        category: "provenance",
        field: "ledger_event_id",
        draft_paths: &["ledger_event_id", "event_id"],
        signed_paths: &["ledger_event_id", "signature_event_id", "event_id"],
    },
    DraftSignedFieldSpec {
        category: "provenance",
        field: "actor",
        draft_paths: &["actor", "created_by"],
        signed_paths: &["actor", "signed_by", "signer_id"],
    },
];

const CHRONOLOGY_EVENT_KIND_PATHS: &[&str] =
    &["kind", "type", "event_kind", "event_type", "category"];
const CHRONOLOGY_EVENT_STATUS_PATHS: &[&str] = &[
    "status",
    "state",
    "lifecycle_status",
    "review_status",
    "outcome",
];
const CHRONOLOGY_EVENT_DATE_PATHS: &[&str] = &[
    "date",
    "event_date",
    "occurred_at",
    "timestamp",
    "created_at",
    "updated_at",
    "recorded_at",
    "signed_at",
    "at",
    "time",
];
const CHRONOLOGY_EVIDENCE_PATHS: &[&str] = &[
    "evidence",
    "evidence_ref",
    "evidence_refs",
    "evidence_reference",
    "evidence_references",
    "source",
    "source.id",
    "source_record",
    "source_record_id",
    "source_record_ids",
    "source_records",
    "ledger_event_id",
    "ledger_event_ids",
    "digest",
    "checksum",
    "sha256",
    "manifest_digest",
    "artifact_uri",
    "document_uri",
];
const CHRONOLOGY_MISSING_EVIDENCE_PATHS: &[&str] = &[
    "missing_evidence",
    "missing_evidence_marker",
    "evidence_missing",
    "needs_evidence",
    "provenance_missing",
    "source_missing",
];
const WORKFLOW_EVIDENCE_RECORD_ARRAY_KEYS: &[&str] = &[
    "workflows",
    "workflow_records",
    "workflow_evidence_records",
    "workflow_evidence",
    "lifecycle_events",
    "events",
    "records",
    "items",
];
const WORKFLOW_STATE_PATHS: &[&str] = &[
    "workflow_state",
    "workflow_status",
    "workflow.state",
    "workflow.status",
    "lifecycle_state",
    "lifecycle_status",
    "lifecycle.state",
    "lifecycle.status",
    "act_lifecycle_state",
    "act_lifecycle_status",
    "state",
    "status",
    "phase",
];
const WORKFLOW_STATE_LABELS: &[&str] = &[
    "draft",
    "pending",
    "queued",
    "review",
    "under_review",
    "awaiting_review",
    "approved",
    "accepted",
    "rejected",
    "signed",
    "sealed",
    "archived",
    "corrected",
    "cancelled",
    "completed",
    "failed",
    "open",
    "closed",
    "missing",
    "unknown",
];
const WORKFLOW_HUMAN_REVIEW_PATHS: &[&str] = &[
    "human_review.decision",
    "human_review.status",
    "human_review_decision",
    "human_review_status",
    "human_verification.decision",
    "human_verification.status",
    "human_verification_decision",
    "human_verification_status",
    "operator_review.decision",
    "operator_review.status",
    "operator_review_decision",
    "operator_review_status",
    "review.decision",
    "review.status",
    "review_decision",
    "review_status",
    "reviewer_decision",
];
const WORKFLOW_LEDGER_REF_MARKERS: &[&str] = &[
    "ledger_ref",
    "ledger_refs",
    "ledger_event",
    "ledger_event_id",
    "ledger_event_ids",
    "ledger_entry",
    "ledger_anchor",
];
const WORKFLOW_ARCHIVE_REF_MARKERS: &[&str] = &[
    "archive_ref",
    "archive_refs",
    "archive_id",
    "archive_package",
    "archive_manifest",
    "manifest_id",
    "preservation_ref",
];
const WORKFLOW_SIGNATURE_REF_MARKERS: &[&str] = &[
    "signature_ref",
    "signature_refs",
    "signature_id",
    "signature_bundle",
    "signature_bundle_id",
    "signed_document_ref",
    "timestamp_token",
    "doctimestamp",
];
const WORKFLOW_DIGEST_MARKERS: &[&str] =
    &["digest", "checksum", "sha256", "sha_256", "hash", "fixity"];
const WORKFLOW_IMPORTED_GENERATED_DOCUMENT_REF_MARKERS: &[&str] = &[
    "imported_document",
    "imported_document_ref",
    "imported_document_id",
    "imported_source",
    "source_record",
    "source_record_id",
    "source_record_ids",
    "generated_document",
    "generated_document_ref",
    "generated_document_id",
    "document_ref",
    "document_refs",
    "document_id",
    "document_uri",
    "document_path",
    "canonical_document",
    "ocr_document",
];

#[derive(Debug, Clone, Copy)]
struct PrivacyFalseClaimFlagSpec {
    id: &'static str,
    field_names: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, Default)]
struct PrivacyReceiptCounts {
    receipt_count: usize,
    review_receipt_count: usize,
    drill_receipt_count: usize,
    other_receipt_count: usize,
}

impl PrivacyReceiptCounts {
    fn add(&mut self, other: Self) {
        self.receipt_count += other.receipt_count;
        self.review_receipt_count += other.review_receipt_count;
        self.drill_receipt_count += other.drill_receipt_count;
        self.other_receipt_count += other.other_receipt_count;
    }
}

#[derive(Debug, Default)]
struct RetentionCandidatePresenceCounts {
    records_with_blockers: usize,
    records_without_blockers: usize,
    blocker_count_total: usize,
    records_with_required_approvals: usize,
    records_without_required_approvals: usize,
    required_approval_count_total: usize,
    records_with_legal_hold_blockers: usize,
    records_without_legal_hold_blockers: usize,
    legal_hold_blocker_count_total: usize,
    records_with_findings: usize,
    records_without_findings: usize,
    finding_count_total: usize,
}

const PRIVACY_CONTROL_COLLECTIONS: &[&str] = &[
    "processors",
    "dpias",
    "breach_playbooks",
    "transfer_controls",
    "retention_policies",
    "retention_executions",
    "dsr_requests",
];
const PRIVACY_RETENTION_DUE_CANDIDATES_KEY: &str = "retention_due_candidates";
const PRIVACY_RETENTION_CANDIDATE_RESOLUTIONS_KEY: &str = "retention_candidate_resolutions";
const PRIVACY_RISK_PATHS: &[&str] = &[
    "risk_level",
    "risk",
    "risk.rating",
    "risk.level",
    "assessment.risk",
    "assessment.risk_level",
];
const PRIVACY_STATUS_PATHS: &[&str] = &[
    "status",
    "state",
    "lifecycle_status",
    "execution_status",
    "decision_state",
];
const PRIVACY_ADVISORY_REVIEW_STATUS_PATHS: &[&str] = &[
    "advisory_review.status",
    "advisory_review_status",
    "review.status",
    "review_status",
    "review.advisory_status",
];
const PRIVACY_RECEIPT_ARRAY_PATHS: &[&str] = &[
    "evidence_receipts",
    "review_receipts",
    "receipts",
    "review.receipts",
    "advisory_review.receipts",
];
const PRIVACY_RECEIPT_KIND_PATHS: &[&str] = &["evidence_type", "receipt_type", "type", "kind"];
const PRIVACY_RETENTION_EXECUTION_STATUS_PATHS: &[&str] =
    &["execution_status", "status", "workflow.status"];
const PRIVACY_RETENTION_EXECUTION_OUTCOME_PATHS: &[&str] =
    &["outcome", "execution_outcome", "result.outcome"];
const PRIVACY_RETENTION_EVIDENCE_STATE_PATHS: &[&str] = &[
    "evidence_state",
    "candidate_evidence_state",
    "prior_execution.evidence_state",
];
const PRIVACY_RETENTION_DUE_CANDIDATE_STATUS_PATHS: &[&str] =
    &["status", "state", "execution_status"];
const PRIVACY_RETENTION_DUE_CANDIDATE_OUTCOME_PATHS: &[&str] =
    &["outcome", "execution_outcome", "prior_execution.outcome"];
const PRIVACY_RETENTION_CANDIDATE_RESOLUTION_DISPOSITION_PATHS: &[&str] =
    &["disposition", "resolution_disposition"];
const PRIVACY_DSR_TYPE_PATHS: &[&str] = &["request_type", "type", "dsr_type"];
const PRIVACY_DSR_STATUS_PATHS: &[&str] = &["status", "state"];
const PRIVACY_DSR_OUTCOME_PATHS: &[&str] = &["outcome", "execution_outcome"];

const PRIVACY_RISK_LABELS: &[&str] = &[
    "low", "medium", "high", "critical", "severe", "none", "missing", "unknown",
];
const PRIVACY_STATUS_LABELS: &[&str] = &[
    "draft",
    "active",
    "under_review",
    "retired",
    "pending",
    "completed",
    "awaiting_review",
    "blocked",
    "executed",
    "open",
    "review_closed",
    "current",
    "due_soon",
    "overdue",
    "no_receipt",
    "missing",
    "unknown",
];
const PRIVACY_ADVISORY_STATUS_LABELS: &[&str] = &[
    "no_receipt",
    "current",
    "due_soon",
    "overdue",
    "under_review",
    "missing",
    "unknown",
];
const PRIVACY_RECEIPT_KIND_LABELS: &[&str] = &["review", "drill", "missing", "unknown"];
const PRIVACY_RETENTION_EXECUTION_STATUS_LABELS: &[&str] = &[
    "awaiting_review",
    "blocked",
    "executed",
    "missing",
    "unknown",
];
const PRIVACY_RETENTION_EXECUTION_OUTCOME_LABELS: &[&str] = &[
    "blocked_missing_policy",
    "blocked_stale_policy",
    "blocked_policy_mismatch",
    "blocked_legal_hold",
    "blocked_destructive_action",
    "blocked_approval_mismatch",
    "blocked_missing_target",
    "manual_review_required",
    "bounded_archive_recorded",
    "bounded_no_action_recorded",
    "already_executed",
    "missing",
    "unknown",
];
const PRIVACY_RETENTION_EVIDENCE_STATE_LABELS: &[&str] = &[
    "review_queued",
    "blocked",
    "bounded_archive_recorded",
    "bounded_no_action_recorded",
    "prior_bounded_evidence_available",
    "missing",
    "unknown",
];
const PRIVACY_RETENTION_DUE_CANDIDATE_STATUS_LABELS: &[&str] = &[
    "awaiting_review",
    "blocked",
    "executed",
    "open",
    "review_closed",
    "missing",
    "unknown",
];
const PRIVACY_RETENTION_DUE_CANDIDATE_OUTCOME_LABELS: &[&str] = &[
    "blocked_missing_policy",
    "blocked_stale_policy",
    "blocked_policy_mismatch",
    "blocked_legal_hold",
    "blocked_destructive_action",
    "blocked_approval_mismatch",
    "blocked_missing_target",
    "blocked_unsupported_period",
    "manual_review_required",
    "bounded_archive_recorded",
    "bounded_no_action_recorded",
    "already_executed",
    "missing",
    "unknown",
];
const PRIVACY_RETENTION_CANDIDATE_RESOLUTION_DISPOSITION_LABELS: &[&str] = &[
    "evidence_acknowledged",
    "follow_up_required",
    "blocked_follow_up",
    "missing",
    "unknown",
];
const PRIVACY_DSR_TYPE_LABELS: &[&str] = &[
    "export",
    "rectification",
    "erasure",
    "restriction",
    "missing",
    "unknown",
];
const PRIVACY_DSR_STATUS_LABELS: &[&str] = &["pending", "completed", "missing", "unknown"];
const PRIVACY_DSR_OUTCOME_LABELS: &[&str] = &[
    "fulfilled",
    "partially_fulfilled",
    "rejected",
    "no_action_required",
    "missing",
    "unknown",
];

const PRIVACY_FALSE_CLAIM_FLAG_SPECS: &[PrivacyFalseClaimFlagSpec] = &[
    PrivacyFalseClaimFlagSpec {
        id: "legal_approval",
        field_names: &[
            "legal_approval",
            "legal_approval_claimed",
            "legal_review_accepted",
            "legal_acceptance_claimed",
            "legal_disposal_approved",
        ],
    },
    PrivacyFalseClaimFlagSpec {
        id: "legal_completion",
        field_names: &[
            "legal_completion",
            "legal_completion_claimed",
            "legal_certification_completed",
            "legal_certification_claimed",
            "legal_disposal_completed",
        ],
    },
    PrivacyFalseClaimFlagSpec {
        id: "authority_notification",
        field_names: &[
            "authority_notified",
            "authority_notification",
            "authority_notification_claimed",
            "authority_notification_completed",
        ],
    },
    PrivacyFalseClaimFlagSpec {
        id: "data_subject_notification",
        field_names: &[
            "subjects_notified",
            "subject_notification_claimed",
            "data_subject_notification",
            "data_subject_notification_claimed",
            "data_subjects_notified",
        ],
    },
    PrivacyFalseClaimFlagSpec {
        id: "transfer_approval",
        field_names: &["transfer_approved", "transfer_approval_claimed"],
    },
    PrivacyFalseClaimFlagSpec {
        id: "transfer_execution",
        field_names: &[
            "data_transfer_executed",
            "transfer_executed",
            "transfer_execution_claimed",
        ],
    },
    PrivacyFalseClaimFlagSpec {
        id: "dpia_authority_filing",
        field_names: &[
            "authority_filing_completed",
            "authority_filing_claimed",
            "dpia_authority_filing",
            "dpia_authority_filing_claimed",
        ],
    },
    PrivacyFalseClaimFlagSpec {
        id: "dpia_completion",
        field_names: &[
            "dpia_completed",
            "dpia_completion",
            "dpia_completion_claimed",
            "completion_claimed",
        ],
    },
    PrivacyFalseClaimFlagSpec {
        id: "compliance_certification",
        field_names: &[
            "compliance_certification_completed",
            "compliance_certification_claimed",
        ],
    },
    PrivacyFalseClaimFlagSpec {
        id: "privacy_compliance_completion",
        field_names: &[
            "privacy_compliance_completed",
            "privacy_compliance_completion_claimed",
        ],
    },
    PrivacyFalseClaimFlagSpec {
        id: "gdpr_compliance_completion",
        field_names: &[
            "gdpr_compliance_completed",
            "gdpr_compliance_completion_claimed",
        ],
    },
    PrivacyFalseClaimFlagSpec {
        id: "destructive_disposal",
        field_names: &[
            "destructive_disposal_completed",
            "destructive_disposal_claimed",
            "disposal_completed",
        ],
    },
    PrivacyFalseClaimFlagSpec {
        id: "deletion_completion",
        field_names: &[
            "deletion_completed",
            "delete_completed",
            "data_deleted",
            "deletion_claimed",
        ],
    },
    PrivacyFalseClaimFlagSpec {
        id: "anonymization_completion",
        field_names: &[
            "anonymization_completed",
            "anonymize_completed",
            "anonymization_claimed",
        ],
    },
    PrivacyFalseClaimFlagSpec {
        id: "redaction_completion",
        field_names: &[
            "redaction_completed",
            "redacted_completed",
            "redaction_claimed",
        ],
    },
    PrivacyFalseClaimFlagSpec {
        id: "full_erasure",
        field_names: &[
            "full_erasure_completed",
            "full_erasure_claimed",
            "destructive_mutation_completed",
        ],
    },
    PrivacyFalseClaimFlagSpec {
        id: "erasure_completion",
        field_names: &["erasure_completed", "erasure_completion_claimed"],
    },
    PrivacyFalseClaimFlagSpec {
        id: "legal_hold_mutation",
        field_names: &[
            "legal_hold_mutated",
            "legal_hold_resolved",
            "legal_hold_mutation_claimed",
        ],
    },
    PrivacyFalseClaimFlagSpec {
        id: "retention_policy_mutation",
        field_names: &[
            "retention_policy_mutated",
            "retention_policy_changed",
            "retention_policy_mutation_claimed",
        ],
    },
];

#[derive(Debug, Clone, Copy)]
struct DocumentArchiveNoClaimFlagSpec {
    id: &'static str,
    field_names: &'static [&'static str],
}

#[derive(Debug, Default)]
struct DocumentArchivePathCounts {
    path_value_count: usize,
    archive_evidence_path_count: usize,
    evidence_index_path_count: usize,
    pdf_accessibility_path_count: usize,
    external_validator_path_count: usize,
    canonical_pdf_path_count: usize,
    signed_pdf_path_count: usize,
    evidence_index_object_present: bool,
}

#[derive(Debug, Default)]
struct DocumentArchiveFixityCounts {
    digest_field_count: usize,
    sha256_field_count: usize,
    checksum_field_count: usize,
    fixity_section_count: usize,
}

#[derive(Debug, Default)]
struct DocumentArchiveSignedDocumentSummary {
    present: bool,
    status: String,
    signed_pdf_digest_present: bool,
    signature_metadata_present: bool,
    timestamp_token_present: bool,
}

#[derive(Debug, Default)]
struct DocumentArchiveExternalValidatorSummary {
    sections_present: usize,
    attachment_count: usize,
    status_counts: BTreeMap<String, usize>,
    raw_report_reference_count: usize,
    raw_payload_field_count: usize,
}

#[derive(Debug, Default)]
struct DocumentArchivePdfAccessibilitySummary {
    evidence_section_count: usize,
    report_version_counts: BTreeMap<String, usize>,
    v12_report_count: usize,
    blocker_counts: BTreeMap<String, usize>,
    blocker_total: usize,
    table_semantics_object_count: usize,
    row_header_cell_count_total: usize,
    column_header_cell_count_total: usize,
    table_rows_missing_header_count_total: usize,
    row_header_scope_true_count: usize,
    column_header_scope_true_count: usize,
}

const DOCUMENT_ARCHIVE_VALIDATION_STATUS_PATHS: &[&str] = &[
    "document_bundle.validation_report.status",
    "archive_package.validation_report.status",
    "validation_report.status",
    "validation.status",
    "report.status",
    "status",
    "evidence_status",
];
const DOCUMENT_ARCHIVE_SIGNED_STATUS_PATHS: &[&str] = &[
    "document_bundle.validation_report.signed_document.status",
    "archive_package.signed_document.status",
    "validation_report.signed_document.status",
    "signed_document.status",
    "signed.status",
    "signature.status",
    "signature_status",
    "status",
];
const DOCUMENT_ARCHIVE_EXTERNAL_VALIDATOR_STATUS_PATHS: &[&str] = &[
    "attachment_status",
    "bundle_attachment_status",
    "evidence_status",
    "status",
    "raw_report.preservation_status",
    "raw_report.status",
];
const DOCUMENT_ARCHIVE_VALIDATION_REPORT_PATHS: &[&str] = &[
    "document_bundle.validation_report",
    "archive_package.validation_report",
    "validation_report",
    "validation.report",
    "report",
];
const DOCUMENT_ARCHIVE_VALIDATION_REPORT_MARKER_PATHS: &[&str] = &[
    "document_bundle.validation_report.report_kind",
    "archive_package.validation_report.report_kind",
    "validation_report.report_kind",
    "validation.report.report_kind",
    "report.report_kind",
    "report_kind",
];
const DOCUMENT_ARCHIVE_STATUS_LABELS: &[&str] = &[
    "technical_ok",
    "technical_warning",
    "technical_error",
    "technical",
    "present",
    "attached",
    "signed",
    "unsigned",
    "not_present",
    "not_available",
    "not_attempted",
    "missing",
    "blocked",
    "failed",
    "error",
    "warning",
    "warnings",
    "valid",
    "invalid",
    "passed",
    "pass",
    "ok",
    "partial",
    "unknown",
    "pdf_accessibility_report_attached",
    "pdf_accessibility_report_unavailable",
    "pdf_accessibility_evidence_attached",
    "pdf_accessibility_evidence_unavailable",
    "pdf_accessibility_evidence_partially_available",
    "external_validator_report_metadata_attached",
    "no_external_validator_report_metadata_attached",
    "raw_report_manifest_only",
    "raw_report_attached",
];
const DOCUMENT_ARCHIVE_PDF_UA_BLOCKER_LABELS: &[&str] = &[
    "missing_struct_tree_root",
    "content_is_not_tagged",
    "missing_role_map",
    "role_map_incomplete",
    "heading_hierarchy_skips_levels",
    "unsupported_heading_level",
    "key_value_tables_not_tagged_as_tables",
    "vote_tables_not_tagged_as_tables",
    "vote_table_headers_not_tagged",
    "no_alt_text_model",
    "non_text_content_not_accounted_for",
    "layout_artifacts_not_marked",
    "limited_tagged_structure",
];
const DOCUMENT_ARCHIVE_NO_CLAIM_FLAG_SPECS: &[DocumentArchiveNoClaimFlagSpec] = &[
    DocumentArchiveNoClaimFlagSpec {
        id: "pdf_ua_conformance",
        field_names: &[
            "pdf_ua_claimed",
            "pdfua_claimed",
            "pdf_ua_conformance_claimed",
            "pdfua_conformance_claimed",
            "pdf_ua_certification_claimed",
        ],
    },
    DocumentArchiveNoClaimFlagSpec {
        id: "dglab_certification",
        field_names: &[
            "dglab_certification_claimed",
            "dglab_acceptance_claimed",
            "official_dglab_acceptance_claimed",
        ],
    },
    DocumentArchiveNoClaimFlagSpec {
        id: "legal_validity",
        field_names: &[
            "legal_validity_claimed",
            "legal_effect_claimed",
            "legal_acceptance_claimed",
            "legal_sufficiency_claimed",
        ],
    },
    DocumentArchiveNoClaimFlagSpec {
        id: "signature_validity",
        field_names: &[
            "signature_validity_claimed",
            "signature_valid_claimed",
            "qualified_signature_claimed",
            "signature_qualification_claimed",
        ],
    },
    DocumentArchiveNoClaimFlagSpec {
        id: "archive_certification",
        field_names: &[
            "archive_certification_claimed",
            "legal_archive_certification_claimed",
            "archive_certified",
        ],
    },
    DocumentArchiveNoClaimFlagSpec {
        id: "provider_validation",
        field_names: &[
            "provider_validation_claimed",
            "provider_validated",
            "trust_provider_validation_performed",
            "live_provider_validation_performed",
        ],
    },
    DocumentArchiveNoClaimFlagSpec {
        id: "external_validator_success",
        field_names: &[
            "external_validation_claimed",
            "external_validator_success_claimed",
            "external_validator_success",
            "external_certification_claimed",
        ],
    },
    DocumentArchiveNoClaimFlagSpec {
        id: "legal_review",
        field_names: &[
            "legal_review_completed",
            "legal_review_claimed",
            "legal_review_accepted",
        ],
    },
];

fn workflow_provenance_review_report_payload(arguments: &Value) -> Result<Value, String> {
    let args = arguments
        .as_object()
        .ok_or_else(|| "arguments must be an object".to_string())?;
    if args.keys().any(|key| key != "workflow_evidence") {
        return Err(
            "workflow provenance review arguments accept only workflow_evidence".to_string(),
        );
    }
    let workflow_evidence = args
        .get("workflow_evidence")
        .ok_or_else(|| "workflow_evidence must be supplied".to_string())?;
    let (evidence, input_format) = workflow_evidence_value(workflow_evidence)?;
    let records = workflow_evidence_records(&evidence);
    let state_counts = workflow_state_counts(&evidence, records.as_slice());
    let human_review_counts = workflow_human_review_decision_counts(&evidence, records.as_slice());
    let missing_human_review_decision_count =
        human_review_counts.get("missing").copied().unwrap_or(0);
    let evidence_marker_counts = workflow_evidence_marker_counts(&evidence);
    let warning_counts = workflow_warning_marker_counts(&evidence);

    Ok(json!({
        "kind": "chancela_mcp_workflow_provenance_review_report",
        "schema_version": 1,
        "source": "local_mcp_deterministic_workflow_provenance_reviewer",
        "offline": true,
        "local_json_only": true,
        "local_json_or_text_only": true,
        "deterministic": true,
        "aggregate_counts_only": true,
        "human_verification_required": true,
        "bridge_calls": false,
        "api_calls": false,
        "provider_calls": false,
        "ai_provider_calls": false,
        "legal_service_calls": false,
        "http_sse_transport_added": false,
        "raw_document_text_echoed": false,
        "raw_uploaded_bytes_echoed": false,
        "contacts_echoed": false,
        "credentials_secrets_access_codes_echoed": false,
        "secrets_in_resource": false,
        "legal_validity_claimed": false,
        "source_certification_claimed": false,
        "workflow_completion_claimed": false,
        "provider_assurance_claimed": false,
        "trust_claimed": false,
        "external_validation_claimed": false,
        "signature_qualification_claimed": false,
        "extraction_accuracy_claimed": false,
        "claims": {
            "legal_validity": false,
            "source_certification": false,
            "workflow_completion": false,
            "provider_assurance": false,
            "provider": false,
            "trust": false,
            "external_validation": false,
            "signature_qualification": false,
            "extraction_accuracy": false,
            "archive_certification": false
        },
        "workflow_provenance_summary": {
            "input_format": input_format,
            "record_count": records.len(),
            "workflow_lifecycle_state_counts": state_counts,
            "human_review_decision_status_counts": human_review_counts,
            "missing_human_review_decision_count": missing_human_review_decision_count,
            "evidence_marker_counts": evidence_marker_counts,
            "warning_counts": warning_counts,
            "raw_values_echoed": false
        },
        "recognized_fields": {
            "record_arrays": WORKFLOW_EVIDENCE_RECORD_ARRAY_KEYS,
            "workflow_lifecycle_state": WORKFLOW_STATE_PATHS,
            "human_review_decision_status": WORKFLOW_HUMAN_REVIEW_PATHS,
            "ledger_refs": WORKFLOW_LEDGER_REF_MARKERS,
            "archive_refs": WORKFLOW_ARCHIVE_REF_MARKERS,
            "signature_refs": WORKFLOW_SIGNATURE_REF_MARKERS,
            "digest_markers": WORKFLOW_DIGEST_MARKERS,
            "imported_generated_document_refs": WORKFLOW_IMPORTED_GENERATED_DOCUMENT_REF_MARKERS
        },
        "workflow_provenance_review_caveats": [
            "This is a deterministic local aggregate report over caller-supplied workflow_evidence JSON or text only.",
            "Caller-supplied values, document text, contacts, credentials, secrets, access codes, and uploaded bytes are not echoed.",
            "Unrecognized workflow, lifecycle, and human-review labels are counted as other instead of being echoed.",
            "Evidence marker counts only indicate field-marker presence; they do not validate ledger, archive, signature, digest, imported-document, generated-document, or source-record authenticity."
        ],
        "operator_boundaries": [
            "No bridge, API, AI-provider, legal-service, HTTP/SSE, registry, trust, archive, signature, extraction, or provider calls were made.",
            "No legal validity, source certification, workflow completion, provider assurance, trust status, external validation, signature qualification, or extraction accuracy is claimed.",
            "Human review and normal platform evidence checks remain required."
        ]
    }))
}

fn workflow_evidence_value(value: &Value) -> Result<(Value, &'static str), String> {
    match value {
        Value::Object(_) => Ok((value.clone(), "json_object")),
        Value::Array(_) => Ok((value.clone(), "json_array")),
        Value::String(text) => match serde_json::from_str::<Value>(text) {
            Ok(parsed) if parsed.is_object() => Ok((parsed, "json_string_object")),
            Ok(parsed) if parsed.is_array() => Ok((parsed, "json_string_array")),
            Ok(_) => {
                Err("workflow_evidence JSON text must decode to an object or array".to_string())
            }
            Err(_) => Ok((Value::String(text.clone()), "text_metadata")),
        },
        _ => Err("workflow_evidence must be a JSON object, array, or text string".to_string()),
    }
}

fn workflow_evidence_records(evidence: &Value) -> Vec<&Value> {
    let mut records = Vec::new();
    match evidence {
        Value::Array(values) => {
            records.extend(values.iter().filter(|value| value.is_object()));
        }
        Value::Object(_) => {
            collect_workflow_evidence_records(evidence, &mut records);
            if records.is_empty() {
                records.push(evidence);
            }
        }
        _ => {}
    }
    records
}

fn collect_workflow_evidence_records<'a>(value: &'a Value, records: &mut Vec<&'a Value>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let normalized = normalize_chronology_label(key);
                if WORKFLOW_EVIDENCE_RECORD_ARRAY_KEYS.contains(&normalized.as_str())
                    && let Value::Array(values) = child
                {
                    records.extend(values.iter().filter(|value| value.is_object()));
                    continue;
                }
                collect_workflow_evidence_records(child, records);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_workflow_evidence_records(child, records);
            }
        }
        _ => {}
    }
}

fn workflow_state_counts(evidence: &Value, records: &[&Value]) -> BTreeMap<String, usize> {
    let mut counts = initialized_workflow_state_counts();
    if records.is_empty() {
        if let Value::String(text) = evidence {
            count_workflow_text_labels(text, WORKFLOW_STATE_LABELS, &mut counts);
        }
        return counts;
    }

    for record in records {
        let state = privacy_bounded_classification(
            first_located_value(record, WORKFLOW_STATE_PATHS),
            "missing",
            WORKFLOW_STATE_LABELS,
        );
        increment_count(&mut counts, state);
    }
    counts
}

fn initialized_workflow_state_counts() -> BTreeMap<String, usize> {
    WORKFLOW_STATE_LABELS
        .iter()
        .chain(["other"].iter())
        .map(|label| ((*label).to_string(), 0usize))
        .collect()
}

fn workflow_human_review_decision_counts(
    evidence: &Value,
    records: &[&Value],
) -> BTreeMap<String, usize> {
    let mut counts = initialized_human_review_decision_counts();
    if records.is_empty() {
        if let Value::String(text) = evidence {
            let normalized = normalize_chronology_label(text);
            for label in ["pending", "accepted", "rejected"] {
                if normalized.contains(label) {
                    increment_count(&mut counts, label.to_string());
                }
            }
        }
        return counts;
    }

    for record in records {
        let bucket = workflow_human_review_decision_bucket(first_located_value(
            record,
            WORKFLOW_HUMAN_REVIEW_PATHS,
        ));
        increment_count(&mut counts, bucket.to_string());
    }
    counts
}

fn initialized_human_review_decision_counts() -> BTreeMap<String, usize> {
    ["pending", "accepted", "rejected", "missing", "other"]
        .into_iter()
        .map(|label| (label.to_string(), 0usize))
        .collect()
}

fn workflow_human_review_decision_bucket(value: Option<LocatedValue<'_>>) -> &'static str {
    let Some(located) = value else {
        return "missing";
    };
    if is_unknown_comparison_value(located.value) {
        return "missing";
    }
    let normalized = match located.value {
        Value::String(value) => normalize_chronology_label(value),
        Value::Bool(true) => return "accepted",
        Value::Bool(false) => return "rejected",
        Value::Number(_) | Value::Array(_) | Value::Object(_) => return "other",
        Value::Null => return "missing",
    };
    match normalized.as_str() {
        "pending"
        | "pending_human_verification"
        | "awaiting_review"
        | "under_review"
        | "needs_review"
        | "review_required"
        | "queued"
        | "open" => "pending",
        "accepted" | "accepted_by_human" | "approved" | "verified" | "verified_by_human"
        | "completed" | "passed" => "accepted",
        "rejected" | "rejected_by_human" | "denied" | "declined" | "failed" => "rejected",
        "missing" | "unknown" | "not_available" | "n/a" => "missing",
        _ => "other",
    }
}

fn workflow_evidence_marker_counts(evidence: &Value) -> Value {
    json!({
        "ledger_refs": meeting_marker_key_count(evidence, WORKFLOW_LEDGER_REF_MARKERS),
        "archive_refs": meeting_marker_key_count(evidence, WORKFLOW_ARCHIVE_REF_MARKERS),
        "signature_refs": meeting_marker_key_count(evidence, WORKFLOW_SIGNATURE_REF_MARKERS),
        "digest_markers": meeting_marker_key_count(evidence, WORKFLOW_DIGEST_MARKERS),
        "imported_generated_document_refs": meeting_marker_key_count(
            evidence,
            WORKFLOW_IMPORTED_GENERATED_DOCUMENT_REF_MARKERS
        ),
        "values_echoed": false
    })
}

fn workflow_warning_marker_counts(evidence: &Value) -> Value {
    json!({
        "raw_content_field_count": meeting_marker_key_count(evidence, MEETING_RAW_CONTENT_KEY_MARKERS),
        "contact_field_count": meeting_marker_key_count(evidence, MEETING_CONTACT_KEY_MARKERS),
        "secret_like_field_count": meeting_marker_key_count(evidence, MEETING_SECRET_KEY_MARKERS),
        "raw_values_echoed": false
    })
}

fn count_workflow_text_labels(text: &str, labels: &[&str], counts: &mut BTreeMap<String, usize>) {
    let normalized = normalize_chronology_label(text);
    for label in labels {
        if normalized.contains(label) {
            increment_count(counts, (*label).to_string());
        }
    }
}

fn meeting_metadata_extraction_review_report_payload(arguments: &Value) -> Result<Value, String> {
    let args = arguments
        .as_object()
        .ok_or_else(|| "arguments must be an object".to_string())?;
    if args.keys().any(|key| key != "meeting_document") {
        return Err(
            "meeting metadata extraction arguments accept only meeting_document".to_string(),
        );
    }
    let meeting_document = args
        .get("meeting_document")
        .ok_or_else(|| "meeting_document must be supplied".to_string())?;
    let (metadata, input_format) = meeting_document_metadata_value(meeting_document)?;

    let mut candidate_fields = BTreeMap::new();
    for spec in MEETING_METADATA_CANDIDATE_SPECS {
        let count = meeting_metadata_key_count(&metadata, spec.key_names);
        candidate_fields.insert(
            spec.id.to_string(),
            json!({
                "present": count > 0,
                "candidate_count": count,
                "ambiguous": count > 1,
                "values_echoed": false
            }),
        );
    }

    let agenda_summary = meeting_agenda_item_count_summary(&metadata);
    let second_call_counts =
        meeting_boolean_marker_counts(&metadata, MEETING_SECOND_CALL_KEYS, "second_call");
    let evidence_reference_count =
        meeting_metadata_key_count(&metadata, MEETING_EVIDENCE_REFERENCE_KEYS);
    let channel_counts = meeting_channel_classification_counts(&metadata);
    let raw_content_marker_count =
        meeting_marker_key_count(&metadata, MEETING_RAW_CONTENT_KEY_MARKERS);
    let contact_marker_count = meeting_marker_key_count(&metadata, MEETING_CONTACT_KEY_MARKERS);
    let secret_marker_count = meeting_marker_key_count(&metadata, MEETING_SECRET_KEY_MARKERS);

    let mut blockers = BTreeSet::new();
    let mut warnings = BTreeSet::new();
    for required in ["meeting_date", "dispatch_date"] {
        let present = candidate_fields
            .get(required)
            .and_then(|field| field.get("present"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let ambiguous = candidate_fields
            .get(required)
            .and_then(|field| field.get("ambiguous"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !present {
            blockers.insert(format!("{required}_missing"));
        }
        if ambiguous {
            warnings.insert(format!("{required}_ambiguous"));
        }
    }
    for advisory in ["meeting_time", "channel"] {
        let present = candidate_fields
            .get(advisory)
            .and_then(|field| field.get("present"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let ambiguous = candidate_fields
            .get(advisory)
            .and_then(|field| field.get("ambiguous"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !present {
            warnings.insert(format!("{advisory}_missing"));
        }
        if ambiguous {
            warnings.insert(format!("{advisory}_ambiguous"));
        }
    }
    if agenda_summary
        .get("agenda_item_count_present")
        .and_then(Value::as_bool)
        != Some(true)
    {
        blockers.insert("agenda_item_count_missing".to_string());
    }
    if agenda_summary
        .get("ambiguous")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        warnings.insert("agenda_item_count_ambiguous".to_string());
    }
    if evidence_reference_count == 0 {
        blockers.insert("evidence_reference_missing".to_string());
    }
    if second_call_counts
        .get("observation_count")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        == 0
    {
        warnings.insert("second_call_present_missing".to_string());
    }
    if raw_content_marker_count > 0 {
        warnings.insert("raw_content_marker_supplied_not_echoed".to_string());
    }
    if contact_marker_count > 0 {
        warnings.insert("name_contact_email_or_phone_marker_supplied_not_echoed".to_string());
    }
    if secret_marker_count > 0 {
        warnings.insert("secret_access_code_or_credential_marker_supplied_not_echoed".to_string());
    }

    Ok(json!({
        "kind": "chancela_mcp_meeting_metadata_extraction_review_report",
        "schema_version": 1,
        "source": "local_mcp_deterministic_meeting_metadata_reviewer",
        "offline": true,
        "local_json_or_text_metadata_only": true,
        "deterministic": true,
        "aggregate_counts_only": true,
        "human_verification_required": true,
        "ai_provider_called": false,
        "api_called": false,
        "legal_validity_claimed": false,
        "source_certification_claimed": false,
        "workflow_completion_claimed": false,
        "bridge_calls": false,
        "api_calls": false,
        "provider_calls": false,
        "ai_provider_calls": false,
        "legal_service_calls": false,
        "http_sse_transport_added": false,
        "raw_document_text_echoed": false,
        "raw_document_bytes_echoed": false,
        "names_contacts_emails_phones_echoed": false,
        "secrets_access_codes_credentials_echoed": false,
        "secrets_in_resource": false,
        "claims": {
            "legal_validity": false,
            "source_certification": false,
            "workflow_completion": false,
            "ai_completion": false,
            "provider": false,
            "trust": false,
            "external_validation": false,
            "archive_certification": false,
            "signature_qualification": false
        },
        "meeting_metadata_summary": {
            "input_format": input_format,
            "candidate_fields": candidate_fields,
            "agenda_item_count": agenda_summary,
            "second_call_present": second_call_counts,
            "evidence_reference_present": {
                "present": evidence_reference_count > 0,
                "candidate_count": evidence_reference_count,
                "values_echoed": false
            },
            "channel_classification_counts": channel_counts,
            "safety_marker_counts": {
                "raw_content_marker_count": raw_content_marker_count,
                "name_contact_email_phone_marker_count": contact_marker_count,
                "secret_access_code_credential_marker_count": secret_marker_count,
                "raw_values_echoed": false
            }
        },
        "blocking_review_findings": blockers.into_iter().collect::<Vec<_>>(),
        "review_warnings": warnings.into_iter().collect::<Vec<_>>(),
        "recognized_fields": {
            "meeting_date": MEETING_METADATA_CANDIDATE_SPECS[0].key_names,
            "meeting_time": MEETING_METADATA_CANDIDATE_SPECS[1].key_names,
            "dispatch_date": MEETING_METADATA_CANDIDATE_SPECS[2].key_names,
            "channel": MEETING_METADATA_CANDIDATE_SPECS[3].key_names,
            "agenda_item_count": MEETING_AGENDA_ITEM_COUNT_KEYS,
            "agenda_item_arrays": MEETING_AGENDA_ARRAY_KEYS,
            "second_call_present": MEETING_SECOND_CALL_KEYS,
            "evidence_reference_present": MEETING_EVIDENCE_REFERENCE_KEYS
        },
        "meeting_metadata_review_caveats": [
            "This is a deterministic local aggregate report over caller-supplied JSON or text metadata only.",
            "Recognized metadata values are not echoed; date, time, channel, agenda, second-call, and evidence observations are represented as counts or bounded buckets.",
            "Missing and ambiguous metadata remains a blocker or warning for human review, not inferred truth.",
            "Raw document text, names, contacts, emails, phone numbers, secrets, access codes, credentials, and uploaded bytes are not echoed.",
            "Counts do not validate notice sufficiency, quorum, agenda authority, legal validity, source certification, workflow completion, or provider assurance."
        ],
        "operator_boundaries": [
            "No bridge, API, AI-provider, legal-service, HTTP/SSE, registry, trust, archive, signature, or provider calls were made.",
            "No legal validity, source certification, workflow completion, provider assurance, or trust status is claimed.",
            "Human verification and normal platform evidence checks remain required."
        ]
    }))
}

fn document_archive_review_summary_report_payload(arguments: &Value) -> Result<Value, String> {
    let args = arguments
        .as_object()
        .ok_or_else(|| "arguments must be an object".to_string())?;
    let document_archive = args
        .get("document_archive")
        .ok_or_else(|| "document_archive must be supplied".to_string())?;
    if !document_archive.is_object() {
        return Err("document_archive must be an object".to_string());
    }
    let validation_report_present = document_archive_report_present(document_archive);
    let validation_status = document_archive_bounded_label_at_paths(
        document_archive,
        DOCUMENT_ARCHIVE_VALIDATION_STATUS_PATHS,
        "missing",
    );
    let raw_report_field_count = count_raw_report_fields(document_archive);
    let raw_payload_field_count = count_raw_payload_fields(document_archive);
    let path_counts = document_archive_path_counts(document_archive);
    let fixity_counts = document_archive_fixity_counts(document_archive);
    let signed_document_summary = document_archive_signed_document_summary(document_archive);
    let external_validator_summary = document_archive_external_validator_summary(document_archive);
    let pdf_accessibility_summary = document_archive_pdf_accessibility_summary(document_archive);
    let no_claim_counts = document_archive_no_claim_flag_counts(document_archive);

    let missing_no_claim_flags = no_claim_counts
        .iter()
        .filter_map(|(flag, counts)| {
            (counts.get("explicit_false").copied().unwrap_or(0) == 0).then_some(flag.clone())
        })
        .collect::<Vec<_>>();
    let truthy_no_claim_flag_total = no_claim_counts
        .values()
        .map(|counts| counts.get("truthy").copied().unwrap_or(0))
        .sum::<usize>();

    let mut missing_evidence_blockers = BTreeSet::new();
    if !validation_report_present {
        missing_evidence_blockers.insert("validation_report_missing");
    }
    if !fixity_counts.digest_present() {
        missing_evidence_blockers.insert("digest_or_fixity_missing");
    }
    if !signed_document_summary.present {
        missing_evidence_blockers.insert("signed_document_metadata_missing");
    } else if !signed_document_summary.signed_pdf_digest_present {
        missing_evidence_blockers.insert("signed_pdf_digest_missing");
    }
    if external_validator_summary.sections_present == 0 {
        missing_evidence_blockers.insert("external_validator_summary_missing");
    } else if external_validator_summary.attachment_count == 0 {
        missing_evidence_blockers.insert("external_validator_attachments_missing");
    }
    if !pdf_accessibility_summary.evidence_present() {
        missing_evidence_blockers.insert("pdf_accessibility_evidence_missing");
    }
    if pdf_accessibility_summary.v12_report_count == 0 {
        missing_evidence_blockers.insert("pdf_accessibility_v12_report_missing");
    }
    if !path_counts.evidence_index_present() {
        missing_evidence_blockers.insert("archive_evidence_index_missing");
    }
    if !missing_no_claim_flags.is_empty() {
        missing_evidence_blockers.insert("explicit_no_claim_flags_missing");
    }
    if truthy_no_claim_flag_total > 0 {
        missing_evidence_blockers.insert("truthy_no_claim_flags_present");
    }

    Ok(json!({
        "kind": "chancela_mcp_document_archive_review_summary_report",
        "schema_version": 1,
        "source": "local_mcp_deterministic_document_archive_summarizer",
        "offline": true,
        "local_json_only": true,
        "deterministic": true,
        "aggregate_counts_only": true,
        "bridge_calls": false,
        "api_calls": false,
        "provider_calls": false,
        "ai_provider_calls": false,
        "legal_service_calls": false,
        "http_sse_transport_added": false,
        "raw_reports_exposed": false,
        "raw_document_bytes_exposed": false,
        "raw_report_bytes_echoed": false,
        "digest_values_echoed": false,
        "path_values_echoed": false,
        "secrets_in_resource": false,
        "claims": {
            "pdf_ua_conformance": false,
            "dglab_certification": false,
            "legal_validity": false,
            "signature_validity": false,
            "qualified_signature": false,
            "archive_certification": false,
            "provider_validation": false,
            "external_validator_success": false,
            "trust_validation": false,
            "legal_review": false
        },
        "validation_summary": {
            "validation_report_present": validation_report_present,
            "primary_status": validation_status,
            "raw_report_field_count": raw_report_field_count,
            "raw_payload_field_count": raw_payload_field_count,
            "raw_reports_exposed": false
        },
        "fixity_summary": {
            "digest_present": fixity_counts.digest_present(),
            "digest_field_count": fixity_counts.digest_field_count,
            "sha256_field_count": fixity_counts.sha256_field_count,
            "checksum_field_count": fixity_counts.checksum_field_count,
            "fixity_section_count": fixity_counts.fixity_section_count,
            "digest_values_echoed": false
        },
        "signed_document_summary": {
            "present": signed_document_summary.present,
            "status": signed_document_summary.status,
            "signed_pdf_digest_present": signed_document_summary.signed_pdf_digest_present,
            "signature_metadata_present": signed_document_summary.signature_metadata_present,
            "timestamp_token_present": signed_document_summary.timestamp_token_present,
            "signature_validation_performed": false,
            "signature_validity_claimed": false
        },
        "external_validator_summary": {
            "sections_present": external_validator_summary.sections_present,
            "attachment_count": external_validator_summary.attachment_count,
            "status_counts": external_validator_summary.status_counts,
            "raw_report_reference_count": external_validator_summary.raw_report_reference_count,
            "raw_payload_field_count": external_validator_summary.raw_payload_field_count,
            "raw_reports_exposed": false,
            "provider_validation_performed": false,
            "external_validator_success_claimed": false
        },
        "pdf_accessibility_v12_summary": {
            "evidence_present": pdf_accessibility_summary.evidence_present(),
            "evidence_section_count": pdf_accessibility_summary.evidence_section_count,
            "report_version_counts": pdf_accessibility_summary.report_version_counts,
            "v12_report_count": pdf_accessibility_summary.v12_report_count,
            "blocker_total": pdf_accessibility_summary.blocker_total,
            "blocker_counts": pdf_accessibility_summary.blocker_counts,
            "table_header_counts": {
                "table_semantics_object_count": pdf_accessibility_summary.table_semantics_object_count,
                "row_header_cell_count_total": pdf_accessibility_summary.row_header_cell_count_total,
                "column_header_cell_count_total": pdf_accessibility_summary.column_header_cell_count_total,
                "table_rows_missing_header_count_total": pdf_accessibility_summary.table_rows_missing_header_count_total,
                "row_header_scope_true_count": pdf_accessibility_summary.row_header_scope_true_count,
                "column_header_scope_true_count": pdf_accessibility_summary.column_header_scope_true_count
            },
            "pdf_ua_conformance_claimed": false,
            "dglab_certification_claimed": false,
            "legal_validity_claimed": false
        },
        "archive_path_summary": {
            "evidence_index_present": path_counts.evidence_index_present(),
            "path_value_count": path_counts.path_value_count,
            "archive_evidence_path_count": path_counts.archive_evidence_path_count,
            "evidence_index_path_count": path_counts.evidence_index_path_count,
            "pdf_accessibility_path_count": path_counts.pdf_accessibility_path_count,
            "external_validator_path_count": path_counts.external_validator_path_count,
            "canonical_pdf_path_count": path_counts.canonical_pdf_path_count,
            "signed_pdf_path_count": path_counts.signed_pdf_path_count,
            "path_values_echoed": false
        },
        "no_claim_flag_observations": {
            "by_flag": no_claim_counts,
            "missing_explicit_false_flags": missing_no_claim_flags,
            "truthy_flag_total": truthy_no_claim_flag_total
        },
        "missing_evidence_blockers": missing_evidence_blockers.into_iter().collect::<Vec<_>>(),
        "document_archive_review_caveats": [
            "This is a deterministic local aggregate summary over caller-supplied document_archive JSON only.",
            "The report does not echo raw reports, raw document bytes, digest values, path values, IDs, names, notes, or secrets.",
            "Unrecognized statuses and PDF/UA blocker values are counted as other instead of being echoed.",
            "Truthy caller-supplied no-claim fields are counted as blockers only and do not create conformance, certification, legal-validity, signature-validity, provider-validation, external-validator-success, or legal-review claims.",
            "Counts do not validate PDF/UA conformance, DGLAB certification, legal validity, signature validity, archive certification, provider validation, external-validator success, trust validation, or legal review."
        ],
        "operator_boundaries": [
            "No bridge, API, HTTP/SSE, AI-provider, legal-service, signature, archive-certification, external-validator, trust-list, DGLAB, or provider calls were made.",
            "No PDF/UA conformance, DGLAB certification, legal validity, signature validity, qualified signature, archive certification, provider validation, external-validator success, trust validation, or legal review is claimed.",
            "Human review, legal review, normal platform permissions, and source evidence checks remain required."
        ]
    }))
}

fn draft_signed_comparison_report_payload(arguments: &Value) -> Result<Value, String> {
    let args = arguments
        .as_object()
        .ok_or_else(|| "arguments must be an object".to_string())?;
    let draft = args
        .get("draft")
        .filter(|value| value.is_object())
        .ok_or_else(|| "draft must be an object".to_string())?;
    let signed = args
        .get("signed")
        .filter(|value| value.is_object())
        .ok_or_else(|| "signed must be an object".to_string())?;
    let case_id = args.get("case_id").and_then(Value::as_str);

    let mut status_counts = BTreeMap::from([
        ("different".to_string(), 0usize),
        ("matched".to_string(), 0usize),
        ("missing_draft".to_string(), 0usize),
        ("missing_signed".to_string(), 0usize),
        ("unknown".to_string(), 0usize),
    ]);
    let comparisons = DRAFT_SIGNED_FIELD_SPECS
        .iter()
        .map(|spec| {
            let comparison = compare_draft_signed_field(spec, draft, signed);
            let status = comparison["status"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            *status_counts.entry(status).or_insert(0) += 1;
            comparison
        })
        .collect::<Vec<_>>();
    let (compared_draft_paths, compared_signed_paths) = compared_draft_signed_paths();

    Ok(json!({
        "kind": "chancela_mcp_draft_signed_comparison_report",
        "schema_version": 1,
        "case_id": case_id,
        "source": "local_mcp_deterministic_comparator",
        "offline": true,
        "local_json_only": true,
        "deterministic": true,
        "bridge_calls": false,
        "api_calls": false,
        "ai_provider_calls": false,
        "signature_validation_performed": false,
        "trust_validation_performed": false,
        "claims": {
            "legal_validity": false,
            "legal_effect": false,
            "provider": false,
            "provider_completion": false,
            "notarization": false,
            "trust": false,
            "trust_validation": false,
            "external_validation": false,
            "signature_validity": false,
            "qualified_signature": false,
            "signature_qualification": false,
            "archive_certification": false,
            "source_certification": false
        },
        "comparison_summary": status_counts,
        "field_results": comparisons,
        "unmapped_fields": {
            "draft": unmapped_scalar_fields(draft, "draft", &compared_draft_paths),
            "signed": unmapped_scalar_fields(signed, "signed", &compared_signed_paths)
        },
        "operator_boundaries": [
            "This is a deterministic local metadata comparison over caller-supplied JSON only.",
            "Missing and unknown fields are reported without inferring completion.",
            "Digest, status, timestamp, and reference matches or differences are technical review signals only.",
            "No legal validity, trust validation, signature validity, qualified signature status, provider completion, or notarization is claimed."
        ]
    }))
}

fn privacy_control_review_summary_report_payload(arguments: &Value) -> Result<Value, String> {
    let args = arguments
        .as_object()
        .ok_or_else(|| "arguments must be an object".to_string())?;
    let privacy_controls = args
        .get("privacy_controls")
        .ok_or_else(|| "privacy_controls must be supplied".to_string())?;
    let privacy_controls = privacy_controls
        .as_object()
        .ok_or_else(|| "privacy_controls must be an object".to_string())?;
    let retention_due_candidates_report =
        privacy_retention_due_candidates_report(privacy_controls)?;
    let retention_candidate_resolution_records =
        privacy_retention_candidate_resolution_records(privacy_controls)?;

    let mut total_records = 0usize;
    let mut record_counts = BTreeMap::new();
    let mut risk_counts = BTreeMap::new();
    let mut status_counts = BTreeMap::new();
    let mut risk_counts_by_category = BTreeMap::new();
    let mut status_counts_by_category = BTreeMap::new();
    let mut advisory_review_status_counts = BTreeMap::new();
    let mut advisory_review_status_counts_by_category = BTreeMap::new();
    let mut missing_advisory_review_counts = BTreeMap::new();
    let mut missing_advisory_review_total = 0usize;
    let mut receipt_counts = PrivacyReceiptCounts::default();
    let mut receipt_counts_by_category = BTreeMap::new();
    let mut retention_execution_status_counts = BTreeMap::new();
    let mut retention_execution_outcome_counts = BTreeMap::new();
    let mut retention_execution_evidence_state_counts = BTreeMap::new();
    let mut dsr_type_counts = BTreeMap::new();
    let mut dsr_status_counts = BTreeMap::new();
    let mut dsr_outcome_counts = BTreeMap::new();
    let mut false_claim_flag_counts = initial_privacy_false_claim_flag_counts();

    for collection in PRIVACY_CONTROL_COLLECTIONS {
        let records = privacy_control_records(privacy_controls, collection)?;
        total_records += records.len();
        record_counts.insert((*collection).to_string(), records.len());

        let mut category_risk_counts = BTreeMap::new();
        let mut category_status_counts = BTreeMap::new();
        let mut category_advisory_counts = BTreeMap::new();
        let mut category_missing_advisory = 0usize;
        let mut category_receipt_counts = PrivacyReceiptCounts::default();

        for record in records {
            let risk = privacy_bounded_classification(
                first_located_value(record, PRIVACY_RISK_PATHS),
                "missing",
                PRIVACY_RISK_LABELS,
            );
            increment_count(&mut risk_counts, risk.clone());
            increment_count(&mut category_risk_counts, risk);

            let status = privacy_bounded_classification(
                first_located_value(record, PRIVACY_STATUS_PATHS),
                "missing",
                PRIVACY_STATUS_LABELS,
            );
            increment_count(&mut status_counts, status.clone());
            increment_count(&mut category_status_counts, status);

            let advisory_status = privacy_bounded_classification(
                first_located_value(record, PRIVACY_ADVISORY_REVIEW_STATUS_PATHS),
                "missing",
                PRIVACY_ADVISORY_STATUS_LABELS,
            );
            if advisory_status == "missing" {
                category_missing_advisory += 1;
                missing_advisory_review_total += 1;
            }
            increment_count(&mut advisory_review_status_counts, advisory_status.clone());
            increment_count(&mut category_advisory_counts, advisory_status);

            let record_receipt_counts = privacy_receipt_counts(collection, record);
            category_receipt_counts.add(record_receipt_counts);
            receipt_counts.add(record_receipt_counts);

            for spec in PRIVACY_FALSE_CLAIM_FLAG_SPECS {
                if let Some(counts) = false_claim_flag_counts.get_mut(spec.id) {
                    count_privacy_false_claim_flag_observations(record, spec, counts);
                }
            }

            if *collection == "retention_executions" {
                let status = privacy_bounded_classification(
                    first_located_value(record, PRIVACY_RETENTION_EXECUTION_STATUS_PATHS),
                    "missing",
                    PRIVACY_RETENTION_EXECUTION_STATUS_LABELS,
                );
                increment_count(&mut retention_execution_status_counts, status);

                let outcome = privacy_bounded_classification(
                    first_located_value(record, PRIVACY_RETENTION_EXECUTION_OUTCOME_PATHS),
                    "missing",
                    PRIVACY_RETENTION_EXECUTION_OUTCOME_LABELS,
                );
                increment_count(&mut retention_execution_outcome_counts, outcome);

                let evidence_state = privacy_bounded_classification(
                    first_located_value(record, PRIVACY_RETENTION_EVIDENCE_STATE_PATHS),
                    "missing",
                    PRIVACY_RETENTION_EVIDENCE_STATE_LABELS,
                );
                increment_count(
                    &mut retention_execution_evidence_state_counts,
                    evidence_state,
                );
            }

            if *collection == "dsr_requests" {
                let request_type = privacy_bounded_classification(
                    first_located_value(record, PRIVACY_DSR_TYPE_PATHS),
                    "missing",
                    PRIVACY_DSR_TYPE_LABELS,
                );
                increment_count(&mut dsr_type_counts, request_type);

                let status = privacy_bounded_classification(
                    first_located_value(record, PRIVACY_DSR_STATUS_PATHS),
                    "missing",
                    PRIVACY_DSR_STATUS_LABELS,
                );
                increment_count(&mut dsr_status_counts, status);

                let outcome = privacy_bounded_classification(
                    first_located_value(record, PRIVACY_DSR_OUTCOME_PATHS),
                    "missing",
                    PRIVACY_DSR_OUTCOME_LABELS,
                );
                increment_count(&mut dsr_outcome_counts, outcome);
            }
        }

        risk_counts_by_category.insert((*collection).to_string(), category_risk_counts);
        status_counts_by_category.insert((*collection).to_string(), category_status_counts);
        advisory_review_status_counts_by_category
            .insert((*collection).to_string(), category_advisory_counts);
        missing_advisory_review_counts.insert((*collection).to_string(), category_missing_advisory);
        receipt_counts_by_category.insert(
            (*collection).to_string(),
            privacy_receipt_counts_value(category_receipt_counts),
        );
    }
    record_counts.insert("total_records".to_string(), total_records);

    let retention_due_candidate_counts =
        retention_due_candidate_counts(retention_due_candidates_report)?;
    let retention_candidate_resolution_counts =
        retention_candidate_resolution_counts(retention_candidate_resolution_records);

    let false_claim_explicit_false_total = false_claim_flag_counts
        .values()
        .map(|counts| counts.get("explicit_false").copied().unwrap_or(0))
        .sum::<usize>();
    let false_claim_truthy_total = false_claim_flag_counts
        .values()
        .map(|counts| counts.get("truthy").copied().unwrap_or(0))
        .sum::<usize>();
    let false_claim_other_present_total = false_claim_flag_counts
        .values()
        .map(|counts| counts.get("other_present").copied().unwrap_or(0))
        .sum::<usize>();

    Ok(json!({
        "kind": "chancela_mcp_privacy_control_review_summary_report",
        "schema_version": 1,
        "source": "local_mcp_deterministic_privacy_control_summarizer",
        "offline": true,
        "local_json_only": true,
        "deterministic": true,
        "aggregate_counts_only": true,
        "bridge_calls": false,
        "api_calls": false,
        "provider_calls": false,
        "ai_provider_calls": false,
        "legal_service_calls": false,
        "secrets_in_resource": false,
        "claims": {
            "legal_approval": false,
            "legal_completion": false,
            "authority_notification": false,
            "data_subject_notification": false,
            "transfer_approval": false,
            "transfer_execution": false,
            "dpia_authority_filing": false,
            "dpia_completion": false,
            "compliance_certification": false,
            "privacy_compliance_completion": false,
            "gdpr_compliance_completion": false,
            "destructive_disposal": false,
            "deletion_completion": false,
            "anonymization_completion": false,
            "redaction_completion": false,
            "full_erasure": false,
            "erasure_completion": false,
            "legal_hold_mutation": false,
            "retention_policy_mutation": false,
            "provider": false,
            "legal_service": false
        },
        "privacy_control_summary": {
            "record_counts": record_counts,
            "risk_counts": risk_counts,
            "risk_counts_by_category": risk_counts_by_category,
            "status_counts": status_counts,
            "status_counts_by_category": status_counts_by_category,
            "advisory_review_status_counts": advisory_review_status_counts,
            "advisory_review_status_counts_by_category": advisory_review_status_counts_by_category,
            "missing_advisory_review_counts": {
                "total_records_missing_advisory_review_status": missing_advisory_review_total,
                "by_category": missing_advisory_review_counts
            },
            "review_drill_receipt_counts": {
                "total": privacy_receipt_counts_value(receipt_counts),
                "by_category": receipt_counts_by_category
            },
            "false_claim_flag_counts": {
                "by_flag": false_claim_flag_counts,
                "totals": {
                    "explicit_false": false_claim_explicit_false_total,
                    "truthy": false_claim_truthy_total,
                    "other_present": false_claim_other_present_total
                }
            },
            "retention_execution_counts": {
                "record_count": record_counts.get("retention_executions").copied().unwrap_or(0),
                "execution_status_counts": retention_execution_status_counts,
                "outcome_counts": retention_execution_outcome_counts,
                "evidence_state_counts": retention_execution_evidence_state_counts
            },
            "retention_due_candidate_counts": retention_due_candidate_counts,
            "retention_candidate_resolution_counts": retention_candidate_resolution_counts,
            "dsr_request_counts": {
                "record_count": record_counts.get("dsr_requests").copied().unwrap_or(0),
                "request_type_counts": dsr_type_counts,
                "status_counts": dsr_status_counts,
                "outcome_counts": dsr_outcome_counts
            }
        },
        "privacy_review_caveats": [
            "This is a deterministic local aggregate summary over caller-supplied privacy_controls JSON only.",
            "The report does not echo record names, titles, ids, notes, legal bases, recipients, subjects, data categories, actor names, raw evidence text, or secrets.",
            "Unrecognized risk, status, receipt, retention, candidate, resolution, and DSR labels are counted as other instead of being echoed.",
            "Truthy caller-supplied no-claim fields are counted as caveats only and do not create approval, notification, transfer, filing, certification, completion, disposal, deletion, anonymization, redaction, erasure, legal-hold mutation, or retention-policy mutation claims.",
            "Counts do not validate legal sufficiency, authority notification, data-subject notification, transfer approval, transfer execution, DPIA filing, DPIA completion, compliance certification, privacy/GDPR compliance completion, destructive disposal, deletion, anonymization, redaction, erasure, legal disposal, legal hold, retention policy, or full erasure."
        ],
        "operator_boundaries": [
            "No bridge, API, AI-provider, legal-service, provider, notification, transfer, filing, certification, disposal, deletion, anonymization, redaction, erasure, legal-hold, or retention-policy calls were made.",
            "No legal approval, legal completion, authority notification, data-subject notification, transfer approval, transfer execution, DPIA authority filing, DPIA completion, compliance certification, privacy/GDPR compliance completion, destructive disposal, deletion, anonymization, redaction, erasure, legal-hold mutation, retention-policy mutation, or full erasure is claimed.",
            "Human review, legal review, normal platform permissions, and source evidence checks remain required."
        ]
    }))
}

fn chronology_review_summary_report_payload(arguments: &Value) -> Result<Value, String> {
    let args = arguments
        .as_object()
        .ok_or_else(|| "arguments must be an object".to_string())?;
    let chronology = args
        .get("chronology")
        .ok_or_else(|| "chronology must be supplied".to_string())?;
    let case_id = args.get("case_id").and_then(Value::as_str);
    let events = chronology_events(chronology)?;

    let mut event_kind_counts = BTreeMap::new();
    let mut status_counts = BTreeMap::new();
    let mut date_values = Vec::new();
    let mut missing_date_count = 0usize;
    let mut events_with_evidence_marker = 0usize;
    let mut events_missing_evidence_marker = 0usize;
    let mut events_with_explicit_missing_evidence_marker = 0usize;

    for event in events {
        if !event.is_object() {
            return Err("chronology events must be objects".to_string());
        }

        let kind = chronology_classification(
            first_located_value(event, CHRONOLOGY_EVENT_KIND_PATHS),
            "missing",
        );
        increment_count(&mut event_kind_counts, kind);

        let status = chronology_classification(
            first_located_value(event, CHRONOLOGY_EVENT_STATUS_PATHS),
            "missing",
        );
        increment_count(&mut status_counts, status);

        match chronology_date_value(event) {
            Some(value) => date_values.push(value),
            None => missing_date_count += 1,
        }

        if has_chronology_evidence_marker(event) {
            events_with_evidence_marker += 1;
        } else {
            events_missing_evidence_marker += 1;
        }
        if has_explicit_missing_evidence_marker(event) {
            events_with_explicit_missing_evidence_marker += 1;
        }
    }

    date_values.sort();
    let first_date = date_values.first().cloned();
    let last_date = date_values.last().cloned();

    Ok(json!({
        "kind": "chancela_mcp_chronology_review_summary_report",
        "schema_version": 1,
        "case_id": case_id,
        "source": "local_mcp_deterministic_chronology_summarizer",
        "offline": true,
        "local_json_only": true,
        "deterministic": true,
        "bridge_calls": false,
        "api_calls": false,
        "provider_calls": false,
        "ai_provider_calls": false,
        "registry_calls": false,
        "legal_service_calls": false,
        "secrets_in_resource": false,
        "claims": {
            "legal_validity": false,
            "legal_effect": false,
            "ownership_determination": false,
            "registry_certification": false,
            "ai_completion": false,
            "ai_completed_claim": false,
            "source_certification": false,
            "provider": false,
            "trust": false,
            "external_validation": false,
            "signature_validity": false,
            "qualified_signature": false,
            "signature_qualification": false,
            "archive_certification": false
        },
        "chronology_summary": {
            "total_events": events.len(),
            "event_kind_counts": event_kind_counts,
            "status_counts": status_counts,
            "date_range": {
                "first": first_date,
                "last": last_date,
                "observed_date_count": date_values.len(),
                "missing_date_count": missing_date_count,
                "basis": "lexical_order_of_supplied_nonempty_date_strings"
            },
            "evidence_marker_counts": {
                "events_with_evidence_marker": events_with_evidence_marker,
                "events_missing_evidence_marker": events_missing_evidence_marker,
                "events_with_explicit_missing_evidence_marker": events_with_explicit_missing_evidence_marker
            }
        },
        "recognized_fields": {
            "event_kind": CHRONOLOGY_EVENT_KIND_PATHS,
            "status": CHRONOLOGY_EVENT_STATUS_PATHS,
            "date": CHRONOLOGY_EVENT_DATE_PATHS,
            "evidence": CHRONOLOGY_EVIDENCE_PATHS,
            "explicit_missing_evidence": CHRONOLOGY_MISSING_EVIDENCE_PATHS
        },
        "chronology_review_caveats": [
            "This is a deterministic local aggregate summary over caller-supplied JSON only.",
            "Counts reflect recognized fields and supplied values; missing fields are review gaps, not completion findings.",
            "The date range is lexical over supplied date strings and does not certify chronological correctness.",
            "Evidence-marker counts do not validate authenticity, provenance, registry status, ownership, legal effect, trust, signature validity, provider assurance, or source certification."
        ],
        "operator_boundaries": [
            "No bridge, API, AI-provider, registry, legal-service, trust, signature, archive, or provider calls were made.",
            "No legal validity, ownership determination, registry certification, AI completion, source certification, trust, external validation, signature qualification, or provider assurance is claimed.",
            "Human review and normal platform evidence checks remain required."
        ]
    }))
}

impl DocumentArchivePathCounts {
    fn evidence_index_present(&self) -> bool {
        self.evidence_index_object_present || self.evidence_index_path_count > 0
    }
}

impl DocumentArchiveFixityCounts {
    fn digest_present(&self) -> bool {
        self.digest_field_count + self.sha256_field_count + self.checksum_field_count > 0
    }
}

impl DocumentArchivePdfAccessibilitySummary {
    fn evidence_present(&self) -> bool {
        self.evidence_section_count > 0
            || !self.report_version_counts.is_empty()
            || self.blocker_total > 0
            || self.table_semantics_object_count > 0
    }
}

impl RetentionCandidatePresenceCounts {
    fn add_record(&mut self, record: &Value) {
        let blocker_count =
            usize_or_array_len_at_paths(record, &["blockers", "blocker_count"]).unwrap_or(0);
        self.blocker_count_total += blocker_count;
        if blocker_count > 0 {
            self.records_with_blockers += 1;
        } else {
            self.records_without_blockers += 1;
        }

        let required_approval_count =
            usize_or_array_len_at_paths(record, &["required_approvals", "required_approval_count"])
                .unwrap_or(0);
        self.required_approval_count_total += required_approval_count;
        if required_approval_count > 0 {
            self.records_with_required_approvals += 1;
        } else {
            self.records_without_required_approvals += 1;
        }

        let legal_hold_blocker_count = usize_or_array_len_at_paths(
            record,
            &["legal_hold_blockers", "legal_hold_blocker_count"],
        )
        .unwrap_or(0);
        self.legal_hold_blocker_count_total += legal_hold_blocker_count;
        if legal_hold_blocker_count > 0 {
            self.records_with_legal_hold_blockers += 1;
        } else {
            self.records_without_legal_hold_blockers += 1;
        }

        let finding_count =
            usize_or_array_len_at_paths(record, &["findings", "finding_count"]).unwrap_or(0);
        self.finding_count_total += finding_count;
        if finding_count > 0 {
            self.records_with_findings += 1;
        } else {
            self.records_without_findings += 1;
        }
    }
}

fn privacy_retention_due_candidates_report(
    privacy_controls: &serde_json::Map<String, Value>,
) -> Result<Option<&Value>, String> {
    let Some(report) = privacy_controls.get(PRIVACY_RETENTION_DUE_CANDIDATES_KEY) else {
        return Ok(None);
    };
    if !report.is_object() {
        return Err("privacy_controls.retention_due_candidates must be an object".to_string());
    }
    Ok(Some(report))
}

fn privacy_retention_candidate_resolution_records(
    privacy_controls: &serde_json::Map<String, Value>,
) -> Result<&[Value], String> {
    let Some(records) = privacy_controls.get(PRIVACY_RETENTION_CANDIDATE_RESOLUTIONS_KEY) else {
        return Ok(&[]);
    };
    let records = records.as_array().ok_or_else(|| {
        "privacy_controls.retention_candidate_resolutions must be an array".to_string()
    })?;
    if let Some(index) = records.iter().position(|record| !record.is_object()) {
        return Err(format!(
            "privacy_controls.retention_candidate_resolutions[{index}] must be an object"
        ));
    }
    Ok(records.as_slice())
}

fn retention_due_candidate_records(report: Option<&Value>) -> Result<&[Value], String> {
    let Some(report) = report else {
        return Ok(&[]);
    };
    let Some(candidates) = report.get("candidates") else {
        return Ok(&[]);
    };
    let candidates = candidates.as_array().ok_or_else(|| {
        "privacy_controls.retention_due_candidates.candidates must be an array".to_string()
    })?;
    if let Some(index) = candidates.iter().position(|record| !record.is_object()) {
        return Err(format!(
            "privacy_controls.retention_due_candidates.candidates[{index}] must be an object"
        ));
    }
    Ok(candidates.as_slice())
}

fn retention_due_candidate_counts(report: Option<&Value>) -> Result<Value, String> {
    let candidates = retention_due_candidate_records(report)?;
    let mut candidate_status_counts = BTreeMap::new();
    let mut outcome_counts = BTreeMap::new();
    let mut evidence_state_counts = BTreeMap::new();
    let mut latest_resolution_disposition_counts = BTreeMap::new();
    let mut candidates_with_latest_resolution = 0usize;
    let mut candidates_without_latest_resolution = 0usize;
    let mut candidates_with_resolution_record_count = 0usize;
    let mut candidates_without_resolution_record_count = 0usize;
    let mut presence_counts = RetentionCandidatePresenceCounts::default();
    let mut no_claim_counts = initial_privacy_false_claim_flag_counts();

    for candidate in candidates {
        let status = privacy_bounded_classification(
            first_located_value(candidate, PRIVACY_RETENTION_DUE_CANDIDATE_STATUS_PATHS),
            "missing",
            PRIVACY_RETENTION_DUE_CANDIDATE_STATUS_LABELS,
        );
        increment_count(&mut candidate_status_counts, status);

        let outcome = privacy_bounded_classification(
            first_located_value(candidate, PRIVACY_RETENTION_DUE_CANDIDATE_OUTCOME_PATHS),
            "missing",
            PRIVACY_RETENTION_DUE_CANDIDATE_OUTCOME_LABELS,
        );
        increment_count(&mut outcome_counts, outcome);

        let evidence_state = privacy_bounded_classification(
            first_located_value(candidate, PRIVACY_RETENTION_EVIDENCE_STATE_PATHS),
            "missing",
            PRIVACY_RETENTION_EVIDENCE_STATE_LABELS,
        );
        increment_count(&mut evidence_state_counts, evidence_state);

        match value_at_dotted_path(candidate, "latest_resolution").filter(|value| value.is_object())
        {
            Some(latest_resolution) => {
                candidates_with_latest_resolution += 1;
                let disposition = privacy_bounded_classification(
                    first_located_value(
                        latest_resolution,
                        PRIVACY_RETENTION_CANDIDATE_RESOLUTION_DISPOSITION_PATHS,
                    ),
                    "missing",
                    PRIVACY_RETENTION_CANDIDATE_RESOLUTION_DISPOSITION_LABELS,
                );
                increment_count(&mut latest_resolution_disposition_counts, disposition);
            }
            None => candidates_without_latest_resolution += 1,
        }

        if usize_at_paths(candidate, &["candidate_resolution_record_count"]).unwrap_or(0) > 0 {
            candidates_with_resolution_record_count += 1;
        } else {
            candidates_without_resolution_record_count += 1;
        }

        presence_counts.add_record(candidate);
        for spec in PRIVACY_FALSE_CLAIM_FLAG_SPECS {
            if let Some(counts) = no_claim_counts.get_mut(spec.id) {
                count_privacy_false_claim_flag_observations(candidate, spec, counts);
            }
        }
    }

    let reported_candidate_count =
        report.and_then(|report| usize_at_paths(report, &["candidate_count"]));
    let reported_suppressed_candidate_count =
        report.and_then(|report| usize_at_paths(report, &["suppressed_candidate_count"]));
    let reported_suppressed_by_bounded_evidence_count =
        report.and_then(|report| usize_at_paths(report, &["suppressed_by_bounded_evidence_count"]));
    let suppression_summary_suppressed_by_bounded_evidence_count = report.and_then(|report| {
        usize_at_paths(
            report,
            &["suppression_summary.suppressed_by_bounded_evidence_count"],
        )
    });
    let reported_candidate_resolution_record_count =
        report.and_then(|report| usize_at_paths(report, &["candidate_resolution_record_count"]));
    let reported_candidates_with_resolution_count =
        report.and_then(|report| usize_at_paths(report, &["candidates_with_resolution_count"]));

    Ok(json!({
        "report_supplied": report.is_some(),
        "candidate_record_count": candidates.len(),
        "reported_candidate_count": reported_candidate_count.unwrap_or(0),
        "candidate_status_counts": candidate_status_counts,
        "outcome_counts": outcome_counts,
        "evidence_state_counts": evidence_state_counts,
        "suppressed_by_bounded_evidence_counts": {
            "suppressed_candidate_count": reported_suppressed_candidate_count.unwrap_or(0),
            "top_level_suppressed_by_bounded_evidence_count": reported_suppressed_by_bounded_evidence_count.unwrap_or(0),
            "suppression_summary_suppressed_by_bounded_evidence_count": suppression_summary_suppressed_by_bounded_evidence_count.unwrap_or(0)
        },
        "candidate_resolution_presence_counts": {
            "reported_candidate_resolution_record_count": reported_candidate_resolution_record_count.unwrap_or(0),
            "reported_candidates_with_resolution_count": reported_candidates_with_resolution_count.unwrap_or(0),
            "candidates_with_latest_resolution": candidates_with_latest_resolution,
            "candidates_without_latest_resolution": candidates_without_latest_resolution,
            "candidates_with_resolution_record_count": candidates_with_resolution_record_count,
            "candidates_without_resolution_record_count": candidates_without_resolution_record_count,
            "latest_resolution_disposition_counts": latest_resolution_disposition_counts
        },
        "blocker_approval_presence_counts": retention_candidate_presence_counts_value(&presence_counts),
        "no_claim_flag_counts": privacy_false_claim_flag_counts_summary(&no_claim_counts)
    }))
}

fn retention_candidate_resolution_counts(records: &[Value]) -> Value {
    let mut disposition_counts = BTreeMap::new();
    let mut evidence_only_counts = initial_boolean_observation_counts();
    let mut records_with_candidate_snapshot = 0usize;
    let mut records_without_candidate_snapshot = 0usize;
    let mut candidate_status_counts = BTreeMap::new();
    let mut outcome_counts = BTreeMap::new();
    let mut evidence_state_counts = BTreeMap::new();
    let mut presence_counts = RetentionCandidatePresenceCounts::default();
    let mut no_claim_counts = initial_privacy_false_claim_flag_counts();

    for record in records {
        let disposition = privacy_bounded_classification(
            first_located_value(
                record,
                PRIVACY_RETENTION_CANDIDATE_RESOLUTION_DISPOSITION_PATHS,
            ),
            "missing",
            PRIVACY_RETENTION_CANDIDATE_RESOLUTION_DISPOSITION_LABELS,
        );
        increment_count(&mut disposition_counts, disposition);

        count_boolean_observation_at_path(record, "evidence_only", &mut evidence_only_counts);

        match value_at_dotted_path(record, "candidate").filter(|value| value.is_object()) {
            Some(candidate) => {
                records_with_candidate_snapshot += 1;
                let status = privacy_bounded_classification(
                    first_located_value(candidate, PRIVACY_RETENTION_DUE_CANDIDATE_STATUS_PATHS),
                    "missing",
                    PRIVACY_RETENTION_DUE_CANDIDATE_STATUS_LABELS,
                );
                increment_count(&mut candidate_status_counts, status);

                let outcome = privacy_bounded_classification(
                    first_located_value(candidate, PRIVACY_RETENTION_DUE_CANDIDATE_OUTCOME_PATHS),
                    "missing",
                    PRIVACY_RETENTION_DUE_CANDIDATE_OUTCOME_LABELS,
                );
                increment_count(&mut outcome_counts, outcome);

                let evidence_state = privacy_bounded_classification(
                    first_located_value(candidate, PRIVACY_RETENTION_EVIDENCE_STATE_PATHS),
                    "missing",
                    PRIVACY_RETENTION_EVIDENCE_STATE_LABELS,
                );
                increment_count(&mut evidence_state_counts, evidence_state);
                presence_counts.add_record(candidate);
            }
            None => records_without_candidate_snapshot += 1,
        }

        for spec in PRIVACY_FALSE_CLAIM_FLAG_SPECS {
            if let Some(counts) = no_claim_counts.get_mut(spec.id) {
                count_privacy_false_claim_flag_observations(record, spec, counts);
            }
        }
    }

    json!({
        "record_count": records.len(),
        "disposition_counts": disposition_counts,
        "evidence_only_counts": evidence_only_counts,
        "candidate_snapshot_counts": {
            "records_with_candidate_snapshot": records_with_candidate_snapshot,
            "records_without_candidate_snapshot": records_without_candidate_snapshot,
            "candidate_status_counts": candidate_status_counts,
            "outcome_counts": outcome_counts,
            "evidence_state_counts": evidence_state_counts
        },
        "blocker_approval_presence_counts": retention_candidate_presence_counts_value(&presence_counts),
        "no_claim_flag_counts": privacy_false_claim_flag_counts_summary(&no_claim_counts)
    })
}

fn retention_candidate_presence_counts_value(counts: &RetentionCandidatePresenceCounts) -> Value {
    json!({
        "records_with_blockers": counts.records_with_blockers,
        "records_without_blockers": counts.records_without_blockers,
        "blocker_count_total": counts.blocker_count_total,
        "records_with_required_approvals": counts.records_with_required_approvals,
        "records_without_required_approvals": counts.records_without_required_approvals,
        "required_approval_count_total": counts.required_approval_count_total,
        "records_with_legal_hold_blockers": counts.records_with_legal_hold_blockers,
        "records_without_legal_hold_blockers": counts.records_without_legal_hold_blockers,
        "legal_hold_blocker_count_total": counts.legal_hold_blocker_count_total,
        "records_with_findings": counts.records_with_findings,
        "records_without_findings": counts.records_without_findings,
        "finding_count_total": counts.finding_count_total
    })
}

fn document_archive_report_present(root: &Value) -> bool {
    DOCUMENT_ARCHIVE_VALIDATION_REPORT_PATHS
        .iter()
        .any(|path| value_at_dotted_path(root, path).is_some())
        || first_located_value(root, DOCUMENT_ARCHIVE_VALIDATION_REPORT_MARKER_PATHS)
            .is_some_and(|located| is_present_chronology_marker_value(located.value))
}

fn document_archive_bounded_label_at_paths(
    root: &Value,
    paths: &'static [&'static str],
    missing_label: &str,
) -> String {
    privacy_bounded_classification(
        first_located_value(root, paths),
        missing_label,
        DOCUMENT_ARCHIVE_STATUS_LABELS,
    )
}

fn count_raw_report_fields(root: &Value) -> usize {
    count_keys_matching(root, is_raw_report_reference_key)
}

fn count_raw_payload_fields(root: &Value) -> usize {
    count_keys_matching(root, is_raw_payload_key)
}

fn document_archive_path_counts(root: &Value) -> DocumentArchivePathCounts {
    let mut counts = DocumentArchivePathCounts::default();
    collect_document_archive_path_counts(root, None, &mut counts);
    counts
}

fn collect_document_archive_path_counts(
    value: &Value,
    key: Option<&str>,
    counts: &mut DocumentArchivePathCounts,
) {
    match value {
        Value::Object(map) => {
            for (child_key, child) in map {
                let normalized = normalize_chronology_label(child_key);
                if normalized == "evidence_index" || normalized == "index_kind" {
                    counts.evidence_index_object_present = true;
                }
                collect_document_archive_path_counts(child, Some(child_key), counts);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_document_archive_path_counts(child, key, counts);
            }
        }
        Value::String(path) => {
            let key = key.unwrap_or_default();
            let normalized_key = normalize_chronology_label(key);
            if !normalized_key.contains("path")
                && !normalized_key.contains("download")
                && !normalized_key.contains("uri")
                && !normalized_key.contains("pointer")
            {
                return;
            }
            counts.path_value_count += 1;
            let normalized_path = path.trim().to_ascii_lowercase();
            if normalized_key.contains("evidence_index")
                || normalized_path == "evidence/index.json"
                || normalized_path.ends_with("/evidence/index.json")
            {
                counts.evidence_index_path_count += 1;
            }
            if normalized_path.starts_with("evidence/") || normalized_key.contains("evidence") {
                counts.archive_evidence_path_count += 1;
            }
            if normalized_path.starts_with("evidence/pdf-accessibility/")
                || normalized_key.contains("pdf_accessibility")
            {
                counts.pdf_accessibility_path_count += 1;
            }
            if normalized_path.starts_with("evidence/external-validators/")
                || normalized_key.contains("external_validator")
            {
                counts.external_validator_path_count += 1;
            }
            if normalized_path.starts_with("documents/") || normalized_key.contains("canonical_pdf")
            {
                counts.canonical_pdf_path_count += 1;
            }
            if normalized_path.starts_with("signed/") || normalized_key.contains("signed_pdf") {
                counts.signed_pdf_path_count += 1;
            }
        }
        _ => {}
    }
}

fn document_archive_fixity_counts(root: &Value) -> DocumentArchiveFixityCounts {
    let mut counts = DocumentArchiveFixityCounts::default();
    collect_document_archive_fixity_counts(root, None, &mut counts);
    counts
}

fn collect_document_archive_fixity_counts(
    value: &Value,
    key: Option<&str>,
    counts: &mut DocumentArchiveFixityCounts,
) {
    match value {
        Value::Object(map) => {
            for (child_key, child) in map {
                let normalized = normalize_chronology_label(child_key);
                if normalized == "fixity" {
                    counts.fixity_section_count += 1;
                }
                if is_present_chronology_marker_value(child) {
                    if normalized.contains("sha256") {
                        counts.sha256_field_count += 1;
                    } else if normalized.contains("digest") {
                        counts.digest_field_count += 1;
                    } else if normalized.contains("checksum") {
                        counts.checksum_field_count += 1;
                    }
                }
                collect_document_archive_fixity_counts(child, Some(child_key), counts);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_document_archive_fixity_counts(child, key, counts);
            }
        }
        _ => {
            let _ = key;
        }
    }
}

fn document_archive_signed_document_summary(root: &Value) -> DocumentArchiveSignedDocumentSummary {
    let mut summary = DocumentArchiveSignedDocumentSummary {
        status: document_archive_bounded_label_at_paths(
            root,
            DOCUMENT_ARCHIVE_SIGNED_STATUS_PATHS,
            "missing",
        ),
        ..DocumentArchiveSignedDocumentSummary::default()
    };
    collect_document_archive_signed_document_summary(root, None, &mut summary);
    if !summary.present {
        summary.status = "not_present".to_string();
    }
    summary
}

fn collect_document_archive_signed_document_summary(
    value: &Value,
    key: Option<&str>,
    summary: &mut DocumentArchiveSignedDocumentSummary,
) {
    match value {
        Value::Object(map) => {
            for (child_key, child) in map {
                let normalized = normalize_chronology_label(child_key);
                if normalized == "signed_document"
                    || normalized == "signed"
                    || normalized == "signed_pdf"
                    || normalized == "signature"
                    || normalized == "signing_metadata"
                {
                    summary.present = true;
                }
                if normalized.contains("signed_pdf_digest")
                    || normalized == "stored_signed_pdf_digest"
                    || normalized == "signed_document_digest"
                {
                    summary.signed_pdf_digest_present |= is_present_chronology_marker_value(child);
                    summary.present |= summary.signed_pdf_digest_present;
                }
                if normalized.contains("signature_bundle")
                    || normalized == "signature_metadata"
                    || normalized == "signing_metadata"
                    || normalized == "signer_certificate_path"
                    || normalized == "signer_cert_subject_present"
                {
                    summary.signature_metadata_present |= is_present_chronology_marker_value(child);
                    summary.present |= summary.signature_metadata_present;
                }
                if normalized.contains("timestamp_token") || normalized.contains("doctimestamp") {
                    summary.timestamp_token_present |= is_present_chronology_marker_value(child);
                    summary.present |= summary.timestamp_token_present;
                }
                collect_document_archive_signed_document_summary(child, Some(child_key), summary);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_document_archive_signed_document_summary(child, key, summary);
            }
        }
        _ => {
            let _ = key;
        }
    }
}

fn document_archive_external_validator_summary(
    root: &Value,
) -> DocumentArchiveExternalValidatorSummary {
    let mut summary = DocumentArchiveExternalValidatorSummary::default();
    collect_document_archive_external_validator_summary(root, None, false, &mut summary);
    summary
}

fn collect_document_archive_external_validator_summary(
    value: &Value,
    key: Option<&str>,
    inside_external_validator: bool,
    summary: &mut DocumentArchiveExternalValidatorSummary,
) {
    let key_is_external = key.is_some_and(is_external_validator_key);
    let inside_external_validator = inside_external_validator || key_is_external;
    if key_is_external && matches!(value, Value::Object(_) | Value::Array(_)) {
        summary.sections_present += 1;
    }

    match value {
        Value::Object(map) => {
            if inside_external_validator {
                let status = document_archive_bounded_label_at_paths(
                    value,
                    DOCUMENT_ARCHIVE_EXTERNAL_VALIDATOR_STATUS_PATHS,
                    "missing",
                );
                increment_count(&mut summary.status_counts, status);
                if let Some(attachments) = map.get("attachments").and_then(Value::as_array) {
                    summary.attachment_count += attachments.len();
                }
            }
            for (child_key, child) in map {
                let normalized = normalize_chronology_label(child_key);
                if inside_external_validator && normalized == "raw_report" {
                    summary.raw_report_reference_count += 1;
                }
                if inside_external_validator && is_raw_payload_key(child_key) {
                    summary.raw_payload_field_count += 1;
                }
                collect_document_archive_external_validator_summary(
                    child,
                    Some(child_key),
                    inside_external_validator,
                    summary,
                );
            }
        }
        Value::Array(values) => {
            if key_is_external {
                summary.attachment_count += values.len();
            }
            for child in values {
                collect_document_archive_external_validator_summary(
                    child,
                    key,
                    inside_external_validator,
                    summary,
                );
            }
        }
        _ => {}
    }
}

fn document_archive_pdf_accessibility_summary(
    root: &Value,
) -> DocumentArchivePdfAccessibilitySummary {
    let mut summary = DocumentArchivePdfAccessibilitySummary::default();
    collect_document_archive_pdf_accessibility_summary(root, None, false, &mut summary);
    summary
}

fn collect_document_archive_pdf_accessibility_summary(
    value: &Value,
    key: Option<&str>,
    inside_pdf_accessibility: bool,
    summary: &mut DocumentArchivePdfAccessibilitySummary,
) {
    let key_is_pdf_accessibility = key.is_some_and(is_pdf_accessibility_key);
    let object_is_pdf_accessibility = document_archive_pdf_accessibility_marker(value);
    let inside_pdf_accessibility =
        inside_pdf_accessibility || key_is_pdf_accessibility || object_is_pdf_accessibility;
    if (key_is_pdf_accessibility || object_is_pdf_accessibility)
        && matches!(value, Value::Object(_) | Value::Array(_))
    {
        summary.evidence_section_count += 1;
    }

    match value {
        Value::Object(map) => {
            if inside_pdf_accessibility {
                if let Some(version) = map
                    .get("report_version")
                    .or_else(|| {
                        map.get("version")
                            .filter(|_| map.contains_key("tagged_structure"))
                    })
                    .and_then(Value::as_u64)
                {
                    increment_count(&mut summary.report_version_counts, version.to_string());
                    if version == 12 {
                        summary.v12_report_count += 1;
                    }
                }
                if let Some(blockers) = map.get("pdf_ua_blockers").and_then(Value::as_array) {
                    for blocker in blockers {
                        summary.blocker_total += 1;
                        let label = blocker
                            .as_str()
                            .map(normalize_chronology_label)
                            .filter(|label| {
                                DOCUMENT_ARCHIVE_PDF_UA_BLOCKER_LABELS.contains(&label.as_str())
                            })
                            .unwrap_or_else(|| "other".to_string());
                        increment_count(&mut summary.blocker_counts, label);
                    }
                }
                if let Some(tables) = value_at_dotted_path(value, "tagged_structure.tables")
                    .or_else(|| {
                        map.get("tables").filter(|tables| {
                            tables
                                .as_object()
                                .is_some_and(|table| table.contains_key("row_header_cell_count"))
                        })
                    })
                    .and_then(Value::as_object)
                {
                    summary.table_semantics_object_count += 1;
                    summary.row_header_cell_count_total += tables
                        .get("row_header_cell_count")
                        .and_then(usize_from_value)
                        .unwrap_or(0);
                    summary.column_header_cell_count_total += tables
                        .get("column_header_cell_count")
                        .and_then(usize_from_value)
                        .unwrap_or(0);
                    summary.table_rows_missing_header_count_total += tables
                        .get("table_rows_missing_header_count")
                        .and_then(usize_from_value)
                        .unwrap_or(0);
                    if tables
                        .get("row_header_cells_have_scope_row")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                    {
                        summary.row_header_scope_true_count += 1;
                    }
                    if tables
                        .get("column_header_cells_have_scope_column")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                    {
                        summary.column_header_scope_true_count += 1;
                    }
                }
            }
            for (child_key, child) in map {
                collect_document_archive_pdf_accessibility_summary(
                    child,
                    Some(child_key),
                    inside_pdf_accessibility,
                    summary,
                );
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_document_archive_pdf_accessibility_summary(
                    child,
                    key,
                    inside_pdf_accessibility,
                    summary,
                );
            }
        }
        _ => {}
    }
}

fn document_archive_no_claim_flag_counts(
    root: &Value,
) -> BTreeMap<String, BTreeMap<String, usize>> {
    let mut counts = DOCUMENT_ARCHIVE_NO_CLAIM_FLAG_SPECS
        .iter()
        .map(|spec| {
            (
                spec.id.to_string(),
                BTreeMap::from([
                    ("explicit_false".to_string(), 0usize),
                    ("truthy".to_string(), 0usize),
                    ("other_present".to_string(), 0usize),
                ]),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for spec in DOCUMENT_ARCHIVE_NO_CLAIM_FLAG_SPECS {
        if let Some(spec_counts) = counts.get_mut(spec.id) {
            count_document_archive_no_claim_observations(root, spec, spec_counts);
        }
    }

    counts
}

fn count_document_archive_no_claim_observations(
    value: &Value,
    spec: &DocumentArchiveNoClaimFlagSpec,
    counts: &mut BTreeMap<String, usize>,
) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if spec.field_names.contains(&key.as_str()) {
                    let bucket = match privacy_boolean_observation(child) {
                        Some(false) => "explicit_false",
                        Some(true) => "truthy",
                        None => "other_present",
                    };
                    *counts.entry(bucket.to_string()).or_insert(0) += 1;
                }
                count_document_archive_no_claim_observations(child, spec, counts);
            }
        }
        Value::Array(values) => {
            for child in values {
                count_document_archive_no_claim_observations(child, spec, counts);
            }
        }
        _ => {}
    }
}

fn meeting_document_metadata_value(value: &Value) -> Result<(Value, &'static str), String> {
    match value {
        Value::Object(_) => Ok((value.clone(), "json_object")),
        Value::String(text) => match serde_json::from_str::<Value>(text) {
            Ok(parsed) if parsed.is_object() => Ok((parsed, "json_string_object")),
            Ok(_) => {
                Err("meeting_document JSON text metadata must decode to an object".to_string())
            }
            Err(_) => Ok((Value::String(text.clone()), "text_metadata")),
        },
        _ => Err("meeting_document must be a JSON object or text metadata string".to_string()),
    }
}

fn meeting_metadata_key_count(value: &Value, key_names: &[&str]) -> usize {
    match value {
        Value::String(text) => meeting_text_label_count(text, key_names),
        _ => meeting_metadata_key_count_json(value, key_names),
    }
}

fn meeting_metadata_key_count_json(value: &Value, key_names: &[&str]) -> usize {
    match value {
        Value::Object(map) => map
            .iter()
            .map(|(key, child)| {
                usize::from(
                    key_names.contains(&normalize_chronology_label(key).as_str())
                        && is_present_chronology_marker_value(child),
                ) + meeting_metadata_key_count_json(child, key_names)
            })
            .sum(),
        Value::Array(values) => values
            .iter()
            .map(|child| meeting_metadata_key_count_json(child, key_names))
            .sum(),
        _ => 0,
    }
}

fn meeting_marker_key_count(value: &Value, key_markers: &[&str]) -> usize {
    match value {
        Value::String(text) => meeting_text_marker_count(text, key_markers),
        _ => meeting_marker_key_count_json(value, key_markers),
    }
}

fn meeting_marker_key_count_json(value: &Value, key_markers: &[&str]) -> usize {
    match value {
        Value::Object(map) => map
            .iter()
            .map(|(key, child)| {
                let normalized = normalize_chronology_label(key);
                usize::from(
                    key_markers.iter().any(|marker| normalized.contains(marker))
                        && is_present_chronology_marker_value(child),
                ) + meeting_marker_key_count_json(child, key_markers)
            })
            .sum(),
        Value::Array(values) => values
            .iter()
            .map(|child| meeting_marker_key_count_json(child, key_markers))
            .sum(),
        _ => 0,
    }
}

fn meeting_text_label_count(text: &str, key_names: &[&str]) -> usize {
    let normalized_text = normalize_chronology_label(text);
    key_names
        .iter()
        .filter(|key| normalized_text.contains(*key))
        .count()
}

fn meeting_text_marker_count(text: &str, key_markers: &[&str]) -> usize {
    let normalized_text = normalize_chronology_label(text);
    let marker_count = key_markers
        .iter()
        .filter(|marker| normalized_text.contains(*marker))
        .count();
    let email_marker = usize::from(text.contains('@'));
    let phone_marker = usize::from(text.chars().filter(|ch| ch.is_ascii_digit()).count() >= 7);
    marker_count + email_marker + phone_marker
}

fn meeting_agenda_item_count_summary(value: &Value) -> Value {
    let explicit_count_observations =
        meeting_metadata_key_count(value, MEETING_AGENDA_ITEM_COUNT_KEYS);
    let (agenda_array_count, agenda_item_total) = meeting_agenda_array_counts(value);
    json!({
        "agenda_item_count_present": explicit_count_observations > 0 || agenda_array_count > 0,
        "explicit_count_observations": explicit_count_observations,
        "agenda_array_observations": agenda_array_count,
        "agenda_item_total_from_arrays": agenda_item_total,
        "ambiguous": explicit_count_observations + agenda_array_count > 1,
        "values_echoed": false
    })
}

fn meeting_agenda_array_counts(value: &Value) -> (usize, usize) {
    match value {
        Value::Object(map) => map
            .iter()
            .fold((0usize, 0usize), |mut counts, (key, child)| {
                let normalized = normalize_chronology_label(key);
                if MEETING_AGENDA_ARRAY_KEYS.contains(&normalized.as_str())
                    && let Value::Array(items) = child
                {
                    counts.0 += 1;
                    counts.1 += items.len();
                }
                let child_counts = meeting_agenda_array_counts(child);
                counts.0 += child_counts.0;
                counts.1 += child_counts.1;
                counts
            }),
        Value::Array(values) => values.iter().fold((0usize, 0usize), |mut counts, child| {
            let child_counts = meeting_agenda_array_counts(child);
            counts.0 += child_counts.0;
            counts.1 += child_counts.1;
            counts
        }),
        Value::String(text) => (
            meeting_text_label_count(text, MEETING_AGENDA_ARRAY_KEYS),
            0usize,
        ),
        _ => (0, 0),
    }
}

fn meeting_boolean_marker_counts(value: &Value, key_names: &[&str], text_label: &str) -> Value {
    let mut counts = initial_boolean_observation_counts();
    collect_meeting_boolean_marker_counts(value, key_names, text_label, &mut counts);
    let observation_count = counts.get("explicit_false").copied().unwrap_or(0)
        + counts.get("truthy").copied().unwrap_or(0)
        + counts.get("other_present").copied().unwrap_or(0);
    json!({
        "present": observation_count > 0,
        "observation_count": observation_count,
        "explicit_false": counts.get("explicit_false").copied().unwrap_or(0),
        "truthy": counts.get("truthy").copied().unwrap_or(0),
        "other_present": counts.get("other_present").copied().unwrap_or(0),
        "values_echoed": false
    })
}

fn collect_meeting_boolean_marker_counts(
    value: &Value,
    key_names: &[&str],
    text_label: &str,
    counts: &mut BTreeMap<String, usize>,
) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key_names.contains(&normalize_chronology_label(key).as_str()) {
                    let bucket = match privacy_boolean_observation(child) {
                        Some(false) => "explicit_false",
                        Some(true) => "truthy",
                        None => "other_present",
                    };
                    increment_count(counts, bucket.to_string());
                }
                collect_meeting_boolean_marker_counts(child, key_names, text_label, counts);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_meeting_boolean_marker_counts(child, key_names, text_label, counts);
            }
        }
        Value::String(text) if normalize_chronology_label(text).contains(text_label) => {
            increment_count(counts, "other_present".to_string());
        }
        _ => {}
    }
}

fn meeting_channel_classification_counts(value: &Value) -> BTreeMap<String, usize> {
    let mut counts = MEETING_CHANNEL_LABELS
        .iter()
        .map(|label| ((*label).to_string(), 0usize))
        .collect::<BTreeMap<_, _>>();
    collect_meeting_channel_classification_counts(value, &mut counts);
    if counts.values().sum::<usize>() == 0 {
        increment_count(&mut counts, "missing".to_string());
    }
    counts
}

fn collect_meeting_channel_classification_counts(
    value: &Value,
    counts: &mut BTreeMap<String, usize>,
) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if MEETING_METADATA_CANDIDATE_SPECS[3]
                    .key_names
                    .contains(&normalize_chronology_label(key).as_str())
                {
                    let label = child
                        .as_str()
                        .map(meeting_channel_label)
                        .unwrap_or_else(|| "other".to_string());
                    increment_count(counts, label);
                    continue;
                }
                collect_meeting_channel_classification_counts(child, counts);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_meeting_channel_classification_counts(child, counts);
            }
        }
        Value::String(text) => {
            let normalized = normalize_chronology_label(text);
            if normalized.contains("hybrid") {
                increment_count(counts, "hybrid".to_string());
            } else if normalized.contains("remote")
                || normalized.contains("online")
                || normalized.contains("video")
                || normalized.contains("teleconference")
            {
                increment_count(counts, "remote".to_string());
            } else if normalized.contains("in_person")
                || normalized.contains("presential")
                || normalized.contains("onsite")
            {
                increment_count(counts, "in_person".to_string());
            } else if normalized.contains("written") {
                increment_count(counts, "written".to_string());
            }
        }
        _ => {}
    }
}

fn meeting_channel_label(value: &str) -> String {
    let normalized = normalize_chronology_label(value);
    if normalized.contains("hybrid") {
        "hybrid".to_string()
    } else if normalized.contains("remote")
        || normalized.contains("online")
        || normalized.contains("video")
        || normalized.contains("teleconference")
    {
        "remote".to_string()
    } else if normalized.contains("in_person")
        || normalized.contains("presential")
        || normalized.contains("onsite")
    {
        "in_person".to_string()
    } else if normalized.contains("written") {
        "written".to_string()
    } else {
        "other".to_string()
    }
}

fn count_keys_matching(value: &Value, predicate: fn(&str) -> bool) -> usize {
    match value {
        Value::Object(map) => map
            .iter()
            .map(|(key, child)| usize::from(predicate(key)) + count_keys_matching(child, predicate))
            .sum(),
        Value::Array(values) => values
            .iter()
            .map(|child| count_keys_matching(child, predicate))
            .sum(),
        _ => 0,
    }
}

fn is_raw_report_reference_key(key: &str) -> bool {
    matches!(
        normalize_chronology_label(key).as_str(),
        "raw_report" | "raw_report_bytes" | "raw_report_content" | "raw_report_path"
    )
}

fn is_raw_payload_key(key: &str) -> bool {
    matches!(
        normalize_chronology_label(key).as_str(),
        "content_base64" | "data_base64" | "raw_bytes" | "raw_report_bytes" | "bytes"
    )
}

fn is_external_validator_key(key: &str) -> bool {
    let key = normalize_chronology_label(key);
    key.contains("external_validator") || key.contains("validator_report")
}

fn is_pdf_accessibility_key(key: &str) -> bool {
    let key = normalize_chronology_label(key);
    key.contains("pdf_accessibility")
        || key == "accessibility_report_json"
        || key == "pdf_ua_blockers"
}

fn document_archive_pdf_accessibility_marker(value: &Value) -> bool {
    let Some(map) = value.as_object() else {
        return false;
    };
    map.get("metadata_schema").and_then(Value::as_str)
        == Some("chancela-pdf-accessibility-evidence/v1")
        || map.get("evidence_kind").and_then(Value::as_str) == Some("pdf_accessibility_report")
        || map.contains_key("pdf_ua_blockers")
        || map.contains_key("accessibility_report_json")
}

fn chronology_events(chronology: &Value) -> Result<&[Value], String> {
    match chronology {
        Value::Array(events) => Ok(events.as_slice()),
        Value::Object(map) => map
            .get("events")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .ok_or_else(|| {
                "chronology must be an array of event objects or an object with an events array"
                    .to_string()
            }),
        _ => Err(
            "chronology must be an array of event objects or an object with an events array"
                .to_string(),
        ),
    }
}

fn chronology_classification(value: Option<LocatedValue<'_>>, missing_label: &str) -> String {
    let Some(located) = value else {
        return missing_label.to_string();
    };
    if is_unknown_comparison_value(located.value) {
        return "unknown".to_string();
    }
    match located.value {
        Value::String(value) => normalize_chronology_label(value),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(_) => "present_array".to_string(),
        Value::Object(_) => "present_object".to_string(),
        Value::Null => "unknown".to_string(),
    }
}

fn normalize_chronology_label(value: &str) -> String {
    let trimmed = value.trim().to_ascii_lowercase();
    let mut out = String::with_capacity(trimmed.len());
    let mut last_was_separator = false;
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | ':' | '/') {
            out.push(ch);
            last_was_separator = false;
        } else if !last_was_separator {
            out.push('_');
            last_was_separator = true;
        }
    }
    let normalized = out.trim_matches('_').to_string();
    if normalized.is_empty() {
        "unknown".to_string()
    } else {
        normalized
    }
}

fn chronology_date_value(event: &Value) -> Option<String> {
    first_located_value(event, CHRONOLOGY_EVENT_DATE_PATHS).and_then(|located| {
        match located.value {
            Value::String(value) if !is_unknown_comparison_value(located.value) => {
                Some(value.trim().to_string())
            }
            Value::Number(value) => Some(value.to_string()),
            _ => None,
        }
    })
}

fn has_chronology_evidence_marker(event: &Value) -> bool {
    CHRONOLOGY_EVIDENCE_PATHS.iter().any(|path| {
        value_at_dotted_path(event, path).is_some_and(is_present_chronology_marker_value)
    })
}

fn has_explicit_missing_evidence_marker(event: &Value) -> bool {
    CHRONOLOGY_MISSING_EVIDENCE_PATHS.iter().any(|path| {
        value_at_dotted_path(event, path).is_some_and(is_explicit_missing_evidence_marker_value)
    })
}

fn is_present_chronology_marker_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(_) => !is_unknown_comparison_value(value),
        Value::Bool(value) => *value,
        Value::Number(_) => true,
        Value::Array(values) => values.iter().any(is_present_chronology_marker_value),
        Value::Object(map) => map.values().any(is_present_chronology_marker_value),
    }
}

fn is_explicit_missing_evidence_marker_value(value: &Value) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::String(value) => matches!(
            normalize_chronology_label(value).as_str(),
            "true"
                | "yes"
                | "missing"
                | "absent"
                | "unavailable"
                | "required"
                | "needed"
                | "needs_review"
        ),
        Value::Number(value) => value.as_i64().is_some_and(|n| n != 0),
        Value::Array(values) => values.iter().any(is_explicit_missing_evidence_marker_value),
        Value::Object(map) => map.values().any(is_explicit_missing_evidence_marker_value),
        Value::Null => false,
    }
}

fn increment_count(counts: &mut BTreeMap<String, usize>, key: String) {
    *counts.entry(key).or_insert(0) += 1;
}

fn privacy_control_records<'a>(
    privacy_controls: &'a serde_json::Map<String, Value>,
    collection: &str,
) -> Result<&'a [Value], String> {
    let Some(records) = privacy_controls.get(collection) else {
        return Ok(&[]);
    };
    let records = records
        .as_array()
        .ok_or_else(|| format!("privacy_controls.{collection} must be an array"))?;
    if let Some(index) = records.iter().position(|record| !record.is_object()) {
        return Err(format!(
            "privacy_controls.{collection}[{index}] must be an object"
        ));
    }
    Ok(records.as_slice())
}

fn privacy_bounded_classification(
    value: Option<LocatedValue<'_>>,
    missing_label: &str,
    allowed_labels: &[&str],
) -> String {
    let Some(located) = value else {
        return missing_label.to_string();
    };
    if is_unknown_comparison_value(located.value) {
        return "unknown".to_string();
    }
    let normalized = match located.value {
        Value::String(value) => normalize_chronology_label(value),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(_) => "present_array".to_string(),
        Value::Object(_) => "present_object".to_string(),
        Value::Null => "unknown".to_string(),
    };
    if allowed_labels.contains(&normalized.as_str()) {
        normalized
    } else {
        "other".to_string()
    }
}

fn initial_privacy_false_claim_flag_counts() -> BTreeMap<String, BTreeMap<String, usize>> {
    PRIVACY_FALSE_CLAIM_FLAG_SPECS
        .iter()
        .map(|spec| {
            (
                spec.id.to_string(),
                BTreeMap::from([
                    ("explicit_false".to_string(), 0usize),
                    ("truthy".to_string(), 0usize),
                    ("other_present".to_string(), 0usize),
                ]),
            )
        })
        .collect()
}

fn privacy_false_claim_flag_counts_summary(
    counts: &BTreeMap<String, BTreeMap<String, usize>>,
) -> Value {
    let explicit_false_total = counts
        .values()
        .map(|counts| counts.get("explicit_false").copied().unwrap_or(0))
        .sum::<usize>();
    let truthy_total = counts
        .values()
        .map(|counts| counts.get("truthy").copied().unwrap_or(0))
        .sum::<usize>();
    let other_present_total = counts
        .values()
        .map(|counts| counts.get("other_present").copied().unwrap_or(0))
        .sum::<usize>();

    json!({
        "by_flag": counts,
        "totals": {
            "explicit_false": explicit_false_total,
            "truthy": truthy_total,
            "other_present": other_present_total
        }
    })
}

fn count_privacy_false_claim_flag_observations(
    value: &Value,
    spec: &PrivacyFalseClaimFlagSpec,
    counts: &mut BTreeMap<String, usize>,
) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if spec.field_names.contains(&key.as_str()) {
                    let bucket = match privacy_boolean_observation(child) {
                        Some(false) => "explicit_false",
                        Some(true) => "truthy",
                        None => "other_present",
                    };
                    *counts.entry(bucket.to_string()).or_insert(0) += 1;
                }
                count_privacy_false_claim_flag_observations(child, spec, counts);
            }
        }
        Value::Array(values) => {
            for child in values {
                count_privacy_false_claim_flag_observations(child, spec, counts);
            }
        }
        _ => {}
    }
}

fn privacy_boolean_observation(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Number(value) => value
            .as_i64()
            .map(|value| value != 0)
            .or_else(|| value.as_u64().map(|value| value != 0)),
        Value::String(value) => match normalize_chronology_label(value).as_str() {
            "true" | "yes" | "y" | "1" | "approved" | "accepted" | "completed" | "complete"
            | "executed" | "notified" | "filed" | "certified" => Some(true),
            "false" | "no" | "n" | "0" | "none" | "not_applicable" | "not_completed"
            | "pending" | "review_only" => Some(false),
            _ => None,
        },
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn privacy_receipt_counts(collection: &str, record: &Value) -> PrivacyReceiptCounts {
    let mut counts = PrivacyReceiptCounts::default();
    for path in PRIVACY_RECEIPT_ARRAY_PATHS {
        let Some(value) = value_at_dotted_path(record, path) else {
            continue;
        };
        let Some(receipts) = value.as_array() else {
            continue;
        };
        for receipt in receipts {
            counts.receipt_count += 1;
            if !receipt.is_object() {
                counts.other_receipt_count += 1;
                continue;
            }
            let mut kind = privacy_bounded_classification(
                first_located_value(receipt, PRIVACY_RECEIPT_KIND_PATHS),
                "missing",
                PRIVACY_RECEIPT_KIND_LABELS,
            );
            if kind == "missing" && collection == "transfer_controls" {
                kind = "review".to_string();
            }
            match kind.as_str() {
                "review" => counts.review_receipt_count += 1,
                "drill" => counts.drill_receipt_count += 1,
                _ => counts.other_receipt_count += 1,
            }
        }
    }
    if counts.receipt_count == 0 {
        privacy_advisory_summary_receipt_counts(record)
    } else {
        counts
    }
}

fn privacy_advisory_summary_receipt_counts(record: &Value) -> PrivacyReceiptCounts {
    let receipt_count = usize_at_paths(record, &["advisory_review.receipt_count", "receipt_count"]);
    let review_receipt_count = usize_at_paths(
        record,
        &[
            "advisory_review.review_receipt_count",
            "review_receipt_count",
        ],
    );
    let drill_receipt_count = usize_at_paths(
        record,
        &["advisory_review.drill_receipt_count", "drill_receipt_count"],
    );
    PrivacyReceiptCounts {
        receipt_count: receipt_count.unwrap_or(0),
        review_receipt_count: review_receipt_count.unwrap_or(0),
        drill_receipt_count: drill_receipt_count.unwrap_or(0),
        other_receipt_count: receipt_count
            .unwrap_or(0)
            .saturating_sub(review_receipt_count.unwrap_or(0) + drill_receipt_count.unwrap_or(0)),
    }
}

fn usize_at_paths(record: &Value, paths: &[&str]) -> Option<usize> {
    paths
        .iter()
        .find_map(|path| value_at_dotted_path(record, path).and_then(usize_from_value))
}

fn usize_or_array_len_at_paths(record: &Value, paths: &[&str]) -> Option<usize> {
    paths.iter().find_map(|path| {
        value_at_dotted_path(record, path).and_then(|value| match value {
            Value::Array(values) => Some(values.len()),
            _ => usize_from_value(value),
        })
    })
}

fn usize_from_value(value: &Value) -> Option<usize> {
    value.as_u64().and_then(|value| usize::try_from(value).ok())
}

fn initial_boolean_observation_counts() -> BTreeMap<String, usize> {
    BTreeMap::from([
        ("explicit_false".to_string(), 0usize),
        ("truthy".to_string(), 0usize),
        ("other_present".to_string(), 0usize),
        ("missing".to_string(), 0usize),
    ])
}

fn count_boolean_observation_at_path(
    record: &Value,
    path: &str,
    counts: &mut BTreeMap<String, usize>,
) {
    let bucket = match value_at_dotted_path(record, path) {
        Some(value) => match privacy_boolean_observation(value) {
            Some(false) => "explicit_false",
            Some(true) => "truthy",
            None => "other_present",
        },
        None => "missing",
    };
    increment_count(counts, bucket.to_string());
}

fn privacy_receipt_counts_value(counts: PrivacyReceiptCounts) -> Value {
    json!({
        "receipt_count": counts.receipt_count,
        "review_receipt_count": counts.review_receipt_count,
        "drill_receipt_count": counts.drill_receipt_count,
        "other_receipt_count": counts.other_receipt_count,
    })
}

fn compare_draft_signed_field(spec: &DraftSignedFieldSpec, draft: &Value, signed: &Value) -> Value {
    let draft_value = first_located_value(draft, spec.draft_paths);
    let signed_value = first_located_value(signed, spec.signed_paths);
    let status = match (draft_value, signed_value) {
        (Some(draft), Some(signed))
            if is_unknown_comparison_value(draft.value)
                || is_unknown_comparison_value(signed.value) =>
        {
            "unknown"
        }
        (Some(draft), Some(signed)) if draft.value == signed.value => "matched",
        (Some(_), Some(_)) => "different",
        (Some(_), None) => "missing_signed",
        (None, Some(_)) => "missing_draft",
        (None, None) => "unknown",
    };

    json!({
        "category": spec.category,
        "field": spec.field,
        "status": status,
        "draft": comparison_side(draft_value),
        "signed": comparison_side(signed_value),
    })
}

fn comparison_side(value: Option<LocatedValue<'_>>) -> Value {
    match value {
        Some(located) => json!({
            "path": located.path,
            "present": true,
            "unknown": is_unknown_comparison_value(located.value),
            "value": located.value,
        }),
        None => json!({
            "path": Value::Null,
            "present": false,
            "unknown": true,
            "value": Value::Null,
        }),
    }
}

fn first_located_value<'a>(
    root: &'a Value,
    paths: &'static [&'static str],
) -> Option<LocatedValue<'a>> {
    paths
        .iter()
        .find_map(|path| value_at_dotted_path(root, path).map(|value| LocatedValue { path, value }))
}

fn value_at_dotted_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

fn is_unknown_comparison_value(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "" | "unknown" | "not_known" | "not known" | "not_available" | "not available" | "n/a"
        ),
        _ => false,
    }
}

fn compared_draft_signed_paths() -> (BTreeSet<String>, BTreeSet<String>) {
    let mut draft_paths = BTreeSet::new();
    let mut signed_paths = BTreeSet::new();
    for spec in DRAFT_SIGNED_FIELD_SPECS {
        for path in spec.draft_paths {
            draft_paths.insert((*path).to_owned());
        }
        for path in spec.signed_paths {
            signed_paths.insert((*path).to_owned());
        }
    }
    (draft_paths, signed_paths)
}

fn unmapped_scalar_fields(
    root: &Value,
    side: &str,
    compared_paths: &BTreeSet<String>,
) -> Vec<Value> {
    let mut fields = Vec::new();
    collect_unmapped_scalar_fields(root, side, "", compared_paths, &mut fields);
    fields
}

fn collect_unmapped_scalar_fields(
    value: &Value,
    side: &str,
    path: &str,
    compared_paths: &BTreeSet<String>,
    out: &mut Vec<Value>,
) {
    match value {
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            for key in keys {
                let child_path = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{path}.{key}")
                };
                collect_unmapped_scalar_fields(&map[key], side, &child_path, compared_paths, out);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                collect_unmapped_scalar_fields(
                    child,
                    side,
                    &format!("{path}[{index}]"),
                    compared_paths,
                    out,
                );
            }
        }
        _ if !path.is_empty() && !compared_paths.contains(path) => {
            out.push(json!({
                "side": side,
                "path": path,
                "value": value,
                "comparison_status": "unmapped",
            }));
        }
        _ => {}
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MermaidGraphKind {
    Shareholders,
    Organs,
    Relationships,
}

impl MermaidGraphKind {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "shareholders" => Some(Self::Shareholders),
            "organs" => Some(Self::Organs),
            "relationships" => Some(Self::Relationships),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Shareholders => "shareholders",
            Self::Organs => "organs",
            Self::Relationships => "relationships",
        }
    }
}

fn mermaid_graph_kind_from_arguments(arguments: &Value) -> Result<MermaidGraphKind, String> {
    let args = match arguments {
        Value::Object(map) => map,
        Value::Null => return Err("missing required argument: kind".to_string()),
        _ => return Err("arguments must be a JSON object".to_string()),
    };
    let value = args
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing required argument: kind".to_string())?;
    MermaidGraphKind::parse(value).ok_or_else(|| {
        format!(
            "unsupported graph kind: {value}; expected one of: shareholders, organs, relationships"
        )
    })
}

fn mermaid_graph_success_text(
    outcome: &ApiOutcome,
    kind: MermaidGraphKind,
) -> Result<String, String> {
    let Some(value) = &outcome.value else {
        return Err("the integration API did not return JSON chronology data".to_string());
    };
    let mermaid = value
        .get("mermaid")
        .and_then(Value::as_object)
        .and_then(|graphs| graphs.get(kind.as_str()))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!(
                "the integration API chronology response did not include mermaid.{}",
                kind.as_str()
            )
        })?;
    let payload = json!({
        "kind": kind.as_str(),
        "mermaid": mermaid,
    });
    serde_json::to_string_pretty(&payload)
        .map_err(|e| format!("could not encode Mermaid graph response: {e}"))
}

fn is_ai_draft_tool(name: &str) -> bool {
    matches!(name, "draft_act" | "draft_minutes")
}

fn is_signature_bundle_validation_tool(name: &str) -> bool {
    name == "validate_signature_bundle"
}

fn ai_draft_success_text(
    outcome: &ApiOutcome,
    tool: &McpTool,
    resolved: &ResolvedCall,
    arguments: &Value,
) -> Result<String, String> {
    let Some(draft) = &outcome.value else {
        return Err(
            "the integration API did not return JSON draft data; refusing to present an AI draft"
                .to_string(),
        );
    };
    ensure_unsealed_draft_response(draft)?;

    let actor = arguments
        .get("actor")
        .and_then(Value::as_str)
        .unwrap_or("api");
    let created_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let source = json!({
        "surface": "mcp",
        "tool": tool.name,
        "endpoint": format!("{} {}", resolved.method.as_str(), resolved.path),
    });
    let source_provenance = ai_draft_source_provenance(tool, &source, arguments);
    let payload = json!({
        "kind": "ai_draft",
        "status": "draft",
        "non_authoritative": true,
        "human_verification_required": true,
        "legal_effect": AI_DRAFT_LEGAL_EFFECT,
        "verification": {
            "status": "pending",
            "checkpoint_status": HUMAN_VERIFICATION_PENDING,
            "checkpoint_allowed_statuses": human_verification_status_values(),
            "required": true,
            "accepted_as_legal_text": false,
            "legal_validity_claimed": false,
            "checkpoint": human_verification_checkpoint(),
        },
        "source_provenance": source_provenance,
        "provenance": {
            "source": source,
            "model": Value::Null,
            "provider": Value::Null,
            "created_at": created_at,
            "actor": actor,
        },
        "draft": draft,
    });

    serde_json::to_string_pretty(&payload)
        .map_err(|e| format!("could not encode AI draft provenance response: {e}"))
}

fn human_verification_status_values() -> Value {
    json!([
        HUMAN_VERIFICATION_PENDING,
        HUMAN_VERIFICATION_ACCEPTED,
        HUMAN_VERIFICATION_REJECTED,
    ])
}

fn human_verification_checkpoint() -> Value {
    json!({
        "status": HUMAN_VERIFICATION_PENDING,
        "allowed_statuses": human_verification_status_values(),
        "accepted_by_human": false,
        "rejected_by_human": false,
        "recorded_by": Value::Null,
        "recorded_at": Value::Null,
        "recorded_note": Value::Null,
        "transition_authority": HUMAN_VERIFICATION_AUTHORITY,
        "acceptance_claim": HUMAN_VERIFICATION_ACCEPTANCE_CLAIM,
        "legal_validity_claimed": false,
    })
}

fn ai_draft_source_provenance(tool: &McpTool, source: &Value, arguments: &Value) -> Value {
    let mut statement_sources = vec![json!({
        "path": "/draft",
        "source_type": "ai_suggestion",
        "source_label": tool.name,
        "human_verified": false,
        "verification_status": "pending",
        "human_verification_status": HUMAN_VERIFICATION_PENDING,
        "human_verification_status_values": human_verification_status_values(),
        "authoritative_source_claimed": false,
        "legal_validity_claimed": false,
    })];
    for (argument, path) in [
        ("book_id", "/draft/book_id"),
        ("title", "/draft/title"),
        ("channel", "/draft/channel"),
        ("retifies", "/draft/retifies"),
    ] {
        if arguments
            .get(argument)
            .is_some_and(|value| !value.is_null())
        {
            statement_sources.push(json!({
                "path": path,
                "source_type": "caller_supplied",
                "source_label": format!("arguments.{argument}"),
                "human_verified": false,
                "verification_status": "pending",
                "human_verification_status": HUMAN_VERIFICATION_PENDING,
                "human_verification_status_values": human_verification_status_values(),
                "authoritative_source_claimed": false,
                "legal_validity_claimed": false,
            }));
        }
    }

    json!({
        "schema_version": 1,
        "status": HUMAN_VERIFICATION_PENDING,
        "status_values": human_verification_status_values(),
        "human_verification_required": true,
        "accepted_as_legal_text": false,
        "legal_validity_claimed": false,
        "human_verification": human_verification_checkpoint(),
        "authoritative_source_claimed": false,
        "source": source.clone(),
        "statement_sources": statement_sources,
    })
}

fn attach_ai_draft_statement_sources(
    tool: &McpTool,
    resolved: &mut ResolvedCall,
    arguments: &Value,
) {
    if !is_ai_draft_tool(tool.name) {
        return;
    }
    let Some(Value::Object(body)) = &mut resolved.body else {
        return;
    };
    let source = json!({
        "surface": "mcp",
        "tool": tool.name,
        "endpoint": format!("{} {}", resolved.method.as_str(), resolved.path),
    });
    let statement_sources = ai_draft_source_provenance(tool, &source, arguments)
        .get("statement_sources")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let provenance = body
        .entry("ai_provenance".to_owned())
        .or_insert_with(|| json!({}));
    if let Value::Object(provenance) = provenance {
        provenance.insert("statement_sources".to_owned(), statement_sources);
    }
}

fn ensure_unsealed_draft_response(value: &Value) -> Result<(), String> {
    let obj = value.as_object().ok_or_else(|| {
        "draft API response was not a JSON object; refusing to present it as an AI draft"
            .to_string()
    })?;
    match obj.get("state").and_then(Value::as_str) {
        Some("Draft") => {}
        Some(other) => {
            return Err(format!(
                "draft API response state was {other:?}, not \"Draft\"; refusing to present it as an AI draft"
            ));
        }
        None => {
            return Err(
                "draft API response did not carry state=\"Draft\"; refusing to present it as an AI draft"
                    .to_string(),
            );
        }
    }

    for field in ["ata_number", "payload_digest", "seal_event_seq"] {
        if obj.get(field).is_some_and(|v| !v.is_null()) {
            return Err(format!(
                "draft API response carried sealed field {field}; refusing to present it as an AI draft"
            ));
        }
    }

    Ok(())
}

fn signature_bundle_validation_success_text(
    outcome: &ApiOutcome,
    resolved: &ResolvedCall,
    arguments: &Value,
) -> Result<String, String> {
    let Some(status_view) = &outcome.value else {
        return signature_bundle_unsupported_text(
            resolved,
            arguments,
            "unsupported",
            "the integration API did not return JSON signature status; no safe validation backend is available through MCP",
        );
    };

    let Some(evidence) = status_view.get("evidence").and_then(Value::as_object) else {
        return signature_bundle_unsupported_text(
            resolved,
            arguments,
            "not_implemented",
            "the integration API response did not include technical signature evidence",
        );
    };
    if evidence.get("status_scope").and_then(Value::as_str) != Some("technical_evidence_only") {
        return signature_bundle_unsupported_text(
            resolved,
            arguments,
            "not_implemented",
            "the integration API response did not mark signature evidence as technical_evidence_only",
        );
    }

    let payload = json!({
        "kind": "signature_bundle_validation",
        "status": "technical_evidence",
        "backend_supported": true,
        "scope": "technical_evidence_only",
        "legal_validation_claimed": false,
        "qualified_signature_claimed_by_mcp": false,
        "source": {
            "surface": "mcp",
            "endpoint": format!("{} {}", resolved.method.as_str(), resolved.path),
        },
        "act_id": arguments.get("act_id").cloned().unwrap_or(Value::Null),
        "signature_status": status_view.get("status").cloned().unwrap_or(Value::Null),
        "finalization": status_view.get("finalization").cloned().unwrap_or(Value::Null),
        "signed": status_view.get("signed").cloned().unwrap_or(Value::Null),
        "pending": status_view.get("pending").cloned().unwrap_or(Value::Null),
        "evidence": Value::Object(evidence.clone()),
        "backend_status": status_view,
    });
    serde_json::to_string_pretty(&payload)
        .map_err(|e| format!("could not encode signature evidence response: {e}"))
}

fn signature_bundle_unsupported_text(
    resolved: &ResolvedCall,
    arguments: &Value,
    status: &str,
    reason: &str,
) -> Result<String, String> {
    let payload = json!({
        "kind": "signature_bundle_validation",
        "status": status,
        "backend_supported": false,
        "scope": "technical_evidence_only",
        "legal_validation_claimed": false,
        "qualified_signature_claimed_by_mcp": false,
        "source": {
            "surface": "mcp",
            "endpoint": format!("{} {}", resolved.method.as_str(), resolved.path),
        },
        "act_id": arguments.get("act_id").cloned().unwrap_or(Value::Null),
        "reason": reason,
    });
    serde_json::to_string_pretty(&payload)
        .map_err(|e| format!("could not encode unsupported signature evidence response: {e}"))
}

fn should_render_as_binary(outcome: &ApiOutcome) -> bool {
    match outcome.content_type.as_deref() {
        Some(content_type) => !is_text_like_content_type(content_type),
        None => std::str::from_utf8(&outcome.bytes).is_err(),
    }
}

fn is_text_like_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();
    media_type.starts_with("text/")
        || media_type.eq_ignore_ascii_case("application/json")
        || media_type
            .rsplit_once('+')
            .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("json"))
}

fn binary_payload_text(outcome: &ApiOutcome) -> String {
    let payload = json!({
        "kind": "binary",
        "encoding": "base64",
        "content_type": outcome.content_type.as_deref().unwrap_or("application/octet-stream"),
        "suggested_filename": suggested_filename(outcome.content_disposition.as_deref()),
        "byte_length": outcome.bytes.len(),
        "data_base64": base64_encode(&outcome.bytes),
    });
    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| {
        r#"{"kind":"binary","encoding":"base64","content_type":"application/octet-stream","suggested_filename":null,"byte_length":0,"data_base64":""}"#.to_string()
    })
}

fn suggested_filename(content_disposition: Option<&str>) -> Option<String> {
    content_disposition.and_then(|value| {
        value.split(';').find_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            if name.trim().eq_ignore_ascii_case("filename") {
                let filename = unquote_header_value(value.trim());
                (!filename.is_empty()).then_some(filename)
            } else {
                None
            }
        })
    })
}

fn unquote_header_value(value: &str) -> String {
    let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
        return value.to_string();
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(escaped) = chars.next() {
                out.push(escaped);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);

        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0b0000_0011) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0b0000_1111) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0b0011_1111) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Honest, key-free message for a bridge failure surfaced to the model.
fn bridge_error_message(e: &BridgeError) -> String {
    // `BridgeError`'s Display is already scrubbed of the key; this just labels it.
    e.to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::{HttpRequest, HttpResponse};
    use crate::config::{McpConfig, Secret};
    use std::cell::RefCell;

    struct MockTransport {
        recorded: RefCell<Vec<HttpRequest>>,
        response: HttpResponse,
    }

    impl MockTransport {
        fn new(status: u16, body: &str) -> Self {
            Self::with_response(HttpResponse::text(status, body))
        }

        fn with_response(response: HttpResponse) -> Self {
            Self {
                recorded: RefCell::new(Vec::new()),
                response,
            }
        }
    }

    impl HttpTransport for MockTransport {
        fn send(&self, req: &HttpRequest) -> Result<HttpResponse, BridgeError> {
            self.recorded.borrow_mut().push(req.clone());
            Ok(self.response.clone())
        }
    }

    fn enabled_cfg() -> McpConfig {
        McpConfig {
            enabled: true,
            tenant_ai_enabled: true,
            api_key: Secret::new("chk_ab12cd_secretsecret"),
            ..McpConfig::default()
        }
    }

    fn req(method: &str, id: i64, params: Value) -> JsonRpcRequest {
        serde_json::from_value(
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }),
        )
        .unwrap()
    }

    #[test]
    fn off_by_default_from_config_refuses() {
        let cfg = McpConfig::default(); // disabled
        let result = McpServer::from_config(&cfg, MockTransport::new(200, "{}"));
        assert!(matches!(result, Err(McpError::Disabled)));
    }

    #[test]
    fn tenant_ai_gate_refuses_even_when_mcp_switch_is_on() {
        let cfg = McpConfig {
            enabled: true,
            api_key: Secret::new("chk_ab12cd_secretsecret"),
            ..McpConfig::default()
        };
        let result = McpServer::from_config(&cfg, MockTransport::new(200, "{}"));
        assert!(matches!(result, Err(McpError::Disabled)));
        assert_eq!(enabled_tool_count(&cfg), 0);
    }

    #[test]
    fn off_by_default_serve_stdio_serves_nothing() {
        // Disabled config: serve_stdio returns Ok without building a transport or reading stdin.
        assert!(serve_stdio(&McpConfig::default()).is_ok());
        assert_eq!(enabled_tool_count(&McpConfig::default()), 0);
    }

    #[test]
    fn tools_list_returns_the_catalog() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server.handle(&req("tools/list", 1, Value::Null)).unwrap();
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), catalog().len());
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"list_entities"));
        assert!(names.contains(&"list_companies"));
        assert!(names.contains(&"get_company_timeline"));
        assert!(names.contains(&"generate_mermaid_graph"));
        assert!(names.contains(&"search_legal_texts"));
        assert!(names.contains(&"draft_minutes"));
        assert!(names.contains(&"export_act_working_copy"));
        assert!(names.contains(&"validate_signature_bundle"));
        assert!(names.contains(&"prepare_archive_export"));
        assert!(names.contains(&"get_external_validator_report_metadata"));
        assert!(names.contains(&"seal_act"));
        let by_name = |name: &str| tools.iter().find(|t| t["name"] == name).unwrap();
        assert_eq!(
            by_name("validate_signature_bundle")["annotations"]["readOnlyHint"],
            json!(true)
        );
        assert_eq!(
            by_name("prepare_archive_export")["annotations"]["readOnlyHint"],
            json!(false)
        );
        // schema + annotations present
        assert!(tools[0]["inputSchema"].is_object());
        assert!(tools[0]["annotations"]["readOnlyHint"].is_boolean());
    }

    #[test]
    fn prompts_list_exposes_static_guidance_without_http_or_secret() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req("prompts/list", 23, Value::Null))
            .unwrap();
        let result = resp.result.unwrap();
        let prompts = result["prompts"].as_array().unwrap();
        assert_eq!(prompts.len(), PROMPT_CATALOG.len());
        let by_name = |name: &str| {
            prompts
                .iter()
                .find(|prompt| prompt["name"].as_str() == Some(name))
                .unwrap()
        };
        let draft_minutes = by_name(DRAFT_MINUTES_REVIEW_PROMPT_NAME);
        assert_eq!(
            draft_minutes["name"],
            json!(DRAFT_MINUTES_REVIEW_PROMPT_NAME)
        );
        assert_eq!(
            draft_minutes["title"],
            json!(DRAFT_MINUTES_REVIEW_PROMPT_TITLE)
        );
        assert_eq!(
            draft_minutes["description"],
            json!(DRAFT_MINUTES_REVIEW_PROMPT_DESCRIPTION)
        );
        assert_eq!(draft_minutes["arguments"], json!([]));
        let compliance_pack = by_name(COMPLIANCE_PACK_GAP_REVIEW_PROMPT_NAME);
        assert_eq!(
            compliance_pack["title"],
            json!(COMPLIANCE_PACK_GAP_REVIEW_PROMPT_TITLE)
        );
        assert_eq!(
            compliance_pack["description"],
            json!(COMPLIANCE_PACK_GAP_REVIEW_PROMPT_DESCRIPTION)
        );
        assert_eq!(compliance_pack["arguments"], json!([]));
        let paper_book = by_name(PAPER_BOOK_OCR_REVIEW_PROMPT_NAME);
        assert_eq!(
            paper_book["title"],
            json!(PAPER_BOOK_OCR_REVIEW_PROMPT_TITLE)
        );
        assert_eq!(
            paper_book["description"],
            json!(PAPER_BOOK_OCR_REVIEW_PROMPT_DESCRIPTION)
        );
        assert_eq!(paper_book["arguments"], json!([]));
        let workflow_provenance = by_name(WORKFLOW_PROVENANCE_REVIEW_PROMPT_NAME);
        assert_eq!(
            workflow_provenance["title"],
            json!(WORKFLOW_PROVENANCE_REVIEW_PROMPT_TITLE)
        );
        assert_eq!(
            workflow_provenance["description"],
            json!(WORKFLOW_PROVENANCE_REVIEW_PROMPT_DESCRIPTION)
        );
        assert_eq!(workflow_provenance["arguments"], json!([]));
        let draft_signed = by_name(DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_NAME);
        assert_eq!(
            draft_signed["title"],
            json!(DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_TITLE)
        );
        assert_eq!(
            draft_signed["description"],
            json!(DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_DESCRIPTION)
        );
        assert_eq!(draft_signed["arguments"], json!([]));
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("chk_ab12cd_secretsecret"));
        assert!(!encoded.contains("secretsecret"));
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn prompts_get_returns_human_review_checklist_without_http_or_secret() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req(
                "prompts/get",
                24,
                json!({ "name": DRAFT_MINUTES_REVIEW_PROMPT_NAME }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        assert_eq!(
            result["description"],
            json!(DRAFT_MINUTES_REVIEW_PROMPT_DESCRIPTION)
        );
        let messages = result["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], json!("user"));
        assert_eq!(messages[0]["content"]["type"], json!("text"));
        let text = messages[0]["content"]["text"].as_str().unwrap();
        for needle in [
            "guidance only",
            "no legal validity",
            "does not sign or seal",
            "does not call any hidden",
            "suggestions only",
        ] {
            assert!(
                text.contains(needle),
                "prompt should contain {needle:?}: {text}"
            );
        }
        assert!(!text.contains("chk_ab12cd_secretsecret"));
        assert!(!text.contains("secretsecret"));
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn prompts_get_returns_compliance_pack_gap_review_without_http_or_secret() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req(
                "prompts/get",
                45,
                json!({ "name": COMPLIANCE_PACK_GAP_REVIEW_PROMPT_NAME }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        assert_eq!(
            result["description"],
            json!(COMPLIANCE_PACK_GAP_REVIEW_PROMPT_DESCRIPTION)
        );
        let messages = result["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], json!("user"));
        assert_eq!(messages[0]["content"]["type"], json!("text"));
        let text = messages[0]["content"]["text"].as_str().unwrap();
        for needle in [
            "DSR",
            "retention",
            "archive",
            "credential secrets",
            "no legal validity",
            "no hidden provider call",
        ] {
            assert!(
                text.contains(needle),
                "prompt should contain {needle:?}: {text}"
            );
        }
        assert!(!text.contains("chk_ab12cd_secretsecret"));
        assert!(!text.contains("secretsecret"));
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn prompts_get_returns_paper_book_ocr_canonical_review_without_http_or_secret() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req(
                "prompts/get",
                47,
                json!({ "name": PAPER_BOOK_OCR_REVIEW_PROMPT_NAME }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        assert_eq!(
            result["description"],
            json!(PAPER_BOOK_OCR_REVIEW_PROMPT_DESCRIPTION)
        );
        let messages = result["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], json!("user"));
        assert_eq!(messages[0]["content"]["type"], json!("text"));
        let text = messages[0]["content"]["text"].as_str().unwrap();
        for needle in [
            "paper-book OCR",
            "canonical-conversion",
            "source images",
            "confidence scores",
            "ledger evidence",
            "no legal validity",
            "no signing",
            "no hidden provider call",
        ] {
            assert!(
                text.contains(needle),
                "prompt should contain {needle:?}: {text}"
            );
        }
        assert!(!text.contains("chk_ab12cd_secretsecret"));
        assert!(!text.contains("secretsecret"));
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn prompts_get_returns_workflow_provenance_review_without_http_or_secret() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req(
                "prompts/get",
                48,
                json!({ "name": WORKFLOW_PROVENANCE_REVIEW_PROMPT_NAME }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        assert_eq!(
            result["description"],
            json!(WORKFLOW_PROVENANCE_REVIEW_PROMPT_DESCRIPTION)
        );
        let messages = result["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], json!("user"));
        assert_eq!(messages[0]["content"]["type"], json!("text"));
        let text = messages[0]["content"]["text"].as_str().unwrap();
        for needle in [
            "workflow provenance",
            "source records",
            "ledger evidence",
            "human review",
            "no legal validity",
            "no hidden provider call",
        ] {
            assert!(
                text.contains(needle),
                "prompt should contain {needle:?}: {text}"
            );
        }
        assert!(!text.contains("chk_ab12cd_secretsecret"));
        assert!(!text.contains("secretsecret"));
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn prompts_get_returns_draft_signed_comparison_review_without_http_or_secret() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req(
                "prompts/get",
                51,
                json!({ "name": DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_NAME }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        assert_eq!(
            result["description"],
            json!(DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_DESCRIPTION)
        );
        let messages = result["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], json!("user"));
        assert_eq!(messages[0]["content"]["type"], json!("text"));
        let text = messages[0]["content"]["text"].as_str().unwrap();
        for needle in [
            "draft",
            "signed artifact",
            "Digest comparison",
            "Text comparison",
            "Version comparison",
            "Mismatch triage",
            "Human-review notes",
            "no legal validity",
            "no source certification",
            "no external validation",
            "no signature qualification",
            "no hidden provider call",
        ] {
            assert!(
                text.contains(needle),
                "prompt should contain {needle:?}: {text}"
            );
        }
        assert!(!text.contains("chk_ab12cd_secretsecret"));
        assert!(!text.contains("secretsecret"));
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn prompts_get_rejects_invalid_prompt_params_without_http() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();

        let missing_params = server.handle(&req("prompts/get", 25, Value::Null)).unwrap();
        assert_eq!(missing_params.error.unwrap().code, codes::INVALID_PARAMS);

        let unknown = server
            .handle(&req("prompts/get", 26, json!({ "name": "unknown_prompt" })))
            .unwrap();
        assert_eq!(unknown.error.unwrap().code, codes::INVALID_PARAMS);

        let arguments = server
            .handle(&req(
                "prompts/get",
                27,
                json!({
                    "name": DRAFT_MINUTES_REVIEW_PROMPT_NAME,
                    "arguments": { "draft_text": "caller supplied text" }
                }),
            ))
            .unwrap();
        let error = arguments.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("does not accept arguments"));

        let workflow_arguments = server
            .handle(&req(
                "prompts/get",
                49,
                json!({
                    "name": WORKFLOW_PROVENANCE_REVIEW_PROMPT_NAME,
                    "arguments": { "workflow_id": "wf_123" }
                }),
            ))
            .unwrap();
        let error = workflow_arguments.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("does not accept arguments"));

        let draft_signed_arguments = server
            .handle(&req(
                "prompts/get",
                52,
                json!({
                    "name": DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_NAME,
                    "arguments": { "draft_id": "act_draft_123" }
                }),
            ))
            .unwrap();
        let error = draft_signed_arguments.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("does not accept arguments"));

        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_list_exposes_local_static_resources() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req("resources/list", 20, Value::Null))
            .unwrap();
        let result = resp.result.unwrap();
        let resources = result["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 8);
        let by_uri = |uri: &str| {
            resources
                .iter()
                .find(|resource| resource["uri"].as_str() == Some(uri))
                .unwrap()
        };
        let status = by_uri(MCP_STATUS_RESOURCE_URI);
        assert_eq!(status["mimeType"], json!("application/json"));
        assert_eq!(
            status["annotations"]["audience"],
            json!(["user", "assistant"])
        );
        let spec_09 = by_uri(MCP_SPEC_09_COVERAGE_RESOURCE_URI);
        assert_eq!(spec_09["mimeType"], json!("application/json"));
        assert_eq!(
            spec_09["annotations"]["audience"],
            json!(["user", "assistant"])
        );
        let workflow_provenance = by_uri(MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI);
        assert_eq!(workflow_provenance["mimeType"], json!("application/json"));
        assert_eq!(
            workflow_provenance["annotations"]["audience"],
            json!(["user", "assistant"])
        );
        let draft_signed = by_uri(MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI);
        assert_eq!(draft_signed["mimeType"], json!("application/json"));
        assert_eq!(
            draft_signed["annotations"]["audience"],
            json!(["user", "assistant"])
        );
        let chronology = by_uri(MCP_CHRONOLOGY_REVIEW_SUMMARY_RESOURCE_URI);
        assert_eq!(chronology["mimeType"], json!("application/json"));
        assert_eq!(
            chronology["annotations"]["audience"],
            json!(["user", "assistant"])
        );
        let privacy = by_uri(MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI);
        assert_eq!(privacy["mimeType"], json!("application/json"));
        assert_eq!(
            privacy["annotations"]["audience"],
            json!(["user", "assistant"])
        );
        let document_archive = by_uri(MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI);
        assert_eq!(document_archive["mimeType"], json!("application/json"));
        assert_eq!(
            document_archive["annotations"]["audience"],
            json!(["user", "assistant"])
        );
        let meeting_metadata = by_uri(MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI);
        assert_eq!(meeting_metadata["mimeType"], json!("application/json"));
        assert_eq!(
            meeting_metadata["annotations"]["audience"],
            json!(["user", "assistant"])
        );
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_mcp_status_returns_operability_without_http_or_secret() {
        let cfg = McpConfig {
            base_url: "http://127.0.0.1:9191".to_string(),
            base_path: "/api/v1".to_string(),
            enabled_tools: EnabledTools::List(vec!["list_entities".into()]),
            ..enabled_cfg()
        };
        let server = McpServer::from_config(&cfg, MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req(
                "resources/read",
                21,
                json!({ "uri": MCP_STATUS_RESOURCE_URI }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        let contents = result["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], json!(MCP_STATUS_RESOURCE_URI));
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
        let text = contents[0]["text"].as_str().unwrap();
        assert!(!text.contains("chk_ab12cd_secretsecret"));
        assert!(!text.contains("secretsecret"));

        let status: Value = serde_json::from_str(text).unwrap();
        assert_eq!(status["kind"], json!("chancela_mcp_status"));
        assert_eq!(status["status"], json!("serving"));
        assert_eq!(status["server"]["name"], json!(SERVER_NAME));
        assert_eq!(
            status["server"]["protocol_version"],
            json!(PROTOCOL_VERSION)
        );
        assert_eq!(status["transport"]["active"], json!("stdio"));
        assert_eq!(status["transport"]["non_stdio_served"], json!(false));
        assert_eq!(status["gates"]["mcp_enabled"], json!(true));
        assert_eq!(status["gates"]["tenant_ai_enabled"], json!(true));
        assert_eq!(status["gates"]["api_key_configured"], json!(true));
        assert_eq!(status["gates"]["api_key_exposed"], json!(false));
        assert_eq!(
            status["integration_api"]["base_url"],
            json!("http://127.0.0.1:9191")
        );
        assert_eq!(
            status["integration_api"]["health_probe"],
            json!("not_performed")
        );
        assert_eq!(status["tools"]["enabled"], json!(1));
        assert_eq!(status["tools"]["catalog"], json!(catalog().len()));
        assert_eq!(status["security"]["secrets_in_resource"], json!(false));
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_workflow_provenance_review_returns_static_categories_without_http_or_secret()
    {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req(
                "resources/read",
                50,
                json!({ "uri": MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        let contents = result["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(
            contents[0]["uri"],
            json!(MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI)
        );
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
        let text = contents[0]["text"].as_str().unwrap();
        assert!(!text.contains("chk_ab12cd_secretsecret"));
        assert!(!text.contains("secretsecret"));

        let review: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            review["kind"],
            json!("chancela_mcp_workflow_provenance_review")
        );
        assert_eq!(review["offline"], json!(true));
        assert_eq!(review["static"], json!(true));
        assert_eq!(review["arguments"], json!([]));
        assert_eq!(review["bridge_calls"], json!(false));
        assert_eq!(review["api_calls"], json!(false));
        assert_eq!(review["provider_calls"], json!(false));
        assert_eq!(review["secrets_in_resource"], json!(false));
        assert_eq!(review["claims"]["legal_validity"], json!(false));
        assert_eq!(review["claims"]["source_certification"], json!(false));
        assert_eq!(review["claims"]["provider"], json!(false));
        assert_eq!(review["claims"]["trust"], json!(false));
        assert_eq!(review["claims"]["external"], json!(false));

        let categories = review["review_categories"].as_array().unwrap();
        let category_ids = categories
            .iter()
            .map(|category| category["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        for expected in [
            "act_lifecycle",
            "book_chain",
            "source_records",
            "ledger_events",
            "imported_evidence",
            "signature_archive_technical_evidence",
            "operator_review_notes",
        ] {
            assert!(
                category_ids.contains(&expected),
                "resource should include category {expected:?}: {review}"
            );
        }
        for category in categories {
            assert!(!category["checkpoints"].as_array().unwrap().is_empty());
        }
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_workflow_provenance_review_accepts_arguments_and_counts_without_echoing_raw_values()
     {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let evidence_a = json!({
            "workflows": [
                {
                    "workflow_state": "draft",
                    "human_review": { "status": "pending" },
                    "ledger_event_id": "ledger-secret-1",
                    "archive_ref": "archive-secret-1",
                    "signature_ref": "signature-secret-1",
                    "content_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                },
                {
                    "lifecycle_status": "signed",
                    "human_review_decision": "accepted",
                    "imported_document_id": "imported-secret-1",
                    "generated_document_ref": "generated-secret-1",
                    "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "raw_document_text": "RAW WORKFLOW BODY THAT MUST NOT ECHO",
                    "contact": {
                        "name": "Sensitive Reviewer",
                        "email": "reviewer@example.com",
                        "phone": "+351 900 111 222"
                    },
                    "credentials": "Bearer chk_ab12cd_secretsecret"
                },
                {
                    "workflow_state": "archived",
                    "ledger_ref": "ledger-secret-2",
                    "manifest_id": "manifest-secret-1",
                    "source_record_id": "source-secret-1",
                    "checksum": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "access_code": "919191",
                    "uploaded_bytes": "AAECAwQF"
                }
            ]
        });
        let evidence_b = json!({
            "workflows": [
                {
                    "uploaded_bytes": "AAECAwQF",
                    "access_code": "919191",
                    "checksum": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "source_record_id": "source-secret-1",
                    "manifest_id": "manifest-secret-1",
                    "ledger_ref": "ledger-secret-2",
                    "workflow_state": "archived"
                },
                {
                    "credentials": "Bearer chk_ab12cd_secretsecret",
                    "contact": {
                        "phone": "+351 900 111 222",
                        "email": "reviewer@example.com",
                        "name": "Sensitive Reviewer"
                    },
                    "raw_document_text": "RAW WORKFLOW BODY THAT MUST NOT ECHO",
                    "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "generated_document_ref": "generated-secret-1",
                    "imported_document_id": "imported-secret-1",
                    "human_review_decision": "accepted",
                    "lifecycle_status": "signed"
                },
                {
                    "content_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "signature_ref": "signature-secret-1",
                    "archive_ref": "archive-secret-1",
                    "ledger_event_id": "ledger-secret-1",
                    "human_review": { "status": "pending" },
                    "workflow_state": "draft"
                }
            ]
        });
        let params_a = json!({
            "uri": MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI,
            "arguments": {
                "workflow_evidence": evidence_a
            }
        });
        let params_b = json!({
            "arguments": {
                "workflow_evidence": evidence_b
            },
            "uri": MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI
        });

        let response_a = server
            .handle(&req("resources/read", 85, params_a))
            .unwrap()
            .result
            .unwrap();
        let response_b = server
            .handle(&req("resources/read", 86, params_b))
            .unwrap()
            .result
            .unwrap();
        let text_a = response_a["contents"][0]["text"].as_str().unwrap();
        let text_b = response_b["contents"][0]["text"].as_str().unwrap();
        assert_eq!(
            text_a, text_b,
            "workflow provenance report output must be deterministic"
        );
        for sensitive in [
            "ledger-secret-1",
            "archive-secret-1",
            "signature-secret-1",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "imported-secret-1",
            "generated-secret-1",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "RAW WORKFLOW BODY THAT MUST NOT ECHO",
            "Sensitive Reviewer",
            "reviewer@example.com",
            "+351 900 111 222",
            "chk_ab12cd_secretsecret",
            "ledger-secret-2",
            "manifest-secret-1",
            "source-secret-1",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "919191",
            "AAECAwQF",
        ] {
            assert!(
                !text_a.contains(sensitive),
                "workflow provenance report must not echo caller value {sensitive:?}: {text_a}"
            );
        }
        assert!(!text_a.contains("\"legal_validity\": true"));
        assert!(!text_a.contains("\"source_certification\": true"));
        assert!(!text_a.contains("\"workflow_completion\": true"));
        assert!(!text_a.contains("\"provider_assurance\": true"));
        assert!(!text_a.contains("\"trust\": true"));
        assert!(!text_a.contains("\"external_validation\": true"));
        assert!(!text_a.contains("\"signature_qualification\": true"));
        assert!(!text_a.contains("\"extraction_accuracy\": true"));

        let report: Value = serde_json::from_str(text_a).unwrap();
        assert_eq!(
            report["kind"],
            json!("chancela_mcp_workflow_provenance_review_report")
        );
        assert_eq!(report["local_json_only"], json!(true));
        assert_eq!(report["bridge_calls"], json!(false));
        assert_eq!(report["api_calls"], json!(false));
        assert_eq!(report["provider_calls"], json!(false));
        assert_eq!(report["ai_provider_calls"], json!(false));
        assert_eq!(report["raw_document_text_echoed"], json!(false));
        assert_eq!(report["raw_uploaded_bytes_echoed"], json!(false));
        assert_eq!(report["contacts_echoed"], json!(false));
        assert_eq!(
            report["credentials_secrets_access_codes_echoed"],
            json!(false)
        );
        assert_eq!(report["claims"]["legal_validity"], json!(false));
        assert_eq!(report["claims"]["source_certification"], json!(false));
        assert_eq!(report["claims"]["workflow_completion"], json!(false));
        assert_eq!(report["claims"]["provider_assurance"], json!(false));
        assert_eq!(report["claims"]["trust"], json!(false));
        assert_eq!(report["claims"]["external_validation"], json!(false));
        assert_eq!(report["claims"]["signature_qualification"], json!(false));
        assert_eq!(report["claims"]["extraction_accuracy"], json!(false));

        let summary = &report["workflow_provenance_summary"];
        assert_eq!(summary["input_format"], json!("json_object"));
        assert_eq!(summary["record_count"], json!(3));
        assert_eq!(
            summary["workflow_lifecycle_state_counts"]["draft"],
            json!(1)
        );
        assert_eq!(
            summary["workflow_lifecycle_state_counts"]["signed"],
            json!(1)
        );
        assert_eq!(
            summary["workflow_lifecycle_state_counts"]["archived"],
            json!(1)
        );
        assert_eq!(
            summary["human_review_decision_status_counts"]["pending"],
            json!(1)
        );
        assert_eq!(
            summary["human_review_decision_status_counts"]["accepted"],
            json!(1)
        );
        assert_eq!(
            summary["human_review_decision_status_counts"]["missing"],
            json!(1)
        );
        assert_eq!(summary["missing_human_review_decision_count"], json!(1));
        assert_eq!(summary["evidence_marker_counts"]["ledger_refs"], json!(2));
        assert_eq!(summary["evidence_marker_counts"]["archive_refs"], json!(2));
        assert_eq!(
            summary["evidence_marker_counts"]["signature_refs"],
            json!(1)
        );
        assert_eq!(
            summary["evidence_marker_counts"]["digest_markers"],
            json!(3)
        );
        assert_eq!(
            summary["evidence_marker_counts"]["imported_generated_document_refs"],
            json!(3)
        );
        assert!(
            summary["warning_counts"]["raw_content_field_count"]
                .as_u64()
                .unwrap()
                >= 2
        );
        assert!(
            summary["warning_counts"]["contact_field_count"]
                .as_u64()
                .unwrap()
                >= 1
        );
        assert!(
            summary["warning_counts"]["secret_like_field_count"]
                .as_u64()
                .unwrap()
                >= 2
        );
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_workflow_provenance_review_rejects_bad_arguments_and_extra_params() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();

        let missing_workflow_evidence = server
            .handle(&req(
                "resources/read",
                87,
                json!({
                    "uri": MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI,
                    "arguments": {}
                }),
            ))
            .unwrap();
        let error = missing_workflow_evidence.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("workflow_evidence must be supplied"));

        let extra_argument = server
            .handle(&req(
                "resources/read",
                88,
                json!({
                    "uri": MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI,
                    "arguments": {
                        "workflow_evidence": {},
                        "raw_document_text": "must not be accepted"
                    }
                }),
            ))
            .unwrap();
        let error = extra_argument.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("accept only workflow_evidence"));

        let unsupported_workflow_evidence = server
            .handle(&req(
                "resources/read",
                89,
                json!({
                    "uri": MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI,
                    "arguments": {
                        "workflow_evidence": 42
                    }
                }),
            ))
            .unwrap();
        let error = unsupported_workflow_evidence.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(
            error
                .message
                .contains("workflow_evidence must be a JSON object, array, or text string")
        );

        let extra_param = server
            .handle(&req(
                "resources/read",
                90,
                json!({
                    "uri": MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI,
                    "cursor": "ignored"
                }),
            ))
            .unwrap();
        let error = extra_param.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("uri plus arguments"));

        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_draft_signed_comparison_review_returns_static_categories_without_http_or_secret()
     {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req(
                "resources/read",
                53,
                json!({ "uri": MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        let contents = result["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(
            contents[0]["uri"],
            json!(MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI)
        );
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
        let text = contents[0]["text"].as_str().unwrap();
        assert!(!text.contains("chk_ab12cd_secretsecret"));
        assert!(!text.contains("secretsecret"));

        let review: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            review["kind"],
            json!("chancela_mcp_draft_signed_comparison_review")
        );
        assert_eq!(review["offline"], json!(true));
        assert_eq!(review["static"], json!(true));
        assert_eq!(review["local_json_only"], json!(true));
        assert_eq!(review["arguments"], json!([]));
        assert_eq!(review["bridge_calls"], json!(false));
        assert_eq!(review["api_calls"], json!(false));
        assert_eq!(review["provider_calls"], json!(false));
        assert_eq!(review["secrets_in_resource"], json!(false));
        assert_eq!(review["claims"]["legal_validity"], json!(false));
        assert_eq!(review["claims"]["source_certification"], json!(false));
        assert_eq!(review["claims"]["provider"], json!(false));
        assert_eq!(review["claims"]["trust"], json!(false));
        assert_eq!(review["claims"]["external_validation"], json!(false));
        assert_eq!(review["claims"]["signature_qualification"], json!(false));

        let categories = review["comparison_categories"].as_array().unwrap();
        let category_ids = categories
            .iter()
            .map(|category| category["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        for expected in [
            "draft_identifiers",
            "signed_artifact_identifiers",
            "digest_comparison",
            "text_comparison",
            "version_lifecycle_comparison",
            "mismatch_triage",
            "human_review_notes",
        ] {
            assert!(
                category_ids.contains(&expected),
                "resource should include category {expected:?}: {review}"
            );
        }
        assert_eq!(
            review["mismatch_triage"]["labels"],
            json!([
                "exact_match",
                "expected_formatting_change",
                "authorized_content_edit",
                "unresolved_mismatch",
                "blocking_mismatch"
            ])
        );
        for category in categories {
            assert!(!category["checkpoints"].as_array().unwrap().is_empty());
        }
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_draft_signed_comparison_report_accepts_arguments_and_is_deterministic_without_http_or_secret()
     {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let params_a = json!({
            "uri": MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI,
            "arguments": {
                "case_id": "case-7",
                "draft": {
                    "id": "act-7",
                    "book_id": "book-7",
                    "entity_id": "ent-7",
                    "state": "Draft",
                    "version": 3,
                    "rendered_document_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "artifact_ref": "drafts/act-7.pdf",
                    "source_record_id": "unknown",
                    "reviewer_note": "caller local note",
                    "signed_pdf_digest": "draft-side-wrong-alias"
                },
                "signed": {
                    "source_act_id": "act-7",
                    "book_id": "book-7",
                    "entity_id": "ent-7",
                    "signature_status": "signed",
                    "signed_version": 3,
                    "signed_document_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "signed_artifact_uri": "signed/act-7.pdf",
                    "signing_time": "2026-07-10T10:00:00Z",
                    "source_record_id": "src-7",
                    "draft_digest": "signed-side-wrong-alias",
                    "signature": {
                        "bundle_id": "sig-7"
                    }
                }
            }
        });
        let params_b = json!({
            "arguments": {
                "signed": {
                    "signature": {
                        "bundle_id": "sig-7"
                    },
                    "source_record_id": "src-7",
                    "draft_digest": "signed-side-wrong-alias",
                    "signing_time": "2026-07-10T10:00:00Z",
                    "signed_artifact_uri": "signed/act-7.pdf",
                    "signed_document_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "signed_version": 3,
                    "signature_status": "signed",
                    "entity_id": "ent-7",
                    "book_id": "book-7",
                    "source_act_id": "act-7"
                },
                "draft": {
                    "reviewer_note": "caller local note",
                    "source_record_id": "unknown",
                    "signed_pdf_digest": "draft-side-wrong-alias",
                    "artifact_ref": "drafts/act-7.pdf",
                    "rendered_document_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "version": 3,
                    "state": "Draft",
                    "entity_id": "ent-7",
                    "book_id": "book-7",
                    "id": "act-7"
                },
                "case_id": "case-7"
            },
            "uri": MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI
        });

        let response_a = server
            .handle(&req("resources/read", 54, params_a))
            .unwrap()
            .result
            .unwrap();
        let response_b = server
            .handle(&req("resources/read", 55, params_b))
            .unwrap()
            .result
            .unwrap();
        let text_a = response_a["contents"][0]["text"].as_str().unwrap();
        let text_b = response_b["contents"][0]["text"].as_str().unwrap();
        assert_eq!(text_a, text_b, "report output must be deterministic");
        assert!(!text_a.contains("chk_ab12cd_secretsecret"));
        assert!(!text_a.contains("secretsecret"));
        assert!(!text_a.contains("\"legal_validity\": true"));
        assert!(!text_a.contains("\"signature_validity\": true"));
        assert!(!text_a.contains("\"provider_completion\": true"));

        let report: Value = serde_json::from_str(text_a).unwrap();
        assert_eq!(
            report["kind"],
            json!("chancela_mcp_draft_signed_comparison_report")
        );
        assert_eq!(report["case_id"], json!("case-7"));
        assert_eq!(
            report["source"],
            json!("local_mcp_deterministic_comparator")
        );
        assert_eq!(report["offline"], json!(true));
        assert_eq!(report["local_json_only"], json!(true));
        assert_eq!(report["deterministic"], json!(true));
        assert_eq!(report["bridge_calls"], json!(false));
        assert_eq!(report["api_calls"], json!(false));
        assert_eq!(report["ai_provider_calls"], json!(false));
        assert_eq!(report["signature_validation_performed"], json!(false));
        assert_eq!(report["trust_validation_performed"], json!(false));
        assert_eq!(report["claims"]["legal_validity"], json!(false));
        assert_eq!(report["claims"]["source_certification"], json!(false));
        assert_eq!(report["claims"]["provider"], json!(false));
        assert_eq!(report["claims"]["trust"], json!(false));
        assert_eq!(report["claims"]["external_validation"], json!(false));
        assert_eq!(report["claims"]["signature_qualification"], json!(false));

        let field_results = report["field_results"].as_array().unwrap();
        let field = |name: &str| {
            field_results
                .iter()
                .find(|field| field["field"] == json!(name))
                .unwrap_or_else(|| panic!("missing field {name}: {report}"))
        };
        assert_eq!(field("act_id")["status"], json!("matched"));
        assert_eq!(field("document_digest")["status"], json!("different"));
        assert_eq!(field("status")["status"], json!("different"));
        assert_eq!(field("artifact_ref")["status"], json!("different"));
        assert_eq!(field("signed_at")["status"], json!("missing_draft"));
        assert_eq!(field("manifest_id")["status"], json!("unknown"));
        assert_eq!(field("source_record_id")["status"], json!("unknown"));
        assert_eq!(field("source_record_id")["draft"]["unknown"], json!(true));
        assert_eq!(
            report["comparison_summary"]["different"],
            json!(3),
            "digest/status/reference differences are counted: {report}"
        );
        assert!(
            report["unmapped_fields"]["draft"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field["path"] == json!("reviewer_note")
                    && field["comparison_status"] == json!("unmapped")),
            "unmapped caller fields should be represented honestly: {report}"
        );
        assert!(
            report["unmapped_fields"]["draft"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field["path"] == json!("signed_pdf_digest")
                    && field["comparison_status"] == json!("unmapped")),
            "signed-only aliases on the draft side should remain visible as unmapped: {report}"
        );
        assert!(
            report["unmapped_fields"]["signed"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field["path"] == json!("draft_digest")
                    && field["comparison_status"] == json!("unmapped")),
            "draft-only aliases on the signed side should remain visible as unmapped: {report}"
        );
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_chronology_review_summary_returns_static_guidance_without_http_or_secret() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req(
                "resources/read",
                58,
                json!({ "uri": MCP_CHRONOLOGY_REVIEW_SUMMARY_RESOURCE_URI }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        let contents = result["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(
            contents[0]["uri"],
            json!(MCP_CHRONOLOGY_REVIEW_SUMMARY_RESOURCE_URI)
        );
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
        let text = contents[0]["text"].as_str().unwrap();
        assert!(!text.contains("chk_ab12cd_secretsecret"));
        assert!(!text.contains("secretsecret"));

        let review: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            review["kind"],
            json!("chancela_mcp_chronology_review_summary")
        );
        assert_eq!(review["offline"], json!(true));
        assert_eq!(review["static"], json!(true));
        assert_eq!(review["local_json_only"], json!(true));
        assert_eq!(review["arguments"], json!([]));
        assert_eq!(review["optional_arguments"][0]["name"], json!("chronology"));
        assert_eq!(review["bridge_calls"], json!(false));
        assert_eq!(review["api_calls"], json!(false));
        assert_eq!(review["provider_calls"], json!(false));
        assert_eq!(review["ai_provider_calls"], json!(false));
        assert_eq!(review["registry_calls"], json!(false));
        assert_eq!(review["legal_service_calls"], json!(false));
        assert_eq!(review["secrets_in_resource"], json!(false));
        assert_eq!(review["claims"]["legal_validity"], json!(false));
        assert_eq!(review["claims"]["ownership_determination"], json!(false));
        assert_eq!(review["claims"]["registry_certification"], json!(false));
        assert_eq!(review["claims"]["ai_completion"], json!(false));
        assert_eq!(review["claims"]["source_certification"], json!(false));

        let categories = review["summary_categories"].as_array().unwrap();
        let category_ids = categories
            .iter()
            .map(|category| category["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        for expected in [
            "event_counts",
            "date_range",
            "evidence_markers",
            "review_caveats",
        ] {
            assert!(
                category_ids.contains(&expected),
                "resource should include category {expected:?}: {review}"
            );
        }
        for category in categories {
            assert!(!category["checkpoints"].as_array().unwrap().is_empty());
        }
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_chronology_review_summary_accepts_arguments_and_counts_chronology_without_http_or_secret()
     {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let params_a = json!({
            "uri": MCP_CHRONOLOGY_REVIEW_SUMMARY_RESOURCE_URI,
            "arguments": {
                "case_id": "chrono-7",
                "chronology": {
                    "events": [
                        {
                            "kind": "Act Created",
                            "status": "Draft",
                            "occurred_at": "2026-07-10",
                            "source_record_id": "src-7"
                        },
                        {
                            "event_type": "Seal",
                            "state": "Sealed",
                            "timestamp": "2026-07-12T10:00:00Z",
                            "evidence": [],
                            "evidence_missing": true
                        },
                        {
                            "type": "ledger.event",
                            "status": "unknown",
                            "created_at": "",
                            "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        }
                    ]
                }
            }
        });
        let params_b = json!({
            "arguments": {
                "chronology": {
                    "events": [
                        {
                            "source_record_id": "src-7",
                            "occurred_at": "2026-07-10",
                            "status": "Draft",
                            "kind": "Act Created"
                        },
                        {
                            "evidence_missing": true,
                            "evidence": [],
                            "timestamp": "2026-07-12T10:00:00Z",
                            "state": "Sealed",
                            "event_type": "Seal"
                        },
                        {
                            "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "created_at": "",
                            "status": "unknown",
                            "type": "ledger.event"
                        }
                    ]
                },
                "case_id": "chrono-7"
            },
            "uri": MCP_CHRONOLOGY_REVIEW_SUMMARY_RESOURCE_URI
        });

        let response_a = server
            .handle(&req("resources/read", 59, params_a))
            .unwrap()
            .result
            .unwrap();
        let response_b = server
            .handle(&req("resources/read", 60, params_b))
            .unwrap()
            .result
            .unwrap();
        let text_a = response_a["contents"][0]["text"].as_str().unwrap();
        let text_b = response_b["contents"][0]["text"].as_str().unwrap();
        assert_eq!(text_a, text_b, "summary output must be deterministic");
        assert!(!text_a.contains("chk_ab12cd_secretsecret"));
        assert!(!text_a.contains("secretsecret"));
        assert!(!text_a.contains("\"legal_validity\": true"));
        assert!(!text_a.contains("\"registry_certification\": true"));
        assert!(!text_a.contains("\"ai_completed_claim\": true"));

        let report: Value = serde_json::from_str(text_a).unwrap();
        assert_eq!(
            report["kind"],
            json!("chancela_mcp_chronology_review_summary_report")
        );
        assert_eq!(report["case_id"], json!("chrono-7"));
        assert_eq!(
            report["source"],
            json!("local_mcp_deterministic_chronology_summarizer")
        );
        assert_eq!(report["offline"], json!(true));
        assert_eq!(report["local_json_only"], json!(true));
        assert_eq!(report["deterministic"], json!(true));
        assert_eq!(report["bridge_calls"], json!(false));
        assert_eq!(report["api_calls"], json!(false));
        assert_eq!(report["provider_calls"], json!(false));
        assert_eq!(report["ai_provider_calls"], json!(false));
        assert_eq!(report["registry_calls"], json!(false));
        assert_eq!(report["legal_service_calls"], json!(false));
        assert_eq!(report["secrets_in_resource"], json!(false));
        assert_eq!(report["claims"]["legal_validity"], json!(false));
        assert_eq!(report["claims"]["ownership_determination"], json!(false));
        assert_eq!(report["claims"]["registry_certification"], json!(false));
        assert_eq!(report["claims"]["ai_completion"], json!(false));
        assert_eq!(report["claims"]["ai_completed_claim"], json!(false));
        assert_eq!(report["claims"]["source_certification"], json!(false));
        assert_eq!(report["claims"]["external_validation"], json!(false));

        let summary = &report["chronology_summary"];
        assert_eq!(summary["total_events"], json!(3));
        assert_eq!(summary["event_kind_counts"]["act_created"], json!(1));
        assert_eq!(summary["event_kind_counts"]["seal"], json!(1));
        assert_eq!(summary["event_kind_counts"]["ledger.event"], json!(1));
        assert_eq!(summary["status_counts"]["draft"], json!(1));
        assert_eq!(summary["status_counts"]["sealed"], json!(1));
        assert_eq!(summary["status_counts"]["unknown"], json!(1));
        assert_eq!(summary["date_range"]["first"], json!("2026-07-10"));
        assert_eq!(summary["date_range"]["last"], json!("2026-07-12T10:00:00Z"));
        assert_eq!(summary["date_range"]["observed_date_count"], json!(2));
        assert_eq!(summary["date_range"]["missing_date_count"], json!(1));
        assert_eq!(
            summary["evidence_marker_counts"]["events_with_evidence_marker"],
            json!(2)
        );
        assert_eq!(
            summary["evidence_marker_counts"]["events_missing_evidence_marker"],
            json!(1)
        );
        assert_eq!(
            summary["evidence_marker_counts"]["events_with_explicit_missing_evidence_marker"],
            json!(1)
        );
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_chronology_review_summary_rejects_bad_arguments_and_extra_params() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();

        let bad_arguments = server
            .handle(&req(
                "resources/read",
                61,
                json!({
                    "uri": MCP_CHRONOLOGY_REVIEW_SUMMARY_RESOURCE_URI,
                    "arguments": { "chronology": { "events": [null] } }
                }),
            ))
            .unwrap();
        let error = bad_arguments.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("events must be objects"));

        let missing_chronology = server
            .handle(&req(
                "resources/read",
                62,
                json!({
                    "uri": MCP_CHRONOLOGY_REVIEW_SUMMARY_RESOURCE_URI,
                    "arguments": { "case_id": "chrono-7" }
                }),
            ))
            .unwrap();
        let error = missing_chronology.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("chronology must be supplied"));

        let extra_param = server
            .handle(&req(
                "resources/read",
                63,
                json!({
                    "uri": MCP_CHRONOLOGY_REVIEW_SUMMARY_RESOURCE_URI,
                    "cursor": "ignored"
                }),
            ))
            .unwrap();
        let error = extra_param.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("uri plus arguments"));

        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_privacy_control_review_summary_returns_static_guidance_without_http_or_secret()
     {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req(
                "resources/read",
                64,
                json!({ "uri": MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        let contents = result["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(
            contents[0]["uri"],
            json!(MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI)
        );
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
        let text = contents[0]["text"].as_str().unwrap();
        assert!(!text.contains("chk_ab12cd_secretsecret"));
        assert!(!text.contains("secretsecret"));

        let review: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            review["kind"],
            json!("chancela_mcp_privacy_control_review_summary")
        );
        assert_eq!(review["offline"], json!(true));
        assert_eq!(review["static"], json!(true));
        assert_eq!(review["local_json_only"], json!(true));
        assert_eq!(review["arguments"], json!([]));
        assert_eq!(
            review["optional_arguments"][0]["name"],
            json!("privacy_controls")
        );
        assert_eq!(
            review["expected_input_shape"]["resources_read_params"]["uri"],
            json!(MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI)
        );
        assert_eq!(review["bridge_calls"], json!(false));
        assert_eq!(review["api_calls"], json!(false));
        assert_eq!(review["provider_calls"], json!(false));
        assert_eq!(review["ai_provider_calls"], json!(false));
        assert_eq!(review["legal_service_calls"], json!(false));
        assert_eq!(review["secrets_in_resource"], json!(false));

        for claim in [
            "legal_approval",
            "legal_completion",
            "authority_notification",
            "data_subject_notification",
            "transfer_approval",
            "transfer_execution",
            "dpia_authority_filing",
            "dpia_completion",
            "compliance_certification",
            "privacy_compliance_completion",
            "gdpr_compliance_completion",
            "destructive_disposal",
            "deletion_completion",
            "anonymization_completion",
            "redaction_completion",
            "full_erasure",
            "erasure_completion",
            "legal_hold_mutation",
            "retention_policy_mutation",
            "provider",
            "legal_service",
        ] {
            assert_eq!(
                review["claims"][claim],
                json!(false),
                "claim {claim} should be pinned false: {review}"
            );
        }

        let categories = review["privacy_control_categories"].as_array().unwrap();
        for expected in [
            "processors",
            "dpias",
            "breach_playbooks",
            "transfer_controls",
            "retention_policies",
            "retention_executions",
            "dsr_requests",
            "retention_due_candidates",
            "retention_candidate_resolutions",
        ] {
            assert!(
                categories.iter().any(|category| category == expected),
                "resource should include privacy category {expected:?}: {review}"
            );
        }
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_privacy_control_review_summary_accepts_arguments_and_counts_without_echoing_secrets()
     {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let privacy_controls_a = json!({
            "processors": [
                {
                    "name": "Sensitive Processor SA",
                    "purpose": "Payroll secret purpose",
                    "legal_basis": "GDPR-Art-6-secret",
                    "data_categories": ["employee identifiers", "payroll details"],
                    "risk_level": "High",
                    "status": "Active"
                }
            ],
            "dpias": [
                {
                    "title": "Payroll DPIA secret title",
                    "legal_basis": "DPIA legal secret",
                    "data_categories": ["biometrics secret"],
                    "risk_level": "Critical",
                    "status": "Active",
                    "advisory_review": {
                        "status": "current",
                        "receipt_count": 2,
                        "review_receipt_count": 1,
                        "drill_receipt_count": 1,
                        "authority_filing_claimed": false,
                        "legal_acceptance_claimed": false,
                        "legal_certification_claimed": false,
                        "completion_claimed": false,
                        "compliance_certification_claimed": false,
                        "legal_completion_claimed": false
                    },
                    "evidence_receipts": [
                        {
                            "evidence_type": "drill",
                            "notes": "password_hash=secret",
                            "authority_filing_completed": false,
                            "legal_review_accepted": false,
                            "legal_certification_completed": false,
                            "external_delivery_completed": false,
                            "dpia_completed": false,
                            "compliance_certification_completed": false
                        },
                        {
                            "evidence_type": "review",
                            "notes": "api-key-secret",
                            "authority_filing_completed": false,
                            "legal_review_accepted": false,
                            "legal_certification_completed": false,
                            "external_delivery_completed": false,
                            "dpia_completed": false,
                            "compliance_certification_completed": false
                        }
                    ]
                }
            ],
            "breach_playbooks": [
                {
                    "title": "Incident secret title",
                    "notification_roles": ["DPO secret"],
                    "risk_level": "High",
                    "status": "under_review",
                    "advisory_review": {
                        "status": "under_review",
                        "receipt_count": 2,
                        "review_receipt_count": 1,
                        "drill_receipt_count": 1,
                        "authority_notification_claimed": false,
                        "subject_notification_claimed": false,
                        "legal_completion_claimed": false
                    },
                    "evidence_receipts": [
                        {
                            "evidence_type": "drill",
                            "notes": "authority secret note",
                            "authority_notified": false,
                            "subjects_notified": false
                        },
                        {
                            "evidence_type": "review",
                            "notes": "subject secret note",
                            "authority_notified": false,
                            "subjects_notified": false
                        }
                    ]
                }
            ],
            "transfer_controls": [
                {
                    "name": "Transfer secret",
                    "recipient": "UK Support Ltd secret recipient",
                    "legal_basis": "Transfer legal secret",
                    "data_categories": ["support tickets secret"],
                    "risk_level": "Medium",
                    "status": "Draft",
                    "advisory_review": {
                        "status": "current",
                        "receipt_count": 1,
                        "review_receipt_count": 1,
                        "drill_receipt_count": 0,
                        "transfer_approval_claimed": false,
                        "transfer_execution_claimed": false,
                        "legal_completion_claimed": false
                    },
                    "evidence_receipts": [
                        {
                            "notes": "approval secret note",
                            "transfer_approved": true,
                            "data_transfer_executed": false
                        }
                    ]
                }
            ],
            "retention_policies": [
                {
                    "name": "Retention secret",
                    "legal_basis": "Retention legal secret",
                    "risk_level": "password_hash=secret",
                    "status": "active",
                    "disposal_action": "delete"
                }
            ],
            "retention_executions": [
                {
                    "execution_status": "awaiting_review",
                    "outcome": "manual_review_required",
                    "evidence_state": "review_queued",
                    "review_closure_evidence": [
                        { "label": "secret label", "value": "secret value" }
                    ],
                    "destructive_disposal_completed": false,
                    "full_erasure_completed": false,
                    "would_execute": false
                },
                {
                    "execution_status": "executed",
                    "outcome": "bounded_archive_recorded",
                    "evidence_state": "bounded_archive_recorded",
                    "deletion_completed": true,
                    "destructive_disposal_completed": false,
                    "full_erasure_completed": false,
                    "would_execute": false
                }
            ],
            "dsr_requests": [
                {
                    "subject_user_id": "subject-secret",
                    "request_type": "erasure",
                    "status": "completed",
                    "outcome": "partially_fulfilled",
                    "execution_notes": "dsr secret note",
                    "erasure_preflight": {
                        "destructive_mutation_completed": false,
                        "full_erasure_completed": false
                    }
                },
                {
                    "subject_user_id": "subject-secret-2",
                    "request_type": "export",
                    "status": "pending",
                    "reason": "export reason secret"
                }
            ],
            "unknown_local_extra": [
                {
                    "name": "ignored secret extra"
                }
            ]
        });
        let privacy_controls_b = json!({
            "unknown_local_extra": [
                {
                    "name": "ignored secret extra"
                }
            ],
            "dsr_requests": [
                {
                    "reason": "export reason secret",
                    "status": "pending",
                    "request_type": "export",
                    "subject_user_id": "subject-secret-2"
                },
                {
                    "erasure_preflight": {
                        "full_erasure_completed": false,
                        "destructive_mutation_completed": false
                    },
                    "execution_notes": "dsr secret note",
                    "outcome": "partially_fulfilled",
                    "status": "completed",
                    "request_type": "erasure",
                    "subject_user_id": "subject-secret"
                }
            ],
            "retention_executions": [
                {
                    "would_execute": false,
                    "full_erasure_completed": false,
                    "destructive_disposal_completed": false,
                    "review_closure_evidence": [
                        { "value": "secret value", "label": "secret label" }
                    ],
                    "evidence_state": "review_queued",
                    "outcome": "manual_review_required",
                    "execution_status": "awaiting_review"
                },
                {
                    "would_execute": false,
                    "full_erasure_completed": false,
                    "destructive_disposal_completed": false,
                    "deletion_completed": true,
                    "evidence_state": "bounded_archive_recorded",
                    "outcome": "bounded_archive_recorded",
                    "execution_status": "executed"
                }
            ],
            "retention_policies": [
                {
                    "disposal_action": "delete",
                    "status": "active",
                    "risk_level": "password_hash=secret",
                    "legal_basis": "Retention legal secret",
                    "name": "Retention secret"
                }
            ],
            "transfer_controls": [
                {
                    "evidence_receipts": [
                        {
                            "data_transfer_executed": false,
                            "transfer_approved": true,
                            "notes": "approval secret note"
                        }
                    ],
                    "advisory_review": {
                        "legal_completion_claimed": false,
                        "transfer_execution_claimed": false,
                        "transfer_approval_claimed": false,
                        "drill_receipt_count": 0,
                        "review_receipt_count": 1,
                        "receipt_count": 1,
                        "status": "current"
                    },
                    "status": "Draft",
                    "risk_level": "Medium",
                    "data_categories": ["support tickets secret"],
                    "legal_basis": "Transfer legal secret",
                    "recipient": "UK Support Ltd secret recipient",
                    "name": "Transfer secret"
                }
            ],
            "breach_playbooks": [
                {
                    "evidence_receipts": [
                        {
                            "subjects_notified": false,
                            "authority_notified": false,
                            "notes": "authority secret note",
                            "evidence_type": "drill"
                        },
                        {
                            "subjects_notified": false,
                            "authority_notified": false,
                            "notes": "subject secret note",
                            "evidence_type": "review"
                        }
                    ],
                    "advisory_review": {
                        "legal_completion_claimed": false,
                        "subject_notification_claimed": false,
                        "authority_notification_claimed": false,
                        "drill_receipt_count": 1,
                        "review_receipt_count": 1,
                        "receipt_count": 2,
                        "status": "under_review"
                    },
                    "status": "under_review",
                    "risk_level": "High",
                    "notification_roles": ["DPO secret"],
                    "title": "Incident secret title"
                }
            ],
            "dpias": [
                {
                    "evidence_receipts": [
                        {
                            "compliance_certification_completed": false,
                            "dpia_completed": false,
                            "external_delivery_completed": false,
                            "legal_certification_completed": false,
                            "legal_review_accepted": false,
                            "authority_filing_completed": false,
                            "notes": "password_hash=secret",
                            "evidence_type": "drill"
                        },
                        {
                            "compliance_certification_completed": false,
                            "dpia_completed": false,
                            "external_delivery_completed": false,
                            "legal_certification_completed": false,
                            "legal_review_accepted": false,
                            "authority_filing_completed": false,
                            "notes": "api-key-secret",
                            "evidence_type": "review"
                        }
                    ],
                    "advisory_review": {
                        "legal_completion_claimed": false,
                        "compliance_certification_claimed": false,
                        "completion_claimed": false,
                        "legal_certification_claimed": false,
                        "legal_acceptance_claimed": false,
                        "authority_filing_claimed": false,
                        "drill_receipt_count": 1,
                        "review_receipt_count": 1,
                        "receipt_count": 2,
                        "status": "current"
                    },
                    "status": "Active",
                    "risk_level": "Critical",
                    "data_categories": ["biometrics secret"],
                    "legal_basis": "DPIA legal secret",
                    "title": "Payroll DPIA secret title"
                }
            ],
            "processors": [
                {
                    "status": "Active",
                    "risk_level": "High",
                    "data_categories": ["employee identifiers", "payroll details"],
                    "legal_basis": "GDPR-Art-6-secret",
                    "purpose": "Payroll secret purpose",
                    "name": "Sensitive Processor SA"
                }
            ]
        });
        let params_a = json!({
            "uri": MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI,
            "arguments": {
                "privacy_controls": privacy_controls_a
            }
        });
        let params_b = json!({
            "arguments": {
                "privacy_controls": privacy_controls_b
            },
            "uri": MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI
        });

        let response_a = server
            .handle(&req("resources/read", 65, params_a))
            .unwrap()
            .result
            .unwrap();
        let response_b = server
            .handle(&req("resources/read", 66, params_b))
            .unwrap()
            .result
            .unwrap();
        let text_a = response_a["contents"][0]["text"].as_str().unwrap();
        let text_b = response_b["contents"][0]["text"].as_str().unwrap();
        assert_eq!(text_a, text_b, "summary output must be deterministic");
        for secret in [
            "Sensitive Processor SA",
            "Payroll secret purpose",
            "GDPR-Art-6-secret",
            "employee identifiers",
            "Payroll DPIA secret title",
            "password_hash=secret",
            "api-key-secret",
            "UK Support Ltd secret recipient",
            "subject-secret",
            "ignored secret extra",
        ] {
            assert!(
                !text_a.contains(secret),
                "summary must not echo caller value {secret:?}: {text_a}"
            );
        }
        assert!(!text_a.contains("\"legal_approval\": true"));
        assert!(!text_a.contains("\"legal_completion\": true"));
        assert!(!text_a.contains("\"authority_notification\": true"));
        assert!(!text_a.contains("\"data_subject_notification\": true"));
        assert!(!text_a.contains("\"transfer_approval\": true"));
        assert!(!text_a.contains("\"transfer_execution\": true"));
        assert!(!text_a.contains("\"dpia_authority_filing\": true"));
        assert!(!text_a.contains("\"dpia_completion\": true"));
        assert!(!text_a.contains("\"compliance_certification\": true"));
        assert!(!text_a.contains("\"privacy_compliance_completion\": true"));
        assert!(!text_a.contains("\"gdpr_compliance_completion\": true"));
        assert!(!text_a.contains("\"destructive_disposal\": true"));
        assert!(!text_a.contains("\"deletion_completion\": true"));
        assert!(!text_a.contains("\"anonymization_completion\": true"));
        assert!(!text_a.contains("\"redaction_completion\": true"));
        assert!(!text_a.contains("\"full_erasure\": true"));

        let report: Value = serde_json::from_str(text_a).unwrap();
        assert_eq!(
            report["kind"],
            json!("chancela_mcp_privacy_control_review_summary_report")
        );
        assert_eq!(
            report["source"],
            json!("local_mcp_deterministic_privacy_control_summarizer")
        );
        assert_eq!(report["offline"], json!(true));
        assert_eq!(report["local_json_only"], json!(true));
        assert_eq!(report["deterministic"], json!(true));
        assert_eq!(report["aggregate_counts_only"], json!(true));
        assert_eq!(report["bridge_calls"], json!(false));
        assert_eq!(report["api_calls"], json!(false));
        assert_eq!(report["provider_calls"], json!(false));
        assert_eq!(report["ai_provider_calls"], json!(false));
        assert_eq!(report["legal_service_calls"], json!(false));
        assert_eq!(report["secrets_in_resource"], json!(false));

        for claim in [
            "legal_approval",
            "legal_completion",
            "authority_notification",
            "data_subject_notification",
            "transfer_approval",
            "transfer_execution",
            "dpia_authority_filing",
            "dpia_completion",
            "compliance_certification",
            "privacy_compliance_completion",
            "gdpr_compliance_completion",
            "destructive_disposal",
            "deletion_completion",
            "anonymization_completion",
            "redaction_completion",
            "full_erasure",
            "erasure_completion",
            "legal_hold_mutation",
            "retention_policy_mutation",
            "provider",
            "legal_service",
        ] {
            assert_eq!(
                report["claims"][claim],
                json!(false),
                "report claim {claim} should be false: {report}"
            );
        }

        let summary = &report["privacy_control_summary"];
        assert_eq!(summary["record_counts"]["total_records"], json!(9));
        assert_eq!(summary["record_counts"]["processors"], json!(1));
        assert_eq!(summary["record_counts"]["retention_executions"], json!(2));
        assert_eq!(summary["record_counts"]["dsr_requests"], json!(2));
        assert_eq!(summary["risk_counts"]["high"], json!(2));
        assert_eq!(summary["risk_counts"]["critical"], json!(1));
        assert_eq!(summary["risk_counts"]["medium"], json!(1));
        assert_eq!(summary["risk_counts"]["other"], json!(1));
        assert_eq!(summary["risk_counts"]["missing"], json!(4));
        assert_eq!(summary["status_counts"]["active"], json!(3));
        assert_eq!(summary["status_counts"]["under_review"], json!(1));
        assert_eq!(summary["status_counts"]["draft"], json!(1));
        assert_eq!(summary["status_counts"]["awaiting_review"], json!(1));
        assert_eq!(summary["status_counts"]["executed"], json!(1));
        assert_eq!(summary["status_counts"]["completed"], json!(1));
        assert_eq!(summary["status_counts"]["pending"], json!(1));
        assert_eq!(
            summary["advisory_review_status_counts"]["current"],
            json!(2)
        );
        assert_eq!(
            summary["advisory_review_status_counts"]["under_review"],
            json!(1)
        );
        assert_eq!(
            summary["advisory_review_status_counts"]["missing"],
            json!(6)
        );
        assert_eq!(
            summary["missing_advisory_review_counts"]["total_records_missing_advisory_review_status"],
            json!(6)
        );
        assert_eq!(
            summary["missing_advisory_review_counts"]["by_category"]["retention_executions"],
            json!(2)
        );
        assert_eq!(
            summary["missing_advisory_review_counts"]["by_category"]["dsr_requests"],
            json!(2)
        );
        assert_eq!(
            summary["review_drill_receipt_counts"]["total"]["receipt_count"],
            json!(5)
        );
        assert_eq!(
            summary["review_drill_receipt_counts"]["total"]["review_receipt_count"],
            json!(3)
        );
        assert_eq!(
            summary["review_drill_receipt_counts"]["total"]["drill_receipt_count"],
            json!(2)
        );
        assert_eq!(
            summary["review_drill_receipt_counts"]["by_category"]["transfer_controls"]["review_receipt_count"],
            json!(1)
        );
        assert_eq!(
            summary["retention_execution_counts"]["record_count"],
            json!(2)
        );
        assert_eq!(
            summary["retention_execution_counts"]["execution_status_counts"]["awaiting_review"],
            json!(1)
        );
        assert_eq!(
            summary["retention_execution_counts"]["execution_status_counts"]["executed"],
            json!(1)
        );
        assert_eq!(
            summary["retention_execution_counts"]["outcome_counts"]["manual_review_required"],
            json!(1)
        );
        assert_eq!(
            summary["retention_execution_counts"]["outcome_counts"]["bounded_archive_recorded"],
            json!(1)
        );
        assert_eq!(
            summary["retention_execution_counts"]["evidence_state_counts"]["review_queued"],
            json!(1)
        );
        assert_eq!(
            summary["retention_execution_counts"]["evidence_state_counts"]["bounded_archive_recorded"],
            json!(1)
        );
        assert_eq!(summary["dsr_request_counts"]["record_count"], json!(2));
        assert_eq!(
            summary["dsr_request_counts"]["request_type_counts"]["erasure"],
            json!(1)
        );
        assert_eq!(
            summary["dsr_request_counts"]["request_type_counts"]["export"],
            json!(1)
        );
        assert_eq!(
            summary["dsr_request_counts"]["status_counts"]["completed"],
            json!(1)
        );
        assert_eq!(
            summary["dsr_request_counts"]["status_counts"]["pending"],
            json!(1)
        );
        assert_eq!(
            summary["dsr_request_counts"]["outcome_counts"]["partially_fulfilled"],
            json!(1)
        );
        assert_eq!(
            summary["dsr_request_counts"]["outcome_counts"]["missing"],
            json!(1)
        );
        assert_eq!(
            summary["false_claim_flag_counts"]["by_flag"]["transfer_approval"]["explicit_false"],
            json!(1)
        );
        assert_eq!(
            summary["false_claim_flag_counts"]["by_flag"]["transfer_approval"]["truthy"],
            json!(1)
        );
        assert_eq!(
            summary["false_claim_flag_counts"]["by_flag"]["transfer_execution"]["explicit_false"],
            json!(2)
        );
        assert_eq!(
            summary["false_claim_flag_counts"]["by_flag"]["deletion_completion"]["truthy"],
            json!(1)
        );
        assert_eq!(
            summary["false_claim_flag_counts"]["by_flag"]["full_erasure"]["explicit_false"],
            json!(4)
        );
        assert_eq!(
            summary["false_claim_flag_counts"]["totals"]["truthy"],
            json!(2)
        );
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_privacy_control_review_summary_counts_retention_candidate_aggregates_without_echoing_sensitive_values()
     {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let due_fixture: Value = serde_json::from_str(include_str!(
            "../../../contracts/retention.due-candidates.json"
        ))
        .unwrap();
        let resolution_fixture: Value = serde_json::from_str(include_str!(
            "../../../contracts/retention.candidate-resolutions.json"
        ))
        .unwrap();
        let fixture_candidate = due_fixture["candidates"][0].clone();
        let fixture_resolution = resolution_fixture.as_array().unwrap()[0].clone();
        let unknown_candidate = json!({
            "candidate_id": "candidate-secret-alpha",
            "policy_name": "Secret retention policy name",
            "legal_basis": "Secret legal basis text",
            "data_categories": ["Secret payroll category"],
            "recipients": ["Secret recipient"],
            "subject_user_id": "subject-secret-alpha",
            "notes": "operator secret note",
            "status": "secret raw status label",
            "outcome": "secret raw outcome label",
            "candidate_evidence_state": "secret raw evidence state",
            "candidate_resolution_record_count": 2,
            "latest_resolution": {
                "id": "latest-resolution-secret",
                "recorded_by": "privacy secret actor",
                "disposition": "secret raw disposition",
                "note": "latest secret note",
                "legal_completion_claimed": "maybe"
            },
            "blockers": [{ "message": "secret blocker text" }],
            "required_approvals": [{ "reason": "secret approval text" }],
            "legal_hold_blockers": [],
            "findings": [{ "message": "secret finding text" }],
            "destructive_disposal_completed": false,
            "disposal_completed": true,
            "full_erasure_completed": false,
            "erasure_completed": "maybe",
            "legal_hold_mutated": false,
            "retention_policy_mutated": "no"
        });
        let unknown_resolution = json!({
            "id": "resolution-record-secret",
            "candidate_id": "candidate-secret-alpha",
            "candidate_fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "recorded_by": "privacy manager secret",
            "disposition": "secret raw disposition",
            "note": "resolution secret note",
            "evidence": [
                {
                    "label": "secret evidence label",
                    "value": "secret raw evidence text"
                }
            ],
            "evidence_only": true,
            "destructive_disposal_completed": false,
            "disposal_completed": "yes",
            "full_erasure_completed": false,
            "erasure_completed": false,
            "legal_hold_mutated": true,
            "retention_policy_changed": "maybe",
            "legal_completion_claimed": false,
            "legal_disposal_completed": false,
            "candidate": {
                "candidate_id": "candidate-secret-alpha",
                "status": "secret candidate status",
                "outcome": "secret candidate outcome",
                "candidate_evidence_state": "secret candidate evidence state",
                "blocker_count": 2,
                "required_approval_count": 0,
                "legal_hold_blocker_count": 1,
                "finding_count": 3
            }
        });
        let due_candidates_a = json!({
            "candidate_count": 2,
            "suppressed_candidate_count": due_fixture["suppressed_candidate_count"],
            "suppressed_by_bounded_evidence_count": due_fixture["suppressed_by_bounded_evidence_count"],
            "candidate_resolution_record_count": 3,
            "candidates_with_resolution_count": 2,
            "suppression_summary": due_fixture["suppression_summary"],
            "candidates": [fixture_candidate.clone(), unknown_candidate.clone()]
        });
        let due_candidates_b = json!({
            "suppression_summary": due_fixture["suppression_summary"],
            "candidates_with_resolution_count": 2,
            "candidate_resolution_record_count": 3,
            "suppressed_by_bounded_evidence_count": due_fixture["suppressed_by_bounded_evidence_count"],
            "suppressed_candidate_count": due_fixture["suppressed_candidate_count"],
            "candidate_count": 2,
            "candidates": [unknown_candidate, fixture_candidate]
        });
        let resolutions_a = json!([fixture_resolution.clone(), unknown_resolution.clone()]);
        let resolutions_b = json!([unknown_resolution, fixture_resolution]);

        let params_a = json!({
            "uri": MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI,
            "arguments": {
                "privacy_controls": {
                    "retention_due_candidates": due_candidates_a,
                    "retention_candidate_resolutions": resolutions_a
                }
            }
        });
        let params_b = json!({
            "arguments": {
                "privacy_controls": {
                    "retention_candidate_resolutions": resolutions_b,
                    "retention_due_candidates": due_candidates_b
                }
            },
            "uri": MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI
        });
        let response_a = server
            .handle(&req("resources/read", 69, params_a))
            .unwrap()
            .result
            .unwrap();
        let response_b = server
            .handle(&req("resources/read", 70, params_b))
            .unwrap()
            .result
            .unwrap();
        let text_a = response_a["contents"][0]["text"].as_str().unwrap();
        let text_b = response_b["contents"][0]["text"].as_str().unwrap();
        assert_eq!(
            text_a, text_b,
            "retention aggregate output must be deterministic"
        );
        for sensitive in [
            "retention-candidate-unsupported",
            "retention-candidate-resolution-1",
            "Unsupported archival period",
            "Board preservation hold",
            "privacy-manager",
            "Correct the retention schedule",
            "candidate-secret-alpha",
            "Secret retention policy name",
            "Secret legal basis text",
            "Secret payroll category",
            "Secret recipient",
            "subject-secret-alpha",
            "operator secret note",
            "secret raw status label",
            "secret raw disposition",
            "latest-resolution-secret",
            "secret evidence label",
            "secret raw evidence text",
            "privacy manager secret",
            "secret blocker text",
            "secret approval text",
            "secret finding text",
        ] {
            assert!(
                !text_a.contains(sensitive),
                "retention summary must not echo sensitive caller value {sensitive:?}: {text_a}"
            );
        }
        assert!(!text_a.contains("\"destructive_disposal\": true"));
        assert!(!text_a.contains("\"deletion_completion\": true"));
        assert!(!text_a.contains("\"erasure_completion\": true"));
        assert!(!text_a.contains("\"legal_hold_mutation\": true"));
        assert!(!text_a.contains("\"retention_policy_mutation\": true"));

        let report: Value = serde_json::from_str(text_a).unwrap();
        let summary = &report["privacy_control_summary"];
        assert_eq!(summary["record_counts"]["total_records"], json!(0));

        let due = &summary["retention_due_candidate_counts"];
        assert_eq!(due["report_supplied"], json!(true));
        assert_eq!(due["candidate_record_count"], json!(2));
        assert_eq!(due["reported_candidate_count"], json!(2));
        assert_eq!(due["candidate_status_counts"]["blocked"], json!(1));
        assert_eq!(due["candidate_status_counts"]["other"], json!(1));
        assert_eq!(
            due["outcome_counts"]["blocked_unsupported_period"],
            json!(1)
        );
        assert_eq!(due["outcome_counts"]["other"], json!(1));
        assert_eq!(due["evidence_state_counts"]["blocked"], json!(1));
        assert_eq!(due["evidence_state_counts"]["other"], json!(1));
        assert_eq!(
            due["suppressed_by_bounded_evidence_counts"]["suppressed_candidate_count"],
            json!(2)
        );
        assert_eq!(
            due["suppressed_by_bounded_evidence_counts"]["top_level_suppressed_by_bounded_evidence_count"],
            json!(2)
        );
        assert_eq!(
            due["suppressed_by_bounded_evidence_counts"]["suppression_summary_suppressed_by_bounded_evidence_count"],
            json!(2)
        );
        assert_eq!(
            due["candidate_resolution_presence_counts"]["reported_candidate_resolution_record_count"],
            json!(3)
        );
        assert_eq!(
            due["candidate_resolution_presence_counts"]["reported_candidates_with_resolution_count"],
            json!(2)
        );
        assert_eq!(
            due["candidate_resolution_presence_counts"]["candidates_with_latest_resolution"],
            json!(2)
        );
        assert_eq!(
            due["candidate_resolution_presence_counts"]["candidates_with_resolution_record_count"],
            json!(2)
        );
        assert_eq!(
            due["candidate_resolution_presence_counts"]["latest_resolution_disposition_counts"]["blocked_follow_up"],
            json!(1)
        );
        assert_eq!(
            due["candidate_resolution_presence_counts"]["latest_resolution_disposition_counts"]["other"],
            json!(1)
        );
        assert_eq!(
            due["blocker_approval_presence_counts"]["records_with_blockers"],
            json!(2)
        );
        assert_eq!(
            due["blocker_approval_presence_counts"]["records_with_required_approvals"],
            json!(2)
        );
        assert_eq!(
            due["blocker_approval_presence_counts"]["records_with_legal_hold_blockers"],
            json!(1)
        );
        assert_eq!(
            due["blocker_approval_presence_counts"]["records_without_legal_hold_blockers"],
            json!(1)
        );
        assert_eq!(
            due["no_claim_flag_counts"]["by_flag"]["destructive_disposal"]["truthy"],
            json!(1)
        );
        assert_eq!(
            due["no_claim_flag_counts"]["by_flag"]["erasure_completion"]["other_present"],
            json!(1)
        );

        let resolutions = &summary["retention_candidate_resolution_counts"];
        assert_eq!(resolutions["record_count"], json!(2));
        assert_eq!(
            resolutions["disposition_counts"]["blocked_follow_up"],
            json!(1)
        );
        assert_eq!(resolutions["disposition_counts"]["other"], json!(1));
        assert_eq!(resolutions["evidence_only_counts"]["truthy"], json!(2));
        assert_eq!(
            resolutions["candidate_snapshot_counts"]["records_with_candidate_snapshot"],
            json!(2)
        );
        assert_eq!(
            resolutions["candidate_snapshot_counts"]["candidate_status_counts"]["blocked"],
            json!(1)
        );
        assert_eq!(
            resolutions["candidate_snapshot_counts"]["candidate_status_counts"]["other"],
            json!(1)
        );
        assert_eq!(
            resolutions["candidate_snapshot_counts"]["outcome_counts"]["blocked_unsupported_period"],
            json!(1)
        );
        assert_eq!(
            resolutions["candidate_snapshot_counts"]["outcome_counts"]["other"],
            json!(1)
        );
        assert_eq!(
            resolutions["candidate_snapshot_counts"]["evidence_state_counts"]["blocked"],
            json!(1)
        );
        assert_eq!(
            resolutions["candidate_snapshot_counts"]["evidence_state_counts"]["other"],
            json!(1)
        );
        assert_eq!(
            resolutions["blocker_approval_presence_counts"]["records_with_blockers"],
            json!(2)
        );
        assert_eq!(
            resolutions["blocker_approval_presence_counts"]["records_with_required_approvals"],
            json!(1)
        );
        assert_eq!(
            resolutions["no_claim_flag_counts"]["by_flag"]["legal_hold_mutation"]["truthy"],
            json!(1)
        );
        assert_eq!(
            resolutions["no_claim_flag_counts"]["by_flag"]["retention_policy_mutation"]["other_present"],
            json!(1)
        );
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_privacy_control_review_summary_allows_missing_retention_candidate_inputs() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req(
                "resources/read",
                71,
                json!({
                    "uri": MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI,
                    "arguments": {
                        "privacy_controls": {}
                    }
                }),
            ))
            .unwrap();
        let text = resp.result.unwrap()["contents"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        let report: Value = serde_json::from_str(&text).unwrap();
        let summary = &report["privacy_control_summary"];
        assert_eq!(summary["record_counts"]["total_records"], json!(0));
        assert_eq!(
            summary["retention_due_candidate_counts"]["report_supplied"],
            json!(false)
        );
        assert_eq!(
            summary["retention_due_candidate_counts"]["candidate_record_count"],
            json!(0)
        );
        assert_eq!(
            summary["retention_due_candidate_counts"]["suppressed_by_bounded_evidence_counts"]["top_level_suppressed_by_bounded_evidence_count"],
            json!(0)
        );
        assert_eq!(
            summary["retention_due_candidate_counts"]["candidate_resolution_presence_counts"]["candidates_with_latest_resolution"],
            json!(0)
        );
        assert_eq!(
            summary["retention_candidate_resolution_counts"]["record_count"],
            json!(0)
        );
        assert_eq!(
            summary["retention_candidate_resolution_counts"]["evidence_only_counts"]["missing"],
            json!(0)
        );
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_document_archive_review_summary_returns_static_guidance_without_http_or_secret()
     {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req(
                "resources/read",
                71,
                json!({ "uri": MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        let contents = result["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(
            contents[0]["uri"],
            json!(MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI)
        );
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
        let text = contents[0]["text"].as_str().unwrap();
        assert!(!text.contains("chk_ab12cd_secretsecret"));
        assert!(!text.contains("secretsecret"));

        let review: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            review["kind"],
            json!("chancela_mcp_document_archive_review_summary")
        );
        assert_eq!(review["offline"], json!(true));
        assert_eq!(review["static"], json!(true));
        assert_eq!(review["local_json_only"], json!(true));
        assert_eq!(review["arguments"], json!([]));
        assert_eq!(review["bridge_calls"], json!(false));
        assert_eq!(review["api_calls"], json!(false));
        assert_eq!(review["provider_calls"], json!(false));
        assert_eq!(review["http_sse_transport_added"], json!(false));
        assert_eq!(review["raw_reports_exposed"], json!(false));
        assert_eq!(review["raw_document_bytes_exposed"], json!(false));
        assert_eq!(review["secrets_in_resource"], json!(false));
        for claim in [
            "pdf_ua_conformance",
            "dglab_certification",
            "legal_validity",
            "signature_validity",
            "qualified_signature",
            "archive_certification",
            "provider_validation",
            "external_validator_success",
            "trust_validation",
            "legal_review",
        ] {
            assert_eq!(
                review["claims"][claim],
                json!(false),
                "static resource claim {claim} should be false: {review}"
            );
        }

        let categories = review["summary_categories"].as_array().unwrap();
        let category_ids = categories
            .iter()
            .map(|category| category["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        for expected in [
            "validation_and_fixity",
            "signed_document_state",
            "external_validator_attachments",
            "pdf_accessibility_v12",
            "archive_paths",
        ] {
            assert!(
                category_ids.contains(&expected),
                "resource should include category {expected:?}: {review}"
            );
        }
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_document_archive_review_summary_accepts_arguments_and_is_deterministic_without_raw_reports_or_overclaims()
     {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let document_archive_a = json!({
            "document_bundle": {
                "document": {
                    "id": "doc-secret-id-that-must-not-echo",
                    "pdf_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                },
                "validation_report": {
                    "report_kind": "document_bundle_validation",
                    "scope": "generated_document_bundle",
                    "status": "technical_warning",
                    "fixity": {
                        "canonical_pdf_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "canonical_pdf_digest_matches_metadata": true,
                        "signed_pdf_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    },
                    "signed_document": {
                        "present": true,
                        "status": "signed",
                        "signed_pdf_digest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                        "signature_metadata": {
                            "signature_bundle_id": "sig-secret-that-must-not-echo"
                        },
                        "timestamp_token_present": true,
                        "signature_validity_claimed": false
                    },
                    "pdf_accessibility": {
                        "evidence_kind": "pdf_accessibility_report",
                        "metadata_schema": "chancela-pdf-accessibility-evidence/v1",
                        "evidence_status": "pdf_accessibility_report_attached",
                        "pdf_ua_claimed": false,
                        "dglab_certification_claimed": false,
                        "legal_validity_claimed": false,
                        "archive_certification_claimed": false,
                        "provider_validation_claimed": false,
                        "external_validator_success_claimed": false,
                        "legal_review_completed": false,
                        "report_version": 12,
                        "pdf_ua_blockers": [
                            "limited_tagged_structure",
                            "caller secret blocker value"
                        ],
                        "accessibility_report_json": {
                            "version": 12,
                            "pdf_ua_claimed": false,
                            "pdf_ua_blockers": ["limited_tagged_structure"],
                            "tagged_structure": {
                                "tables": {
                                    "row_header_cell_count": 3,
                                    "column_header_cell_count": 4,
                                    "table_rows_missing_header_count": 0,
                                    "row_header_cells_have_scope_row": true,
                                    "column_header_cells_have_scope_column": true
                                }
                            }
                        }
                    },
                    "evidence_index": {
                        "index_kind": "document_bundle_evidence_index",
                        "bundle_paths": {
                            "canonical_pdf_download": "/v1/acts/act-secret/document",
                            "signed_pdf_download": "/v1/acts/act-secret/document/signed",
                            "validation_report_json_pointer": "/validation_report"
                        },
                        "external_validator_reports": {
                            "bundle_attachment_status": "external_validator_report_metadata_attached",
                            "attachments": [
                                {
                                    "case_id": "case-secret-that-must-not-echo",
                                    "validator_family": "eu-dss",
                                    "archive_path": "evidence/external-validators/case-eu-dss.json",
                                    "content_type": "application/json",
                                    "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                                    "raw_report": {
                                        "preservation_status": "raw_report_attached",
                                        "content_base64": "RAW-REPORT-SECRET-CONTENT"
                                    }
                                }
                            ]
                        }
                    }
                }
            },
            "archive_package": {
                "evidence_index": {
                    "index_kind": "archive_evidence_index",
                    "evidence_index_path": "evidence/index.json",
                    "documents": [
                        {
                            "canonical_pdf_path": "documents/doc-secret-id-that-must-not-echo.pdf",
                            "document_metadata_path": "metadata/doc-secret-id-that-must-not-echo.json",
                            "signature_evidence_path": "evidence/doc-secret-id-that-must-not-echo.json",
                            "pdf_accessibility_evidence_path": "evidence/pdf-accessibility/doc-secret-id-that-must-not-echo.json",
                            "signed_pdf_path": "signed/doc-secret-id-that-must-not-echo.pdf"
                        }
                    ],
                    "pdf_accessibility_reports": {
                        "attachment_status": "pdf_accessibility_evidence_partially_available",
                        "attachments_total": 2,
                        "attached_count": 1,
                        "unavailable_count": 1,
                        "pdf_ua_claimed": false,
                        "dglab_certification_claimed": false,
                        "legal_validity_claimed": false,
                        "attachments": [
                            {
                                "path": "evidence/pdf-accessibility/doc-secret-id-that-must-not-echo.json",
                                "evidence_status": "pdf_accessibility_report_attached",
                                "pdf_ua_claimed": false,
                                "dglab_certification_claimed": false,
                                "legal_validity_claimed": false,
                                "pdf_ua_blockers": ["limited_tagged_structure"]
                            },
                            {
                                "path": "evidence/pdf-accessibility/book-secret-id-that-must-not-echo.json",
                                "evidence_status": "pdf_accessibility_report_unavailable",
                                "pdf_ua_claimed": false,
                                "dglab_certification_claimed": false,
                                "legal_validity_claimed": false
                            }
                        ]
                    }
                },
                "manifest": {
                    "files": [
                        {
                            "path": "evidence/index.json",
                            "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                        }
                    ]
                }
            }
        });
        let document_archive_b = json!({
            "archive_package": document_archive_a["archive_package"].clone(),
            "document_bundle": document_archive_a["document_bundle"].clone()
        });
        let params_a = json!({
            "uri": MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI,
            "arguments": {
                "case_id": "case-7",
                "document_archive": document_archive_a
            }
        });
        let params_b = json!({
            "arguments": {
                "document_archive": document_archive_b,
                "case_id": "case-7"
            },
            "uri": MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI
        });

        let response_a = server
            .handle(&req("resources/read", 72, params_a))
            .unwrap()
            .result
            .unwrap();
        let response_b = server
            .handle(&req("resources/read", 73, params_b))
            .unwrap()
            .result
            .unwrap();
        let text_a = response_a["contents"][0]["text"].as_str().unwrap();
        let text_b = response_b["contents"][0]["text"].as_str().unwrap();
        assert_eq!(text_a, text_b, "summary output must be deterministic");
        for secret in [
            "RAW-REPORT-SECRET-CONTENT",
            "case-secret-that-must-not-echo",
            "doc-secret-id-that-must-not-echo",
            "sig-secret-that-must-not-echo",
            "caller secret blocker value",
            "act-secret",
            "case-7",
        ] {
            assert!(
                !text_a.contains(secret),
                "summary must not echo caller value {secret:?}: {text_a}"
            );
        }
        assert!(!text_a.contains("chk_ab12cd_secretsecret"));
        assert!(!text_a.contains("secretsecret"));
        assert!(!text_a.contains("\"pdf_ua_conformance\": true"));
        assert!(!text_a.contains("\"dglab_certification\": true"));
        assert!(!text_a.contains("\"legal_validity\": true"));
        assert!(!text_a.contains("\"signature_validity\": true"));
        assert!(!text_a.contains("\"archive_certification\": true"));
        assert!(!text_a.contains("\"provider_validation\": true"));
        assert!(!text_a.contains("\"external_validator_success\": true"));

        let report: Value = serde_json::from_str(text_a).unwrap();
        assert_eq!(
            report["kind"],
            json!("chancela_mcp_document_archive_review_summary_report")
        );
        assert_eq!(
            report["source"],
            json!("local_mcp_deterministic_document_archive_summarizer")
        );
        assert!(
            report.get("case_id").is_none(),
            "summary must not echo caller-supplied IDs: {report}"
        );
        assert_eq!(report["offline"], json!(true));
        assert_eq!(report["local_json_only"], json!(true));
        assert_eq!(report["deterministic"], json!(true));
        assert_eq!(report["aggregate_counts_only"], json!(true));
        assert_eq!(report["bridge_calls"], json!(false));
        assert_eq!(report["api_calls"], json!(false));
        assert_eq!(report["provider_calls"], json!(false));
        assert_eq!(report["ai_provider_calls"], json!(false));
        assert_eq!(report["legal_service_calls"], json!(false));
        assert_eq!(report["http_sse_transport_added"], json!(false));
        assert_eq!(report["raw_reports_exposed"], json!(false));
        assert_eq!(report["raw_document_bytes_exposed"], json!(false));
        assert_eq!(report["raw_report_bytes_echoed"], json!(false));
        assert_eq!(report["digest_values_echoed"], json!(false));
        assert_eq!(report["path_values_echoed"], json!(false));
        assert_eq!(report["secrets_in_resource"], json!(false));

        for claim in [
            "pdf_ua_conformance",
            "dglab_certification",
            "legal_validity",
            "signature_validity",
            "qualified_signature",
            "archive_certification",
            "provider_validation",
            "external_validator_success",
            "trust_validation",
            "legal_review",
        ] {
            assert_eq!(
                report["claims"][claim],
                json!(false),
                "report claim {claim} should be false: {report}"
            );
        }

        assert_eq!(
            report["validation_summary"]["validation_report_present"],
            json!(true)
        );
        assert_eq!(
            report["validation_summary"]["primary_status"],
            json!("technical_warning")
        );
        assert_eq!(report["fixity_summary"]["digest_present"], json!(true));
        assert!(
            report["fixity_summary"]["sha256_field_count"]
                .as_u64()
                .unwrap()
                >= 4,
            "summary should count SHA-256 fields without echoing values: {report}"
        );
        assert_eq!(report["signed_document_summary"]["present"], json!(true));
        assert_eq!(report["signed_document_summary"]["status"], json!("signed"));
        assert_eq!(
            report["signed_document_summary"]["signed_pdf_digest_present"],
            json!(true)
        );
        assert_eq!(
            report["signed_document_summary"]["signature_validation_performed"],
            json!(false)
        );
        assert_eq!(
            report["external_validator_summary"]["attachment_count"],
            json!(1)
        );
        assert_eq!(
            report["external_validator_summary"]["raw_report_reference_count"],
            json!(1)
        );
        assert_eq!(
            report["external_validator_summary"]["raw_payload_field_count"],
            json!(1)
        );
        assert_eq!(
            report["external_validator_summary"]["provider_validation_performed"],
            json!(false)
        );
        assert_eq!(
            report["pdf_accessibility_v12_summary"]["evidence_present"],
            json!(true)
        );
        assert!(
            report["pdf_accessibility_v12_summary"]["v12_report_count"]
                .as_u64()
                .unwrap()
                >= 2,
            "parent sidecar and nested report JSON should be counted: {report}"
        );
        assert!(
            report["pdf_accessibility_v12_summary"]["blocker_counts"]["limited_tagged_structure"]
                .as_u64()
                .unwrap()
                >= 3,
            "known PDF/UA blocker observations should be counted without echoing raw values: {report}"
        );
        assert!(
            report["pdf_accessibility_v12_summary"]["blocker_counts"]["other"]
                .as_u64()
                .unwrap()
                >= 1,
            "unrecognized caller blocker text should be bucketed as other: {report}"
        );
        assert!(
            report["pdf_accessibility_v12_summary"]["table_header_counts"]
                ["row_header_cell_count_total"]
                .as_u64()
                .unwrap()
                >= 3,
            "row-header cells should be counted from supplied table evidence: {report}"
        );
        assert!(
            report["pdf_accessibility_v12_summary"]["table_header_counts"]
                ["column_header_cell_count_total"]
                .as_u64()
                .unwrap()
                >= 4,
            "column-header cells should be counted from supplied table evidence: {report}"
        );
        assert!(
            report["pdf_accessibility_v12_summary"]["table_header_counts"]
                ["row_header_scope_true_count"]
                .as_u64()
                .unwrap()
                >= 1,
            "row-header scope evidence should be counted: {report}"
        );
        assert!(
            report["pdf_accessibility_v12_summary"]["table_header_counts"]
                ["column_header_scope_true_count"]
                .as_u64()
                .unwrap()
                >= 1,
            "column-header scope evidence should be counted: {report}"
        );
        assert_eq!(
            report["archive_path_summary"]["evidence_index_present"],
            json!(true)
        );
        assert!(
            report["archive_path_summary"]["pdf_accessibility_path_count"]
                .as_u64()
                .unwrap()
                >= 2,
            "PDF accessibility path markers should be counted without echoing values: {report}"
        );
        assert_eq!(
            report["no_claim_flag_observations"]["by_flag"]["pdf_ua_conformance"]["explicit_false"],
            json!(5)
        );
        assert_eq!(
            report["no_claim_flag_observations"]["by_flag"]["dglab_certification"]["explicit_false"],
            json!(4)
        );
        assert_eq!(
            report["no_claim_flag_observations"]["by_flag"]["legal_validity"]["explicit_false"],
            json!(4)
        );
        assert_eq!(
            report["no_claim_flag_observations"]["by_flag"]["signature_validity"]["explicit_false"],
            json!(1)
        );
        assert_eq!(
            report["no_claim_flag_observations"]["truthy_flag_total"],
            json!(0)
        );
        assert!(
            report["missing_evidence_blockers"]
                .as_array()
                .unwrap()
                .is_empty(),
            "complete supplied no-claim evidence should not produce blockers: {report}"
        );
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_document_archive_review_summary_does_not_treat_evidence_index_as_validation_report()
     {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let response = server
            .handle(&req(
                "resources/read",
                74,
                json!({
                    "uri": MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI,
                    "arguments": {
                        "document_archive": {
                            "archive_package": {
                                "evidence_index": {
                                    "index_kind": "archive_evidence_index",
                                    "evidence_index_path": "evidence/index.json"
                                }
                            }
                        }
                    }
                }),
            ))
            .unwrap()
            .result
            .unwrap();
        let text = response["contents"][0]["text"].as_str().unwrap();
        let report: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            report["validation_summary"]["validation_report_present"],
            json!(false),
            "archive/evidence index metadata must not masquerade as validation-report evidence: {report}"
        );
        assert_eq!(
            report["archive_path_summary"]["evidence_index_present"],
            json!(true)
        );
        let blockers = report["missing_evidence_blockers"].as_array().unwrap();
        assert!(
            blockers
                .iter()
                .any(|blocker| blocker == "validation_report_missing"),
            "missing validation report should remain a blocker when only evidence-index metadata is supplied: {report}"
        );
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_document_archive_review_summary_rejects_bad_arguments_and_extra_params() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();

        let missing_document_archive = server
            .handle(&req(
                "resources/read",
                75,
                json!({
                    "uri": MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI,
                    "arguments": { "case_id": "case-7" }
                }),
            ))
            .unwrap();
        let error = missing_document_archive.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("document_archive must be supplied"));

        let non_object_document_archive = server
            .handle(&req(
                "resources/read",
                76,
                json!({
                    "uri": MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI,
                    "arguments": { "document_archive": [] }
                }),
            ))
            .unwrap();
        let error = non_object_document_archive.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("document_archive must be an object"));

        let extra_param = server
            .handle(&req(
                "resources/read",
                77,
                json!({
                    "uri": MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI,
                    "cursor": "ignored"
                }),
            ))
            .unwrap();
        let error = extra_param.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("uri plus arguments"));

        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_meeting_metadata_extraction_review_returns_static_guidance_without_http_or_secret()
     {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req(
                "resources/read",
                78,
                json!({ "uri": MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        let contents = result["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(
            contents[0]["uri"],
            json!(MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI)
        );
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
        let text = contents[0]["text"].as_str().unwrap();
        assert!(!text.contains("chk_ab12cd_secretsecret"));
        assert!(!text.contains("secretsecret"));

        let review: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            review["kind"],
            json!("chancela_mcp_meeting_metadata_extraction_review")
        );
        assert_eq!(review["offline"], json!(true));
        assert_eq!(review["static"], json!(true));
        assert_eq!(review["local_json_or_text_metadata_only"], json!(true));
        assert_eq!(review["arguments"], json!([]));
        assert_eq!(
            review["optional_arguments"][0]["name"],
            json!("meeting_document")
        );
        assert_eq!(
            review["expected_input_shape"]["resources_read_params"]["uri"],
            json!(MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI)
        );
        assert_eq!(review["human_verification_required"], json!(true));
        assert_eq!(review["ai_provider_called"], json!(false));
        assert_eq!(review["api_called"], json!(false));
        assert_eq!(review["legal_validity_claimed"], json!(false));
        assert_eq!(review["source_certification_claimed"], json!(false));
        assert_eq!(review["workflow_completion_claimed"], json!(false));
        assert_eq!(review["bridge_calls"], json!(false));
        assert_eq!(review["api_calls"], json!(false));
        assert_eq!(review["provider_calls"], json!(false));
        assert_eq!(review["ai_provider_calls"], json!(false));
        assert_eq!(review["legal_service_calls"], json!(false));
        assert_eq!(review["raw_document_text_echoed"], json!(false));
        assert_eq!(review["raw_document_bytes_echoed"], json!(false));
        assert_eq!(review["names_contacts_emails_phones_echoed"], json!(false));
        assert_eq!(
            review["secrets_access_codes_credentials_echoed"],
            json!(false)
        );
        assert_eq!(review["secrets_in_resource"], json!(false));
        assert_eq!(review["claims"]["legal_validity"], json!(false));
        assert_eq!(review["claims"]["source_certification"], json!(false));
        assert_eq!(review["claims"]["workflow_completion"], json!(false));

        let categories = review["summary_categories"].as_array().unwrap();
        let category_ids = categories
            .iter()
            .map(|category| category["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        for expected in [
            "metadata_candidate_counts",
            "agenda_and_call_markers",
            "evidence_and_safety_markers",
            "human_review_boundaries",
        ] {
            assert!(
                category_ids.contains(&expected),
                "resource should include category {expected:?}: {review}"
            );
        }
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_meeting_metadata_extraction_review_accepts_arguments_and_counts_without_echoing_raw_documents_contacts_or_access_codes()
     {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let meeting_document_a = json!({
            "meeting_date": "2026-07-14",
            "meeting_time": "10:30",
            "dispatch_date": "2026-07-01",
            "channel": "remote video call access code 999999",
            "agenda_items": [
                { "title": "Approve secret acquisition" },
                { "title": "Discuss password rotation" }
            ],
            "second_call_present": true,
            "evidence_reference": {
                "source_record_id": "source-secret-123",
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "contacts": [
                {
                    "name": "Mariana Secret",
                    "email": "secret@example.com",
                    "phone": "+351 912 345 678"
                }
            ],
            "access_code": "999999",
            "credentials": "Bearer chk_ab12cd_secretsecret",
            "raw_document_text": "RAW MINUTES BODY THAT MUST NOT ECHO"
        });
        let meeting_document_b = json!({
            "raw_document_text": "RAW MINUTES BODY THAT MUST NOT ECHO",
            "credentials": "Bearer chk_ab12cd_secretsecret",
            "access_code": "999999",
            "contacts": [
                {
                    "phone": "+351 912 345 678",
                    "email": "secret@example.com",
                    "name": "Mariana Secret"
                }
            ],
            "evidence_reference": {
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "source_record_id": "source-secret-123"
            },
            "second_call_present": true,
            "agenda_items": [
                { "title": "Approve secret acquisition" },
                { "title": "Discuss password rotation" }
            ],
            "channel": "remote video call access code 999999",
            "dispatch_date": "2026-07-01",
            "meeting_time": "10:30",
            "meeting_date": "2026-07-14"
        });
        let params_a = json!({
            "uri": MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI,
            "arguments": {
                "meeting_document": meeting_document_a
            }
        });
        let params_b = json!({
            "arguments": {
                "meeting_document": meeting_document_b
            },
            "uri": MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI
        });

        let response_a = server
            .handle(&req("resources/read", 79, params_a))
            .unwrap()
            .result
            .unwrap();
        let response_b = server
            .handle(&req("resources/read", 80, params_b))
            .unwrap()
            .result
            .unwrap();
        let text_a = response_a["contents"][0]["text"].as_str().unwrap();
        let text_b = response_b["contents"][0]["text"].as_str().unwrap();
        assert_eq!(
            text_a, text_b,
            "meeting review output must be deterministic"
        );
        for sensitive in [
            "2026-07-14",
            "10:30",
            "2026-07-01",
            "remote video call access code 999999",
            "Approve secret acquisition",
            "Discuss password rotation",
            "source-secret-123",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Mariana Secret",
            "secret@example.com",
            "+351 912 345 678",
            "999999",
            "chk_ab12cd_secretsecret",
            "RAW MINUTES BODY THAT MUST NOT ECHO",
        ] {
            assert!(
                !text_a.contains(sensitive),
                "meeting report must not echo caller value {sensitive:?}: {text_a}"
            );
        }
        assert!(!text_a.contains("\"legal_validity\": true"));
        assert!(!text_a.contains("\"source_certification\": true"));
        assert!(!text_a.contains("\"workflow_completion\": true"));
        assert!(!text_a.contains("\"api_called\": true"));
        assert!(!text_a.contains("\"ai_provider_called\": true"));

        let report: Value = serde_json::from_str(text_a).unwrap();
        assert_eq!(
            report["kind"],
            json!("chancela_mcp_meeting_metadata_extraction_review_report")
        );
        assert_eq!(
            report["source"],
            json!("local_mcp_deterministic_meeting_metadata_reviewer")
        );
        assert_eq!(report["offline"], json!(true));
        assert_eq!(report["local_json_or_text_metadata_only"], json!(true));
        assert_eq!(report["deterministic"], json!(true));
        assert_eq!(report["aggregate_counts_only"], json!(true));
        assert_eq!(report["human_verification_required"], json!(true));
        assert_eq!(report["ai_provider_called"], json!(false));
        assert_eq!(report["api_called"], json!(false));
        assert_eq!(report["legal_validity_claimed"], json!(false));
        assert_eq!(report["source_certification_claimed"], json!(false));
        assert_eq!(report["workflow_completion_claimed"], json!(false));
        assert_eq!(report["bridge_calls"], json!(false));
        assert_eq!(report["api_calls"], json!(false));
        assert_eq!(report["provider_calls"], json!(false));
        assert_eq!(report["ai_provider_calls"], json!(false));
        assert_eq!(report["legal_service_calls"], json!(false));
        assert_eq!(report["raw_document_text_echoed"], json!(false));
        assert_eq!(report["raw_document_bytes_echoed"], json!(false));
        assert_eq!(report["names_contacts_emails_phones_echoed"], json!(false));
        assert_eq!(
            report["secrets_access_codes_credentials_echoed"],
            json!(false)
        );
        assert_eq!(report["secrets_in_resource"], json!(false));
        assert_eq!(report["claims"]["legal_validity"], json!(false));
        assert_eq!(report["claims"]["source_certification"], json!(false));
        assert_eq!(report["claims"]["workflow_completion"], json!(false));

        let summary = &report["meeting_metadata_summary"];
        assert_eq!(summary["input_format"], json!("json_object"));
        assert_eq!(
            summary["candidate_fields"]["meeting_date"]["candidate_count"],
            json!(1)
        );
        assert_eq!(
            summary["candidate_fields"]["meeting_time"]["candidate_count"],
            json!(1)
        );
        assert_eq!(
            summary["candidate_fields"]["dispatch_date"]["candidate_count"],
            json!(1)
        );
        assert_eq!(
            summary["candidate_fields"]["channel"]["candidate_count"],
            json!(1)
        );
        assert_eq!(
            summary["agenda_item_count"]["agenda_array_observations"],
            json!(1)
        );
        assert_eq!(
            summary["agenda_item_count"]["agenda_item_total_from_arrays"],
            json!(2)
        );
        assert_eq!(
            summary["second_call_present"]["observation_count"],
            json!(1)
        );
        assert_eq!(summary["second_call_present"]["truthy"], json!(1));
        assert_eq!(
            summary["evidence_reference_present"]["present"],
            json!(true)
        );
        assert_eq!(summary["channel_classification_counts"]["remote"], json!(1));
        assert_eq!(
            summary["safety_marker_counts"]["raw_content_marker_count"],
            json!(1)
        );
        assert!(
            summary["safety_marker_counts"]["name_contact_email_phone_marker_count"]
                .as_u64()
                .unwrap()
                >= 1
        );
        assert!(
            summary["safety_marker_counts"]["secret_access_code_credential_marker_count"]
                .as_u64()
                .unwrap()
                >= 2
        );
        assert!(
            report["blocking_review_findings"]
                .as_array()
                .unwrap()
                .is_empty(),
            "complete supplied metadata should not produce blockers: {report}"
        );
        assert!(report["review_warnings"].as_array().unwrap().iter().any(
            |warning| warning == "secret_access_code_or_credential_marker_supplied_not_echoed"
        ));
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_meeting_metadata_extraction_review_rejects_bad_arguments_and_extra_params() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();

        let missing_meeting_document = server
            .handle(&req(
                "resources/read",
                81,
                json!({
                    "uri": MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI,
                    "arguments": {}
                }),
            ))
            .unwrap();
        let error = missing_meeting_document.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("meeting_document must be supplied"));

        let extra_argument = server
            .handle(&req(
                "resources/read",
                82,
                json!({
                    "uri": MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI,
                    "arguments": {
                        "meeting_document": {},
                        "raw_document_text": "must not be accepted"
                    }
                }),
            ))
            .unwrap();
        let error = extra_argument.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("accept only meeting_document"));

        let non_object_or_string_document = server
            .handle(&req(
                "resources/read",
                83,
                json!({
                    "uri": MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI,
                    "arguments": {
                        "meeting_document": []
                    }
                }),
            ))
            .unwrap();
        let error = non_object_or_string_document.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(
            error
                .message
                .contains("meeting_document must be a JSON object or text metadata string")
        );

        let extra_param = server
            .handle(&req(
                "resources/read",
                84,
                json!({
                    "uri": MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI,
                    "cursor": "ignored"
                }),
            ))
            .unwrap();
        let error = extra_param.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("uri plus arguments"));

        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_privacy_control_review_summary_rejects_bad_arguments_and_extra_params() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();

        let missing_privacy_controls = server
            .handle(&req(
                "resources/read",
                67,
                json!({
                    "uri": MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI,
                    "arguments": { "case_id": "privacy-7" }
                }),
            ))
            .unwrap();
        let error = missing_privacy_controls.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("privacy_controls must be supplied"));

        let non_array_collection = server
            .handle(&req(
                "resources/read",
                68,
                json!({
                    "uri": MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI,
                    "arguments": {
                        "privacy_controls": {
                            "processors": {}
                        }
                    }
                }),
            ))
            .unwrap();
        let error = non_array_collection.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(
            error
                .message
                .contains("privacy_controls.processors must be an array")
        );

        let non_object_record = server
            .handle(&req(
                "resources/read",
                69,
                json!({
                    "uri": MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI,
                    "arguments": {
                        "privacy_controls": {
                            "dpias": [null]
                        }
                    }
                }),
            ))
            .unwrap();
        let error = non_object_record.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(
            error
                .message
                .contains("privacy_controls.dpias[0] must be an object")
        );

        let non_object_due_candidates = server
            .handle(&req(
                "resources/read",
                70,
                json!({
                    "uri": MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI,
                    "arguments": {
                        "privacy_controls": {
                            "retention_due_candidates": []
                        }
                    }
                }),
            ))
            .unwrap();
        let error = non_object_due_candidates.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(
            error
                .message
                .contains("privacy_controls.retention_due_candidates must be an object")
        );

        let non_array_due_candidate_records = server
            .handle(&req(
                "resources/read",
                71,
                json!({
                    "uri": MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI,
                    "arguments": {
                        "privacy_controls": {
                            "retention_due_candidates": {
                                "candidates": {}
                            }
                        }
                    }
                }),
            ))
            .unwrap();
        let error = non_array_due_candidate_records.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(
            error
                .message
                .contains("privacy_controls.retention_due_candidates.candidates must be an array")
        );

        let non_array_candidate_resolutions = server
            .handle(&req(
                "resources/read",
                72,
                json!({
                    "uri": MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI,
                    "arguments": {
                        "privacy_controls": {
                            "retention_candidate_resolutions": {}
                        }
                    }
                }),
            ))
            .unwrap();
        let error = non_array_candidate_resolutions.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(
            error
                .message
                .contains("privacy_controls.retention_candidate_resolutions must be an array")
        );

        let extra_param = server
            .handle(&req(
                "resources/read",
                73,
                json!({
                    "uri": MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI,
                    "cursor": "ignored"
                }),
            ))
            .unwrap();
        let error = extra_param.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("uri plus arguments"));

        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_draft_signed_comparison_report_rejects_bad_arguments_and_extra_params() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();

        let bad_arguments = server
            .handle(&req(
                "resources/read",
                56,
                json!({
                    "uri": MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI,
                    "arguments": { "draft": {}, "signed": null }
                }),
            ))
            .unwrap();
        let error = bad_arguments.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("signed must be an object"));

        let extra_param = server
            .handle(&req(
                "resources/read",
                57,
                json!({
                    "uri": MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI,
                    "cursor": "ignored"
                }),
            ))
            .unwrap();
        let error = extra_param.error.unwrap();
        assert_eq!(error.code, codes::INVALID_PARAMS);
        assert!(error.message.contains("uri plus arguments"));

        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_spec_09_coverage_returns_boundaries_without_http_or_secret() {
        let cfg = McpConfig {
            enabled_tools: EnabledTools::List(vec![
                "list_companies".into(),
                "draft_minutes".into(),
                "prepare_archive_export".into(),
            ]),
            ..enabled_cfg()
        };
        let server = McpServer::from_config(&cfg, MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req(
                "resources/read",
                46,
                json!({ "uri": MCP_SPEC_09_COVERAGE_RESOURCE_URI }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        let contents = result["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], json!(MCP_SPEC_09_COVERAGE_RESOURCE_URI));
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
        let text = contents[0]["text"].as_str().unwrap();
        assert!(!text.contains("chk_ab12cd_secretsecret"));
        assert!(!text.contains("secretsecret"));

        let coverage: Value = serde_json::from_str(text).unwrap();
        assert_eq!(coverage["kind"], json!("chancela_mcp_spec_09_coverage"));
        assert_eq!(coverage["offline"], json!(true));
        assert_eq!(coverage["spec"]["id"], json!("09-ai-mcp"));
        assert_eq!(
            coverage["spec"]["covered_here"],
            json!(["AI-10", "AI-11", "AI-12"])
        );
        assert!(
            !coverage["spec"]["covered_here"]
                .as_array()
                .unwrap()
                .iter()
                .any(|id| id.as_str() == Some("AI-01"))
        );
        assert!(
            !coverage["spec"]["covered_here"]
                .as_array()
                .unwrap()
                .iter()
                .any(|id| id.as_str() == Some("AI-02"))
        );
        assert_eq!(coverage["coverage"]["AI-10"]["status"], json!("partial"));
        assert_eq!(
            coverage["coverage"]["AI-10"]["covered_locally"]["resources"],
            json!([
                MCP_STATUS_RESOURCE_URI,
                MCP_SPEC_09_COVERAGE_RESOURCE_URI,
                MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI,
                MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI,
                MCP_CHRONOLOGY_REVIEW_SUMMARY_RESOURCE_URI,
                MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI,
                MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI,
                MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI
            ])
        );
        assert!(
            coverage["coverage"]["AI-10"]["covered_locally"]["prompts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|name| name.as_str() == Some(COMPLIANCE_PACK_GAP_REVIEW_PROMPT_NAME))
        );
        assert!(
            coverage["coverage"]["AI-10"]["covered_locally"]["prompts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|name| name.as_str() == Some(DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_NAME))
        );
        assert_eq!(
            coverage["mcp_review_aids"]["resources"],
            json!([
                MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI,
                MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI,
                MCP_CHRONOLOGY_REVIEW_SUMMARY_RESOURCE_URI,
                MCP_PRIVACY_CONTROL_REVIEW_SUMMARY_RESOURCE_URI,
                MCP_DOCUMENT_ARCHIVE_REVIEW_SUMMARY_RESOURCE_URI,
                MCP_MEETING_METADATA_EXTRACTION_REVIEW_RESOURCE_URI
            ])
        );
        assert_eq!(
            coverage["mcp_review_aids"]["prompts"],
            json!([
                WORKFLOW_PROVENANCE_REVIEW_PROMPT_NAME,
                DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_NAME
            ])
        );
        assert_eq!(coverage["mcp_review_aids"]["ai_01_claimed"], json!(false));
        assert_eq!(coverage["mcp_review_aids"]["ai_02_claimed"], json!(false));
        assert_eq!(
            coverage["mcp_review_aids"]["full_ai_mcp_completion_claimed"],
            json!(false)
        );
        assert_eq!(
            coverage["coverage"]["AI-11"]["mcp_reimplements_rbac"],
            json!(false)
        );
        assert!(
            coverage["coverage"]["AI-11"]["read_only_tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tool| tool["name"] == json!("list_companies")
                    && tool["permission"] == json!("entity.read"))
        );
        assert!(
            coverage["coverage"]["AI-11"]["write_controlled_tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tool| tool["name"] == json!("draft_minutes")
                    && tool["permission"] == json!("act.draft"))
        );
        assert_eq!(
            coverage["coverage"]["AI-12"]["authorization_forwarded_server_side"],
            json!(true)
        );
        assert_eq!(
            coverage["review_boundaries"]["hidden_provider_calls"],
            json!(false)
        );
        assert_eq!(
            coverage["review_boundaries"]["secrets_in_resource"],
            json!(false)
        );
        assert_eq!(
            coverage["review_boundaries"]["legal_validity_claimed"],
            json!(false)
        );
        assert_eq!(
            coverage["review_boundaries"]["source_certification_claimed"],
            json!(false)
        );
        assert_eq!(coverage["review_boundaries"]["trust_claimed"], json!(false));
        assert_eq!(
            coverage["review_boundaries"]["external_validation_claimed"],
            json!(false)
        );
        assert_eq!(
            coverage["review_boundaries"]["signature_qualification_claimed"],
            json!(false)
        );
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn resources_read_unknown_uri_is_resource_not_found() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server
            .handle(&req(
                "resources/read",
                22,
                json!({ "uri": "chancela://mcp/missing" }),
            ))
            .unwrap();
        let error = resp.error.unwrap();
        assert_eq!(error.code, codes::RESOURCE_NOT_FOUND);
        assert_eq!(error.data.unwrap()["uri"], json!("chancela://mcp/missing"));
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn per_tool_enablement_filters_list_and_call() {
        let cfg = McpConfig {
            enabled_tools: EnabledTools::List(vec!["list_companies".into()]),
            ..enabled_cfg()
        };
        let server = McpServer::from_config(&cfg, MockTransport::new(200, "[]")).unwrap();
        assert_eq!(server.tools().len(), 1);
        assert_eq!(server.tools()[0].name, "list_companies");
        // A disabled tool is reported as unknown/disabled (isError), and no HTTP call is made.
        let resp = server
            .handle(&req(
                "tools/call",
                2,
                json!({ "name": "seal_act", "arguments": { "id": "a1" } }),
            ))
            .unwrap();
        assert_eq!(resp.result.unwrap()["isError"], json!(true));
    }

    #[test]
    fn tools_call_company_alias_routes_to_right_api_call() {
        let cfg = McpConfig {
            enabled_tools: EnabledTools::List(vec!["get_company_timeline".into()]),
            ..enabled_cfg()
        };
        let server =
            McpServer::from_config(&cfg, MockTransport::new(200, r#"{"events":[]}"#)).unwrap();
        let resp = server
            .handle(&req(
                "tools/call",
                30,
                json!({
                    "name": "get_company_timeline",
                    "arguments": { "entity_id": "ent-7" }
                }),
            ))
            .unwrap();
        assert_eq!(resp.result.unwrap()["isError"], json!(false));

        let recorded = server.bridge_recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, crate::bridge::HttpMethod::Get);
        assert_eq!(
            recorded[0].url,
            "http://127.0.0.1:8080/api/v1/entities/ent-7/chronology"
        );
    }

    #[test]
    fn tools_call_routes_to_right_api_call() {
        let server =
            McpServer::from_config(&enabled_cfg(), MockTransport::new(200, r#"{"items":[]}"#))
                .unwrap();
        let resp = server
            .handle(&req(
                "tools/call",
                3,
                json!({ "name": "get_entity", "arguments": { "id": "ent-7" } }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], json!(false));
        // The bridge saw GET /api/v1/entities/ent-7 with the Bearer key.
        let recorded = server.bridge_recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, crate::bridge::HttpMethod::Get);
        assert_eq!(
            recorded[0].url,
            "http://127.0.0.1:8080/api/v1/entities/ent-7"
        );
        assert_eq!(
            recorded[0].header("Authorization"),
            Some("Bearer chk_ab12cd_secretsecret")
        );
    }

    #[test]
    fn tools_call_external_validator_report_metadata_routes_to_safe_metadata_endpoint_only() {
        let cfg = McpConfig {
            enabled_tools: EnabledTools::List(vec![
                "get_external_validator_report_metadata".into(),
            ]),
            ..enabled_cfg()
        };
        let api_response = r#"{
            "evidence_kind": "external_validator_report_metadata",
            "schema": "chancela-external-validator-report-evidence/v1",
            "case_id": "case-7",
            "validator_family": "eu-dss",
            "legal_validity_claimed": false,
            "trust_validation_claimed": false,
            "provider_validation_claimed": false,
            "authenticity_certification_claimed": false,
            "scope": {
                "kind": "external_validator_report",
                "technical_only": true,
                "legal_validity_assessment": "not_assessed",
                "claim": "technical_validator_evidence_only"
            },
            "raw_report": {
                "preservation_status": "raw_report_manifest_only",
                "content_type": "application/json",
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "size_bytes": 42
            }
        }"#;
        let response =
            HttpResponse::text(200, api_response).with_header("Content-Type", "application/json");
        let server = McpServer::from_config(&cfg, MockTransport::with_response(response)).unwrap();
        let resp = server
            .handle(&req(
                "tools/call",
                45,
                json!({
                    "name": "get_external_validator_report_metadata",
                    "arguments": {
                        "case_id": "case-7",
                        "validator_family": "eu-dss"
                    }
                }),
            ))
            .unwrap();

        let result = resp.result.unwrap();
        assert_eq!(result["isError"], json!(false));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(
            !text.contains("chk_ab12cd_secretsecret"),
            "key must never leak in payload: {text}"
        );
        assert!(
            !text.contains("content_base64"),
            "MCP metadata response must not contain inline raw bytes: {text}"
        );
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            payload["evidence_kind"],
            json!("external_validator_report_metadata")
        );
        assert_eq!(payload["case_id"], json!("case-7"));
        assert_eq!(payload["validator_family"], json!("eu-dss"));
        assert_eq!(payload["legal_validity_claimed"], json!(false));
        assert_eq!(payload["trust_validation_claimed"], json!(false));
        assert_eq!(payload["provider_validation_claimed"], json!(false));
        assert_eq!(payload["authenticity_certification_claimed"], json!(false));
        assert_eq!(
            payload["scope"]["claim"],
            json!("technical_validator_evidence_only")
        );
        assert_eq!(
            payload["raw_report"]["preservation_status"],
            json!("raw_report_manifest_only")
        );

        let recorded = server.bridge_recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, crate::bridge::HttpMethod::Get);
        assert_eq!(
            recorded[0].url,
            "http://127.0.0.1:8080/api/v1/external-validator-reports/case-7/eu-dss"
        );
        assert!(!recorded[0].url.contains("raw-report"));
        assert_eq!(
            recorded[0].header("Authorization"),
            Some("Bearer chk_ab12cd_secretsecret")
        );
        assert!(recorded[0].body.is_none());
    }

    #[test]
    fn tools_call_external_validator_report_metadata_rejects_raw_or_upload_args_before_http() {
        let cfg = McpConfig {
            enabled_tools: EnabledTools::List(vec![
                "get_external_validator_report_metadata".into(),
            ]),
            ..enabled_cfg()
        };
        let server = McpServer::from_config(&cfg, MockTransport::new(200, "{}")).unwrap();

        for name in [
            "raw_report",
            "raw",
            "upload",
            "content",
            "content_base64",
            "base64",
            "path",
            "bytes",
        ] {
            let resp = server
                .handle(&req(
                    "tools/call",
                    46,
                    json!({
                        "name": "get_external_validator_report_metadata",
                        "arguments": {
                            "case_id": "case-7",
                            "validator_family": "eu-dss",
                            name: "not forwarded"
                        }
                    }),
                ))
                .unwrap();
            let result = resp.result.unwrap();
            assert_eq!(result["isError"], json!(true), "argument {name}");
            let text = result["content"][0]["text"].as_str().unwrap();
            assert!(
                text.contains(&format!("unknown argument: {name}")),
                "argument {name}: {text}"
            );
        }

        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn tools_call_draft_minutes_posts_to_draft_act_api() {
        let cfg = McpConfig {
            enabled_tools: EnabledTools::List(vec!["draft_minutes".into()]),
            ..enabled_cfg()
        };
        let api_response = r#"{
            "id": "act-7",
            "book_id": "book-7",
            "title": "Ata da Assembleia Geral Anual",
            "channel": "Physical",
            "state": "Draft",
            "ata_number": null,
            "payload_digest": null,
            "seal_event_seq": null
        }"#;
        let server = McpServer::from_config(&cfg, MockTransport::new(201, api_response)).unwrap();
        let resp = server
            .handle(&req(
                "tools/call",
                38,
                json!({
                    "name": "draft_minutes",
                    "arguments": {
                        "book_id": "book-7",
                        "title": "Ata da Assembleia Geral Anual",
                        "channel": "Physical",
                        "actor": "mcp"
                    }
                }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], json!(false));
        let text = result["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).expect("draft tool output is JSON");
        assert_eq!(payload["kind"], json!("ai_draft"));
        assert_eq!(payload["status"], json!("draft"));
        assert_eq!(payload["non_authoritative"], json!(true));
        assert_eq!(payload["human_verification_required"], json!(true));
        assert_eq!(
            payload["legal_effect"],
            json!("none_until_human_verification_and_seal")
        );
        assert_eq!(payload["verification"]["required"], json!(true));
        assert_eq!(payload["verification"]["status"], json!("pending"));
        let verification_status_values = json!([
            "pending_human_verification",
            "accepted_by_human",
            "rejected_by_human"
        ]);
        assert_eq!(
            payload["verification"]["checkpoint_status"],
            json!("pending_human_verification")
        );
        assert_eq!(
            payload["verification"]["checkpoint_allowed_statuses"],
            verification_status_values
        );
        assert_eq!(
            payload["verification"]["accepted_as_legal_text"],
            json!(false)
        );
        assert_eq!(
            payload["verification"]["legal_validity_claimed"],
            json!(false)
        );
        assert_eq!(
            payload["verification"]["checkpoint"]["status"],
            json!("pending_human_verification")
        );
        assert_eq!(
            payload["verification"]["checkpoint"]["accepted_by_human"],
            json!(false)
        );
        assert_eq!(
            payload["verification"]["checkpoint"]["rejected_by_human"],
            json!(false)
        );
        assert_eq!(
            payload["verification"]["checkpoint"]["acceptance_claim"],
            json!("human_review_only_not_legal_certification")
        );
        assert_eq!(
            payload["verification"]["checkpoint"]["legal_validity_claimed"],
            json!(false)
        );
        assert_eq!(payload["source_provenance"]["schema_version"], json!(1));
        assert_eq!(
            payload["source_provenance"]["status"],
            json!("pending_human_verification")
        );
        assert_eq!(
            payload["source_provenance"]["status_values"],
            verification_status_values
        );
        assert_eq!(
            payload["source_provenance"]["human_verification_required"],
            json!(true)
        );
        assert_eq!(
            payload["source_provenance"]["accepted_as_legal_text"],
            json!(false)
        );
        assert_eq!(
            payload["source_provenance"]["legal_validity_claimed"],
            json!(false)
        );
        assert_eq!(
            payload["source_provenance"]["human_verification"]["allowed_statuses"],
            verification_status_values
        );
        assert_eq!(
            payload["source_provenance"]["human_verification"]["rejected_by_human"],
            json!(false)
        );
        assert_eq!(
            payload["source_provenance"]["authoritative_source_claimed"],
            json!(false)
        );
        assert_eq!(
            payload["source_provenance"]["source"]["tool"],
            json!("draft_minutes")
        );
        assert_eq!(
            payload["source_provenance"]["source"]["endpoint"],
            json!("POST /acts")
        );
        let statement_sources = payload["source_provenance"]["statement_sources"]
            .as_array()
            .expect("statement source provenance entries");
        assert!(
            statement_sources
                .iter()
                .any(|source| source["path"] == json!("/draft")
                    && source["source_type"] == json!("ai_suggestion")
                    && source["human_verified"] == json!(false)
                    && source["human_verification_status"] == json!("pending_human_verification")
                    && source["legal_validity_claimed"] == json!(false)),
            "whole-draft AI suggestion provenance missing: {statement_sources:?}"
        );
        assert!(
            statement_sources
                .iter()
                .any(|source| source["path"] == json!("/draft/title")
                    && source["source_type"] == json!("caller_supplied")
                    && source["source_label"] == json!("arguments.title")
                    && source["verification_status"] == json!("pending")
                    && source["human_verification_status_values"] == verification_status_values),
            "title source provenance missing: {statement_sources:?}"
        );
        assert_eq!(payload["provenance"]["source"]["surface"], json!("mcp"));
        assert_eq!(
            payload["provenance"]["source"]["tool"],
            json!("draft_minutes")
        );
        assert_eq!(
            payload["provenance"]["source"]["endpoint"],
            json!("POST /acts")
        );
        assert_eq!(payload["provenance"]["model"], Value::Null);
        assert_eq!(payload["provenance"]["provider"], Value::Null);
        assert_eq!(payload["provenance"]["actor"], json!("mcp"));
        let created_at = payload["provenance"]["created_at"]
            .as_str()
            .expect("created_at");
        time::OffsetDateTime::parse(created_at, &time::format_description::well_known::Rfc3339)
            .expect("created_at is RFC 3339");
        assert_eq!(payload["draft"]["id"], json!("act-7"));
        assert_eq!(payload["draft"]["state"], json!("Draft"));
        assert!(payload["draft"]["ata_number"].is_null());
        assert!(payload["draft"]["payload_digest"].is_null());
        assert!(payload["draft"]["seal_event_seq"].is_null());

        let recorded = server.bridge_recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, crate::bridge::HttpMethod::Post);
        assert_eq!(recorded[0].url, "http://127.0.0.1:8080/api/v1/acts");
        assert_eq!(
            recorded[0].header("Authorization"),
            Some("Bearer chk_ab12cd_secretsecret")
        );
        let body: Value = serde_json::from_str(recorded[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(body["actor"], json!("mcp"));
        assert_eq!(body["book_id"], json!("book-7"));
        assert_eq!(body["channel"], json!("Physical"));
        assert_eq!(body["title"], json!("Ata da Assembleia Geral Anual"));
        assert_eq!(body["ai_provenance"]["source"], json!("mcp"));
        assert_eq!(body["ai_provenance"]["tool"], json!("draft_minutes"));
        assert_eq!(
            body["ai_provenance"]["statement_source"],
            json!("mcp tool arguments")
        );
        let posted_sources = body["ai_provenance"]["statement_sources"]
            .as_array()
            .expect("posted statement sources");
        assert!(
            posted_sources
                .iter()
                .any(|source| source["path"] == json!("/draft")
                    && source["source_type"] == json!("ai_suggestion")
                    && source["source_label"] == json!("draft_minutes")
                    && source["human_verified"] == json!(false)
                    && source["authoritative_source_claimed"] == json!(false)
                    && source["legal_validity_claimed"] == json!(false)),
            "posted whole-draft source missing: {posted_sources:?}"
        );
        assert!(
            posted_sources
                .iter()
                .any(|source| source["path"] == json!("/draft/title")
                    && source["source_type"] == json!("caller_supplied")
                    && source["source_label"] == json!("arguments.title")
                    && source["human_verification_status"] == json!("pending_human_verification")),
            "posted title source missing: {posted_sources:?}"
        );
    }

    #[test]
    fn tools_call_draft_minutes_rejects_non_draft_api_response() {
        let cfg = McpConfig {
            enabled_tools: EnabledTools::List(vec!["draft_minutes".into()]),
            ..enabled_cfg()
        };
        let api_response = r#"{
            "id": "act-7",
            "book_id": "book-7",
            "title": "Ata da Assembleia Geral Anual",
            "channel": "Physical",
            "state": "Sealed",
            "ata_number": 1,
            "payload_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "seal_event_seq": 3
        }"#;
        let server = McpServer::from_config(&cfg, MockTransport::new(201, api_response)).unwrap();
        let resp = server
            .handle(&req(
                "tools/call",
                41,
                json!({
                    "name": "draft_minutes",
                    "arguments": {
                        "book_id": "book-7",
                        "title": "Ata da Assembleia Geral Anual",
                        "channel": "Physical"
                    }
                }),
            ))
            .unwrap();

        let result = resp.result.unwrap();
        assert_eq!(result["isError"], json!(true));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("not \"Draft\""), "{text}");
        assert!(
            !text.contains("human_verification_required\":false"),
            "{text}"
        );
    }

    #[test]
    fn tools_call_draft_minutes_rejects_bad_args_before_http() {
        let cfg = McpConfig {
            enabled_tools: EnabledTools::List(vec!["draft_minutes".into()]),
            ..enabled_cfg()
        };
        let server = McpServer::from_config(&cfg, MockTransport::new(201, "{}")).unwrap();

        let missing = server
            .handle(&req(
                "tools/call",
                39,
                json!({
                    "name": "draft_minutes",
                    "arguments": { "book_id": "book-7", "channel": "Physical" }
                }),
            ))
            .unwrap();
        let result = missing.result.unwrap();
        assert_eq!(result["isError"], json!(true));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("missing required argument: title"), "{text}");

        let unknown = server
            .handle(&req(
                "tools/call",
                40,
                json!({
                    "name": "draft_minutes",
                    "arguments": {
                        "book_id": "book-7",
                        "title": "Ata",
                        "channel": "Physical",
                        "prompt": "draft this for me"
                    }
                }),
            ))
            .unwrap();
        let result = unknown.result.unwrap();
        assert_eq!(result["isError"], json!(true));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("unknown argument: prompt"), "{text}");
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn tools_call_validate_signature_bundle_wraps_technical_status_only() {
        let cfg = McpConfig {
            enabled_tools: EnabledTools::List(vec!["validate_signature_bundle".into()]),
            ..enabled_cfg()
        };
        let response = HttpResponse::text(
            200,
            r#"{
                "status": "signed",
                "finalization": "finalizado_qualificado",
                "require_qualified_for_seal": true,
                "signed": {
                    "family": "QualifiedCertificate",
                    "evidentiary_level": "Qualified",
                    "trusted_list_status": "granted",
                    "signer_cert_subject": "CN=Amelia",
                    "signing_time": "2026-07-09T09:00:00Z",
                    "signed_at": "2026-07-09T09:00:01Z",
                    "signed_pdf_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "timestamp_token": true,
                    "download": "/v1/acts/act-7/document/signed"
                },
                "evidence": {
                    "current_level": "B-T",
                    "timestamp_evidence_present": true,
                    "dss_revocation_evidence_present": false,
                    "dss_revocation_evidence_status": "not_present",
                    "local_b_lt_style_evidence_present": false,
                    "production_b_lt_status": "not_claimed",
                    "live_revocation_fetching": false,
                    "legal_b_lt_claimed": false,
                    "legal_b_lta_claimed": false,
                    "long_term_status": ["timestamped", "lt_not_implemented"],
                    "status_scope": "technical_evidence_only"
                }
            }"#,
        )
        .with_header("Content-Type", "application/json");
        let server = McpServer::from_config(&cfg, MockTransport::with_response(response)).unwrap();
        let resp = server
            .handle(&req(
                "tools/call",
                42,
                json!({
                    "name": "validate_signature_bundle",
                    "arguments": { "act_id": "act-7" }
                }),
            ))
            .unwrap();

        let result = resp.result.unwrap();
        assert_eq!(result["isError"], json!(false));
        let payload: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(payload["kind"], json!("signature_bundle_validation"));
        assert_eq!(payload["status"], json!("technical_evidence"));
        assert_eq!(payload["backend_supported"], json!(true));
        assert_eq!(payload["scope"], json!("technical_evidence_only"));
        assert_eq!(payload["legal_validation_claimed"], json!(false));
        assert_eq!(payload["qualified_signature_claimed_by_mcp"], json!(false));
        assert_eq!(payload["signature_status"], json!("signed"));
        assert_eq!(payload["evidence"]["current_level"], json!("B-T"));
        assert_eq!(
            payload["evidence"]["status_scope"],
            json!("technical_evidence_only")
        );
        assert_eq!(
            payload["backend_status"]["evidence"]["legal_b_lt_claimed"],
            json!(false)
        );

        let recorded = server.bridge_recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, crate::bridge::HttpMethod::Get);
        assert_eq!(
            recorded[0].url,
            "http://127.0.0.1:8080/api/v1/acts/act-7/signature"
        );
        assert_eq!(
            recorded[0].header("Authorization"),
            Some("Bearer chk_ab12cd_secretsecret")
        );
    }

    #[test]
    fn tools_call_generate_mermaid_graph_selects_requested_graph() {
        let response = HttpResponse::text(
            200,
            r#"{
                "events": [],
                "mermaid": {
                    "shareholders": "graph TD\nA",
                    "organs": "timeline\n2026 : Manager",
                    "relationships": "graph LR\nA-->B"
                }
            }"#,
        )
        .with_header("Content-Type", "application/json");
        let server =
            McpServer::from_config(&enabled_cfg(), MockTransport::with_response(response)).unwrap();
        let resp = server
            .handle(&req(
                "tools/call",
                35,
                json!({
                    "name": "generate_mermaid_graph",
                    "arguments": { "entity_id": "ent-7", "kind": "organs" }
                }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], json!(false));
        let payload: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(payload["kind"], json!("organs"));
        assert_eq!(payload["mermaid"], json!("timeline\n2026 : Manager"));

        let recorded = server.bridge_recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, crate::bridge::HttpMethod::Get);
        assert_eq!(
            recorded[0].url,
            "http://127.0.0.1:8080/api/v1/entities/ent-7/chronology?kind=organs"
        );
        assert_eq!(
            recorded[0].header("Authorization"),
            Some("Bearer chk_ab12cd_secretsecret")
        );
    }

    #[test]
    fn tools_call_generate_mermaid_graph_requires_supported_kind_before_http() {
        let server = McpServer::from_config(
            &enabled_cfg(),
            MockTransport::new(200, r#"{"mermaid":{"organs":"timeline"}}"#),
        )
        .unwrap();
        let resp = server
            .handle(&req(
                "tools/call",
                36,
                json!({
                    "name": "generate_mermaid_graph",
                    "arguments": { "entity_id": "ent-7", "kind": "delegated_powers" }
                }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], json!(true));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("unsupported graph kind"), "{text}");
        assert!(server.bridge_recorded().is_empty());
    }

    #[test]
    fn tools_call_binary_archive_package_returns_base64_payload_with_metadata() {
        let response = HttpResponse::bytes(200, b"PK".to_vec())
            .with_header("Content-Type", "application/zip")
            .with_header(
                "Content-Disposition",
                "attachment; filename=\"chancela-preservation-book-book-7.zip\"",
            );
        let server =
            McpServer::from_config(&enabled_cfg(), MockTransport::with_response(response)).unwrap();
        let resp = server
            .handle(&req(
                "tools/call",
                32,
                json!({ "name": "export_book_archive_package", "arguments": { "book_id": "book-7" } }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], json!(false));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(
            !text.contains("chk_ab12cd_secretsecret"),
            "key must never leak in payload: {text}"
        );
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["kind"], json!("binary"));
        assert_eq!(payload["encoding"], json!("base64"));
        assert_eq!(payload["content_type"], json!("application/zip"));
        assert_eq!(
            payload["suggested_filename"],
            json!("chancela-preservation-book-book-7.zip")
        );
        assert_eq!(payload["byte_length"], json!(2));
        assert_eq!(payload["data_base64"], json!("UEs="));

        let recorded = server.bridge_recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, crate::bridge::HttpMethod::Get);
        assert_eq!(
            recorded[0].url,
            "http://127.0.0.1:8080/api/v1/books/book-7/archive/package"
        );
        assert_eq!(
            recorded[0].header("Authorization"),
            Some("Bearer chk_ab12cd_secretsecret")
        );
    }

    #[test]
    fn tools_call_prepare_archive_export_routes_to_archive_package_endpoint() {
        let cfg = McpConfig {
            enabled_tools: EnabledTools::List(vec!["prepare_archive_export".into()]),
            ..enabled_cfg()
        };
        let response = HttpResponse::bytes(200, b"PK".to_vec())
            .with_header("Content-Type", "application/zip")
            .with_header(
                "Content-Disposition",
                "attachment; filename=\"chancela-preservation-book-book-7.zip\"",
            );
        let server = McpServer::from_config(&cfg, MockTransport::with_response(response)).unwrap();
        let resp = server
            .handle(&req(
                "tools/call",
                44,
                json!({
                    "name": "prepare_archive_export",
                    "arguments": {
                        "book_id": "book-7",
                        "legal_hold": true,
                        "legal_hold_reason": "retention review"
                    }
                }),
            ))
            .unwrap();

        let result = resp.result.unwrap();
        assert_eq!(result["isError"], json!(false));
        let payload: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(payload["kind"], json!("binary"));
        assert_eq!(payload["encoding"], json!("base64"));
        assert_eq!(payload["content_type"], json!("application/zip"));

        let recorded = server.bridge_recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, crate::bridge::HttpMethod::Get);
        assert_eq!(
            recorded[0].url,
            "http://127.0.0.1:8080/api/v1/books/book-7/archive/package?legal_hold=true&legal_hold_reason=retention%20review"
        );
        assert_eq!(
            recorded[0].header("Authorization"),
            Some("Bearer chk_ab12cd_secretsecret")
        );
    }

    #[test]
    fn tools_call_ledger_archive_document_builds_filter_query() {
        let response = HttpResponse::bytes(200, b"%PDF".to_vec())
            .with_header("Content-Type", "application/pdf; profile=PDF/A-2u")
            .with_header(
                "Content-Disposition",
                "attachment; filename=\"arquivo-book-book-7.pdf\"",
            );
        let server =
            McpServer::from_config(&enabled_cfg(), MockTransport::with_response(response)).unwrap();
        let resp = server
            .handle(&req(
                "tools/call",
                33,
                json!({
                    "name": "export_ledger_archive_document",
                    "arguments": {
                        "chain": "book:book-7",
                        "scope": "book:book-7",
                        "kind": "book.opened",
                        "limit": 1
                    }
                }),
            ))
            .unwrap();
        assert_eq!(resp.result.unwrap()["isError"], json!(false));

        let recorded = server.bridge_recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, crate::bridge::HttpMethod::Get);
        assert_eq!(
            recorded[0].url,
            "http://127.0.0.1:8080/api/v1/ledger/archive/document?chain=book%3Abook-7&kind=book.opened&limit=1&scope=book%3Abook-7"
        );
        assert_eq!(
            recorded[0].header("Authorization"),
            Some("Bearer chk_ab12cd_secretsecret")
        );
    }

    #[test]
    fn tools_call_act_working_copy_returns_markdown_text() {
        let markdown = "# WORKING COPY - NON-EVIDENTIARY\n\nAta da Assembleia Geral Anual\n";
        let response = HttpResponse::text(200, markdown)
            .with_header("Content-Type", "text/markdown; charset=utf-8")
            .with_header(
                "Content-Disposition",
                "attachment; filename=\"act-act-7-working-copy.md\"",
            );
        let server =
            McpServer::from_config(&enabled_cfg(), MockTransport::with_response(response)).unwrap();
        let resp = server
            .handle(&req(
                "tools/call",
                37,
                json!({ "name": "export_act_working_copy", "arguments": { "id": "act-7" } }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], json!(false));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, markdown);
        assert!(!text.contains("\"kind\": \"binary\""), "{text}");

        let recorded = server.bridge_recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, crate::bridge::HttpMethod::Get);
        assert_eq!(
            recorded[0].url,
            "http://127.0.0.1:8080/api/v1/acts/act-7/document/working-copy"
        );
        assert_eq!(
            recorded[0].header("Authorization"),
            Some("Bearer chk_ab12cd_secretsecret")
        );
    }

    #[test]
    fn tools_call_json_content_type_remains_text_json() {
        let response = HttpResponse::text(200, r#"{"items":[]}"#)
            .with_header("Content-Type", "application/json; charset=utf-8");
        let server =
            McpServer::from_config(&enabled_cfg(), MockTransport::with_response(response)).unwrap();
        let resp = server
            .handle(&req(
                "tools/call",
                34,
                json!({ "name": "list_entities", "arguments": {} }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], json!(false));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"items\": []"), "{text}");
        assert!(!text.contains("\"kind\": \"binary\""), "{text}");
    }

    #[test]
    fn tools_call_trust_catalog_uses_base_path_query_and_bearer() {
        let cfg = McpConfig {
            base_path: "/bridge/base".to_string(),
            ..enabled_cfg()
        };
        let server =
            McpServer::from_config(&cfg, MockTransport::new(200, r#"{"results":[]}"#)).unwrap();
        let resp = server
            .handle(&req(
                "tools/call",
                31,
                json!({
                    "name": "search_trust_catalog",
                    "arguments": { "search": "multicert services", "limit": 2 }
                }),
            ))
            .unwrap();
        assert_eq!(resp.result.unwrap()["isError"], json!(false));

        let recorded = server.bridge_recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, crate::bridge::HttpMethod::Get);
        assert_eq!(
            recorded[0].url,
            "http://127.0.0.1:8080/bridge/base/trust/catalog?limit=2&search=multicert%20services"
        );
        assert_eq!(
            recorded[0].header("Authorization"),
            Some("Bearer chk_ab12cd_secretsecret")
        );
    }

    #[test]
    fn tools_call_write_sends_post_body() {
        let server =
            McpServer::from_config(&enabled_cfg(), MockTransport::new(201, r#"{"id":"new"}"#))
                .unwrap();
        let _ = server
            .handle(&req("tools/call", 4, json!({ "name": "create_entity", "arguments": { "name": "Encosto Estratégico Lda" } })))
            .unwrap();
        let recorded = server.bridge_recorded();
        assert_eq!(recorded[0].method, crate::bridge::HttpMethod::Post);
        assert_eq!(recorded[0].url, "http://127.0.0.1:8080/api/v1/entities");
        assert!(recorded[0].body.as_deref().unwrap().contains("Encosto"));
    }

    #[test]
    fn error_401_maps_to_honest_tool_error() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(401, "no")).unwrap();
        let resp = server
            .handle(&req(
                "tools/call",
                5,
                json!({ "name": "list_entities", "arguments": {} }),
            ))
            .unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], json!(true));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("401"), "expected 401 in: {text}");
        assert!(
            !text.contains("secretsecret"),
            "key must never leak: {text}"
        );
    }

    #[test]
    fn error_403_and_429_map_honestly() {
        for (status, needle) in [(403u16, "403"), (429u16, "429")] {
            let server =
                McpServer::from_config(&enabled_cfg(), MockTransport::new(status, "x")).unwrap();
            let resp = server
                .handle(&req(
                    "tools/call",
                    6,
                    json!({ "name": "list_entities", "arguments": {} }),
                ))
                .unwrap();
            let text = resp.result.unwrap()["content"][0]["text"]
                .as_str()
                .unwrap()
                .to_string();
            assert!(text.contains(needle), "expected {needle} in: {text}");
        }
    }

    #[test]
    fn initialize_reports_protocol_and_server_info() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server.handle(&req("initialize", 7, json!({}))).unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], json!(PROTOCOL_VERSION));
        assert_eq!(result["serverInfo"]["name"], json!(SERVER_NAME));
        assert!(result["capabilities"]["prompts"].is_object());
        assert_eq!(
            result["capabilities"]["prompts"]["listChanged"],
            json!(false)
        );
        assert!(result["capabilities"]["tools"].is_object());
        assert!(result["capabilities"]["resources"].is_object());
    }

    #[test]
    fn notification_yields_no_response() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let notif: JsonRpcRequest = serde_json::from_value(
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        )
        .unwrap();
        assert!(server.handle(&notif).is_none());
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let resp = server.handle(&req("unknown/method", 8, json!({}))).unwrap();
        assert_eq!(resp.error.unwrap().code, codes::METHOD_NOT_FOUND);
    }

    #[test]
    fn run_loop_reads_and_writes_ndjson() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "[]")).unwrap();
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
        let mut out: Vec<u8> = Vec::new();
        server
            .run(std::io::Cursor::new(input.as_bytes()), &mut out)
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        // Exactly one response line (the notification produced none).
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("\"tools\""));
    }

    #[test]
    fn malformed_line_yields_parse_error() {
        let server = McpServer::from_config(&enabled_cfg(), MockTransport::new(200, "{}")).unwrap();
        let mut out: Vec<u8> = Vec::new();
        server
            .run(std::io::Cursor::new(b"not json\n" as &[u8]), &mut out)
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("-32700"));
    }

    // Test-only accessor for the mock transport's recorded requests.
    impl McpServer<MockTransport> {
        fn bridge_recorded(&self) -> Vec<HttpRequest> {
            self.bridge.transport_ref().recorded.borrow().clone()
        }
    }
}
