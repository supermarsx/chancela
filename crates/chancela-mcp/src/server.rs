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
                    "description": "Read-only static workflow provenance review aid. Contains no secrets, performs no bridge or provider calls, and makes no legal-validity, source-certification, provider, or trust claims.",
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
        let draft_signed_arguments = if uri == MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI {
            if params.keys().any(|key| key != "uri" && key != "arguments") {
                return JsonRpcResponse::error(
                    id,
                    codes::INVALID_PARAMS,
                    "draft-signed comparison resource accepts only uri or uri plus arguments",
                );
            }
            match params.get("arguments") {
                Some(arguments) => Some(arguments),
                None => None,
            }
        } else {
            None
        };
        let payload = match uri {
            MCP_STATUS_RESOURCE_URI => self.status_resource_payload(),
            MCP_SPEC_09_COVERAGE_RESOURCE_URI => self.spec_09_coverage_resource_payload(),
            MCP_WORKFLOW_PROVENANCE_REVIEW_RESOURCE_URI => {
                self.workflow_provenance_review_resource_payload()
            }
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
                ],
                "prompts": [
                    WORKFLOW_PROVENANCE_REVIEW_PROMPT_NAME,
                    DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_NAME,
                ],
                "purpose": "offline_human_review_guidance_plus_deterministic_local_draft_signed_metadata_comparison",
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
        assert_eq!(resources.len(), 4);
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
                MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI
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
                MCP_DRAFT_SIGNED_COMPARISON_REVIEW_RESOURCE_URI
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
