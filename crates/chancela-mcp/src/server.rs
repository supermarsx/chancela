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

const DRAFT_MINUTES_REVIEW_PROMPT_NAME: &str = "draft_minutes_human_review_checklist";
const DRAFT_MINUTES_REVIEW_PROMPT_TITLE: &str = "Draft Minutes Human Review Checklist";
const DRAFT_MINUTES_REVIEW_PROMPT_DESCRIPTION: &str = "Human-review checklist for draft minutes. Guidance only; no legal validity, signing, or hidden provider call.";
const COMPLIANCE_PACK_GAP_REVIEW_PROMPT_NAME: &str = "compliance_pack_gap_review";
const COMPLIANCE_PACK_GAP_REVIEW_PROMPT_TITLE: &str = "Compliance Pack Gap Review";
const COMPLIANCE_PACK_GAP_REVIEW_PROMPT_DESCRIPTION: &str = "Human-review prompt for DSR, retention, and archive evidence gaps. Guidance only; no legal-validity or provider claims.";

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
        let payload = match uri {
            MCP_STATUS_RESOURCE_URI => self.status_resource_payload(),
            MCP_SPEC_09_COVERAGE_RESOURCE_URI => self.spec_09_coverage_resource_payload(),
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
                        "resources": [MCP_STATUS_RESOURCE_URI, MCP_SPEC_09_COVERAGE_RESOURCE_URI],
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
            "review_boundaries": {
                "hidden_provider_calls": false,
                "additional_credentials_required": false,
                "resource_read_forwards_api_key": false,
                "secrets_in_resource": false,
                "legal_validity_claimed": false,
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

        let resolved = match resolve_call(tool, &arguments) {
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
        assert_eq!(resources.len(), 2);
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
        assert_eq!(coverage["coverage"]["AI-10"]["status"], json!("partial"));
        assert_eq!(
            coverage["coverage"]["AI-10"]["covered_locally"]["resources"],
            json!([MCP_STATUS_RESOURCE_URI, MCP_SPEC_09_COVERAGE_RESOURCE_URI])
        );
        assert!(
            coverage["coverage"]["AI-10"]["covered_locally"]["prompts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|name| name.as_str() == Some(COMPLIANCE_PACK_GAP_REVIEW_PROMPT_NAME))
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
        assert_eq!(
            body,
            json!({
                "actor": "mcp",
                "ai_provenance": {
                    "source": "mcp",
                    "tool": "draft_minutes",
                    "statement_source": "mcp tool arguments"
                },
                "book_id": "book-7",
                "channel": "Physical",
                "title": "Ata da Assembleia Geral Anual"
            })
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
