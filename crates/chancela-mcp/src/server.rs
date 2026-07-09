//! The MCP server: JSON-RPC dispatch over the tool registry + the stdio serve loop.
//!
//! **Off by default is enforced structurally**: [`McpServer::from_config`] returns
//! [`McpError::Disabled`] unless both the MCP process switch and tenant AI/MCP gate are enabled, and
//! [`serve_stdio`] returns early (serving nothing, touching no I/O) before it ever reads stdin. There
//! is no way to serve a disabled server — "off" is genuinely zero surface, not a soft flag.
//!
//! Dispatch handles the MCP subset needed for a tool server: `initialize`, `notifications/*`,
//! `ping`, `tools/list`, `tools/call`. `tools/call` resolves the tool to an `/api/v1` request via
//! [`crate::registry::resolve_call`] and forwards it through the [`ApiBridge`] with the configured
//! key. Authorization is entirely server-side (the key's principal); this layer never re-checks it.

use std::io::{BufRead, Write};

use serde_json::{Value, json};

use crate::bridge::{ApiBridge, ApiOutcome, BridgeError, HttpTransport, ReqwestTransport};
use crate::config::{EnabledTools, McpConfig, McpTransport};
use crate::error::McpError;
use crate::jsonrpc::{JsonRpcRequest, JsonRpcResponse, codes};
use crate::registry::{McpTool, ResolvedCall, ToolError, catalog, resolve_call};

/// The MCP protocol version this server implements.
pub const PROTOCOL_VERSION: &str = "2025-06-18";
/// Advertised server name.
pub const SERVER_NAME: &str = "chancela-mcp";

/// The running MCP server: the enabled tool subset + the api-key bridge.
pub struct McpServer<T: HttpTransport> {
    tools: Vec<McpTool>,
    bridge: ApiBridge<T>,
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
        let tools = catalog()
            .into_iter()
            .filter(|t| config.enabled_tools.allows(t.name))
            .collect();
        Ok(Self {
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
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": { "name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION") },
            "instructions": "Chancela platform operations as permission-gated MCP tools. Every tool call is authorized server-side by the configured API key's RBAC principal.",
        })
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
    let payload = json!({
        "kind": "ai_draft",
        "status": "draft",
        "non_authoritative": true,
        "human_verification_required": true,
        "legal_effect": "none_until_human_verification_and_seal",
        "verification": {
            "status": "pending",
            "required": true,
            "accepted_as_legal_text": false,
        },
        "provenance": {
            "source": {
                "surface": "mcp",
                "tool": tool.name,
                "endpoint": format!("{} {}", resolved.method.as_str(), resolved.path),
            },
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
        assert!(names.contains(&"seal_act"));
        // schema + annotations present
        assert!(tools[0]["inputSchema"].is_object());
        assert!(tools[0]["annotations"]["readOnlyHint"].is_boolean());
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
        assert_eq!(
            payload["verification"]["accepted_as_legal_text"],
            json!(false)
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
        assert!(result["capabilities"]["tools"].is_object());
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
        let resp = server.handle(&req("resources/list", 8, json!({}))).unwrap();
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
