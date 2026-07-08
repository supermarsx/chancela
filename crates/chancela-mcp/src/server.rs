//! The MCP server: JSON-RPC dispatch over the tool registry + the stdio serve loop.
//!
//! **Off by default is enforced structurally**: [`McpServer::from_config`] returns
//! [`McpError::Disabled`] when `enabled == false`, and [`serve_stdio`] returns early (serving
//! nothing, touching no I/O) before it ever reads stdin. There is no way to serve a disabled
//! server — "off" is genuinely zero surface, not a soft flag.
//!
//! Dispatch handles the MCP subset needed for a tool server: `initialize`, `notifications/*`,
//! `ping`, `tools/list`, `tools/call`. `tools/call` resolves the tool to an `/api/v1` request via
//! [`crate::registry::resolve_call`] and forwards it through the [`ApiBridge`] with the configured
//! key. Authorization is entirely server-side (the key's principal); this layer never re-checks it.

use std::io::{BufRead, Write};

use serde_json::{Value, json};

use crate::bridge::{ApiBridge, BridgeError, HttpTransport, ReqwestTransport};
use crate::config::{EnabledTools, McpConfig, McpTransport};
use crate::error::McpError;
use crate::jsonrpc::{JsonRpcRequest, JsonRpcResponse, codes};
use crate::registry::{McpTool, ToolError, catalog, resolve_call};

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
    /// Build a server from config + a transport. **Refuses a disabled config** (`McpError::Disabled`)
    /// — off by default means not served. The enabled-tools policy filters the catalog here, so a
    /// disabled tool is absent from `tools/list` and unreachable via `tools/call`.
    pub fn from_config(config: &McpConfig, transport: T) -> Result<Self, McpError> {
        if !config.enabled {
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

        match self.bridge.execute(
            resolved.method,
            &resolved.path,
            &resolved.query,
            resolved.body.as_ref(),
        ) {
            Ok(outcome) if outcome.is_success() => {
                let text = outcome
                    .value
                    .map(|v| serde_json::to_string_pretty(&v).unwrap_or(outcome.raw.clone()))
                    .unwrap_or(outcome.raw);
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
    if !config.enabled {
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
    if !config.enabled {
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
            Self {
                recorded: RefCell::new(Vec::new()),
                response: HttpResponse {
                    status,
                    body: body.to_string(),
                },
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
        assert!(names.contains(&"seal_act"));
        // schema + annotations present
        assert!(tools[0]["inputSchema"].is_object());
        assert!(tools[0]["annotations"]["readOnlyHint"].is_boolean());
    }

    #[test]
    fn per_tool_enablement_filters_list_and_call() {
        let cfg = McpConfig {
            enabled_tools: EnabledTools::List(vec!["list_entities".into()]),
            ..enabled_cfg()
        };
        let server = McpServer::from_config(&cfg, MockTransport::new(200, "[]")).unwrap();
        assert_eq!(server.tools().len(), 1);
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
