//! The extensible MCP tool registry.
//!
//! An [`McpTool`] maps a tool name to `{ description, JSON input schema, the /api/v1 call it makes,
//! the permission the server-side gate enforces }`. **Adding a tool is one entry in [`catalog`],
//! not a rewrite.** Authorization is NOT done here — the `permission` field is documentation of the
//! server-side gate (t65-E3) that the forwarded key is checked against; the MCP server only forwards
//! the key (plan §2, "one RBAC path, no bypass").
//!
//! [`resolve_call`] turns a tool + its JSON arguments into a concrete HTTP call: path placeholders
//! (`{id}`) are filled from arguments; the remaining arguments become the query string (for reads)
//! or the JSON body (for writes). This one rule serves the whole catalog and any future tool.

use crate::bridge::{HttpMethod, percent_encode};
use serde_json::Value;

/// The AI-11 read-only vs write-controlled split. Advisory metadata surfaced to the client; the
/// hard gate is server-side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolAccess {
    /// A read; safe to call speculatively.
    ReadOnly,
    /// A mutation; the client should treat it as write-controlled (human-in-the-loop per AI-03).
    WriteControlled,
}

impl ToolAccess {
    /// MCP `readOnlyHint` value for the tool annotations.
    pub fn read_only_hint(self) -> bool {
        matches!(self, ToolAccess::ReadOnly)
    }
}

/// The `/api/v1` endpoint a tool maps to.
#[derive(Debug, Clone, Copy)]
pub struct ToolCall {
    pub method: HttpMethod,
    /// Path relative to the configured base path, with `{name}` placeholders, e.g.
    /// `/entities/{id}/chronology`.
    pub path_template: &'static str,
}

/// One registry entry: a platform operation exposed as an MCP tool.
#[derive(Debug, Clone)]
pub struct McpTool {
    /// Stable tool name the client calls, e.g. `"list_entities"`.
    pub name: &'static str,
    /// Human title.
    pub title: &'static str,
    /// What the tool does (shown to the model).
    pub description: &'static str,
    /// Read-only vs write-controlled (AI-11).
    pub access: ToolAccess,
    /// The permission the server-side RBAC gate enforces on the forwarded key (documentation of the
    /// t65-E3 gate — NOT enforced in this crate).
    pub permission: &'static str,
    /// JSON Schema for the tool's arguments.
    pub input_schema: Value,
    /// The `/api/v1` call this tool makes.
    pub call: ToolCall,
}

/// A concrete HTTP call resolved from a tool + its arguments.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedCall {
    pub method: HttpMethod,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Option<Value>,
}

/// Failure resolving a tool call from arguments (a client/protocol error, not a server error).
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ToolError {
    /// A `{name}` path placeholder had no corresponding argument.
    #[error("missing required argument: {0}")]
    MissingArgument(String),
    /// A closed-schema tool received an argument it does not declare.
    #[error("unknown argument: {0}")]
    UnknownArgument(String),
    /// `arguments` was present but not a JSON object.
    #[error("arguments must be a JSON object")]
    ArgumentsNotObject,
}

/// Resolve `tool` + `arguments` into a concrete [`ResolvedCall`].
///
/// - Every `{name}` in `path_template` is substituted from `arguments[name]` (URL-encoded); a
///   missing one is [`ToolError::MissingArgument`] (fail-closed — no call is made).
/// - Remaining arguments: for `GET` they become query params; for writes they become the JSON body.
pub fn resolve_call(tool: &McpTool, arguments: &Value) -> Result<ResolvedCall, ToolError> {
    let args_obj = match arguments {
        Value::Null => None,
        Value::Object(map) => Some(map),
        _ => return Err(ToolError::ArgumentsNotObject),
    };

    let placeholders = path_placeholders(tool.call.path_template);
    validate_arguments(tool, args_obj, &placeholders)?;
    let mut path = String::with_capacity(tool.call.path_template.len());
    let mut rest = std::collections::BTreeMap::new();
    if let Some(map) = args_obj {
        for (k, v) in map {
            if !placeholders.contains(&k.as_str()) {
                rest.insert(k.clone(), v.clone());
            }
        }
    }

    // Substitute placeholders.
    let mut chars = tool.call.path_template.char_indices().peekable();
    let template = tool.call.path_template;
    while let Some((i, c)) = chars.next() {
        if c == '{' {
            // read until '}'
            let start = i + 1;
            let end = template[start..].find('}').map(|off| start + off);
            match end {
                Some(end) => {
                    let name = &template[start..end];
                    let value = args_obj
                        .and_then(|m| m.get(name))
                        .ok_or_else(|| ToolError::MissingArgument(name.to_string()))?;
                    path.push_str(&percent_encode(&scalar_to_string(value)));
                    // advance the iterator past the '}'
                    while let Some(&(j, _)) = chars.peek() {
                        if j <= end {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                }
                None => path.push(c), // unterminated '{': treat literally
            }
        } else {
            path.push(c);
        }
    }

    let (query, mut body) = if tool.call.method == HttpMethod::Get {
        let q = rest
            .into_iter()
            .map(|(k, v)| (k, scalar_to_string(&v)))
            .collect::<Vec<_>>();
        (q, None)
    } else if rest.is_empty() {
        (Vec::new(), None)
    } else {
        let obj = rest.into_iter().collect::<serde_json::Map<_, _>>();
        (Vec::new(), Some(Value::Object(obj)))
    };
    ensure_mcp_ai_draft_provenance(tool, &mut body);

    Ok(ResolvedCall {
        method: tool.call.method,
        path,
        query,
        body,
    })
}

fn ensure_mcp_ai_draft_provenance(tool: &McpTool, body: &mut Option<Value>) {
    if !matches!(tool.name, "draft_act" | "draft_minutes") {
        return;
    }
    let Some(Value::Object(map)) = body else {
        return;
    };

    let statement_source = map
        .get("ai_provenance")
        .and_then(Value::as_object)
        .and_then(|p| p.get("statement_source"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| "mcp tool arguments".to_owned());

    map.insert(
        "ai_provenance".to_owned(),
        serde_json::json!({
            "source": "mcp",
            "tool": tool.name,
            "statement_source": statement_source,
        }),
    );
}

fn validate_arguments(
    tool: &McpTool,
    args_obj: Option<&serde_json::Map<String, Value>>,
    placeholders: &[&str],
) -> Result<(), ToolError> {
    if let Some(required) = tool.input_schema.get("required").and_then(Value::as_array) {
        for name in required.iter().filter_map(Value::as_str) {
            let value = args_obj.and_then(|m| m.get(name));
            if value.is_none_or(Value::is_null) {
                return Err(ToolError::MissingArgument(name.to_string()));
            }
        }
    }

    if tool
        .input_schema
        .get("additionalProperties")
        .and_then(Value::as_bool)
        == Some(false)
    {
        let properties = tool
            .input_schema
            .get("properties")
            .and_then(Value::as_object);
        if let Some(args) = args_obj {
            for name in args.keys() {
                let declared = properties.is_some_and(|p| p.contains_key(name));
                if !declared && !placeholders.contains(&name.as_str()) {
                    return Err(ToolError::UnknownArgument(name.clone()));
                }
            }
        }
    }

    Ok(())
}

/// Extract the `{name}` placeholder names from a path template.
fn path_placeholders(template: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{'
            && let Some(off) = template[i + 1..].find('}')
        {
            out.push(&template[i + 1..i + 1 + off]);
            i = i + 1 + off + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// Render a JSON scalar as a plain string for use in a path/query (objects/arrays are JSON-encoded).
fn scalar_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// The frozen tool catalog (plan §3.4 initial AI-11 set + the recommended FLAG 8-E extensions).
/// Each entry is a platform operation; permissions are the server-side gate's, listed for docs.
/// Adding a tool = one more entry here.
pub fn catalog() -> Vec<McpTool> {
    use HttpMethod::*;
    let obj_with_extra = |props: Value, required: &[&str], additional_properties: bool| -> Value {
        serde_json::json!({
            "type": "object",
            "properties": props,
            "required": required,
            "additionalProperties": additional_properties,
        })
    };
    let obj = |props: Value, required: &[&str]| -> Value { obj_with_extra(props, required, true) };
    let closed_obj =
        |props: Value, required: &[&str]| -> Value { obj_with_extra(props, required, false) };
    let id_only = || {
        obj(
            serde_json::json!({ "id": { "type": "string", "description": "resource id" } }),
            &["id"],
        )
    };
    let entity_id_only = || {
        obj(
            serde_json::json!({ "entity_id": { "type": "string", "description": "entity/company id" } }),
            &["entity_id"],
        )
    };
    let book_id_only = || {
        obj(
            serde_json::json!({ "book_id": { "type": "string", "description": "book id" } }),
            &["book_id"],
        )
    };
    let archive_export_args = || {
        closed_obj(
            serde_json::json!({
                "book_id": { "type": "string", "description": "book id" },
                "legal_hold": {
                    "type": "boolean",
                    "description": "optional export-time legal-hold marker for the package"
                },
                "legal_hold_reason": {
                    "type": "string",
                    "description": "required by the API when legal_hold=true"
                }
            }),
            &["book_id"],
        )
    };
    let signature_bundle_args = || {
        closed_obj(
            serde_json::json!({
                "act_id": {
                    "type": "string",
                    "description": "act id whose stored signature status/evidence should be reported"
                }
            }),
            &["act_id"],
        )
    };
    let external_validator_report_metadata_args = || {
        closed_obj(
            serde_json::json!({
                "case_id": {
                    "type": "string",
                    "description": "external-validator report case identity slug"
                },
                "validator_family": {
                    "type": "string",
                    "description": "external-validator family identity slug"
                }
            }),
            &["case_id", "validator_family"],
        )
    };
    let mermaid_graph_args = || {
        obj(
            serde_json::json!({
                "entity_id": { "type": "string", "description": "entity/company id" },
                "kind": {
                    "type": "string",
                    "enum": ["shareholders", "organs", "relationships"],
                    "description": "Mermaid graph kind: shareholders, organs/managers, or relationships"
                }
            }),
            &["entity_id", "kind"],
        )
    };
    let draft_act_args = || {
        closed_obj(
            serde_json::json!({
                "book_id": { "type": "string", "description": "target open book id" },
                "title": { "type": "string", "description": "minutes title/subject" },
                "channel": {
                    "type": "string",
                    "enum": ["Physical", "Hybrid", "Telematic", "WrittenResolution"],
                    "description": "meeting or deliberation channel"
                },
                "retifies": {
                    "type": "string",
                    "description": "optional sealed act id this draft rectifies"
                },
                "ai_provenance": {
                    "type": "object",
                    "description": "optional non-authoritative AI provenance for a draft; accepted human verification is recorded later by the API",
                    "properties": {
                        "source": {
                            "type": "string",
                            "description": "declared AI-assistance source, e.g. mcp"
                        },
                        "tool": {
                            "type": "string",
                            "description": "tool/model/integration identifier when known"
                        },
                        "statement_source": {
                            "type": "string",
                            "description": "where the human statement/instruction came from when known"
                        }
                    },
                    "required": ["source"],
                    "additionalProperties": false
                },
                "actor": {
                    "type": "string",
                    "description": "optional actor label forwarded to the API; defaults server-side to api"
                }
            }),
            &["book_id", "title", "channel"],
        )
    };
    let empty = || obj(serde_json::json!({}), &[]);

    vec![
        McpTool {
            name: "list_entities",
            title: "List entities",
            description: "List the registered entities (companies/foundations), e.g. Encosto Estratégico Lda.",
            access: ToolAccess::ReadOnly,
            permission: "entity.read",
            input_schema: empty(),
            call: ToolCall {
                method: Get,
                path_template: "/entities",
            },
        },
        McpTool {
            name: "list_companies",
            title: "List companies",
            description: "Alias for list_entities: list the registered entities (companies/foundations), e.g. Encosto Estratégico Lda.",
            access: ToolAccess::ReadOnly,
            permission: "entity.read",
            input_schema: empty(),
            call: ToolCall {
                method: Get,
                path_template: "/entities",
            },
        },
        McpTool {
            name: "get_entity",
            title: "Get entity",
            description: "Fetch a single entity by id.",
            access: ToolAccess::ReadOnly,
            permission: "entity.read",
            input_schema: id_only(),
            call: ToolCall {
                method: Get,
                path_template: "/entities/{id}",
            },
        },
        McpTool {
            name: "create_entity",
            title: "Create entity",
            description: "Register a new entity. Fields are passed as the request body.",
            access: ToolAccess::WriteControlled,
            permission: "entity.create",
            input_schema: obj(
                serde_json::json!({ "name": { "type": "string", "description": "legal name, e.g. Encosto Estratégico Lda" } }),
                &["name"],
            ),
            call: ToolCall {
                method: Post,
                path_template: "/entities",
            },
        },
        McpTool {
            name: "import_entity_from_registry",
            title: "Import entity from registry",
            description: "Create an entity from a certidão permanente access code (registo comercial).",
            access: ToolAccess::WriteControlled,
            permission: "entity.create",
            input_schema: obj(
                serde_json::json!({ "access_code": { "type": "string", "description": "certidão permanente access code" } }),
                &["access_code"],
            ),
            call: ToolCall {
                method: Post,
                path_template: "/entities/import-from-registry",
            },
        },
        McpTool {
            name: "chronology",
            title: "Entity chronology",
            description: "The full chronological timeline of an entity's books and acts.",
            access: ToolAccess::ReadOnly,
            permission: "entity.read",
            input_schema: id_only(),
            call: ToolCall {
                method: Get,
                path_template: "/entities/{id}/chronology",
            },
        },
        McpTool {
            name: "get_company_timeline",
            title: "Get company timeline",
            description: "Alias for chronology: fetch the full chronological timeline of an entity/company.",
            access: ToolAccess::ReadOnly,
            permission: "entity.read",
            input_schema: entity_id_only(),
            call: ToolCall {
                method: Get,
                path_template: "/entities/{entity_id}/chronology",
            },
        },
        McpTool {
            name: "generate_mermaid_graph",
            title: "Generate Mermaid graph",
            description: "Return one DOC-31 Mermaid chronology diagram for an entity/company.",
            access: ToolAccess::ReadOnly,
            permission: "entity.read",
            input_schema: mermaid_graph_args(),
            call: ToolCall {
                method: Get,
                path_template: "/entities/{entity_id}/chronology",
            },
        },
        McpTool {
            name: "list_books",
            title: "List books",
            description: "List record books.",
            access: ToolAccess::ReadOnly,
            permission: "book.read",
            input_schema: empty(),
            call: ToolCall {
                method: Get,
                path_template: "/books",
            },
        },
        McpTool {
            name: "export_book_archive_package",
            title: "Export book preservation package",
            description: "Download the read-only preservation ZIP package for a book. The API enforces book.export for the forwarded key.",
            access: ToolAccess::ReadOnly,
            permission: "book.export",
            input_schema: book_id_only(),
            call: ToolCall {
                method: Get,
                path_template: "/books/{book_id}/archive/package",
            },
        },
        McpTool {
            name: "prepare_archive_export",
            title: "Prepare archive export",
            description: "AI-11 write-controlled alias for preparing the existing book archive preservation ZIP. Routes to the API's gated archive-package endpoint; the API enforces book.export for the forwarded key.",
            access: ToolAccess::WriteControlled,
            permission: "book.export",
            input_schema: archive_export_args(),
            call: ToolCall {
                method: Get,
                path_template: "/books/{book_id}/archive/package",
            },
        },
        McpTool {
            name: "open_book",
            title: "Open book",
            description: "Open (create) a new record book. Fields are passed as the request body.",
            access: ToolAccess::WriteControlled,
            permission: "book.open",
            input_schema: obj(
                serde_json::json!({ "title": { "type": "string" }, "entity_id": { "type": "string" } }),
                &[],
            ),
            call: ToolCall {
                method: Post,
                path_template: "/books",
            },
        },
        McpTool {
            name: "draft_act",
            title: "Draft act",
            description: "Draft a new act (minutes/deliberation). Produces a DRAFT only — never a sealed act; human verification (AI-03) precedes sealing.",
            access: ToolAccess::WriteControlled,
            permission: "act.draft",
            input_schema: draft_act_args(),
            call: ToolCall {
                method: Post,
                path_template: "/acts",
            },
        },
        McpTool {
            name: "draft_minutes",
            title: "Draft minutes",
            description: "Alias for draft_act: create a new draft minutes/act through the existing POST /acts API path. This does not generate text; it only forwards caller-provided fields.",
            access: ToolAccess::WriteControlled,
            permission: "act.draft",
            input_schema: draft_act_args(),
            call: ToolCall {
                method: Post,
                path_template: "/acts",
            },
        },
        McpTool {
            name: "advance_act",
            title: "Advance act",
            description: "Advance an act to its next lifecycle stage.",
            access: ToolAccess::WriteControlled,
            permission: "act.advance",
            input_schema: id_only(),
            call: ToolCall {
                method: Post,
                path_template: "/acts/{id}/advance",
            },
        },
        McpTool {
            name: "seal_act",
            title: "Seal act",
            description: "Seal an act (perform the signing step). Server-side gated; step-up-only destructive paths are not key-reachable.",
            access: ToolAccess::WriteControlled,
            permission: "signing.perform",
            input_schema: id_only(),
            call: ToolCall {
                method: Post,
                path_template: "/acts/{id}/seal",
            },
        },
        McpTool {
            name: "generate_document",
            title: "Generate document",
            description: "Generate the PDF/A document for an act.",
            access: ToolAccess::WriteControlled,
            permission: "document.generate",
            input_schema: id_only(),
            call: ToolCall {
                method: Post,
                path_template: "/acts/{id}/document/generate",
            },
        },
        McpTool {
            name: "preview_document",
            title: "Preview document",
            description: "Preview the rendered document for an act without generating a stored artifact.",
            access: ToolAccess::ReadOnly,
            permission: "act.read",
            input_schema: id_only(),
            call: ToolCall {
                method: Get,
                path_template: "/acts/{id}/document/preview",
            },
        },
        McpTool {
            name: "export_act_working_copy",
            title: "Export act working copy",
            description: "Return the read-only Markdown working-copy export for an act. This is non-evidentiary and does not replace the preserved PDF/A or signed PDF.",
            access: ToolAccess::ReadOnly,
            permission: "act.read",
            input_schema: id_only(),
            call: ToolCall {
                method: Get,
                path_template: "/acts/{id}/document/working-copy",
            },
        },
        McpTool {
            name: "validate_signature_bundle",
            title: "Validate signature bundle",
            description: "AI-11 read-only signature-status alias. Reports technical evidence/status from the existing act signature endpoint only; it does not perform or claim legal validation.",
            access: ToolAccess::ReadOnly,
            permission: "act.read",
            input_schema: signature_bundle_args(),
            call: ToolCall {
                method: Get,
                path_template: "/acts/{act_id}/signature",
            },
        },
        McpTool {
            name: "get_ledger",
            title: "Get ledger events",
            description: "List audit-ledger events.",
            access: ToolAccess::ReadOnly,
            permission: "ledger.read",
            input_schema: empty(),
            call: ToolCall {
                method: Get,
                path_template: "/ledger/events",
            },
        },
        McpTool {
            name: "verify_ledger",
            title: "Verify ledger",
            description: "Verify the integrity of the audit-ledger hash chain.",
            access: ToolAccess::ReadOnly,
            permission: "ledger.read",
            input_schema: empty(),
            call: ToolCall {
                method: Get,
                path_template: "/ledger/verify",
            },
        },
        McpTool {
            name: "export_ledger_archive_document",
            title: "Export ledger archive document",
            description: "Download the read-only bounded first page of the ledger archive as PDF/A, TXT, JSON, CSV, or HTML. Optional filters become query parameters; order defaults to newest-first desc.",
            access: ToolAccess::ReadOnly,
            permission: "ledger.read",
            input_schema: obj(
                serde_json::json!({
                    "format": {
                        "type": "string",
                        "enum": ["pdfa", "txt", "json", "csv", "html"],
                        "description": "export format; pdfa is the canonical preserved-evidence rendering"
                    },
                    "q": { "type": "string", "description": "free-text search across event id, seq, kind, scope, actor, justification, chains and hashes" },
                    "chain": { "type": "string", "description": "chain id: global, application, company:<id>, or book:<id>" },
                    "scope": { "type": "string", "description": "substring scope filter" },
                    "kind": { "type": "string", "description": "event kind, or comma-separated event kinds" },
                    "actor": { "type": "string", "description": "exact actor filter" },
                    "from": { "type": "string", "description": "inclusive lower timestamp bound: RFC 3339 or YYYY-MM-DD" },
                    "to": { "type": "string", "description": "upper timestamp bound: RFC 3339 inclusive, or YYYY-MM-DD for the whole day" },
                    "limit": { "type": "integer", "description": "bounded first-page limit after filters; normalized by the API" },
                    "order": {
                        "type": "string",
                        "enum": ["desc"],
                        "description": "newest-first order over global seq; defaults to desc"
                    }
                }),
                &[],
            ),
            call: ToolCall {
                method: Get,
                path_template: "/ledger/archive/document",
            },
        },
        McpTool {
            name: "trust_status",
            title: "Trust status",
            description: "Fetch the local Trusted List status and validation summary.",
            access: ToolAccess::ReadOnly,
            permission: "cae.read",
            input_schema: empty(),
            call: ToolCall {
                method: Get,
                path_template: "/trust/status",
            },
        },
        McpTool {
            name: "search_trust_catalog",
            title: "Search trust catalog",
            description: "Search the local Trusted List catalog, or return the provider catalog when no search term is supplied.",
            access: ToolAccess::ReadOnly,
            permission: "cae.read",
            input_schema: obj(
                serde_json::json!({
                    "search": { "type": "string", "description": "provider or trust-service search text" },
                    "identifier": { "type": "string", "description": "provider or trust-service identifier" },
                    "service_type": { "type": "string", "description": "trust-service type filter" },
                    "status": { "type": "string", "description": "trust-service status filter" },
                    "history": { "type": "string", "description": "history filter: any/none or historical status/text" },
                    "supply_point": { "type": "string", "description": "service supply-point filter" },
                    "limit": { "type": "integer", "description": "maximum number of search results" }
                }),
                &[],
            ),
            call: ToolCall {
                method: Get,
                path_template: "/trust/catalog",
            },
        },
        McpTool {
            name: "list_external_validator_reports",
            title: "List external-validator report summaries",
            description: "List redacted technical metadata summaries for external-validator reports. This read-only tool does not expose raw report bytes or claim legal, trust, provider, certificate-path, or revocation validation.",
            access: ToolAccess::ReadOnly,
            permission: "settings.read",
            input_schema: closed_obj(serde_json::json!({}), &[]),
            call: ToolCall {
                method: Get,
                path_template: "/external-validator-reports",
            },
        },
        McpTool {
            name: "get_external_validator_report_metadata",
            title: "Get external-validator report metadata",
            description: "Fetch one settings.read-gated technical external-validator metadata JSON report by case_id and validator_family. This read-only tool uses only the safe metadata endpoint; it does not expose raw report bytes, upload report content, perform provider validation, or claim legal, trust, authenticity, certification, certificate-path, or revocation validation.",
            access: ToolAccess::ReadOnly,
            permission: "settings.read",
            input_schema: external_validator_report_metadata_args(),
            call: ToolCall {
                method: Get,
                path_template: "/external-validator-reports/{case_id}/{validator_family}",
            },
        },
        McpTool {
            name: "get_trust_provider",
            title: "Get trust provider",
            description: "Fetch a trusted-list provider by stable id.",
            access: ToolAccess::ReadOnly,
            permission: "cae.read",
            input_schema: id_only(),
            call: ToolCall {
                method: Get,
                path_template: "/trust/providers/{id}",
            },
        },
        McpTool {
            name: "get_trust_service",
            title: "Get trust service",
            description: "Fetch a trusted-list service by stable id.",
            access: ToolAccess::ReadOnly,
            permission: "cae.read",
            input_schema: id_only(),
            call: ToolCall {
                method: Get,
                path_template: "/trust/services/{id}",
            },
        },
        McpTool {
            name: "search_law",
            title: "Search legal texts",
            description: "Search the full-text law corpus (cited diplomas, article by article).",
            access: ToolAccess::ReadOnly,
            permission: "law.read",
            input_schema: obj(
                serde_json::json!({ "q": { "type": "string", "description": "free-text query" } }),
                &[],
            ),
            call: ToolCall {
                method: Get,
                path_template: "/law",
            },
        },
        McpTool {
            name: "search_legal_texts",
            title: "Search legal texts",
            description: "Alias for search_law: search the full-text law corpus (cited diplomas, article by article).",
            access: ToolAccess::ReadOnly,
            permission: "law.read",
            input_schema: obj(
                serde_json::json!({ "q": { "type": "string", "description": "free-text query" } }),
                &[],
            ),
            call: ToolCall {
                method: Get,
                path_template: "/law",
            },
        },
        McpTool {
            name: "list_templates",
            title: "List templates",
            description: "List the available document templates.",
            access: ToolAccess::ReadOnly,
            permission: "act.read",
            input_schema: empty(),
            call: ToolCall {
                method: Get,
                path_template: "/templates",
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str) -> McpTool {
        catalog().into_iter().find(|t| t.name == name).unwrap()
    }

    #[test]
    fn catalog_names_are_unique_and_nonempty() {
        let c = catalog();
        assert!(!c.is_empty());
        let mut names: Vec<_> = c.iter().map(|t| t.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate tool name in catalog");
    }

    #[test]
    fn read_tool_with_no_args_maps_to_bare_path() {
        let call = resolve_call(&tool("list_entities"), &Value::Null).unwrap();
        assert_eq!(call.method, HttpMethod::Get);
        assert_eq!(call.path, "/entities");
        assert!(call.query.is_empty());
        assert!(call.body.is_none());
    }

    #[test]
    fn draft_minutes_alias_is_write_controlled_and_routes_to_draft_act_api() {
        let canonical = tool("draft_act");
        let alias = tool("draft_minutes");
        assert_eq!(alias.access, ToolAccess::WriteControlled);
        assert_eq!(alias.permission, "act.draft");
        assert_eq!(alias.input_schema, canonical.input_schema);
        assert_eq!(
            alias.input_schema["required"],
            serde_json::json!(["book_id", "title", "channel"])
        );
        assert_eq!(
            alias.input_schema["additionalProperties"],
            Value::Bool(false)
        );
        assert_eq!(
            alias.input_schema["properties"]["ai_provenance"]["required"],
            serde_json::json!(["source"])
        );
        assert_eq!(
            alias.input_schema["properties"]["ai_provenance"]["additionalProperties"],
            Value::Bool(false)
        );

        let args = serde_json::json!({
            "book_id": "book-7",
            "title": "Ata da Assembleia Geral Anual",
            "channel": "Physical",
            "retifies": "act-3",
            "ai_provenance": {
                "source": "caller-supplied",
                "tool": "caller-tool",
                "statement_source": "operator instruction"
            },
            "actor": "mcp"
        });
        let expected_body = serde_json::json!({
            "book_id": "book-7",
            "title": "Ata da Assembleia Geral Anual",
            "channel": "Physical",
            "retifies": "act-3",
            "ai_provenance": {
                "source": "mcp",
                "tool": "draft_minutes",
                "statement_source": "operator instruction"
            },
            "actor": "mcp"
        });
        let call = resolve_call(&alias, &args).unwrap();
        assert_eq!(call.method, HttpMethod::Post);
        assert_eq!(call.path, "/acts");
        assert!(call.query.is_empty());
        assert_eq!(call.body, Some(expected_body));

        let no_provenance = serde_json::json!({
            "book_id": "book-7",
            "title": "Ata da Assembleia Geral Anual",
            "channel": "Physical",
            "actor": "mcp"
        });
        let call = resolve_call(&alias, &no_provenance).unwrap();
        assert_eq!(
            call.body
                .as_ref()
                .expect("body")
                .get("ai_provenance")
                .expect("mcp provenance is injected"),
            &serde_json::json!({
                "source": "mcp",
                "tool": "draft_minutes",
                "statement_source": "mcp tool arguments"
            })
        );
    }

    #[test]
    fn draft_minutes_missing_required_and_unknown_args_are_fail_closed() {
        let missing = resolve_call(
            &tool("draft_minutes"),
            &serde_json::json!({ "book_id": "book-7", "channel": "Physical" }),
        )
        .unwrap_err();
        assert_eq!(missing, ToolError::MissingArgument("title".to_string()));

        let unknown = resolve_call(
            &tool("draft_minutes"),
            &serde_json::json!({
                "book_id": "book-7",
                "title": "Ata",
                "channel": "Physical",
                "prompt": "draft this for me"
            }),
        )
        .unwrap_err();
        assert_eq!(unknown, ToolError::UnknownArgument("prompt".to_string()));
    }

    #[test]
    fn company_aliases_preserve_entity_read_routes_and_permissions() {
        let list_alias = tool("list_companies");
        assert_eq!(list_alias.access, ToolAccess::ReadOnly);
        assert_eq!(list_alias.permission, "entity.read");
        assert_eq!(list_alias.input_schema, tool("list_entities").input_schema);
        let list_call = resolve_call(&list_alias, &Value::Null).unwrap();
        assert_eq!(list_call.method, HttpMethod::Get);
        assert_eq!(list_call.path, "/entities");
        assert!(list_call.query.is_empty());
        assert!(list_call.body.is_none());

        let timeline_alias = tool("get_company_timeline");
        assert_eq!(timeline_alias.access, ToolAccess::ReadOnly);
        assert_eq!(timeline_alias.permission, "entity.read");
        assert_eq!(
            timeline_alias.input_schema["required"],
            serde_json::json!(["entity_id"])
        );
        let timeline_call = resolve_call(
            &timeline_alias,
            &serde_json::json!({ "entity_id": "ent/pt 1" }),
        )
        .unwrap();
        assert_eq!(timeline_call.method, HttpMethod::Get);
        assert_eq!(timeline_call.path, "/entities/ent%2Fpt%201/chronology");
        assert!(timeline_call.query.is_empty());
        assert!(timeline_call.body.is_none());
    }

    #[test]
    fn path_placeholder_is_substituted_and_encoded() {
        let call =
            resolve_call(&tool("get_entity"), &serde_json::json!({ "id": "ab/12" })).unwrap();
        assert_eq!(call.path, "/entities/ab%2F12");
    }

    #[test]
    fn missing_path_arg_is_fail_closed() {
        let err = resolve_call(&tool("get_entity"), &Value::Null).unwrap_err();
        assert_eq!(err, ToolError::MissingArgument("id".to_string()));
    }

    #[test]
    fn extra_get_args_become_query() {
        let call =
            resolve_call(&tool("search_law"), &serde_json::json!({ "q": "código" })).unwrap();
        assert_eq!(call.path, "/law");
        assert_eq!(call.query, vec![("q".to_string(), "código".to_string())]);
        assert!(call.body.is_none());
    }

    #[test]
    fn legal_texts_alias_preserves_law_search_semantics() {
        let alias = tool("search_legal_texts");
        assert_eq!(alias.access, ToolAccess::ReadOnly);
        assert_eq!(alias.permission, "law.read");
        assert_eq!(alias.input_schema, tool("search_law").input_schema);
        let call = resolve_call(&alias, &serde_json::json!({ "q": "sociedades" })).unwrap();
        assert_eq!(call.method, HttpMethod::Get);
        assert_eq!(call.path, "/law");
        assert_eq!(
            call.query,
            vec![("q".to_string(), "sociedades".to_string())]
        );
        assert!(call.body.is_none());
    }

    #[test]
    fn trust_status_maps_to_status_route() {
        let call = resolve_call(&tool("trust_status"), &Value::Null).unwrap();
        assert_eq!(call.method, HttpMethod::Get);
        assert_eq!(call.path, "/trust/status");
        assert!(call.query.is_empty());
        assert!(call.body.is_none());
    }

    #[test]
    fn search_trust_catalog_args_become_query_params() {
        let tool = tool("search_trust_catalog");
        for name in [
            "search",
            "identifier",
            "service_type",
            "status",
            "history",
            "supply_point",
            "limit",
        ] {
            assert!(
                tool.input_schema["properties"].get(name).is_some(),
                "missing advertised trust catalog filter {name}"
            );
        }
        assert_eq!(tool.access, ToolAccess::ReadOnly);
        assert!(tool.access.read_only_hint());
        assert_eq!(tool.permission, "cae.read");

        let call = resolve_call(
            &tool,
            &serde_json::json!({
                "search": "multicert",
                "identifier": "pt-tsl-1",
                "service_type": "QCertESig",
                "status": "granted",
                "history": "WITHDRAWN",
                "supply_point": "https://example.test/svc",
                "limit": 5
            }),
        )
        .unwrap();
        assert_eq!(call.method, HttpMethod::Get);
        assert_eq!(call.path, "/trust/catalog");
        assert_eq!(
            call.query,
            vec![
                ("history".to_string(), "WITHDRAWN".to_string()),
                ("identifier".to_string(), "pt-tsl-1".to_string()),
                ("limit".to_string(), "5".to_string()),
                ("search".to_string(), "multicert".to_string()),
                ("service_type".to_string(), "QCertESig".to_string()),
                ("status".to_string(), "granted".to_string()),
                (
                    "supply_point".to_string(),
                    "https://example.test/svc".to_string()
                ),
            ]
        );
        assert!(call.body.is_none());
    }

    #[test]
    fn external_validator_reports_tool_is_redacted_read_only_summary_route() {
        let tool = tool("list_external_validator_reports");
        assert_eq!(tool.access, ToolAccess::ReadOnly);
        assert!(tool.access.read_only_hint());
        assert_eq!(tool.permission, "settings.read");
        assert_eq!(tool.input_schema, closed_empty_schema());

        let call = resolve_call(&tool, &Value::Null).unwrap();
        assert_eq!(call.method, HttpMethod::Get);
        assert_eq!(call.path, "/external-validator-reports");
        assert!(call.query.is_empty());
        assert!(call.body.is_none());
    }

    #[test]
    fn external_validator_report_metadata_tool_is_closed_read_only_identity_route() {
        let tool = tool("get_external_validator_report_metadata");
        assert_eq!(tool.access, ToolAccess::ReadOnly);
        assert!(tool.access.read_only_hint());
        assert_eq!(tool.permission, "settings.read");
        assert_eq!(
            tool.input_schema["required"],
            serde_json::json!(["case_id", "validator_family"])
        );
        assert_eq!(
            tool.input_schema["additionalProperties"],
            Value::Bool(false)
        );
        assert!(tool.input_schema["properties"]["case_id"].is_object());
        assert!(tool.input_schema["properties"]["validator_family"].is_object());
        assert_eq!(
            tool.input_schema["properties"]
                .as_object()
                .expect("schema properties")
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["case_id".to_string(), "validator_family".to_string()]
        );

        let call = resolve_call(
            &tool,
            &serde_json::json!({
                "case_id": "case-7",
                "validator_family": "eu-dss"
            }),
        )
        .unwrap();
        assert_eq!(call.method, HttpMethod::Get);
        assert_eq!(call.path, "/external-validator-reports/case-7/eu-dss");
        assert!(call.query.is_empty());
        assert!(call.body.is_none());
    }

    #[test]
    fn external_validator_reports_tool_rejects_raw_or_upload_args() {
        let tool = tool("list_external_validator_reports");
        for name in ["content_base64", "raw_report", "upload"] {
            let err =
                resolve_call(&tool, &serde_json::json!({ name: "not forwarded" })).unwrap_err();
            assert_eq!(err, ToolError::UnknownArgument(name.to_string()));
        }
    }

    #[test]
    fn external_validator_report_metadata_tool_rejects_raw_upload_content_path_or_bytes_args() {
        let tool = tool("get_external_validator_report_metadata");
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
            let err = resolve_call(
                &tool,
                &serde_json::json!({
                    "case_id": "case-7",
                    "validator_family": "eu-dss",
                    name: "not forwarded"
                }),
            )
            .unwrap_err();
            assert_eq!(err, ToolError::UnknownArgument(name.to_string()));
        }
    }

    #[test]
    fn external_validator_reports_tool_forwards_bearer_to_summary_route() {
        use crate::bridge::{ApiBridge, BridgeError, HttpRequest, HttpResponse, HttpTransport};
        use crate::config::{McpConfig, Secret};

        struct NoopTransport;

        impl HttpTransport for NoopTransport {
            fn send(&self, _req: &HttpRequest) -> Result<HttpResponse, BridgeError> {
                unreachable!("registry test only builds the request")
            }
        }

        let tool = tool("list_external_validator_reports");
        let call = resolve_call(&tool, &Value::Null).unwrap();
        let bridge = ApiBridge::new(
            &McpConfig {
                enabled: true,
                tenant_ai_enabled: true,
                base_url: "http://127.0.0.1:8080".to_string(),
                base_path: "/api/v1".to_string(),
                api_key: Secret::new("chk_ab12cd_secretsecret"),
                ..McpConfig::default()
            },
            NoopTransport,
        );

        let req = bridge.build(call.method, &call.path, &call.query, call.body.as_ref());
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(
            req.url,
            "http://127.0.0.1:8080/api/v1/external-validator-reports"
        );
        assert_eq!(
            req.header("Authorization"),
            Some("Bearer chk_ab12cd_secretsecret")
        );
        assert!(req.body.is_none());
    }

    #[test]
    fn external_validator_report_metadata_tool_forwards_bearer_to_safe_metadata_route() {
        use crate::bridge::{ApiBridge, BridgeError, HttpRequest, HttpResponse, HttpTransport};
        use crate::config::{McpConfig, Secret};

        struct NoopTransport;

        impl HttpTransport for NoopTransport {
            fn send(&self, _req: &HttpRequest) -> Result<HttpResponse, BridgeError> {
                unreachable!("registry test only builds the request")
            }
        }

        let tool = tool("get_external_validator_report_metadata");
        let call = resolve_call(
            &tool,
            &serde_json::json!({
                "case_id": "case-7",
                "validator_family": "eu-dss"
            }),
        )
        .unwrap();
        let bridge = ApiBridge::new(
            &McpConfig {
                enabled: true,
                tenant_ai_enabled: true,
                base_url: "http://127.0.0.1:8080".to_string(),
                base_path: "/api/v1".to_string(),
                api_key: Secret::new("chk_ab12cd_secretsecret"),
                ..McpConfig::default()
            },
            NoopTransport,
        );

        let req = bridge.build(call.method, &call.path, &call.query, call.body.as_ref());
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(
            req.url,
            "http://127.0.0.1:8080/api/v1/external-validator-reports/case-7/eu-dss"
        );
        assert_eq!(
            req.header("Authorization"),
            Some("Bearer chk_ab12cd_secretsecret")
        );
        assert!(req.body.is_none());
    }

    #[test]
    fn external_validator_catalog_exposes_no_raw_report_route_or_payload_field() {
        let forbidden_terms = ["raw-report", "content_base64", "raw_report", "upload"];
        for tool in catalog() {
            assert!(
                forbidden_terms
                    .iter()
                    .all(|term| !tool.call.path_template.contains(term)),
                "{} must not expose raw external-validator report routes",
                tool.name
            );
            let schema = tool.input_schema.to_string();
            assert!(
                forbidden_terms.iter().all(|term| !schema.contains(term)),
                "{} must not expose raw external-validator payload fields",
                tool.name
            );
        }
    }

    #[test]
    fn trust_detail_routes_substitute_and_encode_path_ids() {
        let provider = resolve_call(
            &tool("get_trust_provider"),
            &serde_json::json!({ "id": "provider/pt 1" }),
        )
        .unwrap();
        assert_eq!(provider.path, "/trust/providers/provider%2Fpt%201");

        let service = resolve_call(
            &tool("get_trust_service"),
            &serde_json::json!({ "id": "service/qualified 1" }),
        )
        .unwrap();
        assert_eq!(service.path, "/trust/services/service%2Fqualified%201");
    }

    #[test]
    fn book_archive_package_routes_with_book_export_permission() {
        let tool = tool("export_book_archive_package");
        assert_eq!(tool.access, ToolAccess::ReadOnly);
        assert_eq!(tool.permission, "book.export");

        let call = resolve_call(&tool, &serde_json::json!({ "book_id": "book/pt 1" })).unwrap();
        assert_eq!(call.method, HttpMethod::Get);
        assert_eq!(call.path, "/books/book%2Fpt%201/archive/package");
        assert!(call.query.is_empty());
        assert!(call.body.is_none());
    }

    #[test]
    fn prepare_archive_export_is_write_controlled_closed_alias_for_archive_package() {
        let tool = tool("prepare_archive_export");
        assert_eq!(tool.access, ToolAccess::WriteControlled);
        assert_eq!(tool.permission, "book.export");
        assert_eq!(
            tool.input_schema["required"],
            serde_json::json!(["book_id"])
        );
        assert_eq!(
            tool.input_schema["additionalProperties"],
            Value::Bool(false)
        );

        let call = resolve_call(
            &tool,
            &serde_json::json!({
                "book_id": "book/pt 1",
                "legal_hold": true,
                "legal_hold_reason": "retention review"
            }),
        )
        .unwrap();
        assert_eq!(call.method, HttpMethod::Get);
        assert_eq!(call.path, "/books/book%2Fpt%201/archive/package");
        assert_eq!(
            call.query,
            vec![
                ("legal_hold".to_string(), "true".to_string()),
                (
                    "legal_hold_reason".to_string(),
                    "retention review".to_string()
                ),
            ]
        );
        assert!(call.body.is_none());

        let unknown = resolve_call(
            &tool,
            &serde_json::json!({ "book_id": "book-7", "format": "dglab" }),
        )
        .unwrap_err();
        assert_eq!(unknown, ToolError::UnknownArgument("format".to_string()));
    }

    #[test]
    fn export_ledger_archive_document_filters_become_query_params() {
        let call = resolve_call(
            &tool("export_ledger_archive_document"),
            &serde_json::json!({
                "chain": "book:book-7",
                "format": "json",
                "q": "approved digest",
                "scope": "book:book-7",
                "kind": "book.opened,document.generated",
                "actor": "owner",
                "from": "2026-07-01",
                "to": "2026-07-09",
                "limit": 1,
                "order": "desc"
            }),
        )
        .unwrap();
        assert_eq!(call.method, HttpMethod::Get);
        assert_eq!(call.path, "/ledger/archive/document");
        assert_eq!(
            call.query,
            vec![
                ("actor".to_string(), "owner".to_string()),
                ("chain".to_string(), "book:book-7".to_string()),
                ("format".to_string(), "json".to_string()),
                ("from".to_string(), "2026-07-01".to_string()),
                (
                    "kind".to_string(),
                    "book.opened,document.generated".to_string()
                ),
                ("limit".to_string(), "1".to_string()),
                ("order".to_string(), "desc".to_string()),
                ("q".to_string(), "approved digest".to_string()),
                ("scope".to_string(), "book:book-7".to_string()),
                ("to".to_string(), "2026-07-09".to_string()),
            ]
        );
        assert!(call.body.is_none());
    }

    #[test]
    fn act_working_copy_export_is_read_only_and_routes_to_markdown_endpoint() {
        let tool = tool("export_act_working_copy");
        assert_eq!(tool.access, ToolAccess::ReadOnly);
        assert_eq!(tool.permission, "act.read");

        let call = resolve_call(&tool, &serde_json::json!({ "id": "act/pt 1" })).unwrap();
        assert_eq!(call.method, HttpMethod::Get);
        assert_eq!(call.path, "/acts/act%2Fpt%201/document/working-copy");
        assert!(call.query.is_empty());
        assert!(call.body.is_none());
    }

    #[test]
    fn validate_signature_bundle_is_read_only_closed_status_alias() {
        let tool = tool("validate_signature_bundle");
        assert_eq!(tool.access, ToolAccess::ReadOnly);
        assert_eq!(tool.permission, "act.read");
        assert_eq!(tool.input_schema["required"], serde_json::json!(["act_id"]));
        assert_eq!(
            tool.input_schema["additionalProperties"],
            Value::Bool(false)
        );

        let call = resolve_call(&tool, &serde_json::json!({ "act_id": "act/pt 1" })).unwrap();
        assert_eq!(call.method, HttpMethod::Get);
        assert_eq!(call.path, "/acts/act%2Fpt%201/signature");
        assert!(call.query.is_empty());
        assert!(call.body.is_none());

        let unknown = resolve_call(
            &tool,
            &serde_json::json!({ "act_id": "act-7", "bundle_bytes": "..." }),
        )
        .unwrap_err();
        assert_eq!(
            unknown,
            ToolError::UnknownArgument("bundle_bytes".to_string())
        );
    }

    #[test]
    fn generate_mermaid_graph_routes_through_chronology_with_kind() {
        let tool = tool("generate_mermaid_graph");
        assert_eq!(tool.access, ToolAccess::ReadOnly);
        assert_eq!(tool.permission, "entity.read");
        assert_eq!(
            tool.input_schema["required"],
            serde_json::json!(["entity_id", "kind"])
        );

        let call = resolve_call(
            &tool,
            &serde_json::json!({ "entity_id": "ent/pt 1", "kind": "organs" }),
        )
        .unwrap();
        assert_eq!(call.method, HttpMethod::Get);
        assert_eq!(call.path, "/entities/ent%2Fpt%201/chronology");
        assert_eq!(call.query, vec![("kind".to_string(), "organs".to_string())]);
        assert!(call.body.is_none());
    }

    #[test]
    fn advisory_permissions_match_current_api_gates() {
        assert_eq!(tool("chronology").permission, "entity.read");
        assert_eq!(tool("generate_mermaid_graph").permission, "entity.read");
        assert_eq!(tool("preview_document").permission, "act.read");
        assert_eq!(tool("export_act_working_copy").permission, "act.read");
        assert_eq!(tool("list_templates").permission, "act.read");
        assert_eq!(
            tool("export_book_archive_package").permission,
            "book.export"
        );
        assert_eq!(tool("prepare_archive_export").permission, "book.export");
        assert_eq!(tool("validate_signature_bundle").permission, "act.read");
        assert_eq!(
            tool("export_ledger_archive_document").permission,
            "ledger.read"
        );

        for name in [
            "trust_status",
            "search_trust_catalog",
            "list_external_validator_reports",
            "get_external_validator_report_metadata",
            "get_trust_provider",
            "get_trust_service",
        ] {
            let read_tool = tool(name);
            assert_eq!(read_tool.access, ToolAccess::ReadOnly);
            if matches!(
                name,
                "list_external_validator_reports" | "get_external_validator_report_metadata"
            ) {
                assert_eq!(read_tool.permission, "settings.read");
            } else {
                assert_eq!(read_tool.permission, "cae.read");
            }
        }
    }

    #[test]
    fn write_args_become_body_and_path_arg_is_removed_from_body() {
        let call = resolve_call(
            &tool("advance_act"),
            &serde_json::json!({ "id": "act-1", "note": "n" }),
        )
        .unwrap();
        assert_eq!(call.method, HttpMethod::Post);
        assert_eq!(call.path, "/acts/act-1/advance");
        // `id` went into the path, only `note` remains in the body.
        assert_eq!(call.body, Some(serde_json::json!({ "note": "n" })));
    }

    #[test]
    fn create_entity_body_carries_fields() {
        let call = resolve_call(
            &tool("create_entity"),
            &serde_json::json!({ "name": "Encosto Estratégico Lda" }),
        )
        .unwrap();
        assert_eq!(call.method, HttpMethod::Post);
        assert_eq!(call.path, "/entities");
        assert_eq!(
            call.body,
            Some(serde_json::json!({ "name": "Encosto Estratégico Lda" }))
        );
    }

    #[test]
    fn non_object_arguments_rejected() {
        let err = resolve_call(&tool("list_entities"), &serde_json::json!([1, 2, 3])).unwrap_err();
        assert_eq!(err, ToolError::ArgumentsNotObject);
    }

    fn closed_empty_schema() -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": false,
        })
    }
}
