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

    let (query, body) = if tool.call.method == HttpMethod::Get {
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

    Ok(ResolvedCall {
        method: tool.call.method,
        path,
        query,
        body,
    })
}

/// Extract the `{name}` placeholder names from a path template.
fn path_placeholders(template: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(off) = template[i + 1..].find('}') {
                out.push(&template[i + 1..i + 1 + off]);
                i = i + 1 + off + 1;
                continue;
            }
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
    let obj = |props: Value, required: &[&str]| -> Value {
        serde_json::json!({
            "type": "object",
            "properties": props,
            "required": required,
            "additionalProperties": true,
        })
    };
    let id_only = || {
        obj(
            serde_json::json!({ "id": { "type": "string", "description": "resource id" } }),
            &["id"],
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
            input_schema: obj(
                serde_json::json!({ "book_id": { "type": "string" }, "kind": { "type": "string" } }),
                &[],
            ),
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
            permission: "document.read",
            input_schema: id_only(),
            call: ToolCall {
                method: Get,
                path_template: "/acts/{id}/document/preview",
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
            name: "list_templates",
            title: "List templates",
            description: "List the available document templates.",
            access: ToolAccess::ReadOnly,
            permission: "template.read",
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
}
