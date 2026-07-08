//! Minimal JSON-RPC 2.0 types for the MCP stdio protocol.
//!
//! MCP over stdio is newline-delimited JSON-RPC 2.0: each line is one request, notification, or
//! response object. This module models exactly that subset — no batching, no server-initiated
//! requests (the v1 tool surface is request/response only).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Standard JSON-RPC 2.0 error codes plus the MCP-relevant application codes.
pub mod codes {
    /// Invalid JSON was received.
    pub const PARSE_ERROR: i64 = -32700;
    /// The JSON is not a valid Request object.
    pub const INVALID_REQUEST: i64 = -32600;
    /// The method does not exist / is not available.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// Invalid method parameters.
    pub const INVALID_PARAMS: i64 = -32602;
    /// Internal JSON-RPC error.
    pub const INTERNAL_ERROR: i64 = -32603;
}

/// An inbound JSON-RPC message. A request carries an `id`; a notification omits it (`id == None`).
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    /// Protocol tag; expected to be `"2.0"`.
    #[serde(default)]
    pub jsonrpc: String,
    /// Request id. Absent ⇒ this is a notification (no response is sent).
    #[serde(default)]
    pub id: Option<Value>,
    /// Method name, e.g. `"tools/list"`.
    pub method: String,
    /// Method parameters (method-specific shape).
    #[serde(default)]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    /// A notification has no `id` and therefore expects no response.
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// The error object of a JSON-RPC error response.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    /// Error code (see [`codes`]).
    pub code: i64,
    /// Short human-readable message.
    pub message: String,
    /// Optional structured detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// An outbound JSON-RPC response. Exactly one of `result`/`error` is present.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    /// Always `"2.0"`.
    pub jsonrpc: &'static str,
    /// Echoes the request id (`null` when the request could not be parsed).
    pub id: Value,
    /// Success payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Failure payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    /// A success response for `id`.
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    /// An error response for `id`.
    pub fn error(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}
