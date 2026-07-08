//! Top-level crate errors for the MCP server lifecycle (config load, enablement, transport
//! selection). Per-request/per-tool failures are modelled separately (`bridge::BridgeError`,
//! `registry::ToolError`) so they can be mapped to honest MCP tool results rather than aborting
//! the server.

use thiserror::Error;

/// Errors raised while starting or configuring the MCP server.
#[derive(Debug, Error)]
pub enum McpError {
    /// The server is disabled (`enabled = false`). Off by default means *not served*: constructing
    /// or serving a disabled server is refused so there is zero surface when off.
    #[error("MCP server is disabled (off by default); not served")]
    Disabled,

    /// A required configuration value was missing or malformed. The message never contains the API
    /// key (see [`crate::config::Secret`]).
    #[error("MCP configuration error: {0}")]
    Config(String),

    /// The requested transport is recognised but not implemented in this build (only `stdio`
    /// ships in v1; `http-sse` is reserved for a later, opt-in, exposure-reviewed release).
    #[error("MCP transport not supported in this build: {0}")]
    UnsupportedTransport(String),

    /// The stdio serve loop failed on an I/O error.
    #[error("MCP stdio I/O error: {0}")]
    Io(#[from] std::io::Error),
}
