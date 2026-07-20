//! `chancela-mcp` — an MCP (Model Context Protocol) server that exposes the platform's operations
//! as permission-gated tools (spec AI-10/11/12), authenticating to the integration API (`/api/v1`)
//! with an API key.
//!
//! # Design (t65-E2)
//!
//! - **Transport: hand-rolled JSON-RPC 2.0 over stdio.** The official Rust SDK (`rmcp`) exists on
//!   crates.io, but v1 chose a small, self-contained newline-delimited JSON-RPC implementation: it
//!   keeps deps conservative (only `serde`/`serde_json`/`reqwest`/`thiserror`, all workspace-inherited),
//!   needs no async runtime (a blocking stdio loop + blocking `reqwest`), pins no fast-moving SDK on a
//!   security-sensitive crate, and makes every unit test deterministic against a mock transport. The
//!   `initialize` / `tools/list` / `tools/call` subset MCP needs is small and stable. `rmcp` remains a
//!   drop-in future option — the [`server`] dispatch is isolated behind [`jsonrpc`] types.
//! - **One RBAC path.** The server is an **HTTP client of the integration API**: it forwards a
//!   configured key and never re-implements authorization. Every tool call is gated server-side by the
//!   key's principal (t65-E3). See [`bridge`].
//! - **Extensible registry.** A tool is one [`registry::McpTool`] entry mapping a name → JSON input
//!   schema → an `/api/v1` call → the permission the server enforces. See [`registry::catalog`].
//! - **Off by default.** [`server::McpServer::from_config`] refuses unless both the process MCP
//!   switch and tenant AI/MCP gate are enabled; nothing is served, no I/O happens, zero surface. See
//!   [`config`].
//!
//! The live end-to-end wiring against a running `/api/v1` lands in t65-E3/E4/E5; this crate is
//! buildable and unit-tested now against a mock HTTP transport.

pub mod bridge;
pub mod config;
pub mod error;
pub mod jsonrpc;
pub mod registry;
pub mod server;

pub use config::{EnabledTools, McpConfig, McpTransport, Secret};
pub use error::McpError;
pub use registry::{McpTool, ToolAccess, catalog};
pub use server::{McpServer, PROTOCOL_VERSION, SERVER_NAME, serve_stdio};
