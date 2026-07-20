//! `chancela-mcp` binary — launch the stdio MCP server from environment configuration.
//!
//! **Off by default.** With `CHANCELA_MCP_ENABLED` or `CHANCELA_AI_ENABLED` unset/false the process
//! prints a short notice to stderr and exits 0 without serving anything (zero surface). When both
//! gates are enabled it requires `CHANCELA_MCP_API_KEY` and serves newline-delimited JSON-RPC 2.0
//! over stdin/stdout, so an AI client (Claude Desktop / Claude Code) can launch it as an MCP server.
//!
//! stdout is reserved for the JSON-RPC protocol stream; all diagnostics go to stderr. The API key is
//! never printed.

use std::process::ExitCode;

use chancela_mcp::config::McpConfig;
use chancela_mcp::server::{enabled_tool_count, serve_stdio};

fn main() -> ExitCode {
    let config = match McpConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("chancela-mcp: configuration error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if !config.served() {
        eprintln!(
            "chancela-mcp: disabled (set CHANCELA_AI_ENABLED=1, CHANCELA_MCP_ENABLED=1, and CHANCELA_MCP_API_KEY to enable). Not serving."
        );
        return ExitCode::SUCCESS;
    }

    eprintln!(
        "chancela-mcp: serving {} tool(s) over stdio → integration API at {}{}",
        enabled_tool_count(&config),
        config.base_url,
        config.base_path,
    );

    match serve_stdio(&config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("chancela-mcp: serve error: {e}");
            ExitCode::FAILURE
        }
    }
}
