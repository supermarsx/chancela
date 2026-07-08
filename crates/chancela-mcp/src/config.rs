//! MCP server configuration — read from the process environment when the server launches.
//!
//! **Off by default.** [`McpConfig::from_env`] yields `enabled = false` unless
//! `CHANCELA_MCP_ENABLED` is explicitly truthy, and a disabled config never builds a running
//! server (see [`crate::server`]). Every knob mirrors the frozen `Settings.mcp` contract in
//! `.orchestration/plans/t65.md` §3.3.
//!
//! **The API key never appears in `Debug` output** — it is wrapped in [`Secret`], whose `Debug`
//! renders `***`. Nothing in this crate logs the plaintext key.

use crate::error::McpError;

/// A configuration value that must never be printed (the integration API key). Its `Debug`/`Display`
/// deliberately redact the contents; `expose()` is the single, explicit way to read the plaintext.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wrap a plaintext secret.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Read the plaintext. The only path that exposes the secret — used solely to build the
    /// `Authorization` header for the outbound `/api/v1` request.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether a secret was configured at all (non-empty).
    pub fn is_set(&self) -> bool {
        !self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_empty() {
            "Secret(unset)"
        } else {
            "Secret(***)"
        })
    }
}

/// The MCP wire transport. `stdio` is the only transport implemented in v1 (local desktop /
/// Claude Desktop / Claude Code). `HttpSse` is reserved and refused by this build until an
/// exposure-reviewed opt-in ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpTransport {
    /// Newline-delimited JSON-RPC 2.0 over stdin/stdout.
    Stdio,
    /// Reserved: HTTP + Server-Sent Events (remote). Not served by this build.
    HttpSse,
}

/// Which tools the registry exposes. Per-tool enablement is part of "max-configurable".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnabledTools {
    /// Every tool in the catalog is served.
    All,
    /// Only the named tools are served (unknown names are simply not present).
    List(Vec<String>),
}

impl EnabledTools {
    /// Whether a tool with `name` is enabled under this policy.
    pub fn allows(&self, name: &str) -> bool {
        match self {
            EnabledTools::All => true,
            EnabledTools::List(names) => names.iter().any(|n| n == name),
        }
    }
}

/// The resolved MCP server configuration.
#[derive(Debug, Clone)]
pub struct McpConfig {
    /// Master switch. `false` (default) ⇒ the server is not served; zero surface.
    pub enabled: bool,
    /// Wire transport.
    pub transport: McpTransport,
    /// Base URL of the integration API the tools call, e.g. `http://127.0.0.1:8080`.
    pub base_url: String,
    /// Versioned base path the handlers are mounted under, e.g. `/api/v1`.
    pub base_path: String,
    /// The API key the MCP server authenticates with (`chk_<prefix>_<secret>`). Redacted in `Debug`.
    pub api_key: Secret,
    /// Per-tool enablement.
    pub enabled_tools: EnabledTools,
    /// Bind address for `HttpSse` only (unused by `Stdio`).
    pub bind: Option<String>,
}

impl Default for McpConfig {
    /// The safe default: **disabled**, stdio, loopback base URL, no key. Constructing a server
    /// from this is refused (`McpError::Disabled`).
    fn default() -> Self {
        Self {
            enabled: false,
            transport: McpTransport::Stdio,
            base_url: "http://127.0.0.1:8080".to_string(),
            base_path: "/api/v1".to_string(),
            api_key: Secret::new(""),
            enabled_tools: EnabledTools::All,
            bind: None,
        }
    }
}

impl McpConfig {
    /// Build a config from the environment (mirrors the existing `CHANCELA_*` env idiom):
    ///
    /// | Var | Meaning | Default |
    /// |---|---|---|
    /// | `CHANCELA_MCP_ENABLED` | master switch (`1`/`true`/`yes`/`on`) | `false` |
    /// | `CHANCELA_MCP_TRANSPORT` | `stdio` \| `http-sse` | `stdio` |
    /// | `CHANCELA_MCP_BASE_URL` | integration API base URL | `http://127.0.0.1:8080` |
    /// | `CHANCELA_MCP_BASE_PATH` | integration API base path | `/api/v1` |
    /// | `CHANCELA_MCP_API_KEY` | the `chk_...` key (required when enabled) | — |
    /// | `CHANCELA_MCP_ENABLED_TOOLS` | `all` or a comma list of tool names | `all` |
    /// | `CHANCELA_MCP_BIND` | bind addr (http-sse only) | — |
    ///
    /// When `enabled`, `CHANCELA_MCP_API_KEY` must be present and non-empty, else
    /// [`McpError::Config`] (the key is never echoed).
    pub fn from_env() -> Result<Self, McpError> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());

        let enabled = get("CHANCELA_MCP_ENABLED")
            .as_deref()
            .map(is_truthy)
            .unwrap_or(false);

        let transport = match get("CHANCELA_MCP_TRANSPORT").as_deref() {
            None | Some("stdio") => McpTransport::Stdio,
            Some("http-sse") | Some("httpsse") | Some("http") => McpTransport::HttpSse,
            Some(other) => {
                return Err(McpError::Config(format!(
                    "unknown CHANCELA_MCP_TRANSPORT: {other}"
                )));
            }
        };

        let base_url =
            get("CHANCELA_MCP_BASE_URL").unwrap_or_else(|| "http://127.0.0.1:8080".to_string());
        let base_path = get("CHANCELA_MCP_BASE_PATH").unwrap_or_else(|| "/api/v1".to_string());
        let api_key = Secret::new(get("CHANCELA_MCP_API_KEY").unwrap_or_default());

        let enabled_tools = match get("CHANCELA_MCP_ENABLED_TOOLS").as_deref() {
            None | Some("all") | Some("*") => EnabledTools::All,
            Some(list) => EnabledTools::List(
                list.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
            ),
        };

        let bind = get("CHANCELA_MCP_BIND");

        let config = Self {
            enabled,
            transport,
            base_url,
            base_path,
            api_key,
            enabled_tools,
            bind,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate cross-field invariants. Only enforced when `enabled` (a disabled config is inert).
    pub fn validate(&self) -> Result<(), McpError> {
        if !self.enabled {
            return Ok(());
        }
        if !self.api_key.is_set() {
            return Err(McpError::Config(
                "CHANCELA_MCP_API_KEY is required when the MCP server is enabled".to_string(),
            ));
        }
        if self.base_url.is_empty() {
            return Err(McpError::Config("base_url must not be empty".to_string()));
        }
        Ok(())
    }
}

/// Parse a truthy environment flag: `1`/`true`/`yes`/`on` (case-insensitive) are true; all else false.
fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled_with_no_key() {
        let c = McpConfig::default();
        assert!(!c.enabled);
        assert!(!c.api_key.is_set());
        assert_eq!(c.transport, McpTransport::Stdio);
    }

    #[test]
    fn secret_never_prints_plaintext() {
        let s = Secret::new("chk_ab12cd_deadbeefdeadbeef");
        let shown = format!("{s:?}");
        assert_eq!(shown, "Secret(***)");
        assert!(!shown.contains("deadbeef"));
        // And the whole config redacts too.
        let c = McpConfig {
            api_key: s,
            ..McpConfig::default()
        };
        assert!(!format!("{c:?}").contains("deadbeef"));
    }

    #[test]
    fn enabled_without_key_is_rejected() {
        let c = McpConfig {
            enabled: true,
            ..McpConfig::default()
        };
        assert!(matches!(c.validate(), Err(McpError::Config(_))));
    }

    #[test]
    fn enabled_tools_list_filters() {
        let e = EnabledTools::List(vec!["list_entities".into(), "verify_ledger".into()]);
        assert!(e.allows("list_entities"));
        assert!(!e.allows("seal_act"));
        assert!(EnabledTools::All.allows("anything"));
    }

    #[test]
    fn truthy_parsing() {
        for t in ["1", "true", "TRUE", "yes", "On"] {
            assert!(is_truthy(t), "{t} should be truthy");
        }
        for f in ["0", "false", "", "no", "maybe"] {
            assert!(!is_truthy(f), "{f} should be falsy");
        }
    }
}
