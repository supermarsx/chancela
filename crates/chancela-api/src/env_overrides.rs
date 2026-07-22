//! Server environment-override registry — the authoritative catalog of every process env var the
//! `chancela-server` binary reads, plus the persisted, startup-applied override store that makes the
//! non-secret ones settable from the config admin panel (t14, "make all the api server env vars
//! overridable ... as they should").
//!
//! # Why a registry and not a pile of `set_var` calls
//! Almost every var is read **once at process start** (funnelled through `AppState::try_from_env` and
//! `chancela-server/main.rs`) or lazily on first use by a dependency crate that reads
//! `std::env::var` independently. The only mechanism that makes *all* of them overridable without a
//! multi-week cross-crate config refactor is to stamp the process environment at the very start of
//! `main`, before anything reads it. Precedence then falls out for free:
//!
//! ```text
//! explicit override  >  ambient env var  >  code default
//! ```
//!
//! An override `set_var`s over the ambient value; an unset override leaves the ambient env; unset both
//! hits the code default.
//!
//! # The tiers ("as they should", not "every var an editable box")
//! * **Tier A** — editable, non-secret, restart-to-apply. The core deliverable.
//! * **Tier B** — secret, or a pointer at a secret. **Never** written to the override file and **never**
//!   echoed on the wire: the view carries only a `configured` flag. A real write path (v2) would route
//!   through the AEAD credential store like the SMTP password, not this file.
//! * **Tier C** — a security boundary. Editable **only** behind an explicit acknowledgement (see
//!   [`ServerEnvUpdateRequest::acknowledge`]) that the server enforces with a `422`. Ceiling vars are
//!   **narrow-only** — an override may tighten them, never loosen them.
//! * **Tier D** — derived / read-only. Rendered as facts, never editable (e.g. `CHANCELA_DATA_DIR`,
//!   which is chicken-and-egg: the override file itself lives under it).
//!
//! Vars that already own a typed `Settings` slice with a defined precedence (the connector allow-list
//! ceiling, the ZK shared-object root) are **excluded** from the generic store via
//! [`EnvVarSpec::excluded_typed_slice`], so we never create two competing precedence rules for one
//! variable. They still appear in the view as read-only cross-links.
//!
//! # Ownership (t14 executors)
//! * **e1 (this module, contract):** the registry data model, the var catalog, the wire types
//!   ([`ServerEnvVarView`] / [`ServerEnvResponse`] / [`ServerEnvUpdateRequest`]), and `load`/`save`
//!   plus the `apply_from_data_dir` **stub**.
//! * **e2:** the `apply` body — the `unsafe` `std::env::set_var` stage that must run before any other
//!   thread reads env (edition-2024 caveat) — and the `main.rs` call ordering.
//! * **e3:** the `GET`/`PUT /v1/platform/env` handler that builds [`ServerEnvVarView`] rows from this
//!   registry joined with live state, enforces validation / narrow-only / the acknowledgement gate,
//!   masks Tier-B secrets, and appends the `server.env.overridden` ledger event.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The override file, resolved under `CHANCELA_DATA_DIR`. Deliberately **not** the settings document:
/// it must be readable in `main.rs` *before* `AppState`/`settings.json` are loaded, and keeping it
/// separate leaves the whole-document `PUT /v1/settings` semantics untouched.
pub const OVERRIDES_FILE: &str = "env-overrides.json";

/// The ledger event e3 appends on a successful `PUT` (records *which* keys changed, never values).
pub const ENV_OVERRIDDEN_EVENT: &str = "server.env.overridden";

// ---------------------------------------------------------------------------------------------
// Classification enums (response-only; stable wire strings)
// ---------------------------------------------------------------------------------------------

/// The treatment tier. Serialized as the bare letter (`"A"`/`"B"`/`"C"`/`"D"`) the plan speaks in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EnvVarTier {
    /// Editable, non-secret, restart-to-apply.
    A,
    /// Secret / secret-pointer — display-only, never echoed.
    B,
    /// Security boundary — editable only behind acknowledgement; some narrow-only.
    C,
    /// Derived / read-only.
    D,
}

/// Which layer supplied the value the live process actually resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvVarSource {
    /// The persisted override file won.
    Override,
    /// An ambient process env var won (no override set).
    Env,
    /// Neither set — the code default applies.
    Default,
}

/// Coarse grouping the web renders sections from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvVarGroup {
    Logging,
    Network,
    Session,
    RateLimit,
    Hsts,
    Cors,
    Database,
    Credentials,
    Cache,
    Cluster,
    PostgresTls,
    Trust,
    Signing,
    Csc,
    Cmd,
    Scap,
    Connectors,
    Storage,
    PaperBook,
    Mcp,
}

/// The validator kind the web uses to pick an input control and give a client-side hint. The server
/// re-validates authoritatively via [`EnvVarValidator::validate`]; this is a UX affordance, not the
/// security boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvVarValidatorKind {
    FreeText,
    Path,
    Bool,
    Unsigned,
    Enum,
    HttpUrl,
    SocketAddr,
    HostList,
    Duration,
}

// ---------------------------------------------------------------------------------------------
// Registry data model
// ---------------------------------------------------------------------------------------------

/// The per-var validator. Const-constructible so the whole [`REGISTRY`] is a `const` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvVarValidator {
    /// Any non-empty string.
    FreeText,
    /// A filesystem path (non-empty; existence is not checked here).
    Path,
    /// A boolean literal (`true`/`false`/`1`/`0`/`on`/`off`/`yes`/`no`, case-insensitive).
    Bool,
    /// An unsigned integer (`u64`).
    Unsigned,
    /// One of a fixed set of literals.
    Enum(&'static [&'static str]),
    /// An absolute `http`/`https` URL.
    HttpUrl,
    /// A `host:port` socket address.
    SocketAddr,
    /// A comma-separated list of non-empty hosts.
    HostList,
    /// A duration — either bare seconds or a `humantime` literal (`1s`, `2m`, `10s`, ...).
    Duration,
}

impl EnvVarValidator {
    /// The wire kind for the web.
    pub fn kind(&self) -> EnvVarValidatorKind {
        match self {
            EnvVarValidator::FreeText => EnvVarValidatorKind::FreeText,
            EnvVarValidator::Path => EnvVarValidatorKind::Path,
            EnvVarValidator::Bool => EnvVarValidatorKind::Bool,
            EnvVarValidator::Unsigned => EnvVarValidatorKind::Unsigned,
            EnvVarValidator::Enum(_) => EnvVarValidatorKind::Enum,
            EnvVarValidator::HttpUrl => EnvVarValidatorKind::HttpUrl,
            EnvVarValidator::SocketAddr => EnvVarValidatorKind::SocketAddr,
            EnvVarValidator::HostList => EnvVarValidatorKind::HostList,
            EnvVarValidator::Duration => EnvVarValidatorKind::Duration,
        }
    }

    /// The allowed literals, for [`EnvVarValidator::Enum`] only (fed to the web as select options).
    pub fn allowed(&self) -> Option<&'static [&'static str]> {
        match self {
            EnvVarValidator::Enum(values) => Some(values),
            _ => None,
        }
    }

    /// Authoritative server-side validation. `Err` carries an operator-facing reason.
    ///
    /// e3 is free to tighten any arm (e.g. clamp `Unsigned` ranges per var); this baseline rejects
    /// the obviously-malformed so a bad override can never reach `set_var`.
    pub fn validate(&self, value: &str) -> Result<(), String> {
        let trimmed = value.trim();
        match self {
            EnvVarValidator::FreeText | EnvVarValidator::Path => {
                if trimmed.is_empty() {
                    return Err("value must not be empty".to_string());
                }
            }
            EnvVarValidator::Bool => {
                let ok = matches!(
                    trimmed.to_ascii_lowercase().as_str(),
                    "true" | "false" | "1" | "0" | "on" | "off" | "yes" | "no"
                );
                if !ok {
                    return Err(format!("`{value}` is not a boolean"));
                }
            }
            EnvVarValidator::Unsigned => {
                if trimmed.parse::<u64>().is_err() {
                    return Err(format!("`{value}` is not a non-negative integer"));
                }
            }
            EnvVarValidator::Enum(values) => {
                if !values.contains(&trimmed) {
                    return Err(format!("`{value}` is not one of {values:?}"));
                }
            }
            EnvVarValidator::HttpUrl => {
                let lower = trimmed.to_ascii_lowercase();
                if !(lower.starts_with("http://") || lower.starts_with("https://")) {
                    return Err(format!("`{value}` is not an http(s) URL"));
                }
            }
            EnvVarValidator::SocketAddr => {
                if trimmed.parse::<std::net::SocketAddr>().is_err() {
                    return Err(format!("`{value}` is not a host:port socket address"));
                }
            }
            EnvVarValidator::HostList => {
                if trimmed.is_empty() || trimmed.split(',').any(|h| h.trim().is_empty()) {
                    return Err("value must be a comma-separated list of non-empty hosts".to_string());
                }
            }
            EnvVarValidator::Duration => {
                if trimmed.is_empty() {
                    return Err("value must not be empty".to_string());
                }
                // Accept bare seconds or a humantime-ish `<number><unit>` token.
                let bare_secs = trimmed.parse::<u64>().is_ok();
                let human = trimmed
                    .strip_suffix(|c: char| c.is_ascii_alphabetic())
                    .map(|head| !head.is_empty() && head.chars().all(|c| c.is_ascii_digit()))
                    .unwrap_or(false);
                if !(bare_secs || human) {
                    return Err(format!("`{value}` is not a duration (e.g. `10` or `10s`)"));
                }
            }
        }
        Ok(())
    }
}

/// One declared server env var. The whole catalog is a `const` [`REGISTRY`] table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvVarSpec {
    /// The exact env var name the server reads.
    pub name: &'static str,
    /// The section the web groups it under.
    pub group: EnvVarGroup,
    /// The treatment tier.
    pub tier: EnvVarTier,
    /// Holds (or points at) a secret — never echoed; display-only via a `configured` flag.
    pub secret: bool,
    /// A security boundary — a change needs acknowledgement (see [`Self::acknowledgement_required`]).
    pub boundary: bool,
    /// A ceiling that an override may only **tighten**, never loosen (e.g. an egress allow-list).
    pub narrow_only: bool,
    /// Editing this requires the operator to acknowledge the risk; e3 enforces a `422` otherwise.
    pub acknowledgement_required: bool,
    /// `Some(reason)` when the var already owns a typed `Settings` slice: it is excluded from the
    /// generic override store (no double precedence) and shown read-only with a cross-link.
    pub excluded_typed_slice: Option<&'static str>,
    /// The code default (`None` when there is none / it is derived at runtime). Never carries a secret.
    pub default_value: Option<&'static str>,
    /// How a proposed override is validated.
    pub validator: EnvVarValidator,
}

impl EnvVarSpec {
    /// Whether the panel presents an editor for this var. Tier A and Tier C are editable (C behind the
    /// acknowledgement gate); Tier B/D and any typed-slice-excluded var are not.
    pub fn is_editable(&self) -> bool {
        self.excluded_typed_slice.is_none()
            && matches!(self.tier, EnvVarTier::A | EnvVarTier::C)
    }

    /// The wire descriptor of this var's validator (kind + enum options).
    pub fn validator_view(&self) -> EnvVarValidatorView {
        EnvVarValidatorView {
            kind: self.validator.kind(),
            allowed: self
                .validator
                .allowed()
                .map(|values| values.iter().map(|v| (*v).to_string()).collect()),
        }
    }
}

/// Look up a spec by exact env var name.
pub fn find(name: &str) -> Option<&'static EnvVarSpec> {
    REGISTRY.iter().find(|spec| spec.name == name)
}

/// The full registry.
pub fn registry() -> &'static [EnvVarSpec] {
    REGISTRY
}

// A tiny alias keeps the giant table below readable.
use EnvVarGroup as G;
use EnvVarTier as T;
use EnvVarValidator as V;

/// The authoritative catalog. Source-of-truth is plan t14 Appendix A (audited `file:line`, default,
/// startup/runtime, secret, boundary). Dynamic per-provider *families* (CSC secrets, connector secret
/// refs) are **not** static rows — see [`DYNAMIC_SECRET_FAMILIES`]; e3 expands them per configured
/// provider at request time, always as Tier B (display-only).
pub const REGISTRY: &[EnvVarSpec] = &[
    // ---- Logging ------------------------------------------------------------------------------
    spec_a("CHANCELA_LOG", G::Logging, Some("info"), V::FreeText),
    spec_a("RUST_LOG", G::Logging, Some("info"), V::FreeText),
    spec_a(
        "CHANCELA_LOG_FORMAT",
        G::Logging,
        Some("json"),
        V::Enum(&["json", "text", "pretty", "compact"]),
    ),
    // ---- Network / static assets --------------------------------------------------------------
    spec_a("CHANCELA_ADDR", G::Network, Some("127.0.0.1:8080"), V::SocketAddr),
    spec_a("CHANCELA_WEB_DIST", G::Network, Some("/srv/web"), V::Path),
    // ---- Session ------------------------------------------------------------------------------
    spec_a(
        "CHANCELA_SESSION_MAX_LIFETIME",
        G::Session,
        Some("604800"),
        V::Unsigned,
    ),
    // ---- HSTS ---------------------------------------------------------------------------------
    spec_a("CHANCELA_HSTS_MAX_AGE", G::Hsts, Some("63072000"), V::Unsigned),
    spec_a(
        "CHANCELA_HSTS_INCLUDE_SUBDOMAINS",
        G::Hsts,
        Some("true"),
        V::Bool,
    ),
    spec_a("CHANCELA_HSTS_PRELOAD", G::Hsts, Some("false"), V::Bool),
    // ---- Rate limit ---------------------------------------------------------------------------
    // Numerics are Tier A; the on/off switch and the proxy-trust flag are security boundaries.
    boundary("CHANCELA_RATE_LIMIT_ENABLED", G::RateLimit, Some("true"), V::Bool),
    spec_a(
        "CHANCELA_RATE_LIMIT_PER_SECOND",
        G::RateLimit,
        Some("50"),
        V::Unsigned,
    ),
    spec_a("CHANCELA_RATE_LIMIT_BURST", G::RateLimit, Some("100"), V::Unsigned),
    boundary(
        "CHANCELA_RATE_LIMIT_TRUST_FORWARDED_FOR",
        G::RateLimit,
        Some("false"),
        V::Bool,
    ),
    // ---- CORS ---------------------------------------------------------------------------------
    boundary("CHANCELA_CORS_ALLOWED_ORIGINS", G::Cors, None, V::HostList),
    // ---- Database -----------------------------------------------------------------------------
    secret("CHANCELA_DB_KEY", G::Database),
    secret("CHANCELA_DB_KEY_FILE", G::Database),
    boundary(
        "CHANCELA_DB_KEY_SOURCE",
        G::Database,
        Some("operator"),
        V::Enum(&["operator", "file", "env", "kms"]),
    ),
    derived("CHANCELA_DB_BACKEND", G::Database, Some("sqlite")),
    secret("DATABASE_URL", G::Database),
    secret("DATABASE_URL_FILE", G::Database),
    // ---- Credential store ---------------------------------------------------------------------
    secret("CHANCELA_CREDENTIAL_KEY", G::Credentials),
    secret("CHANCELA_CREDENTIAL_KEY_FILE", G::Credentials),
    boundary(
        "CHANCELA_CREDENTIAL_STRICT",
        G::Credentials,
        Some("false"),
        V::Bool,
    ),
    // ---- Cache / Redis ------------------------------------------------------------------------
    spec_a("CHANCELA_CACHE", G::Cache, Some("off"), V::Enum(&["off", "redis"])),
    secret("REDIS_URL", G::Cache),
    secret("REDIS_URL_FILE", G::Cache),
    // ---- Paper-book OCR -----------------------------------------------------------------------
    spec_a("CHANCELA_PAPER_BOOK_OCR_COMMAND", G::PaperBook, None, V::Path),
    spec_a(
        "CHANCELA_PAPER_BOOK_OCR_ARGS_TEMPLATE",
        G::PaperBook,
        None,
        V::FreeText,
    ),
    spec_a(
        "CHANCELA_PAPER_BOOK_OCR_ENGINE_NAME",
        G::PaperBook,
        None,
        V::FreeText,
    ),
    spec_a(
        "CHANCELA_PAPER_BOOK_OCR_ENGINE_VERSION",
        G::PaperBook,
        None,
        V::FreeText,
    ),
    spec_a(
        "CHANCELA_PAPER_BOOK_OCR_TIMEOUT_SECS",
        G::PaperBook,
        None,
        V::Unsigned,
    ),
    spec_a(
        "CHANCELA_PAPER_BOOK_OCR_MAX_STDOUT_BYTES",
        G::PaperBook,
        None,
        V::Unsigned,
    ),
    // ---- Signing ------------------------------------------------------------------------------
    boundary("CHANCELA_LOCAL_SIGNING", G::Signing, Some("false"), V::Bool),
    spec_a("CHANCELA_CSC_PROVIDERS", G::Csc, None, V::FreeText),
    spec_a("CHANCELA_PTEID_PKCS11_MODULE", G::Signing, None, V::Path),
    // ---- SCAP ---------------------------------------------------------------------------------
    spec_a(
        "CHANCELA_SCAP_ENV",
        G::Scap,
        Some("preprod"),
        V::Enum(&["preprod", "prod"]),
    ),
    spec_a("CHANCELA_SCAP_BASE_URL", G::Scap, None, V::HttpUrl),
    spec_a("CHANCELA_SCAP_PROVIDER_FILTER", G::Scap, None, V::FreeText),
    secret("CHANCELA_SCAP_APPLICATION_ID", G::Scap),
    secret("CHANCELA_SCAP_SECRET", G::Scap),
    // ---- CMD ----------------------------------------------------------------------------------
    spec_a(
        "CHANCELA_CMD_ENV",
        G::Cmd,
        Some("preprod"),
        V::Enum(&["preprod", "prod"]),
    ),
    secret("CHANCELA_CMD_APPLICATION_ID", G::Cmd),
    secret("CHANCELA_CMD_HTTP_BASIC_USERNAME", G::Cmd),
    secret("CHANCELA_CMD_HTTP_BASIC_PASSWORD", G::Cmd),
    spec_a("CHANCELA_CMD_AMA_CERT_PEM", G::Cmd, None, V::Path),
    // ---- MCP probe (derived) ------------------------------------------------------------------
    derived("CHANCELA_MCP_ENABLED", G::Mcp, Some("false")),
    // ---- Cluster identity (derived) -----------------------------------------------------------
    derived("CHANCELA_NODE_ROLE", G::Cluster, None),
    derived("CHANCELA_NODE_ADDRESS", G::Cluster, None),
    derived("CHANCELA_ADVERTISED_URL", G::Cluster, None),
    // ---- Cluster cadence (Tier A) -------------------------------------------------------------
    spec_a(
        "CHANCELA_PROMOTE_POLL_INTERVAL",
        G::Cluster,
        Some("1s"),
        V::Duration,
    ),
    spec_a(
        "CHANCELA_HEARTBEAT_INTERVAL",
        G::Cluster,
        Some("2s"),
        V::Duration,
    ),
    spec_a(
        "CHANCELA_NODE_STALE_AFTER",
        G::Cluster,
        Some("10s"),
        V::Duration,
    ),
    spec_a(
        "CHANCELA_LEADER_WATCHDOG_INTERVAL",
        G::Cluster,
        None,
        V::Duration,
    ),
    spec_a(
        "CHANCELA_CHANGEFEED_POLL_INTERVAL",
        G::Cluster,
        None,
        V::Duration,
    ),
    spec_a(
        "CHANCELA_CLUSTER_WRITE_MODE",
        G::Cluster,
        Some("redirect"),
        V::Enum(&["redirect", "proxy", "reject"]),
    ),
    // ---- Postgres TLS (boundary) --------------------------------------------------------------
    boundary(
        "CHANCELA_PG_SSLMODE",
        G::PostgresTls,
        Some("verify-full"),
        V::Enum(&["disable", "allow", "prefer", "require", "verify-ca", "verify-full"]),
    ),
    boundary("CHANCELA_PG_TLS_ROOT_CERT", G::PostgresTls, None, V::Path),
    // ---- Trust / validation URLs (Tier A) -----------------------------------------------------
    spec_a("CHANCELA_CAE_URL", G::Trust, None, V::HttpUrl),
    spec_a("CHANCELA_TSL_URL", G::Trust, None, V::HttpUrl),
    spec_a("CHANCELA_LOTL_URL", G::Trust, None, V::HttpUrl),
    spec_a("CHANCELA_TSA_URL", G::Trust, None, V::HttpUrl),
    spec_a("CHANCELA_LAW_URL", G::Trust, None, V::HttpUrl),
    spec_a("CHANCELA_REGISTRY_URL", G::Trust, None, V::HttpUrl),
    // ---- Trust anchors (boundary — clearing weakens verification) -----------------------------
    boundary("CHANCELA_TSL_TRUST_ANCHOR", G::Trust, None, V::FreeText),
    boundary("CHANCELA_TSL_TRUST_ANCHOR_SHA256", G::Trust, None, V::FreeText),
    // ---- Connectors ---------------------------------------------------------------------------
    // The egress ceiling already has a typed slice (`connectors.allowed_hosts`, env is the ceiling):
    // excluded from the generic store, narrow-only, shown read-only with a cross-link.
    EnvVarSpec {
        name: "CHANCELA_CONNECTOR_ALLOWED_HOSTS",
        group: G::Connectors,
        tier: T::C,
        secret: false,
        boundary: true,
        narrow_only: true,
        acknowledgement_required: true,
        excluded_typed_slice: Some(
            "connectors.allowed_hosts — env is the deployment egress ceiling; the panel may only narrow it",
        ),
        default_value: None,
        validator: V::HostList,
    },
    boundary("CHANCELA_CONNECTOR_SECRETS_DIR", G::Connectors, None, V::Path),
    // ---- ZK shared object root (typed slice; env wins) ----------------------------------------
    EnvVarSpec {
        name: "CHANCELA_ZK_SHARED_OBJECT_ROOT",
        group: G::Storage,
        tier: T::C,
        secret: false,
        boundary: true,
        narrow_only: false,
        acknowledgement_required: true,
        excluded_typed_slice: Some(
            "data_management.zk_shared_object_root — already a typed settings slice; env takes precedence",
        ),
        default_value: None,
        validator: V::Path,
    },
    // ---- Data dir (derived; chicken-and-egg — the override file lives under it) ----------------
    derived("CHANCELA_DATA_DIR", G::Storage, None),
];

/// Dynamic per-provider **secret** families that expand at request time (one entry per configured
/// provider / connector ref), always Tier B / display-only. Names are `PREFIX` + a runtime token +
/// `SUFFIX`. e3 enumerates the configured providers and emits a masked `configured` row per resolved
/// name; none are ever written to the override file.
pub const DYNAMIC_SECRET_FAMILIES: &[&str] = &[
    "CHANCELA_CSC_<PROVIDER>_CLIENT_ID",
    "CHANCELA_CSC_<PROVIDER>_CLIENT_SECRET",
    "CHANCELA_CSC_<PROVIDER>_ACCESS_TOKEN",
    "CHANCELA_CONNECTOR_SECRET_<REF>",
    "CHANCELA_CONNECTOR_SECRET_<REF>_FILE",
];

// -- const-fn constructors (keep the table above declarative) -----------------------------------

/// Tier A: editable, non-secret, restart-to-apply.
const fn spec_a(
    name: &'static str,
    group: EnvVarGroup,
    default_value: Option<&'static str>,
    validator: EnvVarValidator,
) -> EnvVarSpec {
    EnvVarSpec {
        name,
        group,
        tier: T::A,
        secret: false,
        boundary: false,
        narrow_only: false,
        acknowledgement_required: false,
        excluded_typed_slice: None,
        default_value,
        validator,
    }
}

/// Tier C: security boundary, editable behind acknowledgement (server-enforced `422`).
const fn boundary(
    name: &'static str,
    group: EnvVarGroup,
    default_value: Option<&'static str>,
    validator: EnvVarValidator,
) -> EnvVarSpec {
    EnvVarSpec {
        name,
        group,
        tier: T::C,
        secret: false,
        boundary: true,
        narrow_only: false,
        acknowledgement_required: true,
        excluded_typed_slice: None,
        default_value,
        validator,
    }
}

/// Tier B: secret / secret-pointer, display-only.
const fn secret(name: &'static str, group: EnvVarGroup) -> EnvVarSpec {
    EnvVarSpec {
        name,
        group,
        tier: T::B,
        secret: true,
        boundary: false,
        narrow_only: false,
        acknowledgement_required: false,
        excluded_typed_slice: None,
        default_value: None,
        validator: V::FreeText,
    }
}

/// Tier D: derived / read-only.
const fn derived(
    name: &'static str,
    group: EnvVarGroup,
    default_value: Option<&'static str>,
) -> EnvVarSpec {
    EnvVarSpec {
        name,
        group,
        tier: T::D,
        secret: false,
        boundary: false,
        narrow_only: false,
        acknowledgement_required: false,
        excluded_typed_slice: None,
        default_value,
        validator: V::FreeText,
    }
}

// ---------------------------------------------------------------------------------------------
// Wire types (the frozen contract e3/e4/e5 build against)
// ---------------------------------------------------------------------------------------------

/// The validator descriptor the web reads to pick an input control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvVarValidatorView {
    pub kind: EnvVarValidatorKind,
    /// The allowed literals for [`EnvVarValidatorKind::Enum`]; `None` otherwise.
    pub allowed: Option<Vec<String>>,
}

/// One env var as rendered by `GET /v1/platform/env`: the declared classification joined with the
/// value the **live** process resolved. Secrets never carry a value — only [`Self::configured`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServerEnvVarView {
    pub name: String,
    pub group: EnvVarGroup,
    pub tier: EnvVarTier,
    /// Whether the panel presents an editor (Tier A/C and not typed-slice-excluded).
    pub editable: bool,
    /// Holds (or points at) a secret — value is never echoed.
    pub secret: bool,
    /// A security boundary — a change needs acknowledgement.
    pub boundary: bool,
    /// A ceiling an override may only tighten, never loosen.
    pub narrow_only: bool,
    /// Editing requires the operator to acknowledge the risk (server enforces `422`).
    pub acknowledgement_required: bool,
    /// `Some(reason)` → managed by a typed settings slice; shown read-only with a cross-link.
    pub excluded_typed_slice: Option<String>,
    /// Which layer supplied the resolved value.
    pub source: EnvVarSource,
    /// Whether the live process currently has a value for this var (the only signal for secrets).
    pub configured: bool,
    /// The value the live process resolved. `None` for secrets (never echoed) and when unset.
    pub effective_value: Option<String>,
    /// The persisted override, if any. `None` for secrets and when no override is set.
    pub override_value: Option<String>,
    /// The code default. `None` for secrets and vars with no default.
    pub default_value: Option<String>,
    /// The stored override differs from what the live process resolved → takes effect on next restart.
    pub restart_pending: bool,
    /// How a proposed override is validated (input-control hint + enum options).
    pub validator: EnvVarValidatorView,
}

/// `GET /v1/platform/env` and the body returned by a successful `PUT`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServerEnvResponse {
    /// Every registry var (static rows + expanded dynamic secret families), grouped by the web.
    pub vars: Vec<ServerEnvVarView>,
    /// True if any var's stored override differs from the live value (a restart is pending).
    pub restart_pending: bool,
    /// Where the override file lives (informational; under `CHANCELA_DATA_DIR`).
    pub overrides_path: String,
    /// RFC3339 timestamp the view was built.
    pub generated_at: String,
}

/// `PUT /v1/platform/env` — replace the non-secret override map.
///
/// The map is the **complete** desired override set (keys absent from it are cleared). Only Tier A and
/// Tier C vars may appear; a secret, derived, or typed-slice-excluded key is rejected. Any boundary
/// var that changes must have its name listed in [`Self::acknowledge`], or the server returns `422`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerEnvUpdateRequest {
    /// name → override value. The full desired set (not a delta).
    pub overrides: BTreeMap<String, String>,
    /// Boundary var names whose risk the operator explicitly acknowledges (the `allow_insecure` mould).
    #[serde(default)]
    pub acknowledge: Vec<String>,
}

// ---------------------------------------------------------------------------------------------
// Persistence + startup application
// ---------------------------------------------------------------------------------------------

/// The persisted override file (`env-overrides.json`). Non-secret keys only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvOverrides {
    #[serde(default)]
    pub overrides: BTreeMap<String, String>,
}

/// The resolved path to the override file under a data dir.
pub fn overrides_path(data_dir: &Path) -> PathBuf {
    data_dir.join(OVERRIDES_FILE)
}

/// Read the override file. A missing file is not an error — it yields an empty set (precedence then
/// falls straight through to the ambient env / code default).
pub fn load(data_dir: &Path) -> std::io::Result<EnvOverrides> {
    let path = overrides_path(data_dir);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(EnvOverrides::default()),
        Err(e) => Err(e),
    }
}

/// Persist the override file atomically (temp write + rename), creating the data dir if needed.
pub fn save(data_dir: &Path, overrides: &EnvOverrides) -> std::io::Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let path = overrides_path(data_dir);
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(overrides)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, &path)
}

/// Whether [`apply`] will stamp `name = value`, returning the canonical registry name on success or
/// an operator-facing reason to skip on failure. **Pure** — the actual `unsafe` `set_var` and the
/// operator warning live in [`apply`], so the whole gate is unit-testable without touching the
/// process environment.
///
/// A key is applied only when it is a registry-known var that is editable (Tier A/C), non-secret, and
/// not managed by a typed settings slice, and its value passes the registry validator. Everything else
/// — an unknown key, a secret, a derived/typed-slice-excluded var, or a malformed value — is skipped,
/// so even a hand-edited `env-overrides.json` can never push a forbidden or garbage value into the
/// process env. e3's write path already enforces the same rules; this is defence in depth for the
/// file, which `apply` reads with no author to trust.
fn should_apply(name: &str, value: &str) -> Result<&'static str, String> {
    let spec = find(name).ok_or_else(|| format!("`{name}` is not a known server env var"))?;
    if spec.secret {
        return Err(format!(
            "`{name}` is a secret and is never applied from {OVERRIDES_FILE}"
        ));
    }
    if let Some(reason) = spec.excluded_typed_slice {
        return Err(format!("`{name}` is managed by a typed settings slice ({reason})"));
    }
    if !spec.is_editable() {
        return Err(format!(
            "`{name}` is tier {:?} and is not overridable",
            spec.tier
        ));
    }
    spec.validator.validate(value).map_err(|e| format!("`{name}`: {e}"))?;
    Ok(spec.name)
}

/// Stamp the process environment from `overrides`, applying precedence `override > env > default`.
///
/// # Safety / ordering — the R1 invariant (edition 2024)
/// `std::env::set_var` is `unsafe` in edition 2024 because it is **not thread-safe**: on some
/// platforms it reallocates the whole `environ` block, so a concurrent `getenv` in another thread is a
/// data race. The `unsafe` block below is sound **only** because this runs while the process is
/// effectively single-threaded — as the first statement in `chancela-server`'s synchronous `main`,
/// *before* `init_tracing`, *before* `AppState::try_from_env`, and *before* the tokio runtime spawns
/// any worker thread. `main.rs` upholds this ordering; do not call `apply` once the runtime is up.
///
/// Precedence falls straight out of `set_var`: a present, valid override wins over the ambient env
/// (`override > env`); a var absent from `overrides` is left untouched, so the ambient env — or, if
/// unset, the code default — still applies (`env > default`). It never clears a var it did not set.
pub fn apply(overrides: &EnvOverrides) {
    for (name, value) in &overrides.overrides {
        match should_apply(name, value) {
            Ok(canonical) => {
                // SAFETY: `apply` runs before any other thread reads the environment — the first
                // statement in `main`, before `init_tracing`/`try_from_env`/the tokio runtime (see
                // the ordering contract above). No concurrent `getenv` can race this `set_var`.
                unsafe {
                    std::env::set_var(canonical, value);
                }
            }
            Err(reason) => {
                // Tracing is not yet initialised at this point (it, too, reads env after `apply`), so
                // report a skipped override on stderr — the process's log sink at this stage.
                eprintln!("chancela: ignoring env override — {reason}");
            }
        }
    }
}

/// Load the persisted overrides under `data_dir` and [`apply`] them to the process environment.
///
/// This is the single entry point `chancela-server/main.rs` calls, as the very first thing in `main`.
/// A missing override file is a no-op (precedence falls through to the ambient env / code default); an
/// unreadable or malformed file is reported on stderr and skipped rather than aborting boot — a
/// corrupt overrides file must never wedge the server, and the ambient environment remains a valid
/// configuration.
///
/// See [`apply`] for the R1 safety invariant: this **must** be called before any other thread reads
/// the environment.
pub fn apply_from_data_dir(data_dir: &Path) {
    match load(data_dir) {
        Ok(overrides) => apply(&overrides),
        Err(e) => eprintln!(
            "chancela: could not read {} ({e}); continuing with the ambient environment",
            overrides_path(data_dir).display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn registry_var_names_are_unique() {
        let mut seen = BTreeSet::new();
        for spec in REGISTRY {
            assert!(seen.insert(spec.name), "duplicate registry entry: {}", spec.name);
        }
    }

    #[test]
    fn tier_and_flag_coherence() {
        for spec in REGISTRY {
            match spec.tier {
                T::A => {
                    assert!(!spec.secret, "{} A must not be secret", spec.name);
                    assert!(!spec.boundary, "{} A must not be boundary", spec.name);
                    assert!(
                        !spec.acknowledgement_required,
                        "{} A must not require ack",
                        spec.name
                    );
                }
                T::B => {
                    assert!(spec.secret, "{} B must be secret", spec.name);
                    assert!(!spec.is_editable(), "{} B must not be editable", spec.name);
                }
                T::C => {
                    assert!(spec.boundary, "{} C must be a boundary", spec.name);
                    assert!(
                        spec.acknowledgement_required,
                        "{} C must require ack",
                        spec.name
                    );
                }
                T::D => {
                    assert!(!spec.is_editable(), "{} D must not be editable", spec.name);
                }
            }
            // A ceiling that can only narrow is by definition a boundary.
            if spec.narrow_only {
                assert!(spec.boundary, "{} narrow_only implies boundary", spec.name);
            }
            // A typed-slice-excluded var is never editable through the generic store.
            if spec.excluded_typed_slice.is_some() {
                assert!(
                    !spec.is_editable(),
                    "{} is typed-slice-excluded and must not be editable",
                    spec.name
                );
            }
            // Secrets never carry a default on the wire.
            if spec.secret {
                assert!(spec.default_value.is_none(), "{} secret carries default", spec.name);
            }
        }
    }

    #[test]
    fn validators_accept_defaults_and_reject_garbage() {
        for spec in REGISTRY {
            if let Some(default) = spec.default_value {
                assert!(
                    spec.validator.validate(default).is_ok(),
                    "{} default {:?} fails its own validator",
                    spec.name,
                    default
                );
            }
        }
        assert!(V::Bool.validate("maybe").is_err());
        assert!(V::Unsigned.validate("-1").is_err());
        assert!(V::HttpUrl.validate("ftp://x").is_err());
        assert!(V::SocketAddr.validate("not-an-addr").is_err());
        assert!(V::Enum(&["a", "b"]).validate("c").is_err());
        assert!(V::Duration.validate("10s").is_ok());
        assert!(V::Duration.validate("10").is_ok());
    }

    #[test]
    fn load_missing_file_is_empty() {
        let dir = std::env::temp_dir().join(format!("chancela-env-ovr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let loaded = load(&dir).expect("missing file is not an error");
        assert!(loaded.overrides.is_empty());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = std::env::temp_dir().join(format!("chancela-env-ovr-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut overrides = EnvOverrides::default();
        overrides
            .overrides
            .insert("CHANCELA_LOG".to_string(), "debug".to_string());
        save(&dir, &overrides).expect("save");
        let loaded = load(&dir).expect("load");
        assert_eq!(loaded, overrides);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- apply gate (`should_apply`) — pure, no global-env mutation -----------------------------

    #[test]
    fn should_apply_accepts_editable_non_secret_vars() {
        // Tier A ...
        assert_eq!(should_apply("CHANCELA_LOG", "debug"), Ok("CHANCELA_LOG"));
        // ... and Tier C (the acknowledgement gate is e3's write-time job; the file only holds what
        // e3 already accepted, so `apply` stamps a boundary override the same as any other).
        assert_eq!(
            should_apply("CHANCELA_PG_SSLMODE", "require"),
            Ok("CHANCELA_PG_SSLMODE")
        );
    }

    #[test]
    fn should_apply_rejects_secrets() {
        // A secret must never be applied from the plaintext override file, even if hand-inserted.
        assert!(should_apply("CHANCELA_DB_KEY", "hunter2").is_err());
        assert!(should_apply("DATABASE_URL", "postgres://x").is_err());
    }

    #[test]
    fn should_apply_rejects_unknown_keys() {
        assert!(should_apply("CHANCELA_NOT_A_REAL_VAR", "x").is_err());
    }

    #[test]
    fn should_apply_rejects_derived_and_typed_slice_vars() {
        // Tier D — derived / read-only.
        assert!(should_apply("CHANCELA_DATA_DIR", "/somewhere").is_err());
        assert!(should_apply("CHANCELA_NODE_ROLE", "leader").is_err());
        // Typed-slice-excluded — no double precedence with the settings slice that already owns these.
        assert!(should_apply("CHANCELA_ZK_SHARED_OBJECT_ROOT", "/zk").is_err());
        assert!(should_apply("CHANCELA_CONNECTOR_ALLOWED_HOSTS", "example.pt").is_err());
    }

    #[test]
    fn should_apply_rejects_values_failing_the_validator() {
        // A malformed value can never reach `set_var`.
        assert!(should_apply("CHANCELA_HSTS_MAX_AGE", "soon").is_err());
        assert!(should_apply("CHANCELA_ADDR", "not-a-socket").is_err());
        assert!(should_apply("CHANCELA_LOG_FORMAT", "rainbow").is_err());
    }

    /// Exercises the real `unsafe` `set_var` stage end to end: an override reaches the process env
    /// exactly as a later `std::env::var` (what `try_from_env` and every runtime reader call) would
    /// see it, precedence `override > env` holds, and a var with no override is left untouched
    /// (`env > default`). Uses the paper-book OCR engine vars, which no other test reads (their read
    /// is gated behind `CHANCELA_PAPER_BOOK_OCR_COMMAND`, which no test sets), so this single
    /// env-mutating test does not contaminate any concurrent `try_from_env` test.
    #[test]
    fn apply_sets_overrides_and_leaves_unset_vars_untouched() {
        const OVERRIDDEN: &str = "CHANCELA_PAPER_BOOK_OCR_ENGINE_VERSION";
        const AMBIENT: &str = "CHANCELA_PAPER_BOOK_OCR_ENGINE_NAME";
        const SECRET_IN_FILE: &str = "CHANCELA_SCAP_SECRET";

        // Establish a known baseline: an ambient value for the var we will NOT override, and the
        // overridden/secret vars cleared so the assertions can't be fooled by leftover state.
        // SAFETY: single-threaded test setup; only this test touches these otherwise-unread vars.
        unsafe {
            std::env::set_var(AMBIENT, "ambient-name");
            std::env::remove_var(OVERRIDDEN);
            std::env::remove_var(SECRET_IN_FILE);
        }

        let mut overrides = EnvOverrides::default();
        overrides
            .overrides
            .insert(OVERRIDDEN.to_string(), "9.9.9".to_string());
        // A secret slipped into the file must be ignored, not stamped.
        overrides
            .overrides
            .insert(SECRET_IN_FILE.to_string(), "leaked".to_string());

        apply(&overrides);

        // override > env: the overridden var now resolves to the override value.
        assert_eq!(std::env::var(OVERRIDDEN).as_deref(), Ok("9.9.9"));
        // env > default: a var absent from the override set keeps its ambient value (not clobbered).
        assert_eq!(std::env::var(AMBIENT).as_deref(), Ok("ambient-name"));
        // The secret was skipped by `should_apply` and never reached `set_var`.
        assert!(std::env::var(SECRET_IN_FILE).is_err());

        // Clean up so we leave no global-env residue for other tests.
        // SAFETY: single-threaded test teardown.
        unsafe {
            std::env::remove_var(OVERRIDDEN);
            std::env::remove_var(AMBIENT);
        }
    }
}
