//! `chancela-server` — the single command that brings up the whole application.
//!
//! One `cargo run` at the repo root starts everything the app needs: the HTTP API, the
//! hash-chained event ledger backing it, and (when a web build is present) the web UI served
//! from the same origin. The binary owns almost no logic (ARC-02): it resolves where the web
//! build lives, builds the [`chancela_api`] app (durable to a SQLite store when a data dir is
//! configured, in-memory otherwise — see [`chancela_api::AppState::from_env`]), prints a
//! startup banner reporting which, and serves until a shutdown signal arrives.
//!
//! ## Web UI resolution
//!
//! The directory holding the built web shell (`apps/web/dist`) is resolved in order:
//!   1. `CHANCELA_WEB_DIST` — explicit override (the Docker image sets `/srv/web`).
//!   2. `/srv/web` — the container layout, if it exists.
//!   3. auto-detected `apps/web/dist`, walking up from the current directory — so a plain
//!      `cargo run` from anywhere in the repo just works.
//!
//! If none resolves, the server runs API-only and says so, both in the banner and at `/`.
//!
//! ## Bind address
//!
//! `CHANCELA_ADDR` (default `127.0.0.1:8080`; the Docker image sets `0.0.0.0:8080`) so a dev
//! server is not reachable off-host by accident.
//!
//! At-rest database encryption is optional and feature-gated: when built with `--features
//! sqlcipher`, configure either `CHANCELA_DB_KEY` or `CHANCELA_DB_KEY_FILE`. Invalid, ambiguous, or
//! unsupported encryption configuration aborts startup without printing the key.

use std::net::SocketAddr;
use std::path::PathBuf;

use tokio::net::TcpListener;
use tokio::signal;

/// Environment variable naming the `host:port` to bind.
const ADDR_ENV: &str = "CHANCELA_ADDR";
/// Loopback default used when `CHANCELA_ADDR` is unset.
const DEFAULT_ADDR: &str = "127.0.0.1:8080";
/// Environment variable pointing at the built web shell directory.
const WEB_DIST_ENV: &str = "CHANCELA_WEB_DIST";
/// Container path the Docker image copies the web build to.
const CONTAINER_WEB_DIST: &str = "/srv/web";

/// Environment variable selecting the log formatter: `json` (default, aggregator-friendly) or
/// `pretty` (human-readable, for local dev).
const LOG_FORMAT_ENV: &str = "CHANCELA_LOG_FORMAT";
/// Primary env var for the log level/filter directives; falls back to `RUST_LOG`, then `info`.
const LOG_FILTER_ENV: &str = "CHANCELA_LOG";

/// Initialise the process-wide `tracing` subscriber before anything else runs.
///
/// Level/filter comes from `CHANCELA_LOG`, else `RUST_LOG`, else a sane `info` default. The formatter
/// is JSON by default (structured, one event per line — what a container log aggregator wants) and
/// switches to the coloured `pretty` layout when `CHANCELA_LOG_FORMAT=pretty`. Everything is written to
/// stdout so a supervisor/container captures it. Idempotent-safe: called exactly once from `main`.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    let filter = std::env::var(LOG_FILTER_ENV)
        .ok()
        .or_else(|| std::env::var("RUST_LOG").ok())
        .map(EnvFilter::new)
        .unwrap_or_else(|| EnvFilter::new("info"));

    let pretty = std::env::var(LOG_FORMAT_ENV)
        .map(|v| v.eq_ignore_ascii_case("pretty"))
        .unwrap_or(false);

    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if pretty {
        builder.pretty().init();
    } else {
        builder.json().init();
    }
}

#[tokio::main]
async fn main() {
    init_tracing();

    let raw_addr = std::env::var(ADDR_ENV).unwrap_or_else(|_| DEFAULT_ADDR.to_owned());
    let addr: SocketAddr = raw_addr
        .parse()
        .unwrap_or_else(|e| panic!("{ADDR_ENV}={raw_addr:?} is not a valid host:port: {e}"));

    let web_dist = resolve_web_dist();
    // Resolve the settings data dir the same way `AppState::from_env` will, so the banner can
    // report whether settings persist to disk or live only in memory.
    let data_dir = chancela_api::AppState::resolve_data_dir();
    // Open the store off the runtime worker thread. `try_from_env` is a synchronous store-open
    // that, for the Postgres/cluster backend, drives the sync `postgres` crate's connector via an
    // internal `Runtime::block_on`; calling it directly on a `#[tokio::main]` worker panics with
    // "Cannot start a runtime from within a runtime" and aborts boot. `spawn_blocking` moves it to
    // a blocking-pool thread (the same convention the runtime supervisor uses in `cluster.rs`).
    // The SQLite/in-memory paths are fully sync and unaffected either way.
    let state = tokio::task::spawn_blocking(chancela_api::AppState::try_from_env)
        .await
        .expect("store-open task panicked")
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "invalid Chancela startup configuration");
            std::process::exit(2);
        });
    #[cfg(feature = "e2e")]
    chancela_api::seed_e2e_sessions_from_data_dir(&state).await;

    // Kick off a best-effort background refresh of the CAE catalog. Non-blocking and offline-safe:
    // it no-ops without a configured `CHANCELA_CAE_URL` or while the cached table is still fresh,
    // and never blocks or fails startup. The manual `POST /v1/cae/refresh` is the always-available
    // path; this just keeps the on-disk cache warm for the next start.
    chancela_cae::spawn_background_refresh(data_dir.clone());

    // Summarise the active CAE catalog for the banner before `state` moves into `app`.
    let cae_banner = {
        let catalog = state.cae.read().await;
        let m = catalog.metadata();
        format!(
            "{:?} · Rev.4 {} / Rev.3 {} nodes · generated {}",
            m.origin,
            m.counts.rev4.total(),
            m.counts.rev3.total(),
            m.generated_at
        )
    };

    // Summarise the durable ledger + store for the banner before `state` moves into `app`.
    // When the store is present the ledger persists on disk; report its length, the boot-time
    // chain-verification outcome (§D-boot, surfaced loudly on a break), and the store path +
    // schema version. Only truly in-memory state (no store) gets the "resets on restart" warning.
    let ledger_len = state.ledger.read().await.len();
    let (ledger_status, store_status) = if state.store.is_some() {
        let chain = match state.chain_status.as_deref() {
            Some(Err(e)) => format!("CHAIN BROKEN — {e}; restore from backup"),
            _ => "chain verified".to_owned(),
        };
        let store = data_dir.as_deref().map(|dir| {
            let encryption = if state.database_encryption_configured {
                " · SQLCipher configured"
            } else {
                ""
            };
            format!(
                "{} · schema v{}{}",
                dir.join(chancela_store::DB_FILE).display(),
                chancela_store::schema::SCHEMA_VERSION,
                encryption
            )
        });
        (format!("{ledger_len} events on disk · {chain}"), store)
    } else {
        (
            format!("in-memory hash chain (length {ledger_len}, resets on restart)"),
            None,
        )
    };

    // wp25-sec: warn once at boot if the durable store is a PLAINTEXT SQLite DB (no SQLCipher key).
    // Captured before `state` moves into `app`. Encryption-at-rest stays optional/feature-gated (see
    // the module docs) so builds without the native SQLCipher lib are unaffected; this only makes the
    // recommended production posture visible.
    let store_is_plaintext = state.store.is_some() && !state.database_encryption_configured;

    let app = chancela_api::app(state, web_dist.clone());

    let listener = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));

    let bound = listener.local_addr().unwrap_or(addr);
    print_banner(
        bound,
        web_dist.as_deref(),
        data_dir.as_deref(),
        &cae_banner,
        &ledger_status,
        store_status.as_deref(),
    );
    // Machine-readable startup event beside the human banner, so log aggregators capture a clean
    // "listening" signal with structured fields.
    tracing::info!(
        addr = %bound,
        version = env!("CARGO_PKG_VERSION"),
        persistent = data_dir.is_some(),
        "chancela-server listening"
    );
    if store_is_plaintext {
        tracing::warn!(
            "the durable SQLite database is UNENCRYPTED at rest; for production configure \
             encryption at rest — build with `--features sqlcipher` and set \
             CHANCELA_DB_KEY/CHANCELA_DB_KEY_FILE, or place the data directory on an encrypted volume"
        );
    }

    // wp25-sec: serve with per-connection info so the per-IP rate limiter can read the real TCP
    // peer address (`ConnectInfo<SocketAddr>`). When the deployment sits behind a trusted reverse
    // proxy, set CHANCELA_RATE_LIMIT_TRUST_FORWARDED_FOR=1 to key off X-Forwarded-For / X-Real-IP.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("server error");

    tracing::info!("chancela-server shut down cleanly");
}

/// Locate the built web shell directory, honouring the documented resolution order. Returns
/// `None` (API-only) when no build is found.
fn resolve_web_dist() -> Option<PathBuf> {
    // 1. Explicit override.
    if let Ok(raw) = std::env::var(WEB_DIST_ENV) {
        let dir = PathBuf::from(&raw);
        if dir.is_dir() {
            return Some(dir);
        }
        tracing::warn!(
            web_dist = %raw,
            "{WEB_DIST_ENV} is not a directory; ignoring it"
        );
    }

    // 2. Container layout.
    let container = PathBuf::from(CONTAINER_WEB_DIST);
    if container.is_dir() {
        return Some(container);
    }

    // 3. Auto-detect apps/web/dist by walking up from the current directory, so `cargo run`
    //    from the repo root (or a subdirectory) finds the build without configuration.
    let start = std::env::current_dir().ok()?;
    for base in start.ancestors() {
        let candidate = base.join("apps").join("web").join("dist");
        if candidate.join("index.html").is_file() {
            return Some(candidate);
        }
    }

    None
}

/// Print a tidy, dependency-free startup summary: version, address, web UI status, the API
/// surface, durable ledger + store status, settings persistence status, and how to open the app.
///
/// `store_status` is `Some(..)` only when the durable store is active; `ledger_status` already
/// carries the in-memory warning when it is not.
fn print_banner(
    addr: SocketAddr,
    web_dist: Option<&std::path::Path>,
    data_dir: Option<&std::path::Path>,
    cae_status: &str,
    ledger_status: &str,
    store_status: Option<&str>,
) {
    let version = env!("CARGO_PKG_VERSION");
    let url = format!("http://{addr}");
    let web_status = match web_dist {
        Some(dir) => format!("serving from {}", dir.display()),
        None => {
            "not built — run `npm run build --workspace apps/web` (API-only for now)".to_owned()
        }
    };
    let settings_status = match data_dir {
        Some(dir) => format!("persisting to {}", dir.display()),
        None => "in-memory (set CHANCELA_DATA_DIR to persist)".to_owned(),
    };

    println!();
    println!("  Chancela  v{version}");
    println!("  ─────────────────────────────────────────────");
    println!("  Listening   {url}");
    println!("  Web UI      {web_status}");
    println!("  Ledger      {ledger_status}");
    if let Some(store) = store_status {
        println!("  Store       {store}");
    }
    println!("  Settings    {settings_status}");
    println!("  CAE         {cae_status}");
    println!("  API");
    println!("    GET  /health");
    println!("    GET  /livez");
    println!("    GET  /readyz");
    println!("    GET  /metrics  (internal/allowlisted only)");
    println!("    GET  /v1/entities");
    println!("    POST /v1/entities");
    println!("    GET  /v1/entities/{{id}}");
    println!("    GET  /v1/ledger/verify");
    println!("    POST /v1/backup");
    println!("  ─────────────────────────────────────────────");
    println!("  Open  {url}");
    println!("  Stop  Ctrl+C");
    println!();
}

/// Resolve when the process receives Ctrl+C (all platforms) or a SIGTERM (Unix, e.g. a
/// container stop), letting `axum::serve` drain in-flight requests before exiting.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
