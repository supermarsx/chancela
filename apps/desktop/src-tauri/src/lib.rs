//! Chancela desktop shell (Tauri v2).
//!
//! This is the thin native wrapper for the Personal / Offline edition
//! (spec SCP-10 mode 1, SCP-11): a Tauri v2 WebView that hosts the same web UI
//! the browser client uses and talks to the same Axum API surface, running
//! locally in-process (ARC-03/ARC-04).
//!
//! ## `embedded-server` (default feature)
//!
//! With the `embedded-server` feature (on by default), the app starts the exact
//! `chancela_api::app` the browser client and `chancela-server` serve — the web
//! UI *and* the `/v1` API — on an ephemeral **loopback** port, then navigates
//! the main WebView window to `http://127.0.0.1:<port>`. Because the UI is then
//! loaded from that origin, its relative `/v1/...` fetches are same-origin: no
//! CORS, and zero changes to the web client. Legal behaviour never depends on
//! packaging (SCP-03): the desktop app runs the same code path as the server.
//!
//! Settings persist across launches: the embedded server is built with
//! [`chancela_api::AppState::from_env`]-style resolution, defaulting to the OS
//! per-app data directory so a normal install keeps its configuration out of the
//! box (see [`build_app_state`]).
//!
//! With `--no-default-features` the shell is a bare WebView that loads whatever
//! the Tauri config points at (`devUrl` in dev, the embedded `frontendDist` in a
//! bundle) and expects an API to be reachable there — no in-process server.
//!
//! Intentional constraints:
//! - This crate is NOT part of the repo-root Cargo workspace (see Cargo.toml).
//! - `chancela-api` (and `tokio`/`axum`) are pulled in ONLY behind the feature,
//!   so a `--no-default-features` build stays dependency-light.

/// Runs the desktop application.
///
/// The `mobile_entry_point` attribute lets the same function serve as the
/// entry point on Android/iOS when this crate is built for those targets
/// (Tauri v2, ARC-04). On desktop it is a normal function called from `main`.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default();

    // Single-instance guard (registered FIRST, per the plugin's guidance).
    //
    // Debug and release builds share the bundle identifier `pt.chancela.desktop`,
    // hence the same per-app data dir (`settings.json`/`users.json`) and the same
    // WebView2 user-data profile (`EBWebView`). Running a second copy — e.g.
    // `npm run dev` while a release build (or a previous instance) is still open —
    // means two servers, two writers on the same JSON files, and two WebViews
    // contending for one profile: at best confusing, at worst a hard-to-diagnose
    // launch failure. This plugin makes the second launch focus the already-open
    // window and exit *before* it starts a server or creates a WebView, so there is
    // only ever one live instance. Desktop-only (single-instance is not a mobile
    // concept).
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            use tauri::Manager;
            // A second launch was attempted; bring the existing window forward
            // instead of starting a duplicate.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
            eprintln!("chancela: já existe uma instância aberta — a focar a janela existente");
        }));
    }

    // Remember the window's position and size across launches: restore on start,
    // save on move/resize/close. The plugin also handles the
    // monitor-disconnected case. Desktop-only (no-op / unavailable on mobile).
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_window_state::Builder::default().build());
    }

    // Open external http(s) links in the user's default browser. The web client
    // (apps/web/src/desktop/openExternal.ts) calls `openUrl` from the matching JS
    // plugin; the `opener:allow-open-url` permission is granted to the embedded-server
    // remote origin in capabilities/default.json. Registered on all targets.
    builder = builder.plugin(tauri_plugin_opener::init());

    // Lets the crash screen's "Reiniciar aplicação" action truly relaunch the process
    // (see apps/web/src/desktop/relaunch.ts). Registered on all targets (t26).
    builder = builder.plugin(tauri_plugin_process::init());

    builder
        .setup(|app| {
            start_embedded_server_if_enabled(app)?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Chancela desktop application");
}

/// Environment variable naming the fixed `host:port` the dev-mode embedded server
/// binds. Mirrors `chancela-server`'s `CHANCELA_ADDR` so both honour the same knob.
#[cfg(feature = "embedded-server")]
const DEV_ADDR_ENV: &str = "CHANCELA_ADDR";
/// Default dev bind address. MUST match the Vite dev proxy target in
/// `apps/web/vite.config.ts` (`/v1` + `/health` → `http://127.0.0.1:8080`).
#[cfg(feature = "embedded-server")]
const DEV_DEFAULT_ADDR: &str = "127.0.0.1:8080";

/// ARC-03: start the in-process API+UI server and point the WebView at it.
///
/// Two modes:
/// - **Release / bundle:** start the embedded server on an ephemeral loopback port
///   and navigate the main window to it, so the UI loads same-origin.
/// - **`tauri dev`:** the WebView stays on `devUrl` (the Vite dev server, with
///   hot-reload). Vite proxies `/v1` + `/health` to a *fixed* loopback address, so
///   we start the same embedded API there — no navigation — making `npm run dev`
///   self-contained (no separate `cargo run -p chancela-server` needed). If that
///   address is already taken (the developer is also running `chancela-server`),
///   we log and let the proxy reach the existing server instead of crashing.
#[cfg(feature = "embedded-server")]
fn start_embedded_server_if_enabled(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::Manager;

    // Dev mode keeps the WebView on Vite's devUrl for hot-reload; start the API on
    // the fixed address the Vite proxy targets, but do NOT navigate the window.
    if tauri::is_dev() {
        spawn_dev_server(build_app_state(app));
        return Ok(());
    }

    let state = build_app_state(app);
    let port = spawn_server(state)?;

    // Desktop safe-mode entry (t26): when `CHANCELA_SAFE_MODE` is set we append the same
    // `?safe=1` the manual/browser escape hatch uses, so there is ONE mechanism the web
    // client reasons about (apps/web/src/app/safeMode.ts) rather than a bespoke inject.
    let mut url_str = format!("http://127.0.0.1:{port}/");
    if safe_mode_requested() {
        eprintln!("chancela: CHANCELA_SAFE_MODE definido — a arrancar em modo de segurança");
        url_str.push_str("?safe=1");
    }
    let url = tauri::Url::parse(&url_str)?;

    // Navigate the main window (declared in tauri.conf.json) to the local server,
    // so the UI loads from that origin and its `/v1/...` calls are same-origin.
    let window = app
        .get_webview_window("main")
        .ok_or("desktop shell: no window labelled \"main\" to navigate")?;
    window.navigate(url)?;
    Ok(())
}

/// Feature disabled: the shell loads `devUrl`/`frontendDist` as configured and
/// expects the API to be reachable there. No in-process server.
#[cfg(not(feature = "embedded-server"))]
fn start_embedded_server_if_enabled(_app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

/// Whether `CHANCELA_SAFE_MODE` requests a safe-mode boot. Any value other than the usual
/// falsey spellings (`0`/`false`/`off`/`no`/blank) counts as "on", so `=1` and `=true`
/// both work.
#[cfg(feature = "embedded-server")]
fn safe_mode_requested() -> bool {
    match std::env::var("CHANCELA_SAFE_MODE") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !(v.is_empty() || v == "0" || v == "false" || v == "off" || v == "no")
        }
        Err(_) => false,
    }
}

/// Install a best-effort panic hook that writes each panic to
/// `<crash_dir>/crash/panic-<stamp>.log` (t26), then defers to the previously installed
/// hook (so the normal stderr backtrace still happens). The crash screen references this
/// path pattern generically.
///
/// It MUST never panic itself — a panic inside a panic hook aborts the process — so every
/// fallible step (dir creation, file open, write) is ignored on error.
#[cfg(feature = "embedded-server")]
fn install_panic_hook(crash_base: std::path::PathBuf) {
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let dir = crash_base.join("crash");
        if std::fs::create_dir_all(&dir).is_ok() {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            let path = dir.join(format!("panic-{stamp}.log"));
            if let Ok(mut file) = std::fs::File::create(&path) {
                let location = info
                    .location()
                    .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                    .unwrap_or_else(|| "local desconhecido".to_owned());
                let message = info
                    .payload()
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_owned())
                    .or_else(|| info.payload().downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "(payload não textual)".to_owned());
                let _ = writeln!(
                    file,
                    "Chancela — panic\nstamp_ms: {stamp}\nlocal: {location}\nmensagem: {message}"
                );
            }
        }
        // Preserve the standard behaviour (stderr backtrace, abort/unwind policy).
        default_hook(info);
    }));
}

/// Build the [`chancela_api::AppState`] the embedded server runs on, choosing where
/// settings persist so the desktop app keeps them across launches (spec DAT-10).
///
/// Resolution order:
///   1. An explicit data dir from the environment — `CHANCELA_DATA_DIR`, else a
///      walk-up `chancela-data/` — via [`chancela_api::AppState::resolve_data_dir`].
///      This mirrors `chancela-server`, so a repo/dev run behaves identically to the
///      standalone server and power users can redirect storage.
///   2. **Desktop default:** when nothing is configured, persist under the OS
///      per-app data directory so a normal install gets persistence out of the box:
///      `<app_data_dir>/chancela-data`, where Tauri's `app_data_dir()` already folds
///      in the bundle identifier `pt.chancela.desktop` — e.g. on Windows
///      `%APPDATA%\pt.chancela.desktop\chancela-data`, on Linux
///      `~/.local/share/pt.chancela.desktop/chancela-data`, on macOS
///      `~/Library/Application Support/pt.chancela.desktop/chancela-data`. The
///      directory itself is created lazily on the first settings write.
///   3. If even that cannot be resolved (no home/app-data dir), fall back to pure
///      in-memory state so the app still launches.
///
/// Only `settings.json` is persisted today; all other state remains in memory.
#[cfg(feature = "embedded-server")]
fn build_app_state(app: &tauri::App) -> chancela_api::AppState {
    use tauri::Manager;

    // 1. Explicit env / walk-up data dir wins (parity with chancela-server).
    if let Some(dir) = chancela_api::AppState::resolve_data_dir() {
        eprintln!("chancela: persisting settings to {}", dir.display());
        // Panic logs live alongside the persisted state (t26).
        install_panic_hook(dir.clone());
        // Proactively refresh the CAE cache in that data dir (detached, offline-safe:
        // a no-op without CHANCELA_CAE_URL or while the cache is still fresh).
        chancela_cae::spawn_background_refresh(Some(dir.clone()));
        let state = chancela_api::AppState::with_data_dir(dir.clone());
        report_durable_store(&state, &dir);
        return state;
    }

    // 2. Desktop default: the OS per-app data directory.
    match app.path().app_data_dir() {
        Ok(base) => {
            let dir = base.join("chancela-data");
            eprintln!("chancela: persisting settings to {}", dir.display());
            install_panic_hook(dir.clone());
            chancela_cae::spawn_background_refresh(Some(dir.clone()));
            let state = chancela_api::AppState::with_data_dir(dir.clone());
            report_durable_store(&state, &dir);
            state
        }
        // 3. No app-data dir available: run in memory rather than fail to launch.
        Err(e) => {
            eprintln!(
                "chancela: could not resolve an app-data directory ({e}); \
                 settings will not persist (in-memory only)"
            );
            // No persistent data dir — still capture panics under the OS temp dir so a
            // crash on an unconfigured box is not lost entirely (t26, best-effort).
            install_panic_hook(std::env::temp_dir().join("chancela-data"));
            // Still start the refresh (cacheless): it can supersede the in-memory
            // catalog for this run if a source URL is configured.
            chancela_cae::spawn_background_refresh(None);
            chancela_api::AppState::default()
        }
    }
}

/// Log the durable-store status the same way `chancela-server`'s startup banner does (t30 §3.4):
/// whether the SQLite store opened, how many events the durable ledger holds, the boot-time
/// chain-verification outcome (§D-boot), and the store path + schema version. The desktop shell
/// has no stdout banner, so these lines go to stderr alongside the other `chancela:` startup logs.
///
/// `AppState::with_data_dir` already emits its own loud warning if the store fails to open/load or
/// the chain is broken; this adds the positive confirmation and the on-disk details. The ledger
/// length is read with `try_read` (never blocking, never panicking regardless of async context) —
/// the state is freshly built and uncontended here, so it always succeeds.
#[cfg(feature = "embedded-server")]
fn report_durable_store(state: &chancela_api::AppState, dir: &std::path::Path) {
    if state.store.is_none() {
        eprintln!(
            "chancela: durable store unavailable — the domain runs in memory and will NOT \
             persist across restart (see the warning above)"
        );
        return;
    }

    let db = dir.join(chancela_store::DB_FILE);
    let schema = chancela_store::schema::SCHEMA_VERSION;
    let len = state.ledger.try_read().map(|l| l.len()).unwrap_or(0);
    match state.chain_status.as_deref() {
        Some(Err(e)) => eprintln!(
            "chancela: durable store {} (schema v{schema}) — {len} events on disk, \
             CHAIN BROKEN — {e}; restore from backup",
            db.display()
        ),
        _ => eprintln!(
            "chancela: durable store {} (schema v{schema}) — {len} events on disk, chain verified",
            db.display()
        ),
    }
}

/// Start `chancela_api::app` on its own multi-thread Tokio runtime bound to an
/// ephemeral loopback port, and return that port.
///
/// The runtime lives on a dedicated background thread that owns it for the life
/// of the process; it binds the listener, reports the chosen port back over a
/// channel, then serves forever. Binding a loopback socket is near-instant, so
/// the caller blocks only momentarily before it can navigate the WebView.
///
/// `state` carries the persistence choice made by [`build_app_state`].
#[cfg(feature = "embedded-server")]
fn spawn_server(state: chancela_api::AppState) -> Result<u16, Box<dyn std::error::Error>> {
    use std::net::Ipv4Addr;
    use std::sync::mpsc;

    let web_dist = resolve_web_dist();
    if let Some(dir) = &web_dist {
        eprintln!("chancela: serving embedded web UI from {}", dir.display());
    } else {
        eprintln!(
            "chancela: no apps/web/dist found near the executable; \
             embedded server runs API-only (build the web UI to get the interface)"
        );
    }

    let (tx, rx) = mpsc::channel::<std::io::Result<u16>>();

    std::thread::Builder::new()
        .name("chancela-embedded-server".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_io()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(Err(e));
                    return;
                }
            };

            runtime.block_on(async move {
                let app = chancela_api::app(state, web_dist);

                let listener = match tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        return;
                    }
                };
                let port = match listener.local_addr() {
                    Ok(addr) => addr.port(),
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        return;
                    }
                };

                // Hand the port back so the UI thread can navigate; if the caller
                // has gone away there is nothing to serve.
                if tx.send(Ok(port)).is_err() {
                    return;
                }

                if let Err(e) = axum::serve(listener, app).await {
                    eprintln!("chancela embedded server stopped: {e}");
                }
            });
        })?;

    // Wait for the bind result (fast). A disconnect here means the server thread
    // died before binding.
    let port = rx
        .recv()
        .map_err(|_| "embedded server thread exited before it could bind")??;
    Ok(port)
}

/// Dev-mode counterpart of [`spawn_server`]: start the same `chancela_api::app`
/// bound to the FIXED address the Vite dev proxy targets (`CHANCELA_ADDR`, else
/// `127.0.0.1:8080`), so `npm run dev` is self-contained and needs no separate
/// `chancela-server`.
///
/// Differences from the release path (which must stay exactly as-is):
///   - **No navigation.** The WebView stays on Vite's `devUrl` for hot-reload; the
///     UI is Vite's and its `/v1`/`/health` calls reach us through the proxy.
///   - **API-only.** We serve `chancela_api::app(state, None)` — Vite serves the
///     UI, so the on-disk `dist` is irrelevant and could be stale; `None` gives the
///     API plus a helpful landing page at `/`.
///   - **Graceful bind.** A fixed port can already be in use (the developer is also
///     running `chancela-server`, or a stale instance lingers). That must never
///     crash `tauri dev`: we log a friendly line and return, letting the Vite proxy
///     reach whatever is already listening there.
#[cfg(feature = "embedded-server")]
fn spawn_dev_server(state: chancela_api::AppState) {
    use std::net::SocketAddr;
    use std::sync::mpsc;

    let raw_addr = std::env::var(DEV_ADDR_ENV).unwrap_or_else(|_| DEV_DEFAULT_ADDR.to_owned());
    let addr: SocketAddr = match raw_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "chancela (dev): {DEV_ADDR_ENV}={raw_addr:?} não é um host:port válido ({e}); \
                 a saltar o servidor embutido — inicie o chancela-server manualmente"
            );
            return;
        }
    };

    let (tx, rx) = mpsc::channel::<std::io::Result<()>>();

    let spawned = std::thread::Builder::new()
        .name("chancela-embedded-server-dev".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_io()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(Err(e));
                    return;
                }
            };

            runtime.block_on(async move {
                // API-only: Vite serves the UI in dev, so no web dist here (a stale
                // on-disk dist would only mislead).
                let app = chancela_api::app(state, None);

                let listener = match tokio::net::TcpListener::bind(addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        return;
                    }
                };

                // Report a successful bind, then serve forever.
                if tx.send(Ok(())).is_err() {
                    return;
                }

                if let Err(e) = axum::serve(listener, app).await {
                    eprintln!("chancela (dev) embedded server stopped: {e}");
                }
            });
        });

    if let Err(e) = spawned {
        eprintln!(
            "chancela (dev): não foi possível criar a thread do servidor embutido ({e}); \
             inicie o chancela-server manualmente"
        );
        return;
    }

    // Wait briefly for the bind outcome so the startup logs are deterministic and we
    // can tell a busy port from a real failure. The thread keeps serving after this.
    match rx.recv() {
        Ok(Ok(())) => {
            eprintln!("chancela (dev): API embutida a servir em http://{addr} (proxy do Vite)");
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::AddrInUse => {
            eprintln!(
                "chancela (dev): porta {} ocupada — a usar o servidor existente",
                addr.port()
            );
        }
        Ok(Err(e)) => {
            eprintln!(
                "chancela (dev): não foi possível ligar a {addr} ({e}); \
                 a usar o servidor existente, se houver"
            );
        }
        Err(_) => {
            eprintln!("chancela (dev): a thread do servidor embutido terminou antes de ligar");
        }
    }
}

/// Locate the built web shell directory (`apps/web/dist`) for a run from the
/// repo (e.g. `tauri build --no-bundle`, where the binary sits under
/// `src-tauri/target/<profile>/`). Mirrors `chancela-server`'s resolver:
///   1. `CHANCELA_WEB_DIST` override, if it points at a dir with an `index.html`.
///   2. Walk up from the executable's directory, then the cwd, for
///      `apps/web/dist/index.html`.
///
/// Returns `None` (API-only) when nothing is found — the API still serves a
/// helpful landing page. Embedding the assets into the binary for a full
/// installer is future work; a `--no-bundle` run finds the on-disk build.
#[cfg(feature = "embedded-server")]
fn resolve_web_dist() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;

    if let Ok(raw) = std::env::var("CHANCELA_WEB_DIST") {
        let dir = PathBuf::from(raw);
        if dir.join("index.html").is_file() {
            return Some(dir);
        }
    }

    let mut starts: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            starts.push(dir.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        starts.push(cwd);
    }

    for start in starts {
        for base in start.ancestors() {
            let candidate = base.join("apps").join("web").join("dist");
            if candidate.join("index.html").is_file() {
                return Some(candidate);
            }
        }
    }

    None
}
