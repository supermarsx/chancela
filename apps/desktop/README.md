# @chancela/desktop — Tauri v2 desktop shell

The native shell for Chancela's **Personal / Offline edition** (spec `SCP-10`
mode 1): a [Tauri v2](https://v2.tauri.app/) WebView that hosts the same web UI
the browser client uses (`apps/web`) and runs the same Axum API locally,
in-process on loopback (`ARC-03`, `ARC-04`, `SCP-11`). Legal behavior never
depends on packaging (`SCP-03`) — the desktop app serves the exact
`chancela_api::app` the browser client and `chancela-server` serve.

By default (the `embedded-server` feature) the app boots that server on a random
loopback port and navigates its window to it, so the whole application — web UI
**and** `/v1` API — runs from one process with no external dependencies. See
[Embedded server](#embedded-server-arc-03).

## Why this is excluded from the root builds

`apps/desktop/src-tauri` is deliberately kept out of the repo-root builds, with
**double defense**:

1. The root `Cargo.toml` lists it under `exclude = ["apps/desktop/src-tauri"]`.
2. `src-tauri/Cargo.toml` declares its own empty `[workspace]` table, making it a
   self-contained Cargo workspace.

It is also **not** a member of the root `npm` workspaces (root `package.json`
only lists `apps/web`).

The reason: Tauri pulls in a large native dependency tree (WebView bindings,
bundler, platform SDKs). Keeping it separate means `cargo build`, `cargo test`,
`npm ci`, and CI at the repo root stay fast and don't need any desktop/GUI
system libraries. You build the desktop app explicitly, from this directory.

## Prerequisites

- **Rust** (stable) + Cargo — see the repo root `rust-toolchain.toml`.
- **Node.js ≥ 20** and npm (used by `@tauri-apps/cli` and to build the web UI).
- **Platform WebView / build dependencies:**
  - **Windows** — [WebView2 runtime](https://developer.microsoft.com/microsoft-edge/webview2/)
    (preinstalled on Windows 11; on older Windows install the Evergreen runtime)
    and the MSVC C++ build tools.
  - **macOS** — Xcode Command Line Tools (`xcode-select --install`).
  - **Linux** — WebKitGTK and friends, e.g. on Debian/Ubuntu:
    `libwebkit2gtk-4.1-dev`, `build-essential`, `curl`, `wget`, `file`,
    `libxdo-dev`, `libssl-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`.
    See the [Tauri v2 Linux prerequisites](https://v2.tauri.app/start/prerequisites/#linux).

## First-time setup: generate icons

A `tauri build` (and, on some platforms, `tauri dev`) needs the platform icon
set, which is generated from a source image rather than committed. Run once:

```bash
cd apps/desktop
npm install
npx tauri icon src-tauri/icons/icon-source.png
```

See [`src-tauri/icons/README.md`](src-tauri/icons/README.md) for details.

## Run it (development)

From **this directory** (`apps/desktop`):

```bash
npm install     # installs @tauri-apps/cli (first time only)
npm run dev     # = tauri dev
```

`tauri dev`'s `beforeDevCommand` starts the web dev server for you by running,
from the repo root, `npm run dev --workspace apps/web` (Vite on
<http://localhost:5173>, matched by `devUrl` in `tauri.conf.json`). It then opens
the native window against that URL with hot-reload.

**`npm run dev` is self-contained — no second terminal needed.** In dev the
WebView stays on Vite's `devUrl` (`:5173`) for hot-reload, and Vite's dev proxy
forwards `/v1` and `/health` to a *fixed* loopback address. The shell detects
`tauri dev` via `tauri::is_dev()` and — instead of navigating the window —
starts the **same** embedded `chancela_api` app bound to that fixed address, so
the UI's API calls just work. (It serves API-only in this mode; Vite serves the
UI. Settings/users persistence and the CAE catalog work exactly as in a normal
build.)

The bind address is `CHANCELA_ADDR` (default `127.0.0.1:8080`), which matches the
Vite proxy target in `apps/web/vite.config.ts`.

**Optional external-server override.** If you prefer to run the API yourself (for
example to watch its logs, or to point the proxy at a differently configured
server), just start one on the same address before/while `tauri dev` runs:

```bash
cargo run -p chancela-server   # from the repo root, in another terminal
```

The shell notices the port is already taken, logs
`porta 8080 ocupada — a usar o servidor existente`, and steps aside without
crashing — the Vite proxy then talks to your server instead.

## Build a runnable binary (v1)

The v1 acceptance is a **runnable binary**, not a platform installer:

```bash
cd apps/desktop
npm run tauri build -- --no-bundle
```

`--no-bundle` compiles the release binary and skips packaging. Its
`beforeBuildCommand` first builds the web UI (`npm run build --workspace
apps/web` → `apps/web/dist`, referenced by `frontendDist = ../../web/dist`,
which is also embedded into the binary by `generate_context!`). The resulting
executable is named after the crate (`chancela-desktop`), not the product name:

```
src-tauri/target/release/chancela-desktop.exe   # Windows (`chancela-desktop` on macOS/Linux)
```

Run it directly. With the default `embedded-server` feature it starts the API+UI
on a loopback port and opens the window against it — no server to start first.
It resolves the on-disk `apps/web/dist` by walking up from the executable (or set
`CHANCELA_WEB_DIST`); if none is found it serves API-only with a landing page.

### Full installers (MSI/NSIS/etc.)

```bash
npm run build   # = tauri build (bundles installers)
```

bundles native installers under `src-tauri/target/release/bundle/`. **On Windows
this needs [WiX Toolset v3](https://wixtoolset.org/) for the MSI** (and/or NSIS
for the `.exe` installer); the Tauri CLI downloads NSIS on first use but WiX must
be installed separately. Bundling is **not** required for v1 and is not covered
by this repo's build gate.

> Alternatively, if you have the Tauri CLI installed globally
> (`cargo install tauri-cli --version '^2'`), you can use `cargo tauri dev` /
> `cargo tauri build` instead of the npm scripts. A plain
> `cargo build --manifest-path src-tauri/Cargo.toml` also compiles the crate
> (icons and `apps/web/dist` must already exist — see above).

## Layout

```
apps/desktop/
├─ package.json              @chancela/desktop — @tauri-apps/cli + dev/build scripts
├─ README.md                 this file
└─ src-tauri/
   ├─ Cargo.toml             own workspace; tauri v2 deps; embedded-server feature (default; gates chancela-api/tokio/axum)
   ├─ build.rs               tauri_build::build()
   ├─ tauri.conf.json        productName, identifier, window, devUrl/frontendDist
   ├─ capabilities/
   │  └─ default.json        minimal core:default permissions for the main window
   ├─ icons/
   │  ├─ icon-source.png     1024×1024 placeholder source (committed)
   │  └─ README.md           how to generate the platform icon set
   └─ src/
      ├─ main.rs             thin launcher → chancela_desktop_lib::run()
      └─ lib.rs              Tauri builder; embedded-server (loopback API+UI, ARC-03)
```

## Embedded server (ARC-03)

Offline mode serves the same Axum API the browser client consumes, locally on
loopback. This is the **default** behaviour (the `embedded-server` feature).

What `src/lib.rs` does at startup (outside dev mode):

1. Resolve `apps/web/dist` — `CHANCELA_WEB_DIST`, else walk up from the
   executable's directory / cwd (mirrors `chancela-server`). `None` ⇒ API-only.
2. Build `chancela_api::app(AppState::default(), web_dist)` — the identical
   router the browser client and `chancela-server` use (web UI + `/v1` + ledger).
3. On a dedicated thread owning a multi-thread Tokio runtime, bind
   `127.0.0.1:0` (an OS-chosen free loopback port) and `axum::serve` it forever.
4. Navigate the `main` WebView window to `http://127.0.0.1:<port>/`.

Because the UI is then loaded from that origin, its relative `/v1/...` fetches
are **same-origin** — no CORS, and no changes to the web client.

The `embedded-server` feature gates the `chancela-api` / `tokio` / `axum` path
deps (all `optional`); building `--no-default-features` yields a bare WebView
shell with none of them, expecting an external API at the configured URL.
Rust-side `WebviewWindow::navigate` is not capability-gated, so
`capabilities/default.json` (`core:default`) is sufficient.

> State is in-memory and resets on exit (no persistence yet). Embedding
> `apps/web/dist` into the binary for a self-contained installer (so a bundled
> app needs no on-disk `dist`) is future work; a `--no-bundle` run from the repo
> finds the build on disk.

## Notes for later hardening

- `tauri.conf.json` sets `app.security.csp = null`. Define a restrictive
  Content-Security-Policy before shipping (must allow the loopback origin the
  embedded server navigates to).
- `identifier` is `pt.chancela.desktop`. Confirm the final bundle identifier
  (mobile targets, if added per `ARC-04`, need their own).
- Mobile (Android/iOS) is supported by the same crate via the `staticlib`/
  `cdylib` lib crate types and the `mobile_entry_point` in `lib.rs`, but is not
  set up (`tauri android/ios init`) in this scaffold.
