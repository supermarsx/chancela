# Chancela

**Portugal-compliant livro de atas and corporate-acts platform.**

Chancela is a records, signing, governance, archive, and compliance platform for
Portuguese collective entities (commercial companies, condominiums, associations,
foundations, cooperatives). The **livro de atas** (book of minutes) and the related
**atos societários** are the center of gravity: acts are drafted, deliberated, sealed
into an append-only hash-chained ledger, and preserved as evidentiary archives.

It is designed to run in three editions from a single Rust domain core:

- an **offline desktop monolith** (Tauri),
- a **self-hosted client–server** deployment (Docker),
- a **browser** deployment.

> Chancela **helps produce compliant records; it does not create legal validity** out of
> an invalid meeting, missing powers, or a defective corporate process. See the
> [specification index](spec.md) and its core-principle note.

The full product and legal specification lives in [`spec.md`](spec.md) and the
[`spec/`](spec/) directory (numbered documents 01–11, each grounded in Portuguese law and
using RFC 2119 requirement keywords).

## Repository map

| Path | What it is |
|---|---|
| `Cargo.toml` | Rust workspace manifest (members under `crates/`) |
| `crates/chancela-core` | Domain model: entities, books, acts, sealing, rule packs |
| `crates/chancela-ledger` | Append-only, hash-chained event ledger |
| `crates/chancela-signing` | Signature families / formats / trust (stubs per spec 04) |
| `crates/chancela-archive` | Preservation packages and exports (stubs per spec 08) |
| `crates/chancela-api` | Axum HTTP API layer over the domain core |
| `crates/chancela-server` | Server binary (`chancela-server`) |
| `apps/web` | Vite + React + TypeScript web shell (`@chancela/web`) |
| `apps/desktop` | Tauri v2 desktop shell (own cargo workspace — see below) |
| `docker/` | Dockerfile and Compose for the self-hosted edition |
| `scripts/` | Per-platform orchestration scripts (`*.ps1` on Windows, `*.sh` elsewhere) |
| `spec/`, `spec.md` | Product and legal specification |

## Prerequisites

| Tool | Version |
|---|---|
| Rust (`cargo` + `rustup`) | stable (edition 2024; `rust-version` 1.85) — https://rustup.rs |
| Node.js (`node` + `npm`) | Node **>= 20** — https://nodejs.org |
| `tar` | ships with Windows 10+, macOS, and Linux (used by `npm run package`) |

Docker is only needed for the container edition; it is not required for local development.

## Quickstart

```sh
npm run init     # verify the toolchain and install web dependencies
npm run dev      # run the API server and the web dev server together
```

`npm run init` checks that cargo/rustup/node/npm are present, reports their versions, and
runs `npm install`. `npm run dev` launches `cargo run -p chancela-server` (API on
`127.0.0.1:8080` by default, override with `CHANCELA_ADDR`) alongside the Vite dev server
(`http://localhost:5173`) with prefixed output; Ctrl+C stops both.

## Run everything

One command brings up the HTTP API, the event ledger, and the web UI on a single origin:

```sh
cargo run     # debug build, from the repo root
cargo app     # optimized release build (alias in .cargo/config.toml)
```

Then open http://127.0.0.1:8080. Set `CHANCELA_ADDR` to change the bind address.

The server serves the web UI from `apps/web/dist`; build it once with
`npm run build --workspace apps/web`. Without a build it starts API-only and says so at
startup and on `/`.

## Data, backup and restore

Set **`CHANCELA_DATA_DIR`** to make the app durable: entities, books, acts, registry
extracts and the hash-chained ledger are written to a SQLite store (`chancela.db`) in that
directory, alongside the JSON sidecars (`settings.json`, `users.json`, `cae-catalog.json`,
and the `laws/` archive). The desktop app defaults this to its per-app data directory and
logs the path at startup. **Without** a data dir the server runs entirely in memory and
everything except those sidecars is lost on restart — the startup banner and `GET /health`
(`persistent`, `ledger_length`, `ledger_verified`) say which mode is active. On boot the
durable chain is re-verified; a tampered or truncated store still starts, but the banner and
`/health` report `ledger_verified: false` so you can restore before trusting it.

**Online backup (server running).** `POST /v1/backup` snapshots the store with SQLite
`VACUUM INTO` (transactionally consistent, no downtime), bundles it with the sidecars and a
`manifest.json` into `<data_dir>/backups/chancela-backup-<utc>.zip`, and returns the
manifest (path, size, ledger length, per-file SHA-256 digests). The helper scripts call it
and print that manifest:

```sh
scripts\backup.ps1                       # Windows; default http://127.0.0.1:8080
bash scripts/backup.sh 127.0.0.1:8080    # macOS/Linux; base URL optional
```

An in-memory server has nothing to snapshot and answers `422`; the scripts then point you
at the cold-copy path below.

**Cold copy (app stopped).** Stop the server / close the desktop app and copy the whole
data directory somewhere safe. This is the always-available fallback and needs no running
server.

**Restore.** Use the restore script — it refuses to run while a server is alive at the probe
URL, moves any existing target data dir aside to `<dir>.pre-restore-<stamp>` (never
destroying it), then unpacks the backup zip into a fresh data dir:

```sh
scripts\restore.ps1 -BackupZip <archive.zip> -DataDir <data-dir>
bash scripts/restore.sh <archive.zip> <data-dir> [base-url]
```

Then start the server with `CHANCELA_DATA_DIR` pointing at the restored directory and
confirm the banner shows `chain verified` and `GET /health` reports `ledger_verified: true`.
A cold copy restores the same way (zip the copied directory, or point `CHANCELA_DATA_DIR`
straight at it).

## Scripts

The `init`, `dev` and `package` tasks are native per-platform scripts under `scripts/`:
a PowerShell version (`*.ps1`, used on Windows) and a bash version (`*.sh`, used on
macOS/Linux, run as `bash scripts/<name>.sh` — no execute bit needed). `npm run <task>`
picks the right one automatically: a tiny inline `node` line in `package.json` selects
`.ps1` on Windows and `.sh` otherwise. Node is always available (npm requires it), so this
needs **no extra dependency** and `npm run init` works on a fresh clone before anything is
installed. The remaining tasks (`lint`, `format`, `test`, `build`) are direct `cargo` / npm
chains that compose with `&&` in both `cmd` and POSIX shells. The `backup`/`restore` scripts
are standalone operator tools run directly (not via npm) — see
[Data, backup and restore](#data-backup-and-restore).

| Script | Does |
|---|---|
| `npm run init` | Check toolchain + versions, then `npm install` |
| `npm run dev` | Run server + web dev server concurrently (Ctrl+C stops both) |
| `npm run lint` | `lint:rust` then `lint:web` |
| `npm run lint:rust` | `cargo clippy --workspace --all-targets -- -D warnings` |
| `npm run lint:web` | ESLint over `apps/web` |
| `npm run format` | `cargo fmt --all` then Prettier over `apps/web` |
| `npm run format:check` | `cargo fmt --all --check` then Prettier check |
| `npm run test` | `test:rust` then `test:web` |
| `npm run test:rust` | `cargo test --workspace` |
| `npm run test:web` | Vitest over `apps/web` |
| `npm run build` | `build:rust` then `build:web` |
| `npm run build:rust` | `cargo build --workspace --release` |
| `npm run build:web` | Production web bundle to `apps/web/dist` |
| `npm run package` | Build, then assemble `dist/chancela-<version>-<platform>-<arch>.tar.gz` |

`npm run package` stages the release server binary, the web bundle, the README, and the
license into `dist/chancela-<version>-<platform>-<arch>/` and compresses it with the
system `tar`. Inspect the result with `tar -tzf dist/chancela-*.tar.gz`.

## Docker (self-hosted edition)

Build the container image from the repository root (the build context must be the repo
root so the Dockerfile can reach every crate and the web app):

```sh
docker build -f docker/Dockerfile -t chancela .
docker compose -f docker/docker-compose.yml up
```

Inside the container the server binds `0.0.0.0:8080` (`CHANCELA_ADDR`) and exposes a
`/health` endpoint. See [`docker/`](docker/) for the hardening details (read-only rootfs,
dropped capabilities, non-root user).

## Desktop edition

`apps/desktop` is a **Tauri v2** shell. It is intentionally **excluded from the root cargo
workspace** (the root `Cargo.toml` lists it under `exclude`, and `apps/desktop/src-tauri`
declares its own empty `[workspace]` table) so that `cargo build`/`cargo test` at the repo
root never pull in the heavy Tauri/WebView system dependencies. Building the desktop app is
an explicit, separate step:

```sh
cd apps/desktop
npm install -D @tauri-apps/cli   # or install the Tauri CLI globally
npx tauri dev                    # develop against the web dev server
npx tauri build                  # produce a desktop installer
```

The desktop shell loads the same web frontend (`devUrl` → the Vite dev server;
`frontendDist` → `apps/web/dist`). See [`apps/desktop/README.md`](apps/desktop/README.md)
for platform-specific WebView prerequisites.

## License

MIT — see [`license.md`](license.md).
