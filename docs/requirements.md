# Requirements

These are the requirements for running the self-hosted server editions and the
clients. The authoritative source for the container numbers is
[Security & Hardening → System requirements](security/hardened-docker.md#system-requirements).

## Host resources

| Profile | CPU (min) | CPU (rec.) | RAM (min) | RAM (rec.) | Free disk |
|---|---|---|---|---|---|
| `single-node` (SQLite) | 2 cores | 4 cores | 2 GB | 4 GB | 5 GB runtime |
| `worker` (SQLite + connector worker) | 2 cores | 4 cores | 3 GB | 5 GB | 5 GB plus queued/exported artifacts |
| `postgres` (app + Postgres + Redis) | 4 cores | 4+ cores | 4 GB | 8 GB | 10 GB+ runtime |

The per-service resource limits are ceilings, not the footprint: the app caps at
`2.0` CPU / `1 GB`, the connector worker at `1.0` CPU / `512 MB`, Postgres at
`2.0` CPU / `1 GB`, Redis at `1.0` CPU / `320 MB`.
Size the host above the sum of the ceilings for the profile you run.

!!! info "Build host"
    A first `--build` compiles the Rust workspace in release mode. Budget
    **8–12 GB free disk** for the BuildKit cargo/registry cache and image layers,
    and expect a multi-minute cold build. Subsequent builds reuse the cache
    mounts and are much faster.

The durable data volume (`/var/lib/chancela`, plus `chancela-pgdata` on the
Postgres profile) grows with usage — start with a few GB of headroom and monitor
it. Put the Postgres data volume on **encrypted storage** (see
[Deployment](deployment.md#postgres-durability-backend-redis-cache)).

## Software

| Component | Version | Notes |
|---|---|---|
| Linux kernel | 5.10+ | Modern seccomp/BPF filter and cgroup v2 accounting. |
| cgroups | v2 | Required for the memory / CPU / **pids** limits to be enforced. |
| Docker Engine | 24.0+ | BuildKit is the default builder; `docker compose up` honours `deploy.resources.limits`. |
| Docker Compose | v2.20+ | v2 syntax; `deploy.resources.limits.pids` support. |
| PostgreSQL | 18.4 (`postgres:18.4-alpine3.23`) | `postgres` profile only; pinned by the same digest in standard and hardened Compose. Major upgrades require dump/restore or `pg_upgrade`. |
| Redis | 8.8 (`redis:8.8.0-alpine3.23`) | `postgres` profile only, cache-aside; pinned by the same digest in standard and hardened Compose. Review the Redis 8 licence choice. |

Linux is the target runtime. Docker Desktop on macOS/Windows works for local
builds and smoke tests, but the read-only-rootfs, seccomp, and capability
semantics are Linux-native and only fully apply on a Linux host/VM.

## Client requirements

- **Web UI** — a current evergreen browser (Chromium, Firefox, or Safari) with
  JavaScript enabled. The UI is a single-page app served by the same server; it
  talks to the `/v1/*` API over the same origin.
- **Desktop** — the Tauri v2 desktop app runs on Windows, macOS, and Linux using
  the OS WebView (WebView2 on Windows, WKWebView on macOS, WebKitGTK on Linux).
  It bundles its own SQLite store for offline single-user use.
- **Cartão de Cidadão signing** — requires a PC/SC-capable smart-card reader and
  the Autenticação.gov middleware installed on the client machine (local PKCS#11
  path).
- **MCP** — an MCP-capable client that speaks JSON-RPC 2.0 over stdio; the bridge
  must be enabled with an API key and the tenant AI gate.

## Network

- The server publishes on `127.0.0.1` by default. For real ingress, front it with
  a TLS-terminating reverse proxy (see
  [Extras → Reverse proxy / TLS](extras.md#reverse-proxy-tls)).
- On the Postgres profile, Postgres (`5432`) and Redis (`6379`) are **not**
  published — they are reachable only on the internal compose network.
- Multi-node additionally **requires Redis** for cluster-wide sessions and
  rate-limits, and benefits from a leader-aware load balancer.
- Network connector targets require explicit outbound DNS/HTTPS (or their
  reviewed native protocol ports) and an exact
  `CHANCELA_CONNECTOR_ALLOWED_HOSTS` policy. Private, loopback, link-local, and
  metadata-service destinations fail closed unless both the hostname and
  resolved IP/CIDR are explicitly allowlisted. Pair this application control
  with host/container egress filtering in production.
