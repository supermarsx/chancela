<h1 align="center">Chancela</h1>

<p align="center">
  <strong>Self-hostable, ledger-backed <em>livro de atas</em> for Portuguese collective entities.</strong><br>
  A records, signing and archive tool — not a guarantee of legal validity.
</p>

<p align="center">
  <a href="https://github.com/supermarsx/chancela/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/supermarsx/chancela/ci.yml?branch=main&style=flat-square&label=CI"></a>
  <a href="license.md"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"></a>
  <img alt="Version" src="https://img.shields.io/badge/version-0.1.0-informational?style=flat-square">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-edition%202024-000000?logo=rust&logoColor=white&style=flat-square">
  <img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white&style=flat-square">
  <img alt="Docker" src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white&style=flat-square">
  <img alt="Desktop platforms" src="https://img.shields.io/badge/desktop-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square">
  <a href="https://supermarsx.github.io/chancela/"><img alt="Docs" src="https://img.shields.io/badge/docs-online-1f6feb?style=flat-square"></a>
</p>

<p align="center">
  <img src="docs/assets/hero.png" alt="Chancela dashboard showing a book of minutes with a hash-chained ledger" width="880">
</p>

## What is Chancela

Chancela is a self-hosted platform for keeping the **livro de atas** (book of minutes) and
related **atos societários** of Portuguese collective entities — commercial companies,
condominiums, associations, foundations and cooperatives. Acts are drafted, deliberated,
sealed into an **append-only, hash-chained ledger**, and preserved as fixity-checked
archives, all from a single Rust domain core that runs offline on the desktop, as a
self-hosted server, or in the browser.

## Key capabilities

- **Livro de atas & corporate acts** — draft, deliberate, and seal acts for multiple entity types.
- **Append-only hash-chained ledger** — every act is chained; the chain is re-verified on boot and surfaced via `/health`.
- **Portuguese qualified e-signature seams** — CMD (Chave Móvel Digital) and Cartão de Cidadão via external qualified providers.
- **Fixity export / import** — deterministic preservation packages with per-file SHA-256 digests for backup and interchange.
- **Durable, encryptable storage** — SQLite/SQLCipher (single-node) or a PostgreSQL durability profile.
- **Three editions, one core** — offline Tauri desktop, self-hosted Docker server, and browser.

See the [documentation site](https://supermarsx.github.io/chancela/) for the full capability and configuration reference.

## Quick start (Docker, single node)

The simplest way to run Chancela is the self-hosted single-node image:

```sh
docker compose -f docker/docker-compose.yml --profile single-node up --build
```

Then open <http://127.0.0.1:8080>. The container binds `0.0.0.0:8080` and stores durable
state on the `chancela-data` volume; `GET /health` should report `persistent: true` and
`ledger_verified: true`. The image is SQLCipher-capable — set `CHANCELA_DB_KEY_FILE` (or
`CHANCELA_DB_KEY`) at runtime to encrypt the store at rest.

For a production deployment, follow the **[hardened Docker guide](docs/security/hardened-docker.md)**
(read-only rootfs, dropped capabilities, non-root user, encrypted store). For local
development from source and the desktop build, see the
[documentation site](https://supermarsx.github.io/chancela/).

## How Chancela compares

Chancela is a self-hostable, ledger-backed livro-de-atas platform — a niche the alternatives
only partially cover: PT atas SaaS (Arkeyvata, atas.pt) is cloud-only; JUFIL is a book plus a
local app; Diligent is an enterprise board portal; DocuSign / Signaturit are e-signature rails;
OpenTimestamps is a timestamping primitive. Only Chancela combines **self-host + append-only
hash-chained ledger + PT qualified e-signature (CMD / Cartão de Cidadão) + fixity export/import**.

Verify the cells against your own requirements before deciding — this is a feature comparison,
not a legal-validity guarantee. Full table: **[docs/comparison.md](docs/comparison.md)**.

## Documentation

| Topic | Where |
| --- | --- |
| Full documentation site | <https://supermarsx.github.io/chancela/> |
| Configuration & deployment profiles | [`docker/DEPLOYMENT-PROFILES.md`](docker/DEPLOYMENT-PROFILES.md) |
| Security & hardening | [`docs/security/hardened-docker.md`](docs/security/hardened-docker.md) |
| Feature comparison | [`docs/comparison.md`](docs/comparison.md) |
| Product & legal specification | [`spec.md`](spec.md) |
| Contributing | Issues and pull requests are welcome on [GitHub](https://github.com/supermarsx/chancela) |
| License | [MIT](license.md) |

## Honest caveats

- **It is a records tool, not a legal shortcut.** Chancela helps produce compliant records; it
  does not create legal validity out of an invalid meeting, missing powers, or a defective
  corporate process.
- **Qualified signing needs external providers.** Qualified-signature features still require the
  appropriate qualified provider, certificate, hardware, and onboarding path — Chancela wires the
  seams but does not replace them.
- **The law corpus is tiered.** Cited diplomas carry a status tier — *Verified*, *automated-review*,
  or *pending* — so you can tell reviewed provenance from work in progress.
- **Single-node by design.** Authoritative domain state and ledger sequencing live in one process;
  exactly one instance may write. The PostgreSQL profile is a durability upgrade, not scale-out or HA.

## License

MIT — see [`license.md`](license.md).
