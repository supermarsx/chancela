# Chancela

![Chancela dashboard](assets/hero.png)

**Chancela** is a self-hostable *livro de atas* (minute book) and corporate-acts
platform. It keeps meeting minutes and related corporate records in an
**append-only, hash-chained ledger**, integrates **Portuguese qualified
e-signature** rails, and produces **verifiable export/import bundles** with
per-file fixity — so a record's integrity can be checked independently of the
running system.

It runs as three editions from one codebase: a **desktop** app (Tauri, offline
single-user), a **self-hosted web/API server** (single-node SQLite or a Postgres
durability backend), and an optional **MCP server** for AI-assisted drafting
under the same permissions and audit trail.

!!! warning "What Chancela is — and is not"
    Chancela records, seals, and helps you verify documents. It does **not**, on
    its own, confer legal validity on any document. Legal effect depends on
    Portuguese and EU law and on how you operate the tool — not on the software
    alone. Nothing here is legal advice.

## Start here

<div class="grid cards" markdown>

- :material-rocket-launch: **[Deployment](deployment.md)**
  Run it: single-node SQLite, the Postgres + Redis profile, the hardened
  variant, and multi-node.

- :material-cog: **[Configuration](configuration.md)**
  Environment variables, docker secrets, and the in-app Settings sections.

- :material-shape-outline: **[Capabilities](capabilities.md)**
  Minute-book lifecycle, the ledger, e-signatures, RBAC, templates, exports,
  and clients.

- :material-server: **[Requirements](requirements.md)**
  Host resources, software versions, and client/browser requirements.

- :material-scale-balance: **[Comparison](comparison.md)**
  How Chancela compares with adjacent tools (sourced, with an honesty caveat).

- :material-shield-lock: **[Security & Hardening](security/hardened-docker.md)**
  The hardened, distroless, non-root container images and operations security.

- :material-toolbox: **[Extras](extras.md)**
  Backups, timestamping, reverse proxy/TLS, monitoring, SBOM/scanning, and the
  law-corpus review workflow.

</div>

## Honest positioning

- **Self-host first.** You run it on your own host; your records stay on
  infrastructure you control.
- **Tamper-evident, not tamper-proof.** The ledger is a global spine plus
  per-application/company/book chains. Any break is detected on boot and the
  server drops to a read-only degraded mode until it is repaired or restored.
- **Portuguese qualified e-signature integration.** Chave Móvel Digital (CMD),
  Cartão de Cidadão (CC), CSC/QTSP cloud signing, and local PKCS#12 — behind a
  fail-closed trust gate. Chancela integrates these rails; it is not itself a
  qualified trust service provider.
- **Verifiable fixity.** Book export/import and preservation packages carry
  per-file SHA-256 and a bundle digest; imports are verified before trust and
  quarantined on any mismatch.
- **Honest about limits.** Single-writer by design; the law corpus separates
  human-**Verified** text from **automated-review** and **pending** entries; the
  docs flag where a guarantee is weaker than it looks.
