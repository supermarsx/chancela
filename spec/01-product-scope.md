# 01 — Product Scope and Editions

Requirement prefix: `SCP`

## 1. Vision

Chancela is a **Portugal-first corporate records and signing platform** for managing the
lifecycle of companies and other collective entities. Its category is a **Corporate Acts
Ledger and Archive**, not "minutes software": Portuguese law treats the ata as formal
evidence of deliberations, but real-world workflows also require convocatórias, attendance,
powers of representation, supporting documents, signature validation, registry extracts,
chronology, and long-term preservation.

- **SCP-01** The product MUST manage the full lifecycle of corporate acts: notice,
  deliberation, drafting, approval, signing, sealing, archiving, and export — not only
  document storage.
- **SCP-02** The product MUST support Portuguese commercial companies (CSC) as the primary
  target, and MUST also support associations, foundations, cooperatives, and condominiums
  as first-class entity families (see [03 — Entity type profiles](03-entity-profiles.md)).
- **SCP-03** All deployment modes MUST run the same Rust domain core and the same legal
  rule packs, so that legal behavior never depends on packaging.

## 2. Deployment modes

- **SCP-10** The product MUST run in three equivalent modes:
  1. a fully local **offline monolith** (desktop, air-gapped capable);
  2. a **client-server deployment** for organizations (self-hosted);
  3. a **browser-access deployment** backed by the same core and rules.
- **SCP-11** Online mode MUST be a packaging change, not a product fork: the offline Tauri
  app embeds the same Axum API surface the browser client consumes in server mode.

## 3. Editions

| Edition | Packaging | Intended use |
|---|---|---|
| Personal / Offline | Tauri desktop app, embedded local server + local database | Single professional; air-gapped or low-connectivity use |
| Team / Self-hosted | Dockerized server, browser UI, optional Tauri desktop clients | SMEs, law firms, accounting offices, property managers |
| Mobile Companion | Tauri mobile app with secure local cache | Approval, signing, alerts, quick lookup, disaster continuity |
| Enterprise | HA deployment, SSO, admin panel, policy engine, HSM/KMS options, validation sidecars | Medium and large organizations |

- **SCP-20** The codebase MUST be a **single codebase under one licence** — the
  Chancela Source License (MIT-derived, non-commercial use only; see `license.md`) —
  with edition flags, not separate products per edition.
- **SCP-21** The Mobile Companion MUST be a task-focused subset (review, approve, sign,
  alert triage, quick entity lookup) rather than a pixel-for-pixel desktop copy. Heavy
  drafting and archive administration are out of scope for mobile v1.

## 4. Roadmap and prioritization

The first implementation targets the legally hardest path, because it also solves most of
the other entity families' needs.

- **SCP-30** Phase order MUST be:
  1. **Portuguese commercial-company minutes** with qualified electronic signatures,
     validation, archive, and chronology;
  2. condominium and association rule packs;
  3. foundation and cooperative refinements;
  4. groups of companies, cross-entity transfers, continuity plans;
  5. broader AI/MCP features and external integrations.

## 5. Open decisions (confirm before build-out)

These are the only decisions that materially change effort. Defaults below are the
recommendation; each is tracked until explicitly confirmed.

| ID | Decision area | Default recommendation | Status |
|---|---|---|---|
| SCP-D1 | Local database | Embedded relational store with encrypted pages and append-only event tables offline; server mode compatible with a central RDBMS | Open |
| SCP-D2 | Signature validation | Native Rust validation for the common path; optional EU DSS-compatible sidecar for long-term/edge cases | Open |
| SCP-D3 | Zero-knowledge scope | Repository-level and opt-in (universal ZK complicates search, previews, automation) | Open |
| SCP-D4 | OCR / content extraction | Modular, off by default for sensitive tenants; prefer native text extraction | Open |
| SCP-D5 | Mobile scope | Review/sign/alert/lookup client first; limited drafting, no archive admin in v1 | Open |
| SCP-D6 | Provider purchase links | Trust status from the Portuguese TSL only; purchase URLs from an admin-curated catalog updatable without code releases | Open |

## 6. Out of scope

- **SCP-40** The product MUST NOT claim to confer legal validity on acts; it produces and
  preserves evidence (see the core principle in [spec.md](../spec.md)).
- **SCP-41** The product does not perform registrations at the commercial registry on the
  user's behalf in v1; it prepares and packages the acts and evidence for such filings.
