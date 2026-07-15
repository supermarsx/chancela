# Capabilities

Chancela covers the lifecycle of a *livro de atas* (minute book) and related
corporate acts: drafting, sealing, signing, verifying, exporting, and archiving —
all recorded in a tamper-evident ledger and controlled by role-based access.

!!! warning "No legal-validity guarantee"
    The features below describe what the software does. None of them, alone,
    make a document legally valid. Legal effect depends on Portuguese/EU law and
    how you operate the tool.

## Minute-book (livro de atas) lifecycle

Acts move through an explicit state machine:

`Draft → Review → Convened → Deliberated → TextApproved → Signing → Sealed → Archived`

- **Draft → … → Signing** are ordinary linear transitions.
- **Sealing** (`Signing → Sealed`) assigns the sequential *ata* number, freezes
  the payload, and appends an append-only ledger event. Sealing always produces
  the document (PDF/A); it does not itself require a qualified signature.
- **Archiving** (`Sealed → Archived`) closes the act.

Books themselves have states `Created → Open → Closed`: opening a book seals a
*termo de abertura* (genesis event); closing it records a *termo de encerramento*.

## Append-only hash-chained ledger

Every event carries an intrinsic **Global** chain (`seq` / `prev_hash` / `hash`),
and rides additional **Application**, **Company**, and **Book** chains derived
from its scope.

- **Verification** does a full pass over the global spine (dense sequence run,
  zero-prev genesis, backward links, hash recompute) plus every per-chain link.
  Helpers locate the first break and produce an integrity report.
- **Append is guarded**: a would-be event is validated against each chain head
  before anything is written (genesis-kind and broken-tail guards).
- **Degraded mode**: if any chain fails to verify at boot, the server enters a
  read-only degraded mode — mutations return `503` ("modo só-leitura"), while
  reads and the recovery plane stay available — until the chain is repaired or
  restored.
- **Reanchor** is a last-resort, tamper-evident repair: it rebuilds derivable
  linkage from untouched content and appends a permanent `ledger.reanchored`
  disclosure event. It refuses to run if the ledger already verifies.

HTTP surface: `GET /v1/ledger/verify`, `GET /v1/ledger/integrity`,
`GET /v1/ledger/events`, `POST /v1/ledger/recovery/reanchor|restore`.

## E-signatures

Chancela integrates Portuguese qualified e-signature rails behind a **fail-closed
trust gate** — a non-`Granted` issuer is rejected before any signature or PIN
prompt. It is an integrator of these rails, not itself a qualified trust service
provider.

### Signature formats

| Format | Status |
|---|---|
| **CAdES** | CAdES-B foundation (RSA-PKCS#1-SHA256 and ECDSA-P256-SHA256). |
| **PAdES** | Sign existing PDFs by incremental update; **B-B and B-T** implemented, with local `/DSS`+`/VRI` evidence append (a local `B-LT-local` evidence label). No production B-LT/B-LTA claim. |
| **XAdES** | XMLDSig + XAdES B/T/LT/LTA over the same signature seam, with in-crate exclusive XML canonicalization. Newer; confirm build status before relying on it. |
| ASiC | Not built. |

### Portuguese signing methods

| Method | How it works |
|---|---|
| **CMD — Chave Móvel Digital** | Two-phase remote signing against AMA's SCMD SOAP service (get certificate → dispatch OTP → validate OTP). |
| **CC — Cartão de Cidadão** | Local PC/SC + PKCS#11 via the Autenticação.gov middleware; the PIN stays at the reader. |
| **CSC / QTSP** | Generic Cloud Signature Consortium v2 REST adapter (two-phase remote). |
| **PKCS#12 (local)** | Local soft-certificate signing from a stored PKCS#12. |
| **SCAP** | AMA SCAP professional-attribute-qualified signing (e.g. lawyer/notary capacity); mock-default with honest evidence markers. |
| **Manual (handwritten scan)** | No provider; marked as handwritten/scanned, never qualified, surfaces a manual warning. |

Signature status runs `unsigned → pending → signed`. Whether a qualified
signature is *required* before sealing is a configurable status gate
(`signing.require_qualified_for_seal`, default **off**) — sealing itself never
depends on it.

## RBAC and delegation

- **Permissions** are a compile-time catalog of dotted verbs (e.g.
  `settings.manage`, `role.manage`, `template.manage`). Four meta-permissions
  (role manage/assign, delegation grant/revoke) are non-delegable and never
  attach to an API key.
- **Scopes** narrow only: `Global` → `Entity(id)` → `Book(id)`.
- **Roles as data**: a set of seeded default roles (Owner/Proprietário is
  protected and undeletable, plus Gestor, Signatário, Leitor, Corporate
  Secretary, Auditor, API Client, and more) editable in Settings.
- **Delegation**: grant one permission at a scope, with a start time, optional
  expiry, and optional legal basis — revocable. A permission can only be
  delegated if held **via a role** (no re-delegation, no meta delegation). A
  last-owner guard keeps at least one Owner.
- **Step-up re-auth** protects the most destructive routes: RBAC verb@scope plus
  a type-to-confirm phrase plus an argon2id password / recovery-phrase re-proof.

## Documents and user-authored templates

Chancela ships a built-in templates-as-data catalog and, as of the template
authoring feature, lets operators **create, edit, delete, export, and import**
their own document templates (permission `template.manage`).

- User template ids live in a reserved `user-…/vN` namespace so they can never
  shadow a built-in.
- Templates are validated on save: size limits, strict JSON schema, every
  MiniJinja string must compile, every threshold reference must resolve, and the
  locale is allow-listed (`pt-PT`). Law references are **server-derived**, never
  author-supplied.
- Endpoints: `GET/POST /v1/templates`, `PUT/DELETE /v1/templates/{id}`,
  `GET /v1/templates/{id}/export`, `POST /v1/templates/import`. Template mutations
  append ledger events.

## Book export / import with fixity

- **Export** produces a `chancela-book-bundle` ZIP (book + entity + acts + latest
  document per act + full Book-chain events) with a manifest carrying per-file
  SHA-256 and a bundle digest. No secrets. `POST /v1/books/{id}/export`.
- **Import** is verify-before-trust: manifest digest → per-member SHA-256 →
  standalone chain verify. A clean bundle imports as **Verified**; any break or
  tamper is **Quarantined** (kept isolated and read-only, never merged onto the
  live spine). `POST /v1/books/import`.
- **Restore** verifies every member and that the snapshot ledger verifies in a
  temp dir before an atomic database swap.
- **Preservation package**: a deterministic `chancela-internal-preservation-package`
  ZIP (manifest, PDF/A members, signer/timestamp evidence, validation reports)
  that honestly records `official_dglab_interchange: false` and
  `dglab_certification_claimed: false`. Legal-hold endpoints gate export/mutation.

## Privacy / GDPR tooling

A first privacy slice (not a complete GDPR/DSR implementation):

- **Data-subject requests**: per-user JSON export (excluding secrets) plus a DSR
  request lifecycle (export/rectification/erasure/restriction) with status,
  actors, and execution evidence, recorded as chained audit events.
- **Processor and DPIA registers**: CRUD with strict risk/status enums and audit
  trails.
- **Guest/read-minimal redaction** for minimal-read principals.

## Law corpus (honesty tiers)

The bundled law corpus separates three verification tiers so no fabricated or
paraphrased statute text is ever presented:

| Tier | Meaning |
|---|---|
| **Verified** | Human-approved authentic text: complete verbatim body + full source (diploma, article, DR reference, URL) **and** the human legal-approval marker. |
| **automated_review** | Automatically-vendored authentic text held to the same structural authenticity gate as Verified, but making the weaker, honest claim that it is **not** human-approved. Renders its real body. |
| **Pending** | Placeholder only. Never renders a body — shows the loud `[NÃO VERIFICADO / fonte pendente]` marker. |

The authenticity gate refuses at build time to mark an article Verified or
automated_review without a complete source and a real, non-empty body. See the
[law-corpus review workflow](extras.md#law-corpus-human-legal-review) in Extras.

## Clients: desktop, web, API, MCP

- **Desktop** — a Tauri v2 shell loading the same web frontend; an offline,
  single-user SQLite monolith.
- **Web** — a Vite + React SPA (multiple i18n locales, hand-authored theme),
  the single frontend for all editions.
- **API** — the Axum server on `127.0.0.1:8080`, `/v1/*` (also aliased under
  `/api/v1/*`), Bearer API-key auth (`chk_…`).
- **MCP server** — an **off-by-default** JSON-RPC 2.0 stdio bridge that is itself
  an HTTP client of the API. Enabling it requires an API key
  (`CHANCELA_MCP_API_KEY`) and the tenant AI gate (`settings.ai.enabled` /
  `CHANCELA_AI_ENABLED`). It exposes read-only and write-controlled tools —
  entities, books, drafting/advancing/sealing acts, generating and previewing
  documents, ledger verify/export, trust-catalog and law search, and template
  listing — each tagged with the permission it needs, plus a human-review
  checklist prompt.

## Multi-node HA

Single-writer high availability for the self-hosted Postgres backend: a leader
plus read-only followers, with exactly one writer elected by a PostgreSQL
advisory lock (no consensus protocol — Postgres's single-holder guarantee is the
split-brain prevention). Followers `307`-redirect writes to the leader; on leader
loss a follower is promoted, fences the old leader by bumping `leader_epoch`, and
re-verifies the chain before writing. See
[Deployment → Multi-node](deployment.md#multi-node-leaderfollower).
