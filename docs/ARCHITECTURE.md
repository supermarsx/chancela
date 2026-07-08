# Chancela — Architecture Overview

A navigable map of the Chancela workspace and its major subsystems, grounded in what is
actually built (crate sources + the frozen contracts recorded under `.orchestration/logs/`).
It is an orientation document, not exhaustive API reference — enough that a new engineer can
find the right crate and understand how the pieces compose. All paths are relative to the
repository root.

Chancela is a Portugal-compliant *livro de atas* (book of minutes) and corporate-acts
platform for Portuguese collective entities (commercial companies, condominiums, associations,
foundations, cooperatives). Acts are drafted, deliberated, sealed into an append-only
hash-chained ledger, rendered to PDF/A archives, and optionally qualified-signed. One Rust
domain core drives three editions: an offline **desktop** monolith (Tauri v2), a self-hosted
**client–server** deployment (Docker), and a **browser** deployment.

> Honesty note carried throughout: Chancela **helps produce compliant records; it does not
> create legal validity** out of an invalid meeting, missing powers, or a defective process.
> The signing subsystem produces a **qualified electronic signature** (eIDAS art. 25 /
> DL 12/2021 — handwritten-equivalent); the code makes no probative-value claim.

---

## 1. Workspace layout

Rust workspace (`Cargo.toml`, edition 2024, `rust-version` 1.85, resolver 3). Members live
under `crates/*`; internal edges are path deps so the workspace resolves with no registry. The
DAG is acyclic and the domain/security crates never depend on `chancela-api`.

### Domain + platform core

| Crate | Owns |
|---|---|
| `crates/chancela-core` | Domain model: `Entity`/`Book`/`Act`, sealing (`seal.rs`), rule packs + `EntityProfile` (`rules.rs`/`profile.rs`), and the frozen `DocumentModel`/`LifecycleStage` render seam (`document_model.rs`). Pure leaf. |
| `crates/chancela-ledger` | Append-only, hash-chained, **multi-chain** event ledger (single file `lib.rs`). |
| `crates/chancela-store` | Durable system of record: embedded SQLite store (`schema.rs`, `SCHEMA_VERSION = 4`), hot backup, and the whole integrity/recovery/portability plane (`recovery.rs`). Sits between the domain crates and the API; must not depend on `chancela-api`. |
| `crates/chancela-archive` | Preservation-package model (DOC-20, spec 08). A **compiling stub** — fixes the export-package shape (checksums, provenance, rights/language metadata, signing evidence, retention/legal-hold) but `build_package` returns `ArchiveError::NotImplemented`. |
| `crates/chancela-api` | Axum HTTP layer over everything: DTOs, handlers, `AppState`, the router, the RBAC gate, and the degraded gate. |
| `crates/chancela-server` | The `chancela-server` binary (`main.rs`); binds `127.0.0.1:8080` (`CHANCELA_ADDR`), serves the API + the web bundle from `apps/web/dist`. |

### Documents + registry data

| Crate | Owns |
|---|---|
| `crates/chancela-templates` | Templates-as-data catalog engine: per-locale JSON template specs rendered via minijinja to a `DocumentModel`. Holds the `LegalThreshold` placeholder registry. |
| `crates/chancela-doc` | `DocumentModel` → **PDF/A-2u** bytes over hand-written `lopdf` (deterministic, self-checked byte shape). |
| `crates/chancela-registry` | Certidão-permanente registry integration (read-only import from an access code). Leaf crate. |
| `crates/chancela-cae` | Full CAE (Classificação Portuguesa das Atividades Económicas) library, Rev.3 + Rev.4, with an auto-update/obtainer engine. |
| `crates/chancela-law` | Full-text Portuguese/EU law corpus with a hard Verified/Pending authenticity gate. |

### Signing stack

| Crate | Owns |
|---|---|
| `crates/chancela-signing` | Signing middleware + vocabulary: `SignerProvider` (sync) and `RemoteSigningSource` (two-phase) seams, the `TrustPolicy`/`TimestampProvider` traits, the sign pipeline, and the concrete CC + CMD wirings. |
| `crates/chancela-cmd` | Chave Móvel Digital (AMA/SCMD) SOAP client (`ScmdClient`). |
| `crates/chancela-smartcard` | Cartão de Cidadão local PC/SC + PKCS#11 token access. |
| `crates/chancela-cades` | CAdES-B crypto/format foundation (signed attributes, `SignedData`). |
| `crates/chancela-pades` | PAdES: sign an existing PDF by incremental update (B-B, B-T). |
| `crates/chancela-tsl` | Portuguese Trusted List (ETSI TS 119 612) ingest + QTSP qualification lookup. |
| `crates/chancela-tsa` | RFC 3161 timestamp client. |

### Security + integration surface

| Crate | Owns |
|---|---|
| `crates/chancela-authz` | Scoped RBAC core: permission catalog, `Global`/`Entity`/`Book` scopes, roles-as-data, scoped delegation, and the escalation/attenuation invariants. Pure leaf. |
| `crates/chancela-apikey` | API-key model: sha256-hashed shown-once keys as **attenuated RBAC principals**, per-key rate limiting. Pure leaf. |
| `crates/chancela-mcp` | Off-by-default MCP server exposing platform ops as permission-gated tools over stdio. HTTP client of the integration API. |

### Apps

- `apps/web` — Vite 6 + React 19 + TypeScript 5.7 SPA (`@chancela/web`). The single frontend
  for all three editions.
- `apps/desktop` — Tauri v2 shell. **Excluded from the root cargo workspace** (its own empty
  `[workspace]`) so a root `cargo build`/`test` never pulls in the heavy WebView deps. Loads
  the same web frontend.

### Cross-cutting

- `contracts/*.json` — canonical wire-shape fixtures asserted from both ends: the Rust E2E
  harness (`crates/chancela-server/tests/e2e_contracts.rs`) shape-matches live responses; a
  vitest suite (`apps/web/src/contracts/`) feeds them through the real TS DTO path. A field
  rename/add/remove/retype breaks a test on whichever side moved.
- `spec/`, `spec.md`, `SPEC-COVERAGE.md` — the product + legal specification (RFC 2119 keywords).
- `.orchestration/` — coordination state, task plans (`plans/`), and per-executor frozen-contract
  logs (`logs/`). The `docker/` and `scripts/` dirs hold the container edition and per-platform
  operator tooling.

---

## 2. Multi-chain ledger + integrity / recovery

`crates/chancela-ledger/src/lib.rs` (the chain) + `crates/chancela-store/src/recovery.rs`
(durability, portability, recovery). HTTP surface in `crates/chancela-api/src/`.

### Chains (`ChainId`)

The **global** chain is intrinsic to every event (`Event::seq`/`prev_hash`/`hash`); the other
three ride as `Event::links: Vec<ChainLink>`:

- `ChainId::Global` (`"global"`) — the primary spine every event shares.
- `ChainId::Application` (`"application"`) — settings / users / CAE / law / backups / recovery ops.
- `ChainId::Company(uuid)` (`"company:{uuid}"`) — per-company book actions; genesis kind
  `entity.created`.
- `ChainId::Book(uuid)` (`"book:{uuid}"`) — per-book actions; genesis (seq 0) is the sealed
  `book.opened` termo de abertura.

Chain membership is a pure derivation from an event's `scope` via `Ledger::memberships`; genesis
kinds are enforced by `ChainId::expected_genesis_kind()`.

### Core operations

- **`verify()`** → `Result<u64, LedgerError>` — one pass over the global spine (seq run, zero-prev
  genesis, backward link, `hash` recompute) plus every per-chain link. `verify_chain(&ChainId)`
  isolates one chain. Rich twins: `locate_break`, `first_break`, `integrity_report()`.
- **`try_append(actor, scope, kind, justification, payload)`** → `Result<&Event, AppendError>` —
  validating append: checks would-be links against each joined chain's head (genesis-kind rule +
  broken-tail guard) **before** mutating; `O(links)`, not a full re-verify. On error nothing is
  appended. (Infallible `append` also exists.)
- **`reanchor(actor, reason, at)`** → `ReanchorRecord` — last-resort repair. Rebuilds every
  event's derivable linkage (seq/prev_hash/links/hash) **in place from untouched content** (actor,
  scope, kind, timestamp, payload_digest never change), cascades the spine, and appends a chained
  `ledger.reanchored` disclosure event. Refuses if the ledger already verifies
  (`ReanchorError::AlreadyValid`) or the reason is empty. The disclosure is permanent and
  tamper-evident.
- Boot adoption: `try_from_events` adopts persisted events byte-for-byte (no re-hash) then verifies.

### Per-book portability + whole-store restore (`chancela-store/recovery.rs`)

- **Export** — `Store::export_book` gathers the book + entity + acts + latest doc-per-act + the
  full **Book-chain** member events into a `chancela-book-bundle/v1` `.zip` with a `BundleManifest`
  (per-file sha256 + `bundle_digest`), retained under `<data_dir>/exports/`. No secrets: the crate
  has no access to users/sessions.
- **Import** — `Store::import_book` is verify-before-trust (manifest digest → member sha256 →
  standalone `Ledger::verify_bundle_chain`). Clean ⇒ `ImportVerdict::Verified`; any break/tamper ⇒
  `ImportVerdict::Quarantined` — kept isolated and read-only under the **original** ids, never
  merged onto the live global spine (re-numbering would force a re-hash and destroy
  tamper-evidence). `CollisionPolicy::Refuse` (default) vs `QuarantineCopy`.
- **Restore** — `Store::restore` verifies every member sha256 **and** that the snapshot's ledger
  verifies `Ok` in a temp dir **before** an atomic db-file swap. A bad archive leaves the live
  store untouched (`StoreError::BadBackup`).
- Recovery/audit event kinds all live on the Application chain: `ledger.exported`,
  `ledger.imported`, `ledger.restored`, `ledger.reinitialized`, `data.wiped`.

### Data-management reset taxonomy

Two axes:

- **Destructive reset** (`ResetScope`): `BackendDomain` clears domain tables but **preserves the
  append-only ledger** and emits a chained `data.wiped` (stays auditable); `BackendFactory` clears
  everything including the ledger + sidecar files → blank first-run (the export-first archive is
  then the only record). An optional export-first safety rail applies to both. (A "frontend reset"
  is client-only — no endpoint.)
- **Start-over** (`StartOverScope`, archive-then-fresh, non-destructive): `Book` archives the
  current book (`ledger.exported`) then opens a fresh successor shell; `Instance` archives the
  whole instance, clears domain + events, and seeds a fresh ledger whose genesis **is**
  `ledger.reinitialized`.

### The degraded gate

`AppState.degraded: Arc<RwLock<bool>>` in `crates/chancela-api/src/lib.rs`, set at boot from the
store's `IntegrityReport.healthy`.

- **Trigger**: any chain (global spine or a per-chain link) fails to verify at boot → the server
  enters **degraded read-only** mode instead of refusing to start (or silently starting anyway).
- **Blocks**: the `degraded_gate` middleware returns `503` (honest PT "modo só-leitura") on
  ordinary mutations. Exempt: all reads, plus the recovery plane (reanchor, restore, data reset,
  start-over, book import/export, session).
- **Lifts**: `refresh_degraded` recomputes health after each recovery op — a repaired chain lifts
  the gate, a still-broken one keeps it.

### API files

`recovery.rs` (`GET /v1/ledger/integrity`, `POST /v1/ledger/recovery/reanchor`, `.../restore`),
`bundles.rs` (`POST /v1/books/{id}/export`, `POST /v1/books/import`, `.../start-over`),
`data.rs` (`POST /v1/data/reset`, `.../start-over` — type-to-confirm phrase + step-up re-auth),
`backup.rs` (`POST /v1/backup` — hot `VACUUM INTO` snapshot; in-memory ⇒ 422),
`ledger.rs` (`GET /v1/ledger/events`, `.../verify`).

---

## 3. Document catalog + generation

A linear seam: `chancela-templates` (render) → `chancela-core::DocumentModel` (frozen) →
`chancela-doc` (PDF/A-2u bytes) → `crates/chancela-api/src/documents.rs` (orchestration into the
ledger).

### Templates as data (`crates/chancela-templates/src/lib.rs`)

The catalog is **data, not code**: one `assets/*.json` file per template, embedded via `build.rs`
and parsed (with `deny_unknown_fields`) into runtime `TemplateSpec`s (versioned `id` e.g.
`"csc-ata-ag/v1"`, `family`, `stage: LifecycleStage`, `signature_policy`, a bound `rule_pack_id`,
`blocks`, `locale`). `Registry::find(family, stage)` is the picker. **Block structure is registry
data; minijinja fills only prose fragments** — `render(spec, ctx) -> DocumentModel` is
deterministic (no clock, no RNG; a stateless env per call). Whitespace-only prose is dropped
(giving `{% if %}` conditionals for free); empty KeyValue rows are omitted. Author-facing filters:
`long_date`, `channel_label`, `role_label`, and the `threshold()` function.

### The `DocumentModel` seam (`crates/chancela-core/src/document_model.rs`)

A **frozen** module (field/variant order = serde wire order = digest input):
`DocumentModel { title, entity_name, entity_nipc, subject, language, created_at, blocks }`, with
`Block` variants `Heading`/`Paragraph`/`KeyValue`/`VoteTable`/`SignatureBlock`/`PageBreak`/`Rule`
and `LifecycleStage` (`Convocatoria`, `TermoAbertura`, `Reuniao`, `Deliberacao`, `Ata`,
`Certidao`, `Extrato`, `TermoEncerramento`). Core stays a leaf; `created_at` is caller-supplied.
Both the PDF writer and the web preview consume the same model.

### PDF/A-2u writer (`crates/chancela-doc`)

`pdfa::write(&DocumentModel) -> Vec<u8>`: embeds Noto Serif as Type0/Identity-H/CIDFontType2 with
a mandatory `/ToUnicode` CMap (the "u" conformance), an sRGB `/OutputIntents` ICC profile, and an
uncompressed XMP `/Metadata` stream (`pdfaid:part=2`, `conformance=U`). **Deterministic**: the
trailer `/ID` is SHA-256 over XMP + page streams (never clock/RNG), so the same model reproduces
byte-identical output and a stable `pdf_digest`.

**The seal-hook / signable-shape constraint (D2):** the writer forces a classic cross-reference
table (not a stream) and emits **no Info dict, no AcroForm, no encryption** — the exact byte shape
`chancela-pades::sign_pdf` appends to. `selfcheck::verify` structurally asserts this before
returning (`DocError::Conformance` on failure). This is how the "signable shape" is guaranteed
structurally rather than at the API layer.

### The `LegalThreshold` placeholder registry (`crates/chancela-templates/src/thresholds.rs`)

A central registry of legal numbers (convening periods, quorums, majorities) that are **not yet
legally verified**, so authors must not guess them into prose (WFL-31: compliance lives in the
rule pack, never the template). `LEGAL_THRESHOLDS` currently holds 11 entries, **every one
`value: None`** (unresolved). `LegalThreshold::render()` returns the resolved surface form when
`Some`, else a loud marker `[a definir: {label} ({article_ref})]` — **never a fabricated number**.
Injected via the minijinja `threshold("<id>")` function; an unknown id is a render error (typo-safe),
and an asset-lint test asserts every id used in any template resolves.

### The API documents service (`crates/chancela-api/src/documents.rs`)

`generate(spec, ctx, ...)` = `render` → `pdfa::write` → SHA-256 `pdf_digest` → builds a
`StoredDocument` + a `document.generated` event payload, produced **outside** the ledger mutation
so a failure rolls back cleanly. `spine_template_id(family, stage)` pins one primary template per
`(family, stage)` (never `.next()` arbitrarily). Seal-hook entry points are committed inside the
**same durable transaction** as the domain event: `generate_for_act` in `seal_act_handler` (a
render/write failure rolls the `act.sealed` event back out — a failed seal leaves no trace; a
family with no template proceeds document-less), `generate_for_termo` (book open),
`generate_for_encerramento` (book close). On-demand surface: `POST /v1/acts/{id}/document/generate`
(gated on `Permission::DocumentGenerate`), `GET .../document/preview` (live model, works pre-seal),
`GET .../document` (stored bytes), `GET .../document/bundle` (the DOC-03 preservation bundle whose
`validation_report` slot is the reserved seam for future PAdES output), `GET /v1/templates`.

---

## 4. Qualified signing

Layered stack under `crates/chancela-signing` (vocabulary + wiring), with the crypto/format/trust
crates below and `crates/chancela-api/src/signature.rs` on top. **CMD is the only path wired
end-to-end in the API today.**

### The two seams

- **`SignerProvider`** (sync, `provider.rs`) — given the SHA-256 of the CAdES signed attributes,
  return a `RawSignature` + signing certificate. Used by CC.
- **`RemoteSigningSource`** (two-phase, `remote.rs`) — for remote QES that spans two stateless
  requests with an out-of-band activation between them. `initiate(...)` authenticates, resolves the
  cert + chain, gates against the TSL, takes the PAdES ByteRange digest, and opens a provider
  session dispatching the activation (SMS OTP / SAD); `confirm(session, activation)` submits the
  transient OTP and returns detached CAdES-B ready for `chancela_pades::embed_signature`. The
  resumable handle `RemoteSignSession` is **non-secret and serde-persistable** (provider ref, cert,
  chain, TSL status, byterange digest, signing time — explicitly no PIN/OTP/SAD).

### Providers

- **CC — Cartão de Cidadão** (`chancela-smartcard`, `SmartcardProvider`): local PC/SC + PKCS#11 via
  the Autenticação.gov middleware. Always selects the qualified **signature** cert (label
  `"CITIZEN SIGNATURE CERTIFICATE"`), never the authentication cert. PIN is entered at the reader
  (protected-authentication path, NULL PIN), never entering the process. CC v1 = RSA-2048, CC v2
  (June 2024+) = P-256. **Synchronous** — its single-call PAdES seam is `sign_pdf_cc` (`cc.rs`).
- **CMD — Chave Móvel Digital** (`chancela-cmd`, `ScmdClient`): hand-built SOAP 1.1 against the AMA
  SCMD service — `GetCertificate` → `CCMovelSign` (PIN, dispatches OTP) → `ValidateOtp` (OTP,
  returns a raw signature). Wired through both a sync `CmdProvider` and the resumable
  `CmdRemoteSource`/`cmd_initiate`+`cmd_confirm` (shared cores, byte-identical behaviour).
- **CSC — Cloud Signature Consortium QTSP**: **planned, not implemented** (`chancela-csc`, a future
  peer of `RemoteSigningSource`). No crate exists yet. (Note: the `csc-*` template files in the
  repo are *Código das Sociedades Comerciais* content, unrelated to the CSC standard.)
- **Manual** (handwritten scan) has no provider — `record_manual_signature` yields
  `EvidentiaryLevel::HandwrittenScanned`, never qualified, and must surface `MANUAL_WARNING`.

### Format + trust

- **CAdES** (`chancela-cades`) — the crypto foundation: `signed_attributes_digest`,
  `assemble_cades_b`, `validate_cades_b`. Algorithms `RsaPkcs1Sha256` (CC v1 + CMD) and
  `EcdsaP256Sha256` (CC v2). Crypto, not trust decisions.
- **PAdES** (`chancela-pades`) — signs a PDF by incremental update (`prepare_signature` →
  caller signs → `embed_signature`; `add_signature_timestamp` upgrades B-B→B-T). **B-B and B-T are
  implemented; B-LT/B-LTA are phase-2** (`PadesError::LongTermNotImplemented`).
- **TSL** (`chancela-tsl`) — ingests the Portuguese Trusted List (ETSI TS 119 612), validates its
  own XML-DSig on every refresh, and answers `is_qualified_for_esig` →
  `Granted`/`Withdrawn`/`Unknown`. Wired in via the `TrustPolicy` trait (`TslTrustPolicy` real,
  `StaticTrustPolicy` for tests).
- **TSA** (`chancela-tsa`) — RFC 3161 timestamp client. Verifies token structure + binding
  (PKIStatus, TSTInfo, imprint/nonce match); the TSA's own signature/chain is deferred to TSL +
  CAdES. Exposed via `TimestampProvider`.

The **trust gate is fail-closed and identical across all paths**: if a `TrustPolicy` is supplied, a
non-`Granted` issuer is rejected (`SigningError::UntrustedService`) *before* any signature is
produced — before the card even prompts for a PIN. The qualified path must supply a policy (a
missing TSL URL is a 422).

### API state machine (`signature.rs`, CMD-only in v1)

Wire states `"unsigned"` → `"pending"` → `"signed"`:

- `POST /v1/acts/{id}/signature/cmd/initiate` (RBAC `SigningPerform`, act must be sealed): TSL gate
  → dispatches OTP → persists a **non-secret** `PendingCmdSession` (5-min TTL) → `pending`.
- `POST /v1/acts/{id}/signature/cmd/confirm`: loads the single-use, actor-scoped, TTL-checked
  session (expired ⇒ 410) → `embed_signature` → `validate_pdf_signature` (SIG-24: ByteRange covers
  the whole file except `/Contents`, and the embedded signer cert must equal the session's leaf —
  anti-substitution) → persists the signed document + a chained `document.signed` event and deletes
  the pending session in one commit → `signed`.

PIN and OTP are transient, read into `Zeroizing`, consumed by their single call, and never
persisted/logged/echoed.

### Enforcement gates on STATUS, not the seal

The setting `signing.require_qualified_for_seal` defaults to **`false`**. `finalization_status`
derives a label: a qualified signature ⇒ `finalizado_qualificado`; not sealed ⇒ `rascunho`; sealed
with the flag **on** but no qualified sig ⇒ `aguarda_assinatura_qualificada`; sealed with the flag
**off** ⇒ `finalizado`.

What this honestly means: **sealing always succeeds and always produces the unsigned PDF/A**,
regardless of the flag. The qualified signature is a distinct post-seal step. The flag only
controls the finalization **status label** shown — it never blocks the seal. No endpoint sets the
qualified status directly; it is *derived* from the presence of a validated `Qualified` signed
variant, so it is unbypassable. The artifact is a **qualified electronic signature**; the code and
docs make **no "valor probatório" claim** — the vocabulary is evidentiary *level* + trusted-list
*status*, not probative-value assertions.

### Off by default / external credentials

- Enforcement (`require_qualified_for_seal`) is **off by default**; the non-qualified `finalizado`
  path stays fully usable.
- **CMD production needs external AMA/SCMD credentials**: `CHANCELA_CMD_ENV` (`preprod` default /
  `prod`), `CHANCELA_CMD_APPLICATION_ID`, and — for `prod` only — `CHANCELA_CMD_AMA_CERT_PEM` (the
  field-encryption cert; prod-without-cert is rejected). Secrets come from env only, never the
  settings JSON. Default tests are offline (`MockScmdTransport`); real calls are behind a
  `network-tests` feature + `#[ignore]`.
- **CC production** needs a physical card + reader + Autenticação.gov middleware (module path
  overridable via `CHANCELA_PTEID_PKCS11_MODULE`); real-card tests are `hardware-tests`-gated.
- **TSL/TSA live fetches are feature-gated** and never run in CI.
- CSC provider, PAdES B-LT/B-LTA, and XAdES/ASiC formats are **not built**.

---

## 5. RBAC — the who-may layer

`crates/chancela-authz` (pure core) + `crates/chancela-api/src/{authz,roles,delegations,session}.rs`
(stores + enforcement). Fail-closed throughout.

### The core (`chancela-authz`)

- **Permission catalog** (`permission.rs`) — `enum Permission`, 37 compile-time verbs each with a
  stable dotted serde id (`entity.read`, `book.open`, `signing.perform`, `ledger.recover`,
  `data.wipe`, …). Four **meta** permissions (`RoleManage`, `RoleAssign`, `DelegationGrant`,
  `DelegationRevoke`) are non-delegable and never allowed on an API key. *Verbs are code; which
  verbs a role grants is data.*
- **Scopes** (`scope.rs`) — `Scope::{Global, Entity(id), Book(id)}`, with **narrowing-only**
  coverage: `Global` covers all; `Entity(E)` covers itself + books it owns; `Book(B)` covers only
  itself. A scoped grant can never satisfy a `Global` check. Unknown book → fail-closed.
- **Roles as data** (`role.rs`) — `Role { id, name, permission_set, protected }` + a `RoleCatalog`.
  Four seeded defaults with deterministic ids: **Proprietário/Owner** (all perms, protected,
  undeletable), **Gestor**, **Signatário**, **Leitor**. Protected roles cannot be edited or deleted.
- **Delegation** (`delegation.rs`) — one permission at a scope, optional expiry, revocable.
- **Effective authority + invariants** (`lib.rs`) — `effective_permissions(...)` builds a
  `ScopedPermissionSet` that **partitions role grants from delegated grants** (load-bearing).
  `has_permission` checks the union; `can_define_role`/`can_assign_role` enforce the subset
  invariant; `can_delegate` requires the permission be held **via a role** (forbids re-delegation and
  meta delegation); `last_owner_guard` keeps ≥1 Owner. An in-crate **escalation battery** test
  denies every known escalation path.

### API stores, migration, enforcement

- **Stores** mirror the `users.json` discipline (atomic tmp+rename, malformed-tolerant, serde
  defaults): `roles.json` → `RoleCatalog` (always forces the canonical locked Owner); `delegations.json`
  → `StoredDelegation` (frozen model + audit fields, revoked records retained).
- **No-lockout migration** (`migrate_roles`): every user with no assignments gets a default in one
  idempotent pass — earliest user → Owner@Global (only if none exists), everyone else →
  Gestor@Global. A newly created first user gets Owner@Global via `bootstrap_assignment`.
- **Principal seam (frozen)**: `effective_permissions_for(state, principal, now)` folds a user's
  assignments + live catalog + active delegations; an unknown/inactive user → empty set.
- **Enforcement gate** (`authz.rs`): `require_permission_with(state, eff, perm, scope)` is the
  **principal-source-agnostic** core (builds the `BookScope` at check time) → 403 with a generic,
  non-enumerating message `FORBIDDEN = "sem permissão para esta operação neste âmbito"`. This is the
  exact seam API-key principals compose against. `require_permission` is the session convenience over
  it. 401 = no/invalid session; 403 = valid session but no permission. A **fail-closed route-coverage
  guard** parses `router()` and fails the build if any route is unclassified.
- **Session surface** (`session.rs`): `GET /v1/session/permissions` returns `PermissionGrantView`
  (`permission`, `scope`, `source: role|delegation`) so the web can gate its own UI.

### Step-up re-auth composition

The highest-bar destructive routes compose **three independent gates**: (1) the RBAC verb@scope
check, (2) a type-to-confirm phrase (e.g. `"RECOMEÇAR"`, `"REPOR FÁBRICA"`), and (3)
`require_step_up` — a `ReAuth { password?, recovery_phrase? }` verified via argon2id against the
acting user's stored verifier. A valid session alone is never enough (failure → `STEP_UP_REQUIRED`).
These are the routes annotated `+ step-up`: book start-over, ledger reanchor/restore, data reset,
data start-over. RBAC gates *who*; step-up re-proves *the human at the keyboard*.

---

## 6. Integration surface

All off by default.

### API keys as attenuated principals (`crates/chancela-apikey`)

Pure leaf (depends only on `chancela-authz` + crypto/serde). An `ApiKey` record stores **no
secret** — only `key_hash = sha256(plaintext)` plus a public prefix, the `principal_grant`, creator,
timestamps, revocation, and an optional per-key rate limit. The plaintext `chk_<prefix>_<secret>`
(48-bit prefix + **256-bit** secret) is returned **once** and never stored/logged. `verify()` is a
**constant-time** digest compare. (sha256, not argon2, because a 256-bit CSPRNG token needs no slow
KDF and argon2 on the hot unauthenticated path would be a self-DoS.)

**The attenuation invariant is the crux**: `can_create_key` requires the grant be non-empty, contain
**no meta permission**, and be a **subset of the creator's own authority** — enforced at mint
(`ApiKey::issue` → `IssueError::{EmptyGrant, GrantContainsMeta, GrantExceedsCreator}`), so an
over-powerful key is impossible to construct. `resolve(...)` then re-intersects the key's grant with
the creator's **current** authority (minus meta) → **auto-attenuation**: if the creator is
downgraded, the key silently loses that authority with no re-issue. Crucially, `resolve` returns a
`RequestPrincipal` carrying the **same `ScopedPermissionSet` shape a session yields**, so one
`require_permission_with` gate serves web, integration, and MCP with no bypass. A token-bucket
**per-key rate limiter** (`ratelimit.rs`, default 60 rpm / 20 burst) rounds it out. Its own
escalation battery denies every mint/resolve of excess authority.

### MCP server (`crates/chancela-mcp`)

Off-by-default MCP server exposing platform ops as permission-gated tools. Hand-rolled **JSON-RPC
2.0 over stdio** (no MCP SDK, no async runtime), protocol version `2025-06-18`. `catalog()` holds 16
`McpTool` entries (`list_entities`, `create_entity`, `open_book`, `seal_act`, `generate_document`,
`verify_ledger`, `search_law`, …), each tagged read-only vs write-controlled with a documented
`permission`. **The MCP crate is an HTTP client of the integration API** (`ApiBridge` attaches
`Authorization: Bearer chk_...`, held privately, never logged) — one RBAC path, authz stays
server-side. **Structurally off**: `McpConfig::default()` is `enabled = false`; a disabled config is
refused at construction (`McpError::Disabled`) and `serve_stdio` returns immediately, building no
transport and reading no stdin. Enabling also requires `CHANCELA_MCP_API_KEY`. Only stdio ships
(HTTP/SSE reserved). Step-up-only destructive routes are structurally out of reach for a key
principal (keys can never hold meta, and those routes require step-up credential proof).

### The planned `/api/v1` mount

**Not yet mounted.** The live `chancela-api` router serves handlers at `/v1/*`. The `/api/v1` mount +
the wiring of `chancela-apikey` into the API (an `AppState.api_keys` store, `apikey::resolve` behind
`require_permission_with`, the rate limiter, and an `integration.enabled` extractor gate) are a
planned addition. The reusable enforcement seam it targets already exists and is frozen. The MCP
crate already points at `{base_url}/api/v1` in anticipation.

---

## 7. Law corpus (`crates/chancela-law`)

The full text of every cited diploma, article by article — explicitly the *law analogue* of
`chancela-cae`: a vendored authentic source + `PROVENANCE.md` + a reproducible generator → committed
JSON → `include_str!` → an indexed catalog + a fetch trait, behind a hard authenticity gate.

- **Vendoring** (`dataset.rs`): `EMBEDDED_DIPLOMAS = include_str!("../data/law_corpus.json")` (a JSON
  array of `LawDiploma`), produced by the committed reproducible generator `data/source/gen_law.py`
  (`--check` is the offline CI staleness guard). `src/bin/gen_law.rs` is a pure-cargo verify/inspect
  entry point.
- **The Verified/Pending authenticity gate** (`model.rs`, `corpus.rs`): `enum Verification { Verified,
  Pending }`. A `Verified` article must carry full verbatim `body` **and** a complete `LawSource`
  (diploma + article + `dr_reference` + `url`); `LawCatalog::from_corpus` **refuses** to build
  otherwise (enforced at build time, not just in tests). A `Pending` article **never** renders its
  empty body — `display_body()` returns `UNVERIFIED_MARKER = "[NÃO VERIFICADO / fonte pendente]"`. No
  fabricated, paraphrased, or recalled statute text is ever presented.
- **Current state**: 9 diplomas, 193 articles = **153 Verified + 40 Pending**. The 3 EU regulations
  (`eidas-910-2014`, `gdpr-2016-679`, `eidas2-2024-1183`) are Verified, vendored verbatim from
  EUR-Lex PT OJ HTML (each sha256-pinned). The 6 DRE-sourced PT diplomas (CSC, Código Civil,
  DL 268/94, DL 76-A/2006, Código Cooperativo, Lei 24/2012) stay **Pending** because the DRE portal is
  a JS-gated SPA that curl cannot extract.
- **Sourcing + `network` feature** (`source.rs`): the fetch trait is `DreSource` (transport; distinct
  from the per-article `LawSource` data struct), with `FileLawSource`/`BytesLawSource` and — behind
  `#[cfg(feature = "network")]` — `HttpDreSource` (`CHANCELA_LAW_URL`). Offline embedded corpus is the
  default; network is opt-in.
- **External requirement**: no API credentials. Flipping the 6 PT diplomas to Verified needs
  **source access to the DRE text** — either a headless browser to extract the SPA DOM verbatim, or
  **user-supplied authoritative DRE "descarregar" PDF exports** vendored into `data/source/`.

A separate, curated manifest lives in `crates/chancela-api/src/law.rs` (`LAW_MANIFEST`, 9 statutory
anchors with official URLs; only the two CAE diplomas have pinned, sha256-vendored DR **PDF** URLs
that `POST /v1/law/{id}/fetch` downloads). RBAC `law.read`/`law.manage`.

The domain-adjacent data crates: **`chancela-registry`** owns read-only certidão-permanente import —
`AccessCode` (a masked secret) → `HttpRegistryTransport` → `parse_certidao` → a typed
`RegistryExtract` (matrícula, firma, `LegalForm`, role-tagged `CaeRef`, órgãos, inscrições feed),
a leaf crate with no dep on core; **`chancela-cae`** owns the full CAE library (Rev.3 + Rev.4,
`include_str!` dataset from the official DR diplomas), an indexed `CaeCatalog`, and a data-dir cache
with background auto-update + an official-source obtainer gated by a full-count fidelity check.

---

## 8. Frontend (`apps/web`)

Vite 6 + React 19 + TypeScript 5.7 SPA (`@chancela/web`), react-router-dom 7
(`createBrowserRouter`), @tanstack/react-query 5 (one shared client), Tauri 2 desktop bindings in
`src/desktop/`. Tests: Vitest (co-located) + Playwright (`e2e/`). No CSS framework — one
hand-authored token stylesheet.

- **App shell / routing** (`src/app/`): `providers.tsx` mounts `ToastProvider` above the router so
  toasts survive navigation; `router.tsx` puts `/bem-vindo` (onboarding) outside `Layout` and nests
  everything else under it (PT-PT routes: Painel `/`, `entidades`, `livros`, `atas/:id`, `arquivo`,
  `ferramentas`, `configuracoes`, `cae`, `utilizadores`). `layout.tsx` renders the leather
  background, Tauri `TitleBar`, `AuthGate`, the fixed topbar, `DegradedBanner`, and the routed
  `<main>`. Crash resilience: nested error boundaries + `CrashScreen` + a **safe mode**
  (`safeMode.ts`) that bypasses the appearance layers.
- **Gilt / leather theme**: almost entirely in `src/theme.css` (~4690 lines) as a CSS
  custom-property token layer — a green-ink + old-gold palette (WCAG-AA tuned), an editorial serif
  type stack (no runtime font fetch), and a leather chrome layer. The grain is **procedural**:
  `src/theme/leather.ts` builds an inline `feTurbulence` SVG data-URI (no network). Light default +
  `prefers-color-scheme` + explicit `data-theme` overrides.
- **W1 primitives** (`src/ui/`): `Tooltip` + `IconButton` (`Tooltip.tsx`, gilt bubble,
  hover/focus/Escape, `aria-describedby`) and `FieldHelp` (`FieldHelp.tsx`, a quiet info glyph
  reusing Tooltip), all exported from the `src/ui/index.tsx` barrel.
- **Toast** (`src/ui/toast/`): `success`/`info`/`error`/`show`/`dismiss`; polite vs assertive
  `aria-live`, auto-dismiss (5s / 8s errors), pause on hover, max 4 visible.
- **i18n** (`src/i18n/`): **14 locales** — pt-PT (inlined source fallback), en-US + en-GB (human),
  and 11 machine-quality (pt-BR, da-DK, de-DE, fr-FR, fi-FI, sv-FI, it-IT, nl-NL, pl-PL, sv-SE,
  es-ES). All non-source catalogs code-split via dynamic `import()`; manifest in `registry.ts`.
- **Settings sub-tabs** (`src/features/settings/SettingsPage.tsx`): a deep-linkable (`?sec=`)
  segmented nav over 9 sections — aparência (default), identidade, documentos, assinaturas, gestão,
  utilizadores, integridade (Livros & Integridade), dados (Gestão de Dados), sobre — with debounced
  **autosave** (`useAutosave.ts`) doing a whole-document `PUT /v1/settings` and live
  appearance/locale preview.
- **Onboarding / auth** (t44): `AuthGate` (`src/features/session/`) routes signed-in → app,
  no-user → `/bem-vindo`, users-but-signed-out → `SignIn`, reading the **unauthenticated** roster to
  avoid a 401 lockout. `OnboardingWizard` is a full-screen gilt sibling route
  (welcome → org → user → password → key) that creates the first user, signs in, and PUTs the org
  name + `onboarding.completed`.
- **Animations**: CSS-only in `theme.css`, gated by two kill-switches (`prefers-reduced-motion` and
  `data-safe-mode`) — a 300ms route-enter rise/fade keyed on pathname, an 11s leather "breathe",
  plus tooltip/toast entrances and button/card micro-transitions.

---

## 9. Conventions

- **Per-concern commits.** Work lands in focused, single-concern commits; the coordinator batches
  and commits (executors generally do not commit their own work).
- **`.orchestration/` coordination.** Tasks are planned in `.orchestration/plans/t*.md`, executed by
  named executors, and each executor records its **frozen contracts** (the exact type/function
  signatures other agents may rely on) in `.orchestration/logs/t*-*.md`. These logs are the
  authoritative record of what was actually built and are the ground truth this document is drawn
  from. Cross-side wire shapes are additionally pinned by the `contracts/*.json` fixtures asserted
  from both the Rust E2E harness and the web vitest suite.
- **Security-review gating.** Security-sensitive crates (`chancela-authz`, `chancela-apikey`, the
  signing stack, recovery) carry in-crate **escalation/abuse batteries** and fail-closed defaults; a
  fail-closed route-coverage guard forces every new API route to be explicitly classified
  Exempt/Session/Gated. Lint is `clippy --all-targets -D warnings`.
- **Authenticity / no-fabrication.** Two hard rules are enforced in code, not just convention:
  **law text** is never presented unless `Verified` against a complete DRE/EUR-Lex source (Pending
  articles render an explicit unverified marker); **legal thresholds** (quorums, majorities,
  convening periods) are never guessed into template prose — an unresolved threshold renders a loud
  `[a definir: …]` marker, never a number. Compliance authority lives in rule packs, never templates
  (WFL-31).
- **Honest security vocabulary.** The signing subsystem describes itself as producing a **qualified
  electronic signature** and reasons about evidentiary *level* + trusted-list *status*; it makes no
  probative-value ("valor probatório") claim. Sealing succeeds independently of signing; the
  qualified status is *derived*, never asserted.
- **Off-by-default posture.** The MCP server, the integration `/api/v1` surface (planned), qualified-
  signing enforcement, and all network fetches (CMD, TSL/TSA, law, CAE, registry) are off or
  feature-gated by default. Production qualified signing needs external credentials (AMA/SCMD for
  CMD, a physical card + middleware for CC); flipping the PT law corpus to Verified needs
  authoritative DRE PDFs.
