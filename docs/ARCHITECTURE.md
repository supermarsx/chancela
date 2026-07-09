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
> The signing subsystem can produce a **qualified electronic signature** only when the
> deployment supplies the required qualified provider/certificate/hardware/onboarding path
> (eIDAS art. 25 / DL 12/2021 — handwritten-equivalent); the code makes no probative-value
> claim and creates no legal shortcut around those requirements.

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
| `crates/chancela-store` | Durable system of record: embedded SQLite store (`schema.rs`, `SCHEMA_VERSION = 5`), hot backup, imported-document evidence storage, and the whole integrity/recovery/portability plane (`recovery.rs`). Sits between the domain crates and the API; must not depend on `chancela-api`. |
| `crates/chancela-archive` | Deterministic internal preservation-package builder (DOC-20, spec 08): ZIP manifest, checksums, provenance, rights/language metadata, signing/evidence sidecars, preservation level, retention/legal-hold metadata, and DGLAB-aligned producer/interchange metadata. It explicitly does not claim official DGLAB interchange or certification. |
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
| `crates/chancela-pades` | PAdES: sign an existing PDF by incremental update (B-B, B-T) and append/report local caller-supplied DSS/VRI evidence. |
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
`POST /v1/documents/import/validate` is a read-only candidate-import screen: raw bytes or
JSON/base64 in, structured findings out (content type, size, SHA-256, PDF/PDF-A-ish markers, signed
PDF/ByteRange signals). `POST /v1/documents/import` then persists an accepted candidate as
**non-canonical imported evidence** in `imported_documents` (schema v5) and appends a
`document.imported` event whose payload is metadata only. `GET /v1/documents/imported`,
`GET /v1/documents/imported/{id}`, and `GET /v1/documents/imported/{id}/bytes` expose metadata and
retained bytes through the document-read gate. This does not replace preserved canonical PDF/A
documents, mutate signed records, or prove legal/signature validity.

### Archive packages and working-copy exports

- **Book preservation package** (`crates/chancela-api/src/archive_package.rs`):
  `GET /v1/books/{id}/archive/package` streams a deterministic
  `chancela-internal-preservation-package/v1` ZIP. It is read-only and does not append ledger
  events. The package carries a `manifest.json`, PDF/A members, metadata sidecars, signed PDF
  sidecars when present, signer certificate evidence, timestamp-token evidence when present, and
  per-document validation/evidence reports. Signature evidence reports include embedded DSS/VRI
  counts, `/TU` metadata, and SHA-256 hashes when a signed PDF carries technical revocation
  evidence; they also record that no production/legal B-LT status is claimed. The
  manifest includes structured producer and preservation-interchange metadata, but deliberately
  records `official_dglab_interchange: false` and `dglab_certification_claimed: false`. Before
  package build, the endpoint preflights the inventory for duplicate/non-canonical IDs, path-like
  document metadata, missing or mismatched PDF bytes/digests, inconsistent signed-document sidecars,
  empty timestamp tokens, and impossible signature timestamps; after build it revalidates the
  generated ZIP manifest before returning bytes. The export also accepts
  `legal_hold=true&legal_hold_reason=...` to mark that generated package as non-disposable and add
  `evidence/legal-hold.json`.
- **Book legal hold** (`GET|PUT|DELETE /v1/books/{id}/legal-hold`): stores active hold metadata on
  the book aggregate (`reason`, `actor`, `set_at`), appends ledger events on set/clear, and feeds the
  package retention metadata/evidence automatically while a hold is active.
- **Working-copy Markdown** (`GET /v1/acts/{id}/document/working-copy`): returns `text/markdown`
  for sealed-document review/editing convenience, with an explicit non-evidentiary warning and the
  preserved PDF digest. It is gated like document reads, does not mutate the PDF/A bytes, and does
  not append ledger events.
- **Office working-copy DOCX** (`GET /v1/acts/{id}/document/office`): returns a deterministic
  `application/vnd.openxmlformats-officedocument.wordprocessingml.document` artifact for sealed acts
  that can be opened in office suites. It carries a non-evidentiary warning plus preserved-document
  metadata; the canonical record remains the stored PDF/A or signed PDF. The route is read-only,
  uses the document-read gate, and does not append ledger events.

---

## 4. Qualified signing

Layered stack under `crates/chancela-signing` (vocabulary + wiring), with the crypto/format/trust
crates below and `crates/chancela-api/src/signature.rs` on top. CMD, CC, and configured CSC
providers are wired into the API, but live production use still depends on external credentials,
hardware, and provider onboarding.

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
- **CSC — Cloud Signature Consortium QTSP** (`chancela-csc`): generic CSC v2 REST adapter
  (`oauth2/token`, `credentials/list`, `credentials/info`, `credentials/sendOTP`,
  `credentials/authorize`, `signatures/signHash`) implementing `RemoteSigningSource`. The API loads
  configured provider ids from `CHANCELA_CSC_PROVIDERS` and secrets from
  `CHANCELA_CSC_<PROVIDER>_*`; offline tests use mocked transports. Live QTSP operation is blocked
  on each provider's sandbox/prod onboarding and credentials. (The `csc-*` template assets are
  *Codigo das Sociedades Comerciais* content, unrelated to the CSC standard.)
- **Manual** (handwritten scan) has no provider — `record_manual_signature` yields
  `EvidentiaryLevel::HandwrittenScanned`, never qualified, and must surface `MANUAL_WARNING`.

### Format + trust

- **CAdES** (`chancela-cades`) — the crypto foundation: `signed_attributes_digest`,
  `assemble_cades_b`, `validate_cades_b`. Algorithms `RsaPkcs1Sha256` (CC v1 + CMD) and
  `EcdsaP256Sha256` (CC v2). Crypto, not trust decisions.
- **PAdES** (`chancela-pades`) — signs a PDF by incremental update (`prepare_signature` →
  caller signs → `embed_signature`; `add_signature_timestamp` upgrades B-B→B-T). B-B and B-T are
  implemented. The local core can append deterministic `/DSS` + `/VRI` incremental revisions from
  caller-supplied DER evidence, merge/dedupe existing DSS streams by content hash, add `/TU`
  validation-time metadata, and report OCSP/CRL/certificate/VRI counts and hashes while keeping
  validation scoped to the signed revision. This is still a technical core: it does not add B-LTA
  archive timestamps or make a production B-LT legal sufficiency claim.
- **Revocation evidence** (`chancela-signing::revocation`) — discovers CRL distribution points and
  OCSP AIA responders from the signer certificate, fetches through bounded/mocked transports, and
  validates technical CRL+OCSP evidence before it is attached to DSS: issuer/responder trust,
  freshness windows, certificate status, and supported signature algorithms. Production source
  policy and legal LTV sufficiency remain outside this claim.
- **TSL** (`chancela-tsl`) — ingests the Portuguese Trusted List (ETSI TS 119 612), validates its
  own XML-DSig on every refresh, and answers `is_qualified_for_esig` →
  `Granted`/`Withdrawn`/`Unknown`. Wired in via the `TrustPolicy` trait (`TslTrustPolicy` real,
  `StaticTrustPolicy` for tests).
  `crates/chancela-api/src/trust.rs` also exposes a read-only catalog surface:
  `GET /v1/trust/status`,
  `/catalog?search=&service_type=&status=&history=&supply_point=&limit=`, `/providers/{id}`, and
  `/services/{id}`. It parses cached TSL XML from the data directory when present, otherwise the
  bundled fixture, and reports source, staleness, XML-DSig validation status, provider/service rows,
  search results, and whether a qualified service is actually trusted by a valid list. The parser
  preserves localized and duplicate names, malformed raw status dates, revoked-like statuses, supply
  points, and service history for diagnostics/search; catalog search is token-aware and
  accent-folded, and provider/detail views expose analysis counts, duplicate-service names, history,
  raw dates, and supply-point evidence. It does **not** live-fetch the TSL or provide a
  buy-certificate workflow.
- **TSA** (`chancela-tsa`) — RFC 3161 timestamp client. Verifies token structure and binding
  (PKIStatus, TSTInfo, imprint/nonce match), signed-attribute binding, signer-certificate
  selection, TSA signature algorithms, and offline certificate-path foundations. Exposed via
  `TimestampProvider`. The trust API adds
  `GET /v1/trust/tsa?search=&service_type=&status=&history=&supply_point=&limit=`, a read-only
  diagnostic surface: configured URL (credential-redacted), RFC 3161 profile, accepted hash, offline
  fixture probe, timestamp-token metadata from the fixture, TSL validation status, policy analysis,
  and searchable TSA/QTST records with trust/blocking analysis. It does not send a live timestamp
  request.

The **trust gate is fail-closed and identical across all paths**: if a `TrustPolicy` is supplied, a
non-`Granted` issuer is rejected (`SigningError::UntrustedService`) *before* any signature is
produced — before the card even prompts for a PIN. The qualified path must supply a policy (a
missing TSL URL is a 422).

### API state machine (`signature.rs`)

Wire states `"unsigned"` → `"pending"` → `"signed"`:

- `POST /v1/acts/{id}/signature/cmd/initiate` (RBAC `SigningPerform`, act must be sealed): TSL gate
  → dispatches OTP → persists a **non-secret** `PendingCmdSession` (5-min TTL) → `pending`.
- `POST /v1/acts/{id}/signature/cmd/confirm`: loads the single-use, actor-scoped, TTL-checked
  session (expired ⇒ 410) → `embed_signature` → `validate_pdf_signature` (SIG-24: ByteRange covers
  the whole file except `/Contents`, and the embedded signer cert must equal the session's leaf —
  anti-substitution) → persists the signed document + a chained `document.signed` event and deletes
  the pending session in one commit → `signed`.
- `POST /v1/acts/{id}/signature/cc/sign`: synchronous CC path over an injected or local smartcard
  provider; the PIN stays at the reader / middleware boundary.
- `POST /v1/acts/{id}/signature/remote/{provider}/initiate|confirm`: generic two-phase remote path
  for `cmd` and configured CSC provider ids, using the same pending-session and signed-document
  persistence discipline.
- `POST|GET /v1/acts/{id}/signature/external-invites` and
  `POST /v1/acts/{id}/signature/external-invites/{invite_id}/revoke`: sealed-act invitation
  tracking only. Create returns a high-entropy token once; the stored record keeps only a SHA-256
  hash plus a redacted hint, list/revoke never expose the secret, and revoked/expired invitation
  status is visible. These endpoints do **not** contact an external provider or complete a legal
  remote signature.
- `POST /v1/signature/external-invites/lookup`,
  `POST /v1/signature/external-invites/document/working-copy`, and
  `POST /v1/signature/external-invites/respond`: unauthenticated token-body envelope for the
  external landing page. Lookup reveals only safe invite/act/document metadata and a descriptor for
  the optional working-copy artifact while the token is valid, unexpired, not revoked, and the act is
  sealed. The working-copy endpoint returns non-canonical Markdown only; it never exposes canonical
  PDF/A or signed-PDF bytes. Respond records accepted/declined acknowledgement and audit state only.
  No token material or qualified-signature completion is returned.
- `GET /v1/signature/providers`, `GET /v1/acts/{id}/signature`, and
  `GET /v1/acts/{id}/document/signed` expose provider availability, state, and the signed variant.
  The act signature status response includes a structured `evidence` object that reports the current
  PAdES level (`Unsigned`, `B-B`, `B-T`, or local `B-LT-local` when timestamped DSS evidence is
  embedded), timestamp presence, embedded DSS/VRI counts, `/TU` metadata, SHA-256 hashes, and
  guardrails such as `production_b_lt_status: "not_claimed"` and `legal_b_lt_claimed: false`. This
  is a technical status surface, not a production B-LT/B-LTA or probative-value claim.

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
variant, so it is unbypassable. A signature artifact is qualified only through a qualified
provider/certificate path; the code and docs make **no "valor probatório" claim** and no shortcut
around legal provider/certificate requirements — the vocabulary is evidentiary *level* +
trusted-list *status*, not probative-value assertions.

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
- **CSC production** needs per-QTSP onboarding, `CHANCELA_CSC_PROVIDERS`, each provider base URL,
  and either client credentials or a user access token in `CHANCELA_CSC_<PROVIDER>_*`. Live tests are
  `network-tests` + `#[ignore]`.
- **TSL/TSA live network operations are feature-gated** and never run in CI; the trust UI's TSA
  diagnostics use an offline fixture probe unless a signing path explicitly requests a timestamp.
- Technical CRL+OCSP revocation evidence collection, DSS merge/dedupe, `/TU` metadata, and
  embedded DSS/VRI append/inspection/reporting exist. Production PAdES B-LT/B-LTA, B-LTA archive
  timestamps, and XAdES/ASiC formats are **not built**, and the implemented evidence remains
  technical evidence only.

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
  Nine seeded defaults with deterministic ids: **Proprietário/Owner** (all perms, protected,
  undeletable), **Gestor**, **Signatário**, **Leitor**, **Platform Administrator**,
  **Tenant Administrator**, **Auditor**, **Guest**, and **API Client**. Protected roles cannot be
  edited or deleted.
- **Delegation** (`delegation.rs`) — one permission at a scope, `starts_at`, optional expiry,
  optional `legal_basis` evidence/rationale, revocable.
- **Effective authority + invariants** (`lib.rs`) — `effective_permissions(...)` builds a
  `ScopedPermissionSet` that **partitions role grants from delegated grants** (load-bearing).
  `has_permission` checks the union; `can_define_role`/`can_assign_role` enforce the subset
  invariant; `can_delegate` requires the permission be held **via a role** (forbids re-delegation and
  meta delegation); `last_owner_guard` keeps ≥1 Owner. An in-crate **escalation battery** test
  denies every known escalation path.

### API stores, migration, enforcement

- **Stores** mirror the `users.json` discipline (atomic tmp+rename, malformed-tolerant, serde
  defaults): `roles.json` → `RoleCatalog` (always forces the canonical locked Owner); `delegations.json`
  → `StoredDelegation` (frozen model + `starts_at`/`legal_basis`, audit fields, revoked records
  retained).
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
- **Guest/read-minimal redaction** (`dto.rs`, `registry.rs`): after a read is authorized, callers
  whose effective authority is only the minimal Guest-style read set receive redacted entity and
  registry/certidão fields (`<redacted>` or `null` as appropriate). Normal reader roles keep the
  full view. This is a first privacy slice, not a complete GDPR/DSR implementation.
- **DSR backend slices** (`privacy.rs`): `GET /v1/privacy/users/{id}/export` is gated by
  `user.manage@Global` and returns non-secret JSON for one user: export metadata, safe account
  fields, role assignments, and authored/user-scoped ledger event references. The request lifecycle
  lives at `POST|GET /v1/privacy/users/{id}/dsr-requests` plus complete/status-transition routes
  under `/v1/privacy/dsr-requests/{id}`. It records export/rectification/erasure/restriction
  requests, pending/completed status, timestamps and actors, optional operator reasons, bounded
  execution evidence (`outcome`, execution actor/time, notes, affected record summaries, retention
  and legal-basis reviews), data-dir JSON sidecar durability (`privacy-dsr-requests.json`), and
  chained create/complete audit events. Sensitive credential markers in execution evidence are
  rejected before mutation/audit. It deliberately excludes password and recovery verifiers, API-key
  secrets, bearer tokens, and attestation private-key material.
- **Processor and DPIA registers** (`privacy.rs`): `GET|POST|PATCH /v1/privacy/processors` and
  `GET|POST|PATCH /v1/privacy/dpias` keep compliance registers under `AppState`, with JSON sidecar
  durability (`privacy-processors.json`, `privacy-dpias.json`) when a data directory is configured.
  Authorization accepts either `user.manage@Global` or `settings.manage@Global`; create/update paths
  enforce strict `risk_level` (`low`, `medium`, `high`, `critical`) and `status` (`draft`, `active`,
  `under_review`, `retired`) values and append audit ledger events. The current slice is operational
  bookkeeping only: UI depth, retention automation, and legal review remain product work.

### Step-up re-auth composition

The highest-bar destructive routes compose **three independent gates**: (1) the RBAC verb@scope
check, (2) a type-to-confirm phrase (e.g. `"RECOMEÇAR"`, `"REPOR FÁBRICA"`), and (3)
`require_step_up` — a `ReAuth { password?, recovery_phrase? }` verified via argon2id against the
acting user's stored verifier. A valid session alone is never enough (failure → `STEP_UP_REQUIRED`).
These are the routes annotated `+ step-up`: book start-over, ledger reanchor/restore, data reset,
data start-over. RBAC gates *who*; step-up re-proves *the human at the keyboard*.

---

## 6. Integration surface

The `/api/v1` namespace is live for integration clients. MCP remains off by default, but API-key
lifecycle, persistence, bearer auth, and per-key HTTP rate limiting are now implemented operator
features.

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
`require_permission_with` gate serves web, integration, and MCP with no bypass. The leaf crate also
defines the token-bucket **per-key rate-limit model** (`ratelimit.rs`, default 60 rpm / 20 burst).
Its own escalation battery denies every mint/resolve of excess authority.

The API layer (`crates/chancela-api/src/apikeys.rs`) persists keys to `apikeys.json` when a data
directory is configured and keeps an in-memory registry for pure ephemeral states. Interactive
`user.manage@Global` sessions can list/create/revoke/rotate keys:
`GET/POST /v1/api-keys`, `DELETE /v1/api-keys/{id}`,
`POST /v1/api-keys/{id}/rotate`. Create/rotate return the plaintext secret exactly once; list,
revocation, persistence, backups, and audit events expose only metadata/prefix/hash-backed records.
HTTP bearer requests enforce the key's rate-limit policy before resolving the attenuated RBAC
principal, returning 429 when the token bucket is exhausted. API-key principals cannot manage keys
and cannot satisfy interactive-session or step-up-only routes.

### MCP server (`crates/chancela-mcp`)

Off-by-default MCP server exposing platform ops as permission-gated tools. Hand-rolled **JSON-RPC
2.0 over stdio** (no MCP SDK, no async runtime), protocol version `2025-06-18`. `catalog()` holds
the current tool entries (`list_entities`, `create_entity`, `draft_minutes`,
`generate_mermaid_graph`, `export_book_archive_package`, `export_act_working_copy`,
`export_ledger_archive_document`, `trust_status`, `search_trust_catalog`, `search_law`, …), each
tagged read-only vs write-controlled with a documented `permission`. `draft_minutes` is a
closed-schema alias to `POST /acts`: it forwards caller-supplied `book_id`, `title`, `channel`,
optional `retifies`, and optional `actor`, creates a draft only, and does not generate legal text.
**The MCP crate is an HTTP client of the integration API**
(`ApiBridge` attaches
`Authorization: Bearer chk_...`, held privately, never logged) — one RBAC path, authz stays
server-side. **Structurally off**: `McpConfig::default()` is `enabled = false`; a disabled config is
refused at construction (`McpError::Disabled`) and `serve_stdio` returns immediately, building no
transport and reading no stdin. Enabling also requires `CHANCELA_MCP_API_KEY` and the tenant AI
gate (`settings.ai.enabled`, surfaced to the MCP process as `CHANCELA_AI_ENABLED`) to be true. Only
stdio ships (HTTP/SSE reserved). Step-up-only destructive routes are structurally out of reach for a
key principal (keys can never hold meta, and those routes require step-up credential proof).

### Live `/api/v1` alias and bearer keys

`router(state)` builds the canonical `/v1/*` table and mounts the same table under `/api`, so
`/api/v1/*` is a live alias. Unknown API paths under either namespace return JSON 404s instead of
falling through to the SPA.

Bearer authentication is wired at the router level:

- `Authorization: Bearer chk_...` is parsed by `apikeys::read_bearer_api_key`.
- malformed/unknown keys return 401; valid keys with insufficient grants return 403 through the same
  `require_permission_with` path as sessions.
- a request may carry a web session or a bearer key, never both.
- session-only/self-service routes reject API-key principals even when the key has adjacent
  permissions.

This is enough for the MCP bridge and live integration tests to call `/api/v1` with real bearer
keys. It still does not make a key an interactive administrator: keys are creator-bounded RBAC
principals and cannot cross the session/step-up boundary.

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
  segmented nav over 13 sections — aparência (default), identidade, documentos, assinaturas,
  gestão, privacidade, utilizadores, chaves API, funções, delegações, integridade (Livros &
  Integridade), dados (Gestão de Dados), sobre. Settings document sections use debounced
  **autosave** (`useAutosave.ts`) over `PUT /v1/settings`; API keys, roles, delegations, and
  privacy processor/DPIA registers are standalone lifecycle surfaces with their own permission gates.
- **Dashboard** (`src/features/dashboard/DashboardPage.tsx`): metrics, ledger-integrity status,
  unresolved-compliance warning, profile-derived fiscal-year-aware advisory annual-calendar
  reminders, and the newest-first recent-ledger feed from `GET /v1/dashboard`. The backend covers
  encoded presets for SA/Lda-like commercial entities, associations, foundations, and cooperatives,
  handles missing/invalid fiscal years and leap-day dates deterministically, and suppresses reminders
  when a recent sealed/archive family-appropriate act already exists.
- **Arquivo / ledger UI** (`src/features/ledger/`): verifies the ledger, lists events with
  chain/scope filters, and downloads the same filtered view through
  `GET /v1/ledger/archive/document` as PDF/A.
- **Ferramentas trust catalog** (`src/features/ferramentas/TrustCatalogPage.tsx`): read-only TSL
  explorer over the trust endpoints, with status/source/signature cards, search/filtering,
  provider/service detail panes, TSA diagnostics, and searchable TSA/QTST records. It reflects
  cached/fixture status honestly and has no live refresh, live TSA probe, or purchase flow.
- **Document/signature panels** (`src/features/documents/`, `src/features/signing/`): sealed acts
  expose canonical PDF/A download plus non-evidentiary Markdown and DOCX working-copy downloads.
  The signing panel shows technical PAdES evidence status, provider flows, signed-PDF download, and
  external signer invitation tracking with one-time token display and redacted list/revoke rows.
  `/assinatura-externa` is the token landing page; it removes the token from the URL after first
  read, can fetch a token-body non-evidentiary Markdown working copy for sealed acts, and records
  acknowledgement only. It does not expose canonical PDF/A or signed-PDF downloads and does not
  complete a legal signature.
- **Onboarding / auth** (t44): `AuthGate` (`src/features/session/`) routes signed-in → app,
  no-user → `/bem-vindo`, users-but-signed-out → `SignIn`, reading the **unauthenticated** roster to
  avoid a 401 lockout. `OnboardingWizard` is a full-screen gilt sibling route
  (welcome → org → user → password → recovery phrase → finish) that creates the first user, signs
  in, enforces the server password policy from `GET /v1/session/password-policy`, issues the
  one-time recovery phrase while signed in, and PUTs the org name + `onboarding.completed`.
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
- **CI coverage.** GitHub Actions run Rust format/clippy/tests on Ubuntu, Windows, and macOS; web
  format/lint/tests/build on Node 20 and 24; composed server E2E on every PR/push; Docker server
  image builds on main; Playwright browser E2E on main or `run-browser-tests`; and Windows Tauri
  desktop smoke on main or `run-desktop-tests`. Browser and desktop jobs upload failure artifacts.
- **Authenticity / no-fabrication.** Two hard rules are enforced in code, not just convention:
  **law text** is never presented unless `Verified` against a complete DRE/EUR-Lex source (Pending
  articles render an explicit unverified marker); **legal thresholds** (quorums, majorities,
  convening periods) are never guessed into template prose — an unresolved threshold renders a loud
  `[a definir: …]` marker, never a number. Compliance authority lives in rule packs, never templates
  (WFL-31).
- **Honest security vocabulary.** The signing subsystem describes itself as producing a **qualified
  electronic signature** only through the required qualified provider/certificate path and reasons
  about evidentiary *level* + trusted-list *status*; it makes no probative-value ("valor
  probatório") claim. Sealing succeeds independently of signing; the qualified status is *derived*,
  never asserted.
- **Off-by-default posture.** The MCP server, qualified-signing enforcement, live signing/provider
  tests, and network fetches (CMD, TSL/TSA, law, CAE, registry) are off or feature-gated by default.
  The `/api/v1` alias and API-key lifecycle are implemented, but production qualified signing still
  needs external credentials (AMA/SCMD for CMD, per-QTSP credentials for CSC, a physical card +
  middleware for CC); flipping the PT law corpus to Verified needs authoritative DRE PDFs.
