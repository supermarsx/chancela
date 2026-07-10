# Chancela - Spec Coverage

*Updated 2026-07-10 from committed implementation snapshot `949ddd2`, including
the external signing workflow tool, template law-reference exposure, persisted
platform log tail, entity-list ergonomics, data-storage status/cleanup, local
PDF signature-validation, PDF validator UI, template-filter, operational
trust-provider selection, guarded archive disposal evidence, browser E2E
matrix, UI polish, web unit-test coverage thresholds, AI/MCP assurance copy,
legacy DOC evidence imports and validation UI, bounded ASiC-S signing support,
PDF accessibility metadata modeling, bounded tagged PDF structure, and local
long-term signature evidence status. It is an implementation coverage snapshot,
not a legal certification and not a claim that qualified-trust production
operation is complete.*

Status vocabulary:
**IMPLEMENTED** (landed and verifiable), **PARTIAL** (usable slice landed but
the spec requirement is not complete), **STUB** (shape exists, behavior deferred),
**MISSING** (no implementation), **N/A-v1** (deliberately deferred).

The old exact requirement counts are intentionally not carried forward: the recent
batch changed enough surfaces that the counts need a full line-by-line re-audit before
being useful. The matrix below records the current factual coverage and the remaining
blockers.

---

## Current Status By Spec

| Spec area | Status | Current working-tree coverage | Remaining local work | External / legal blockers |
|---|---|---|---|---|
| spec/01 Product Scope (SCP) | PARTIAL | One Rust core still drives server, web, Docker, and Tauri desktop. Durable mode exists through `CHANCELA_DATA_DIR`; in-memory mode is explicit on `/health`, and Settings now exposes storage mode/data-folder/usage telemetry from `/v1/data/status` plus bounded crash-report/retained-export cleanup through `/v1/data/cleanup`. | Mobile companion remains deferred; edition packaging still needs signed/notarized publication hardening. | None specific. |
| spec/02 Legal & Compliance (LEG) | PARTIAL | Compliance gates, rule-pack failures with structured legal-basis references, DRE/EUR-Lex law corpus authenticity gating, legal-threshold placeholders, bounded template law-reference exposure from rule-pack IDs and threshold references, recovery/audit trails, step-up controls, delegation evidence fields, guest/minimal redaction for entity/registry reads, backend DSR user export, tracked DSR request lifecycle with data-dir JSON durability, bounded DSR execution evidence, user-management DSR UI, processor/DPIA compliance registers with settings UI and data-dir JSON durability, a persisted retention-policy register with non-destructive dry-run reports, audit-only retention execution-request evidence, and guarded non-destructive archive disposal execution evidence with ledger audit exist. DRE-sourced law and template law references remain Pending/fail-closed unless authoritative evidence and legal review are present. | Actual physical deletion, destructive/automated GDPR erasure beyond bounded evidence, complete per-family legal packs, broader redaction/data lifecycle coverage, broader retention/disposal policy automation, exhaustive/verified template law mapping, and legally verified threshold values remain local product work. | Authoritative DRE text/PDF access is needed to mark PT law corpus entries Verified; legal review is needed before replacing threshold placeholders with numbers or treating template references as complete/authoritative. |
| spec/03 Entity Profiles (ENT) | PARTIAL | Five families are modeled; profile/rule-pack binding exists, statute overlays feed compliance findings, bounded capital/permilage weighted tally and quorum consistency checks exist where complete attendance weights are captured, condominium data-quality warnings catch missing meeting time, contradictory attendance counts, and impossible permilagem values/totals, and template assets now cover commercial companies, condominiums, associations, foundations, and cooperatives across many stages. | Deeper family-specific rule packs, groups, legally exhaustive weighted-voting policies, and broader calendar preset depth remain incomplete. | Legal review of non-CSC packs and thresholds. |
| spec/04 Signatures & Trust (SIG) | PARTIAL | CMD, CC, generic CSC remote-signing, and local soft-cert/PKCS#12 signing foundations are exposed in the signing/API layers; PAdES/CAdES signing, bounded single-payload ASiC-S/CAdES container creation and validation, signed-document persistence, provider listing/status metadata, TSL XML-DSig validation/catalog status/search, TSA diagnostics/search, B-T timestamping when configured, local PAdES DSS/VRI append/reporting with existing-DSS merge/dedupe and `/TU` metadata, DocTimeStamp parsing/imprint evidence in signature/archive reports, a gated local arbitrary-PDF/PAdES validation endpoint with Ferramentas UI, additive settings for multiple TSL sources and TSA providers, operational selection of configured TSL/TSA providers in trust refresh/catalog, signing trust-policy selection, and timestamping selection/reporting, external-validator corpus sidecars with strict technical-only status transitions and raw-report preservation metadata, technical timestamp-trust diagnostics with persistence when validator inputs are available, technical CRL+OCSP revocation evidence collection, API/archive embedded DSS/VRI reporting, precise local B-LT/B-LTA technical evidence status with legal flags kept false, signature evidence status reporting/UI, fail-closed trust checks, explicit XAdES/unsupported-ASiC-profile tests/wording, external-signer invitation tracking/UI, token lookup/respond safe working-copy access, gated external-signing envelope APIs, and a Ferramentas external-signing workflow tool with redacted invite listings, status summaries, same-origin token-link handling, and public envelope lookup are present. | SCAP attributes, XAdES generation/validation, ASiC-E/XAdES/multi-payload/manifest support, production/legal PAdES or ASiC B-LT/B-LTA completion or claim, embedded LT/LTA evidence, external-signer legal signing completion, multi-signature VRI/archive timestamp renewal depth, real operator-recorded external validator reports for the corpus, broader provider-management policy automation, and controlled live provider/hardware integration depth remain incomplete. API signing, arbitrary-PDF validation, and external-signing workflow tracking are technical/operational evidence flows, not claims that every seal, uploaded PDF, invite response, or ASiC container is qualified/legal-valid. | Live CMD requires AMA/SCMD credentials and prod cert. Live CSC/QTSP requires provider onboarding and credentials. CC requires card, reader, and Autenticacao.gov middleware. Production TSL/TSA/revocation use requires production network configuration, valid source material, and policy/legal review; path-backed TSA providers and unsupported timestamp digests block deterministically rather than falling back to fake live signing. |
| spec/05 Data Model / Roles (DAT/ROL) | PARTIAL | SQLite-backed durable store, multi-chain ledger, recovery/degraded mode, data-folder permission/usage telemetry with SQLite logical usage estimates, `settings.manage`-gated maintenance cleanup for crash reports and retained exports, users, complete seeded role catalog, scoped RBAC, delegations with `starts_at`/`legal_basis`, sessions, API-key principals, guest redaction first slice, step-up re-auth, password/recovery controls, and guarded non-destructive archive disposal execution evidence with ledger audit are implemented. | Tenant/group model, broader privacy/redaction lifecycle, live SQLCipher/at-rest DB encryption, ZK, sync/connectors, actual physical deletion, broader retention/disposal policy automation, GDPR erasure, and complete data lifecycle policies remain. | None specific beyond legal review for access/redaction policies. |
| spec/06 Workflows (WFL) | PARTIAL | Book/act lifecycle, sealing with structured rule-pack/profile metadata and explicit UI acknowledgement before sealing non-blocking compliance warnings, retification, document generation, closed-book read-only enforcement for pre-existing act patch/advance/seal/archive/convening-dispatch mutations, qualified-signature status, dashboard data including fiscal-year-aware profile-derived annual-calendar reminders with i18n-backed alert copy, actionable open-follow-up reminders, backup/restore, book import/export, historical paper-book validation plus non-canonical preservation/list/download with source page/original-number range metadata and continuation recommendations, start-over/reset workflows, and bounded external-signer invite links with token-gated safe working copies are present. | Full legal-calendar preset depth, OCR/reviewed canonical conversion workflows for preserved paper-book packages, external signer legal completion, richer dashboard feeds, and family-specific workflow depth remain. | Provider credentials for live qualified signing. |
| spec/07 Architecture (ARC) | PARTIAL | Durable store, hot backup/restore, encrypted backup envelopes, recovery mode, `/api/v1` integration alias with JSON 404 namespace guards, persisted API-key lifecycle with bearer principal resolution, HTTP rate limiting, and attenuation tests for creator downgrade/deactivation/scope loss, MCP stdio server, platform service status/control endpoints with settings-backed API/MCP desired state, strict app/API/MCP log-level policy, audit tail, `/v1/platform/logs?service_id=&level=&tail=` for a bounded API-owned structured platform log tail gated by `settings.read`, data-dir persistence to `platform-logs.json` when `CHANCELA_DATA_DIR` is configured with a 512-entry bound and in-memory fallback otherwise, structured log entries from platform service status/control paths, honest supervisor/restart-required outcomes, data status/cleanup endpoints, Docker build/runtime smoke, persistent container data path, release version-consistency guard, tag/manual package-artifact workflow, package manifests/checksums, web unit-test coverage thresholds in CI, CI dependency SBOM generation/checking, report-only npm/Cargo/Docker vulnerability artifacts with an enforced manual mode, Docker OCI metadata/security artifacts, feature-gated SQLCipher keyed-open foundation, optional `CHANCELA_DB_KEY` / `CHANCELA_DB_KEY_FILE` startup wiring that fails closed when unsupported/invalid, and Tauri desktop shell are in tree. | Sync, storage connectors, HA profiles, real supervisor-backed API/MCP process lifecycle, supervisor-forwarded MCP process logs, historical stdout/stderr tailing, broader durable/live structured log sinks and reload/process logging beyond the API-owned tail, SQLCipher migration/rotation/ops strategy, sidecar encryption strategy, repo-level ZK, coverage thresholds beyond web unit tests, broader browser E2E coverage, live provider/hardware integration tests beyond compile-only seams, signed/notarized installers, signed/attested Docker images, and mobile builds remain. | SQLCipher feature verification on this Windows host is blocked by vendored OpenSSL requiring a Windows-compatible Perl rather than the available Cygwin Perl. |
| spec/08 Documents & Archive (DOC) | PARTIAL | Template rendering, frozen `DocumentModel`, deterministic PDF/A-2u writer with embedded fonts and ToUnicode maps, conservative accessibility/PDF-UA blocker reporting without false PDF/UA identification, report-side alt-text/decorative metadata modeling, minimal tagged PDF structure with MCIDs, `StructTreeRoot`, `RoleMap`, `ParentTree`, page `StructParents`, `MarkInfo` true, and artifact marking, seal/book document generation, document bundle endpoint with structured technical validation reports for consistency/fixity/canonical-PDF/signed-document evidence and explicit non-certification flags, signed-document endpoint, Arquivo PDF/A export from ledger filters, working-copy Markdown/TXT/HTML/RTF/ODT/DOCX exports, read-only candidate import validation with fixity, legacy DOC/OLE-CFB recognition, and signed-PDF/PAdES structural status, local arbitrary-PDF signature validation for structure/ByteRange/PAdES/DSS/DocTimeStamp evidence, persisted non-canonical imported-document evidence including legacy DOC bytes with retained bytes/metadata-only ledger events and UI, web pre-persistence import validation evidence/refusal findings for legacy DOC/OLE-CFB candidates, historical paper-book validation plus persisted non-canonical package preservation/list/download with source page/original-number range metadata, retained-export maintenance cleanup, deterministic internal preservation ZIPs with archive evidence reports including DocTimeStamp/imprint evidence, validator corpus raw-report sidecar preservation metadata, inventory preflight/self-validation, DGLAB-aligned internal preservation metadata with explicit non-certification flags, export-time legal-hold marking, persisted book-level legal hold, disposal eligibility/dry-run status, and guarded non-destructive disposal execution evidence are implemented. | Imported-document preservation policy depth, OCR, full PDF/UA delivery beyond minimal tagged structure, richer structure trees/tagging/role maps/marked artifacts, canonical conversion or legal acceptance for legacy DOC/paper-book evidence, production/legal signed-import validation beyond local structural/PAdES checks, official DGLAB interchange/certification, retained-export policy depth, actual physical deletion, broader disposal/retention policy automation, GDPR erasure linkage, and legal acceptance/certification remain incomplete. | Legal review of generated template content/thresholds. |
| spec/09 AI & MCP (AI) | PARTIAL | MCP server and API bridge exist, with tools mapped to `/api/v1` including Mermaid chronology, working-copy, archive package, ledger archive, trust catalog, law tools, exact AI-11 `prepare_archive_export` and `validate_signature_bundle` tools, `draft_minutes`, and AI-11 compatibility aliases (`list_companies`, `get_company_timeline`, `search_legal_texts`); live API bearer tests cover the bridge. MCP now requires both the local MCP switch and a tenant AI gate (`settings.ai.enabled` / `CHANCELA_AI_ENABLED`), draft tools return an explicit non-authoritative `ai_draft` provenance envelope with human verification required and fail closed on sealed/non-draft API shapes, `validate_signature_bundle` wraps the existing signature endpoint as technical evidence only with no legal-validation claim, and the web settings/platform surface can manage the tenant gate and display AI/MCP assurances for gates, API-key RBAC, draft status, and signature-bundle scope without exposing secrets. Law corpus search/browse endpoints and registry import support provenance-adjacent workflows. | AI drafting/extraction/comparison/summarization depth, workflow-level provenance panels beyond MCP output and the settings/platform assurance panel, and non-stdio MCP transports remain. | None specific. |
| spec/10 UX & Design (UX) | PARTIAL | Web shell, 14-locale i18n runtime and catalog completeness checks, onboarding/auth gate, password-policy checklist, settings, Settings-only users/RBAC/delegation/API-key/recovery/privacy/UI platform-operations UI with AI/MCP assurance copy, settings-managed app/API/MCP logging controls, Data Management storage telemetry and cleanup UI, imported-document evidence UI including pre-persistence validation/refusal evidence for non-canonical legacy DOC/OLE-CFB imports, paper-book import list/download UI, document preview, PDF/Markdown/TXT/HTML/RTF/ODT/DOCX working-copy downloads, signature evidence with local B-LT/B-LTA technical labels, external-invite UI, external-invite landing page, Ferramentas external-signing workflow tool, dashboard reminders/work queue with localized alert keys, persisted notification triage with read/dismiss/acknowledge/restore controls, explicit seal-warning acknowledgement modal, compliance source/reference rendering, registered-entity primary filters that wrap without horizontal scrolling, collapsed accordion-style advanced filters that expand into wrapped multi-line controls, fixed/clamped registered-entity table cells with up-to-two-line text where needed, concise Type/Last Activity visible summaries with tooltips, improved template primary/advanced filters, Arquivo UI, Trust/TSL/TSA catalog UI with truncated/copyable digests, a PDF signature validator tool UI, bundled PDF fonts, button hover/leather active states, storage-tab spacing polish, and desktop window controls/smoke coverage are present. | Mobile UX, PDF/UA delivery beyond the bounded tagged-structure slice, richer dashboard ergonomics, broader table ergonomics beyond the entities/templates/storage slices, and broader legal-source/provenance linking remain. | None specific. |
| spec/11 Template Catalog (TPL) | PARTIAL | `chancela-templates` loads 83 JSON template assets; API exposes `GET /v1/templates`, previews, on-demand generation, seal/book hooks, catalog summary metadata for channels, signature policy hints, rule-pack IDs, and bounded `law_references` derived from rule-pack IDs plus threshold references, with Pending status and source provenance. The web catalog can search/filter by those metadata fields, keeps search/family/stage as primary controls, moves locale/channel/signature/rule-pack filters into a collapsed advanced area, and shows metadata in summary/detail views. | Template market parity, legally verified threshold values, broader statute-overlay depth, exhaustive/verified law-reference mapping, and full family/rule-pack validation are not complete. | Legal review before any template wording, law reference, or threshold is treated as authoritative. |

---

## Recent Coverage Added

- **Bounded ASiC-S signing support:** `chancela-signing` can now create and validate bounded
  single-payload ASiC-S/CAdES containers for the supported local signing envelope path. This is not
  ASiC-E, XAdES, multi-payload packaging, manifest processing, embedded LT/LTA evidence, or a legal
  qualified-signature claim.
- **Legacy Word import validation evidence in the web UI:** the document import panel now calls
  `/v1/documents/import/validate` before persistence and renders validation evidence or safe
  refusal findings for legacy `.doc`/OLE-CFB candidates with localized copy. The flow still treats
  legacy Word files as preserved non-canonical evidence only; it does not execute macros, convert to
  canonical PDF/A, or assert legal acceptance.
- **Bounded tagged PDF structure:** `chancela-doc` now emits a minimal tagged structure for generated
  PDFs: MCIDs, `StructTreeRoot`, `RoleMap`, `ParentTree`, page `StructParents`, `MarkInfo` true, and
  artifact marking. The accessibility report still keeps `pdf_ua_claimed: false` and the
  `limited_tagged_structure` blocker, so this is a technical accessibility slice rather than PDF/UA
  delivery or certification.
- **Data storage visibility and bounded cleanup:** `GET /v1/data/status` reports the current
  persistence mode, configured data folder, directory existence/type, read/create/write/delete
  permission probes, durable SQLite open state, schema/ledger counters, and filesystem plus SQLite
  logical usage breakdowns. `POST /v1/data/cleanup` is gated by `settings.manage` and performs
  maintenance cleanup for crash reports and retained exports only, reporting requested/skipped
  targets and byte counts without broad deletion semantics. Data Management renders the same status
  with refresh, copy-path, scan-error, browser-safe open-folder-disabled states, and cleanup
  controls. This does not add durable log retention, SQLCipher production enablement, storage
  migration tooling, arbitrary deletion, GDPR erasure, legal retention execution, or complete data
  lifecycle automation.
- **Local PDF signature validator endpoint:** `POST /v1/signature/pdf/validate` accepts a bounded
  raw PDF or JSON/base64 envelope and returns local technical evidence: file SHA-256/size,
  PDF-structure markers, signature and ByteRange signals, PAdES/CAdES validation where available,
  DSS/VRI/OCSP/CRL/certificate evidence counts/hashes, DocTimeStamp imprint checks, and explicit
  trust/revocation/qualification sections marked not performed. The endpoint is gated by
  `act.read@Global`, fails closed on declared digest/size mismatches, persists no uploaded bytes, and
  does not claim AMA validation, legal effect, qualified status, or live TSL/TSA/revocation checks.
- **PDF validator tool UI:** Ferramentas now has a `Validador PDF` sub-tab that reads an uploaded
  PDF in the browser, computes a declared SHA-256 and byte length when possible, calls
  `/v1/signature/pdf/validate`, and renders a readable local-evidence report covering structure,
  PAdES/CAdES, ByteRange, DSS/VRI, DocTimeStamp, trust, revocation, qualification, and findings.
  Digest/size backend refusals are surfaced as a safe refusal. The UI copy is explicit that this is
  technical local validation only, not AMA/legal/qualified validation.
- **Operational trust-provider selection:** Settings serializes and validates additive
  `signing.tsl_sources` and `signing.tsa_providers` arrays while preserving the legacy
  `signing.tsl_url` and `signing.tsa_url` fields. Enabled TSL sources are now selected for trust
  refresh/catalog views and signing trust-policy construction before the legacy fallback. The
  enabled default TSA provider is selected for timestamping and surfaced in TSA catalog/reporting
  before the legacy fallback. Selection reports configured/enabled/disabled counts and keeps
  deterministic blockers honest: path-backed TSA providers require a future local replay/signing
  implementation, and unsupported timestamp digests block instead of silently producing fake live
  timestamp evidence. This still does not claim production legal trust completion.
- **Template filter ergonomics and wording:** the Minutas catalog now keeps search/family/stage in a
  compact primary filter row and moves locale/channel/signature/rule-pack filters into a
  collapsed-by-default advanced area. The PT source catalog also replaces the awkward
  `Todo o registo` filter label with `Qualquer estado`.
- **Button state and storage-tab polish:** web styling now applies broader button hover and leather
  active states, and the Data Management storage tab has tighter spacing around telemetry and
  maintenance controls. This is UX polish only; it does not expand functional compliance coverage.
- **Platform operations and logging policy:** Settings now carries an additive `platform` section
  with strict app/API/MCP log levels, per-service overrides, API/MCP desired state, last-action
  metadata, and an audit tail. `/v1/platform/services` reports API and MCP status plus limitations,
  `/v1/platform/services/{id}/actions/{action}` records start/stop/restart desired state with
  audit evidence, and `/v1/platform/logs?service_id=&level=&tail=` returns the newest bounded
  API-owned structured platform log tail with strict `settings.read` access and service/level/tail
  validation. When `CHANCELA_DATA_DIR` is configured, the API-owned tail is persisted to
  `platform-logs.json` and bounded to 512 entries; otherwise the in-memory fallback remains.
  Platform status reads and control requests add structured API log entries. The web Settings
  `Operações` tab exposes the same status, log controls, and action buttons, plus an AI/MCP
  assurance panel for managers covering dual gates, API-key RBAC, non-authoritative draft output,
  and technical-only signature-bundle scope without exposing secrets. This is honest
  desired-state/control evidence plus an API-owned log tail only: it is not historical
  stdout/stderr, does not include MCP child-process logs unless forwarded as structured API events,
  and is not a complete durable/live structured sink or reload/process logging pipeline.
- **Entity list ergonomics:** registered-entity filters now keep search/family/type in a compact
  primary area that wraps instead of forcing horizontal scroll, and move the rest into a collapsed
  accordion-style advanced filter area that expands into wrapped multi-line controls. The table uses
  fixed layout and clamped cells so verbose values do not overflow; long text can occupy up to two
  lines, while Type and Last Activity render shorter visible summaries with full tooltips.
- **Template catalog metadata:** `/v1/templates` now exposes each template summary's supported
  meeting channels, signature-policy hint, and rule-pack ID. The web catalog filters/searches those
  fields, renders badges and detail rows for operators, and keeps the 14-locale catalog matrix in
  sync. This improves discoverability but does not make template wording or thresholds legally
  authoritative.
- **Template law references:** templates and `/v1/templates` summaries now expose bounded
  `law_references` derived from rule-pack IDs and threshold references, including source
  provenance and Pending status. The mapping improves operator traceability, but it is not
  exhaustive, does not mark DRE material Verified, and is not a legal review of the template text,
  threshold value, or referenced law.
- **Document bundle validation report:** `GET /v1/acts/{id}/document/bundle` now returns a
  structured technical validation report instead of a placeholder: route/document consistency,
  canonical PDF structure markers, SHA-256 fixity, attachment digest coverage, signed-document
  linkage/evidence when present, and explicit non-certification flags. It is local technical
  evidence only and does not claim PDF/A certification, qualified-signature validity, production
  LTV, DGLAB certification, or trust-provider validation.
- **PDF accessibility metadata and bounded tagging model:** the PDF/A writer's accessibility report
  accepts an explicit report-side alternate-text/decorative-artifact model and generated PDFs now
  include a minimal tagged structure with MCIDs, structure tree, role map, parent tree, page parent
  mapping, MarkInfo, and artifact marking. This narrows the previous accessibility gap, but still
  does not emit PDF/UA identification metadata, keeps `pdf_ua_claimed: false`, and reports the
  structure as limited rather than certified PDF/UA delivery.
- **Password hardening:** `GET /v1/session/password-policy` exposes the server-authoritative rules
  and password-setting paths enforce them: minimum length, character classes, username/common
  password checks, repeat/sequence checks, Argon2 verifiers, sign-in backoff, one-time recovery
  phrases, and step-up composition for destructive actions. Onboarding and user-management UI now
  consume this policy.
- **Arquivo backend and UI:** `GET /v1/ledger/archive/document` renders a filtered ledger chain
  archive as PDF/A-2u without mutating state. The web ledger page lets the operator select chain and
  scope filters and download the same archive document.
- **Archive evidence and working copies:** `GET /v1/books/{id}/archive/package` now streams a
  deterministic internal preservation ZIP with manifest fixity, metadata sidecars, signed-document
  sidecars, timestamp-token evidence when present, DocTimeStamp validation/imprint evidence where
  present, and per-document evidence reports instead of placeholder validation slots. Full external
  validator inputs are still reported as not persisted unless a later flow records them.
  `?legal_hold=true&legal_hold_reason=...` marks that generated
  package as non-disposable and adds `evidence/legal-hold.json`; this is explicit export-time
  evidence, not persisted legal-hold state. `GET /v1/acts/{id}/document/working-copy` exports
  non-evidentiary Markdown, TXT, HTML, RTF, or deterministic ODT for review without mutating the
  preserved PDF/A or ledger, and the web document panel exposes these separately from the official
  PDF/A and DOCX downloads.
- **Archive integrity preflight:** archive package export and disposal dry-run now validate the
  preservation inventory before producing package members: duplicate or non-canonical document IDs,
  path-like metadata, missing PDF bytes, wrong PDF profile/header, digest mismatches, mismatched
  signed-document links, empty signature/certificate/timestamp material, and impossible signed-time
  metadata are refused. Generated ZIP bytes are self-validated with the archive manifest validator
  before being returned.
- **DGLAB-aligned preservation metadata:** internal archive manifests now include structured producer
  and preservation-interchange metadata, deterministic ordering, and validation for missing/blank
  metadata, unsafe members, duplicate IDs, and tampered package members. The manifest explicitly
  records `official_dglab_interchange: false` and `dglab_certification_claimed: false`; this is not
  an official DGLAB package or certification claim.
- **Trust/TSL/TSA catalog API and UI:** `GET /v1/trust/status`, `/catalog?search=&limit=`,
  `/providers/{id}`, `/services/{id}`, and `/tsa?search=&limit=` expose read-only trust status from
  cached XML, a configured enabled TSL source, or the bundled fixture. Ferramentas shows TSL
  source/staleness/XML-DSig status, provider/service search, CA/QC/qualified/trusted flags, plus
  selected TSA configuration, runtime selection diagnostics, offline fixture probe diagnostics,
  timestamp-token metadata, and searchable TSA/QTST records. The parser/search slice preserves
  localized and duplicate names, service history, service supply points, revoked-like statuses, and
  malformed raw status dates for diagnostics; search is token-aware and accent-folded. Live TSA
  timestamping happens only when a signing flow explicitly requests it, and catalog fixture evidence
  is not a legal trust source.
- **Trust structured analysis:** TSL and TSA catalog queries now accept structured filters for
  service type, status, history, and supply points. Provider/service detail exposes analysis counts,
  duplicate-service names, raw dates, history records, and supply-point evidence; TSA records expose
  policy/trust analysis plus blocking reasons so operators can distinguish advisory fixture data
  from a trusted qualified timestamp source.
- **API-key lifecycle and integration API:** `/api/v1/*` is mounted as an alias of `/v1/*`. Bearer
  keys are read from `Authorization: Bearer chk_...`, may not be mixed with web sessions, and resolve
  through the same RBAC permission gate as sessions. The lifecycle is implemented with
  `apikeys.json` persistence, `GET/POST /v1/api-keys`, `DELETE /v1/api-keys/{id}`,
  `POST /v1/api-keys/{id}/rotate`, shown-once create/rotate secrets, audit ledger events,
  per-key HTTP token-bucket enforcement, settings UI, and API/MCP bearer tests.
- **Roles, delegations, guest redaction:** The seeded role catalog now covers Owner, Gestor,
  Signatário, Leitor, Platform Administrator, Tenant Administrator, Auditor, Guest, and API Client.
  Delegations carry `starts_at` and optional `legal_basis` evidence, persist to `delegations.json`,
  and remain non-redelegable. Minimal guest/read-only callers get redacted entity and registry views
  for the implemented first slice.
- **Privacy/DSR backend lifecycle:** `GET /v1/privacy/users/{id}/export` returns a user-scoped,
  non-secret JSON export with metadata, safe account fields, role assignments, and authored ledger
  event references. It is gated by `user.manage@Global` and explicitly excludes credential
  verifiers, recovery phrases, API-key secrets, bearer tokens, and attestation private keys.
  `POST|GET /v1/privacy/users/{id}/dsr-requests` plus complete/status-transition routes track
  export, rectification, erasure, and restriction requests with timestamps, actors, optional
  operator reasons, bounded execution evidence (`outcome`, execution actor/time, notes, affected
  record summaries, retention/legal-basis reviews), fail-closed transitions, JSON sidecar
  durability for restart/restore, and audit ledger events. Sensitive credential markers in
  execution evidence are rejected before mutation/audit. The settings-only user management surface
  exposes create, list, complete, and non-rendered JSON export download actions to `user.manage`
  operators.
- **Processor/DPIA compliance registers:** `GET|POST|PATCH /v1/privacy/processors` and
  `GET|POST|PATCH /v1/privacy/dpias` maintain processor and DPIA registers under the privacy
  module, with data-dir JSON sidecar durability for restart/restore. They are gated by
  `user.manage@Global` or `settings.manage@Global`, enforce strict `risk_level` and `status`
  values, sanitize list output, and append audit ledger events.
  The settings privacy tab adds search/filtering plus create/edit/status/risk controls and only
  loads the registers for operators with the matching permissions.
- **Retention policy register:** `GET|POST|PATCH /v1/privacy/retention-policies` and
  `POST /v1/privacy/retention-policies/dry-run` maintain bounded retention policy records with
  JSON sidecar durability, strict enum validation, sensitive-marker rejection, and create/update
  audit events. Dry-run reports only applicability and always returns `would_execute: false`;
  deletion/anonymization/archival execution remains out of scope. The dry-run surface now accepts an
  optional execution request and records an audit-only execution evidence object with actor,
  requested policy, matched-record summary, legal-hold blockers, operator notes/evidence, and
  `would_execute: false`; destructive, stale, missing-policy, and legal-hold cases remain blocked.
- **Persisted book legal hold:** `GET|PUT|DELETE /v1/books/{id}/legal-hold` stores book-level legal
  hold metadata (`reason`, `actor`, `set_at`) through the existing durable book aggregate and appends
  ledger events on set/clear. Archive packages automatically include active persisted holds in
  retention metadata and evidence sidecars, while the export-time hold option remains available.
- **Archive disposal dry-run and execution evidence:** `GET|POST
  /v1/books/{id}/archive/disposal` reports disposal eligibility and produces a guarded dry-run
  `would_delete` manifest. `dry_run=false` now records a guarded non-destructive execution record
  plus ledger audit event for an eligible closed book under a matching active archive retention
  policy. Execution blocks on active legal-hold policy/book state, degraded or in-memory runtime,
  open book chains, unsealed acts, missing preserved documents, mismatched/missing policy, and
  repeated execution. The record marks source records/package members as disposal evidence only,
  reports `physical_deletion_performed: false`, and performs no physical deletion.
- **Document import validation and persistence:** `POST /v1/documents/import/validate` accepts raw
  bytes or a JSON/base64 envelope and returns a read-only structural report with declared/detected
  content type, byte size, SHA-256 digest, fixity checks against declared size/digest,
  PDF/PDF-A-ish markers, legacy OLE-CFB/`.doc` recognition, signed-PDF/ByteRange signals,
  signed-PDF status (`unsigned`, `structurally_signed`, `valid_pades_b`, `invalid`,
  `indeterminate`), ByteRange digest/coverage metadata, and whether the candidate can be accepted as
  a non-canonical import. Malformed/truncated ByteRange data, duplicate ByteRange markers, ambiguous
  OLE/PDF claims, invalid PAdES/CAdES validation, and declared size/digest mismatches fail closed.
  Legacy DOC imports are accepted only as preserved non-canonical evidence: no macro execution,
  conversion, or canonical PDF/A generation is performed. `POST /v1/documents/import`,
  `GET /v1/documents/imported`, `GET /v1/documents/imported/{id}`, and
  `GET /v1/documents/imported/{id}/bytes` persist and expose validated non-canonical imported
  evidence through store schema v5. The `document.imported` ledger event carries metadata only; raw
  bytes remain in the store. The document panel now validates candidates before persistence, renders
  legacy DOC/OLE-CFB evidence or refusal findings, exposes import/list/metadata/original-byte
  download controls, and keeps all copy explicit that imported documents are non-canonical evidence.
  This does not replace preserved canonical documents, convert legacy Word files, or prove
  legal/signature validity.
- **Historical paper-book validation and preservation:** `POST /v1/books/paper-import/validate`
  returns a read-only report for historical paper-book scans/packages, checking identity metadata,
  date span, page count, source page range, optional original ata-number range, optional digest,
  source filename, and notes. `POST /v1/books/paper-import` re-runs validation and fixity checks,
  preserves PDF/ZIP/octet-stream package bytes in the durable store, appends a metadata-only
  `paper_book_import.preserved` ledger event, and records the import as non-canonical evidence with
  explicit linking metadata plus a continuation recommendation, but no legal, signature-validity,
  qualified-signature, or canonical minutes claim. `GET /v1/books/paper-import[?book_ref=...]`,
  `GET /v1/books/paper-import/{id}`, and `GET /v1/books/paper-import/{id}/bytes` list metadata,
  read metadata, and download retained bytes explicitly. The web book detail flow exposes the same
  list/download surface. OCR, reviewed canonical conversion, and legal acceptance remain follow-up
  work.
- **Closed-book act immutability:** The act mutation API now explicitly rejects patch, advance,
  seal, archive, and convening-dispatch requests for acts whose owning book is no longer open. The
  focused API tests verify open-book behavior still works, closed-book mutations return conflict,
  and failed mutations do not append ledger events or persist state across reload.
- **External signer invitation tracking:** sealed acts can create/list/revoke external signer
  invite records under `/v1/acts/{id}/signature/external-invites`. Tokens are returned exactly once,
  stored hashed/redacted, and audit events are appended; this is tracking/envelope infrastructure,
  not completed remote signing. Unauthenticated token-body lookup/respond endpoints expose only safe
  invite/act/document metadata while the token is live, record accepted/declined acknowledgement
  events, and never return token material or canonical PDF/signed-PDF downloads. A token-body-only
  public endpoint can return a non-canonical Markdown working copy for sealed acts; it is explicitly
  non-evidentiary and not a qualified signature. The signing panel exposes create/list/revoke plus
  one-time token display, and `/assinatura-externa` is the token landing page.
- **External signing workflow tool:** Ferramentas now includes an External Signing tool at
  `/ferramentas?tool=external-signing` for operational tracking. It lists redacted invite records,
  summarizes response/status state, handles same-origin token links, looks up public envelope
  metadata, and uses localized copy. This is still invite/envelope tracking and safe working-copy
  access, not legal signing completion, qualified-signature validation, or canonical signed-PDF
  delivery.
- **Signature evidence status:** `GET /v1/acts/{id}/signature` includes a structured `evidence`
  object that distinguishes unsigned, PAdES B-B, timestamped B-T, local B-LT-style technical
  evidence, and local B-LTA-style DocTimeStamp evidence states, including partial local evidence
  cases. It reports timestamp presence, inspects embedded DSS/VRI evidence when present, reports
  OCSP/CRL/certificate/VRI counts and SHA-256 hashes, reports embedded DocTimeStamp
  validation/imprint binding, maps persisted technical timestamp-trust diagnostics when validator
  inputs were stored with the signed artifact, and keeps `production_b_lt_status: "not_claimed"`,
  `legal_b_lt_claimed: false`, `legal_b_lta_claimed: false`, and `live_revocation_fetching: false`
  instead of implying legal long-term validation. The signing panel shows the same evidence as
  technical status only.
- **Local DSS/VRI and revocation core:** `chancela-pades` can append deterministic `/DSS` + `/VRI`
  incremental revisions from caller-supplied DER evidence, reject empty revocation evidence,
  merge/dedupe pre-existing DSS streams by content hash, write `/TU` validation-time metadata, and
  report OCSP, CRL, certificate, VRI, `/TU`, and evidence hash counts while validating the signed
  revision separately from later DSS bytes. `chancela-signing` exposes the low-level attach/report
  path plus technical CRL+OCSP evidence collection with bounded transports, freshness/status,
  issuer/responder trust, and signature checks. The API plus archive evidence reports surface
  embedded DSS/VRI counts/hashes as technical evidence. This remains non-production-LTV: no
  production B-LT/B-LTA legal sufficiency claim, no multi-signature VRI handling, and no archive
  document timestamp chain.
- **DocTimeStamp and validator corpus:** `chancela-pades` includes deterministic technical
  DocTimeStamp fixtures plus imprint-binding validation, including the future-DocTimeStamp corpus
  case. `docs/fixtures/validator-corpus` tracks generated PDFs, expected EU DSS/Adobe sidecars, and
  pending/recorded external-validator status. `scripts/record-validator-sidecar.mjs` records raw
  operator validator reports with source filename, byte length, SHA-256 hash, media type,
  preservation actor/time, evidence scope, and status transition metadata; the validation script
  enforces technical-only `legal_validity_assessment: not_assessed` sidecars and preserves raw
  report material without transcribing a broader legal pass/fail claim. These fixtures improve
  interoperability evidence but do not replace live qualified validation.
- **Signing provider status and XAdES/ASiC honesty:** settings now include read-only provider-mode
  metadata for CMD/SCMD, CC, CSC/QTSP, and local PKCS#12 so operators can distinguish configured,
  blocked, and local-only paths without entering secrets in the UI. `chancela-signing` now has
  focused signing/validation tests and docs that keep XAdES unsupported while recognizing the
  bounded ASiC-S/CAdES slice. ASiC-E, ASiC-XAdES, multi-payload containers, manifests, embedded
  LT/LTA evidence, and legal qualified-signature claims remain explicitly out of scope.
- **CMD legal integration position:** `docs/CMD-LEGAL-INTEGRATION.md` records the current product
  stance: Chancela can integrate with CMD/CC/QTSP flows without itself becoming the qualified trust
  provider, but cannot honestly create handwritten-equivalent qualified signatures without the
  provider/certificate/hardware/onboarding requirements those flows depend on.
- **Office and working-copy exports:** `GET /v1/acts/{id}/document/office` returns a
  deterministic DOCX working copy for sealed acts with a non-evidentiary warning and
  preserved-document metadata. `GET /v1/acts/{id}/document/working-copy?format=md|txt|html|rtf|odt`
  provides non-evidentiary review copies, with ODT emitted as a deterministic minimal
  OpenDocument Text ZIP using fixed member timestamps. The stored PDF/A or signed PDF remains the
  canonical record, and the document panel exposes DOCX, Markdown, TXT, HTML, RTF, and ODT downloads
  beside the official PDF/A download with localized labels and warning copy.
- **Dashboard reminders:** `GET /v1/dashboard` includes advisory annual-calendar reminders from
  encoded profile calendar presets. Commercial SA/Lda-like entities, associations, foundations, and
  cooperatives are covered where a profile preset defines a fiscal-year offset; unsupported or stale
  profile data emits no false reminder. Due dates use the entity's recorded fiscal-year end when
  valid, fall back explicitly to the default calendar-year model when absent/invalid, clamp leap-day
  edge cases deterministically, suppress reminders when a sealed/archive act already provides a
  recent calendar signal, and now carry i18n keys so the web notification/dashboard copy is resolved
  through the locale catalog. The reminder remains advisory and bounded by current calendar preset
  data.
- **Notification triage and seal acknowledgement:** `GET/PATCH /v1/notifications/triage` persists
  dashboard-derived notification triage per actor in `notification-triage.json` when a data dir is
  configured. The web bell and notifications page now merge dashboard alerts/reminders with
  read/dismissed/acknowledged state, hide resolved items from active views, provide a resolved tab,
  and keep a local-storage fallback for older/missing backends. The ata editor no longer sends an
  implicit warning acknowledgement on clean seals; non-blocking compliance warnings require an
  explicit modal checkbox before the seal request carries `acknowledge_warnings: true`.
- **Compliance source references:** the compliance panel now renders existing source/reference
  metadata on rule findings and convening/statute advisories. `http`/`https` references open as
  external links; structured legal references and unsafe/non-http URL values remain inert text. The
  UI does not fabricate source metadata or mark pending law as verified.
- **DRE corpus guard:** DRE-sourced Portuguese law entries remain Pending unless the repository has
  complete authoritative source text/PDF evidence. The guard prevents accidental presentation of
  partial resolver metadata as verified law text; authoritative DRE exports or equivalent source
  capture are still required before the pending entries can be promoted.
- **Settings-only user management:** the standalone `/utilizadores*` screens now redirect into
  `Configurações -> Utilizadores`, preserving create/edit/access deep-link state. Settings is the
  single canonical user-management surface.
- **Registry chronology:** the registry import layer exposes deterministic chronology events and
  Mermaid shareholders/organs/relationships views for imported extracts. This covers the current
  relationship-graph slice; richer visual editing and source-linked compliance remain future work.
- **MCP tool coverage:** The stdio MCP catalog includes read/write-controlled `/api/v1` tools for
  entity/book/act operations, the `draft_minutes` alias to the draft-act API, Mermaid chronology
  graphs, document preview and working-copy export, book preservation packages, ledger PDF/A archive
  export, exact AI-11 `prepare_archive_export`, technical-only `validate_signature_bundle`,
  TSL trust search/detail, law search, and compatibility aliases for company timeline/legal-text
  terminology. The draft tool uses closed-schema argument validation before any HTTP call; it
  creates only a draft record and does not generate legal text. Successful MCP draft calls are
  wrapped in a non-authoritative provenance envelope (`ai_draft`) with human verification required,
  source endpoint/tool, actor, timestamp, and null model/provider placeholders; sealed or non-draft
  API shapes are refused instead of presented as drafts. The signature-bundle tool wraps the
  existing signature status endpoint as technical evidence only and refuses to claim legal
  validation. The server is still off by default and now additionally refuses to serve unless the
  tenant AI gate is enabled; settings UI exposes that default-off tenant gate to managers.
- **E2E / CI / desktop coverage:** CI now includes multi-OS Rust format/clippy/tests, web
  format/lint/tests/build on Node 20 and 24, web unit tests with enforced Vitest/V8 coverage
  thresholds, composed server E2E, opt-in Playwright browser E2E with artifacts, Docker server image
  build on main, and opt-in Windows Tauri desktop smoke with artifacts. A separate tag/manual
  release workflow builds Linux/Windows/macOS package artifacts and uploads package
  manifests/checksums without claiming signing/notarization. Local scripts include
  `npm run test:e2e`, `npm run check:versions`, Docker smoke, and `apps/desktop` smoke helpers.
  Static-serving E2E now covers encoded/odd API paths so integration clients receive JSON 404s
  rather than the SPA shell. Archive package E2E now covers persisted legal hold after restart and
  blocked disposal with no partial state change. Browser E2E now covers disabled pre-seal document
  downloads, repeated canonical PDF/A download, separate non-evidentiary Markdown/TXT/HTML/RTF/ODT/DOCX
  working-copy downloads, preservation ZIP download, signing fallback UI, and ledger archive PDF/A export. The web
  production build explicitly splits stable React/router/query/Tauri vendor chunks from the app
  bundle, keeping the main application chunk under the default Vite large-chunk warning threshold.
  Current audit caveats remain: browser E2E is not exhaustive, coverage thresholds outside the web
  unit-test lane are not broadly enforced, live signature/provider seams are compile-only, release
  packages are not signed or notarized, and Docker images are not signed or attested.
- **Recent-landed checkpoint:** `npm run test:checkpoint:recent-landed` and the GitHub Actions
  `recent-landed` job pin the cross-cutting recent work: paper import API tests, archive package and
  DocTimeStamp evidence tests, web contract/dashboard/i18n tests, validator corpus sidecar validation, and
  desktop lockfile metadata. The static mode catches accidental removal of the mapped files and
  fixture markers without running the full commands.
- **Release and store hardening foundations:** packaging now stages `manifest.json` and `SHA256SUMS`
  with artifact metadata/checksums and includes the host CLI plus operator scripts when present.
  CI now generates and validates a CycloneDX dependency SBOM from npm/Cargo lockfiles, uploads
  npm/Cargo advisory reports, can make scans blocking on manual `enforce_security_scans=true`
  dispatches, and records Docker image inspect/Syft/Trivy/signing-status artifacts without claiming
  registry publication, signing, attestation, or notarization.
  `chancela-store` has a feature-gated SQLCipher keyed-open foundation with typed unavailable and
  rejected-key errors while preserving default plaintext behavior. API/server startup now resolves
  `CHANCELA_DB_KEY` / `CHANCELA_DB_KEY_FILE`, rejects ambiguous/empty/unreadable key config without
  logging secrets, refuses configured encryption on no-SQLCipher builds before creating a plaintext
  database, and preserves plaintext startup when unset. Plaintext-to-encrypted migration,
  key rotation/ops, and sidecar encryption remain follow-up work.

---

## Remaining Blockers

### Local product work

- Legal/product depth: per-family rule-pack completeness, legally verified
  threshold values, exhaustive/verified template law references, full guest/privacy redaction
  coverage, destructive/automated DSR execution workflows beyond bounded evidence, and DPIA
  documentation depth.
- Data lifecycle/storage: the cleanup endpoint covers crash reports and retained exports only, and
  archive disposal execution is non-destructive evidence only; actual physical deletion, broader
  retention/disposal policy automation, GDPR erasure, broader export-retention policy controls,
  storage migration/recovery tooling, and legal-hold-aware operator workflows remain implementable
  next slices before any data-lifecycle compliance claim.
- Documents/archive: imported-document preservation-policy depth, production/legal signed-import
  validation beyond the local structural/PAdES checks, full PDF/UA delivery beyond the bounded
  tagged-structure slice, richer structure trees/tagging/role maps/marked artifacts, OCR and
  reviewed canonical/legal conversion for preserved legacy DOC and historical paper-book evidence,
  official DGLAB interchange/certification, actual physical deletion, broader disposal/retention
  policy automation, GDPR erasure linkage, legal acceptance/certification, and long-term signature
  evidence packaging beyond the implemented sidecars.
- Trust/signing depth: production/legal B-LT/B-LTA, XAdES, ASiC-E/XAdES/multi-payload/manifests,
  embedded ASiC LT/LTA evidence, PKCS#11/operator certificate workflows, multi-signature/archive
  timestamp renewal depth, production provider-management flows, actual operator validator report
  collection for the corpus, and external signer legal completion beyond invite/envelope tracking.
- Workflow breadth: legal-calendar preset depth beyond the advisory dashboard reminder, OCR,
  operator review, and canonical-conversion flows for preserved paper-book packages, external
  signer document-gated/legal completion flows, richer dashboards, groups/tenancy,
  sync/connectors, live SQLCipher/at-rest DB encryption, ZK, HA, and mobile builds.
- AI feature layer: drafting/extraction/compare/summarize, workflow-level provenance panels beyond
  the MCP envelope and settings/platform assurance panel, human verification checkpoint, and
  additional MCP transports.
- CI/release assurance: broaden browser E2E for critical workflows, add or explicitly waive
  coverage thresholds beyond the web unit-test lane, convert compile-only live signature seams into
  controlled integration lanes where credentials/hardware exist, sign/notarize release packages, and
  sign/attest Docker images.

### External / provider / legal blockers

- **CMD:** production use depends on AMA/SCMD onboarding credentials and the prod field-encryption
  certificate. Offline tests do not prove live SCMD operation.
- **CSC/QTSP:** the generic CSC v2 adapter and API route exist, but each provider still requires
  sandbox/prod onboarding, client credentials or user authorization, credential selection, and live
  provider testing.
- **CC:** production use requires physical Cartao de Cidadao, reader, and Autenticacao.gov
  middleware on the operator machine.
- **TSL/TSA:** trust refresh/catalog, signing trust-policy selection, and timestamping
  selection/reporting now consume configured enabled TSL/TSA entries with legacy fallbacks, but
  production trust operation still needs valid live source material, production network
  configuration, and policy/legal review. TSA diagnostics use an offline fixture probe unless a
  signing flow explicitly requests a timestamp. Path-backed TSA providers and unsupported timestamp
  digests remain deterministic blockers, not fake live signing. The bundled fixture is advisory and
  must not be treated as legal trust completion.
- **Law/legal review:** PT DRE corpus entries need authoritative source text/PDF extraction before
  they can be marked Verified; the current guard intentionally keeps incomplete DRE captures
  Pending. Generated templates, exposed template law references, and threshold values need legal
  review before they are treated as authoritative or complete.
- **Qualified-signature requirements:** CMD/legal-signature copy must stay explicit that there is no
  legal shortcut around qualified provider, qualified certificate, hardware, and onboarding
  requirements.
- **Release trust chain:** release packages are not signed/notarized and Docker images are not
  signed/attested until the workflows have production signing identities, registry publication, and
  verified artifact provenance.

---

## Do Not Overstate

- Chancela helps produce compliant evidence; it does not create legal validity or replace provider
  credentials, qualified-trust onboarding, or legal review.
- A qualified signature artifact can be produced through configured providers, but the repository
  does not include AMA/QTSP credentials, physical CC hardware, or live-provider legal onboarding.
- CMD/CC/CSC flows do not bypass qualified provider/certificate requirements; production legal
  validity still depends on the appropriate qualified trust service and certificate context.
- The Trust/TSL catalog is a visibility surface, not a purchase workflow and not proof of qualified
  trust production readiness.
- External signing workflow screens and public envelope lookup are operational tracking surfaces;
  accepted/declined invite responses are not legal signing completion or qualified-signature
  validation.
- Local B-LT/B-LTA labels report technical evidence observed in the file; they are not production
  or legal long-term-validation claims.
- Template law references are bounded Pending provenance links derived from current rule-pack and
  threshold metadata; they are not exhaustive, legally verified, or a substitute for reviewing the
  generated template wording.
- Accessibility metadata and bounded tagged structure are not PDF/UA delivery; the writer still
  keeps `pdf_ua_claimed: false` and reports limited tagged structure rather than certification.
- Data cleanup is bounded storage maintenance for crash reports and retained exports. Guarded
  archive disposal execution is non-destructive ledger/audit evidence only; it is not physical
  deletion, GDPR erasure, legal retention certification, or certification of data-lifecycle
  compliance.
- The persisted platform log tail covers API-owned structured events only and is bounded to 512
  entries; it is not stdout/stderr capture, MCP child-process logging, complete historical logging,
  or a general observability sink.
- CI and E2E coverage improve release confidence, and web unit tests now enforce coverage
  thresholds, but the current browser suite is not exhaustive and other lanes do not have broad
  coverage thresholds.
- SBOMs, checksums, package manifests, and Docker OCI metadata are not substitutes for package
  signing, notarization, Docker signing, or attestation.
- `/api/v1` API keys are an implemented integration feature, but a bearer key is still an
  attenuated RBAC principal, not an interactive user session or step-up credential.
