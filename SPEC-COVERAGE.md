# Chancela - Spec Coverage

*Updated 2026-07-10 from committed implementation snapshot `35f54d6`,
refreshing the stale `fc0d541` snapshot with the post-`fc0d541` commits:
`5f55141` validator report evidence metadata, `de9302e` imported-document
review state, `5c15008` external signed-invite evidence E2E, `c54fc0e` MCP
status resource, `291dfd2` paper OCR review evidence fields, `1a75083` CI
hardening doc refresh, `fb7d11e` imported-document review UI, and `7267040`
MCP human-review prompt, and `696913f` archive/document-bundle validator
evidence indexing, `696a887` imported-document review browser regression, and
`8a79478` retained-export cleanup guardrails, `9997162` Docker release-trust
metadata hardening, and `35f54d6` durable AI human-verification gate. Earlier
coverage text remains prior snapshot context.
All top-level spec areas remain **PARTIAL**. This is an implementation and test
coverage snapshot, not a legal certification, not production CMD approval, not
DRE verification promotion, not full PDF/UA delivery, and not a claim that
qualified-trust production operation, release signing/notarization/attestation,
live SQLCipher encryption/rotation/migration, legal document acceptance,
signed-PDF legal validity, or destructive GDPR erasure is complete.*

Status vocabulary:
**IMPLEMENTED** (landed and verifiable), **PARTIAL** (usable slice landed but
the spec requirement is not complete), **STUB** (shape exists, behavior deferred),
**MISSING** (no implementation), **N/A-v1** (deliberately deferred).

The old exact requirement counts are intentionally not carried forward: the recent
batch changed enough surfaces that the counts need a full line-by-line re-audit before
being useful. The matrix below records the current factual coverage and the remaining
blockers.

Implementation checkpoints covered here:

- `1d6ccdc` keeps AI/MCP **PARTIAL**: MCP draft responses now expose explicit
  pending/accepted/rejected human-verification status values, a pending checkpoint
  envelope, and false legal-validity flags. This is metadata for human review, not
  a persisted acceptance/rejection workflow or legal certification.
- `e6517f6` keeps Template Catalog **PARTIAL**: authored catalog tests now validate
  required metadata, duplicate template IDs, rule-pack law-reference anchors,
  derived template law references, and non-blank law-reference fields. This is
  regression coverage for catalog metadata, not legal review or exhaustive statute
  mapping.
- `a6e0cfe` keeps Data/Architecture **PARTIAL**: key-ops status now serializes a
  secret-free backup/export-restore migration plan with evidence and non-destructive
  steps, and startup errors point operators to restoring and verifying the ledger.
  It still does not execute migration, prove encryption, or rotate keys.
- `0d38f92` keeps Legal/Data Lifecycle **PARTIAL**: retention execution requests are
  now persisted to `privacy-retention-executions.json` in data-dir mode and listed
  through `GET /v1/privacy/retention-executions` for privacy-manage actors. They
  remain audit-only records with `would_execute: false`, not deletion, anonymization,
  archival execution, or GDPR erasure.
- `fc0d541` keeps Signatures/Documents/Workflows **PARTIAL**: an external invite
  accept response can include a signed PDF upload that is locally screened for PAdES
  structure, ByteRange coverage, and sealed-PDF prefix match, then preserved as
  `ExternalSignerHandoff` / `ExternalSignedPdfTechnicalEvidence`. Trust-list,
  qualified-signature, and legal-validity claims remain explicitly false/not
  performed.
- `5f55141` keeps Signatures/Documents **PARTIAL**: validator corpus scripts now
  build archive-ready external-validator report evidence metadata attachments and
  an evidence JSON index from recorded sidecars. This is technical report metadata,
  not legal validity, trust-list validation, or a qualified-signature decision.
- `de9302e` keeps Documents/Data **PARTIAL**: imported documents now carry stored
  operator review status, reviewer/time/note metadata, and a review endpoint while
  retaining original bytes. Review records workflow decisions only; they do not run
  OCR, convert to PDF/A, replace canonical documents, or claim legal acceptance.
- `5c15008` keeps Signatures/UX **PARTIAL**: browser E2E now covers an external
  signer invite on an already signed act, proving the public tracking flow does not
  fetch or expose the signed PDF and remains working-copy/tracking-only.
- `c54fc0e` keeps AI/MCP/Architecture **PARTIAL**: MCP now advertises and serves a
  read-only `chancela://mcp/status` resource with operability metadata, no API-key
  material, and no integration API health probe.
- `291dfd2` keeps Documents/Workflows **PARTIAL**: paper-book OCR draft review
  evidence now exposes explicit false `canonical_act_created`,
  `canonical_document_created`, and `signature_created` fields and keeps review
  notes out of ledger payloads. It is OCR-review metadata, not canonical conversion.
- `1a75083` keeps CI/Release **PARTIAL**: `docs/CI-E2E-HARDENING-PLAN.md` was
  refreshed for the then-current CI shape, SQLCipher feature lane, web coverage
  command, and focused MCP status checks. This is planning/checklist coverage, not
  a fresh full-green release claim.
- `fb7d11e` keeps Documents/UX **PARTIAL**: the web document panel can display and
  submit imported-document review status/note updates. It is an operator review UI
  for non-canonical evidence, not OCR, conversion, legal acceptance, or PDF/A
  replacement.
- `7267040` keeps AI/MCP **PARTIAL**: MCP prompt discovery now exposes a static
  `draft_minutes_human_review_checklist` prompt. The checklist is guidance-only,
  accepts no caller arguments, performs no hidden provider calls, does not sign or
  seal anything, and creates no legal validity.
- `696913f` keeps Signatures/Documents **PARTIAL**: archive packages now include
  a technical `evidence/index.json`, document-bundle validation reports now expose
  `validation_report.evidence_index`, and validator-corpus evidence attachments
  describe archive-package and document-bundle indexing metadata. These are
  technical metadata indexes only, not legal validity, trust-list validation,
  qualified-signature validation, DGLAB certification, or authority acceptance.
- `696a887` keeps Documents/UX/CI **PARTIAL**: focused browser E2E now route-stubs
  an imported-document review flow and checks conservative non-canonical evidence
  messaging plus review PATCH behavior. This is regression coverage for the review
  UI contract, not exhaustive browser coverage, OCR, conversion, legal acceptance,
  or PDF/A replacement.
- `8a79478` keeps Data/Documents **PARTIAL**: retained-export cleanup now accepts
  export-only dry-run, minimum-age, and keep-latest guardrails with API regression
  tests, while rejecting those policy options for crash cleanup. These controls are
  retained-export cleanup policy guardrails only; they are not GDPR erasure, legal
  disposal approval, physical deletion guarantees beyond the existing bounded
  cleanup behavior, or complete data-lifecycle automation.
- `9997162` keeps Architecture/Release **PARTIAL**: Docker release-trust metadata
  checks now require stronger production-mode anchors such as image/artifact
  digests, HTTPS workflow/run URLs, signing identity or certificate fingerprints,
  and attestation predicate metadata. This validates declared metadata only; it
  does not verify an actual registry push, image signature, attestation, or release
  trust chain.
- `35f54d6` keeps AI/MCP/Workflows **PARTIAL**: AI-origin draft provenance can be
  persisted on acts, MCP draft tools inject non-authoritative provenance, and the
  TextApproved-to-Signing transition is blocked until a human review decision is
  recorded as accepted. The accepted/rejected state is a durable human-review gate
  only; it is not legal validity, an AI quality assessment, or a full provenance UI
  panel.

---

## Current Status By Spec

| Spec area | Status | Current working-tree coverage | Remaining local work | External / legal blockers |
|---|---|---|---|---|
| spec/01 Product Scope (SCP) | PARTIAL | One Rust core still drives server, web, Docker, and Tauri desktop. Durable mode exists through `CHANCELA_DATA_DIR`; in-memory mode is explicit on `/health`, and Settings now exposes storage mode/data-folder/usage telemetry from `/v1/data/status` plus bounded crash-report/retained-export cleanup through `/v1/data/cleanup`. | Mobile companion remains deferred; edition packaging still needs signed/notarized publication hardening. | None specific. |
| spec/02 Legal & Compliance (LEG) | PARTIAL | Compliance gates, rule-pack failures with structured legal-basis references, DRE/EUR-Lex law corpus authenticity gating, legal-threshold placeholders, bounded template law-reference exposure from rule-pack IDs and threshold references, bounded corpus citation resolution that preserves Verified/Pending status, recovery/audit trails, step-up controls, delegation evidence fields, guest/minimal redaction for entity/registry/book/act/imported-document metadata reads, backend DSR user export, tracked DSR request lifecycle with data-dir JSON durability, bounded DSR execution evidence, user-management DSR UI, processor/DPIA compliance registers, privacy breach-playbook and transfer-control registers with settings UI and data-dir JSON durability, a persisted retention-policy register with non-destructive dry-run reports, persisted/listable audit-only retention execution-request evidence, and guarded non-destructive archive disposal execution evidence with ledger audit exist. DRE-sourced law, copied corpus citations, and template law references remain Pending/fail-closed unless authoritative evidence and legal review are present. | Actual physical deletion, destructive/automated GDPR erasure beyond bounded evidence, complete per-family legal packs, privacy/redaction/data lifecycle coverage beyond the current read-redaction and register slices, broader retention/disposal policy automation, exhaustive/verified template/citation law mapping, and legally verified threshold values remain local product work. | Authoritative DRE text/PDF access is needed to mark PT law corpus entries Verified; legal review is needed before replacing threshold placeholders with numbers or treating template/citation references as complete/authoritative. |
| spec/03 Entity Profiles (ENT) | PARTIAL | Five families are modeled; profile/rule-pack binding exists, statute overlays feed compliance findings, bounded capital/permilage weighted tally and quorum consistency checks exist where complete attendance weights are captured, condominium data-quality warnings catch missing meeting time, contradictory attendance counts, and impossible permilagem values/totals, and template assets now cover commercial companies, condominiums, associations, foundations, and cooperatives across many stages. | Deeper family-specific rule packs, groups, legally exhaustive weighted-voting policies, and broader calendar preset depth remain incomplete. | Legal review of non-CSC packs and thresholds. |
| spec/04 Signatures & Trust (SIG) | PARTIAL | CMD, CC, generic CSC remote-signing, and local soft-cert/PKCS#12 signing foundations are exposed in the signing/API layers; PAdES/CAdES signing, bounded single-payload ASiC-S/CAdES container creation and validation, bounded ASiC-E/CAdES manifest container creation and validation for payload digest binding, signed-document persistence, provider listing/status metadata, TSL XML-DSig validation/catalog status/search, TSA diagnostics/search, B-T timestamping when configured, local PAdES DSS/VRI append/reporting with existing-DSS merge/dedupe and `/TU` metadata, DocTimeStamp parsing/imprint evidence in signature/archive reports, a gated local arbitrary-PDF/PAdES validation endpoint with Ferramentas UI, additive settings for multiple TSL sources and TSA providers, operational selection of configured TSL/TSA providers in trust refresh/catalog, signing trust-policy selection, and timestamping selection/reporting, external-validator corpus sidecars with strict technical-only status transitions, raw-report preservation metadata, archive-ready evidence attachment metadata projection, and validator-corpus evidence-indexing metadata for archive package `evidence/index.json` plus document-bundle `validation_report.evidence_index`, technical timestamp-trust diagnostics with persistence when validator inputs are available, technical CRL+OCSP revocation evidence collection, API/archive embedded DSS/VRI reporting, precise local B-LT/B-LTA technical evidence status with legal flags kept false, signature evidence status reporting/UI, fail-closed trust checks with CMD/CC/TSA failure-matrix tests, explicit XAdES/unsupported-ASiC-profile tests/wording, external-signer invitation tracking/UI, token lookup/respond safe working-copy access, optional signed-PDF upload on accepted invite responses stored as `ExternalSignerHandoff` / `ExternalSignedPdfTechnicalEvidence`, gated external-signing envelope APIs, a Ferramentas external-signing workflow tool with redacted invite listings, status summaries, same-origin token-link handling, public envelope lookup, browser E2E proving signed-invite tracking does not expose signed PDFs, and a generated AMA/CMD evidence-pack scaffold with no-approval-claim templates are present. | SCAP attributes, XAdES generation/validation, ASiC-XAdES, ASiC-E profiles beyond the bounded single-manifest CAdES digest-binding path, multiple ASiC-E signatures/manifests/extensions, production/legal PAdES or ASiC B-LT/B-LTA completion or claim, embedded LT/LTA evidence, external-signer legal/qualified completion beyond uploaded technical signed-PDF evidence, multi-signature VRI/archive timestamp renewal depth, real operator-recorded external validator reports for the corpus and attachment population into runtime indexes, broader provider-management policy automation, controlled live provider/hardware integration depth, and production AMA/CMD authority approval remain incomplete. API signing, arbitrary-PDF validation, external-signing workflow tracking/uploaded evidence, validator report evidence metadata/indexing, archive package `evidence/index.json`, document-bundle `validation_report.evidence_index`, and AMA/CMD evidence-pack generation are technical/operational evidence flows, not claims that every seal, uploaded PDF, invite response, ASiC container, validator report, evidence index, or CMD integration is qualified/legal-valid, trust-list validated, or authority-approved. | Live CMD requires AMA/SCMD credentials, prod cert, and authority onboarding/approval. Live CSC/QTSP requires provider onboarding and credentials. CC requires card, reader, and Autenticacao.gov middleware. Production TSL/TSA/revocation use requires production network configuration, valid source material, and policy/legal review; path-backed TSA providers and unsupported timestamp digests block deterministically rather than falling back to fake live signing. |
| spec/05 Data Model / Roles (DAT/ROL) | PARTIAL | SQLite-backed durable store, multi-chain ledger, recovery/degraded mode, data-folder permission/usage telemetry with SQLite logical usage estimates, secret-free database key-ops status/preflight for key config, build capability, database-header format, plaintext-to-encrypted migration refusal, and structured non-destructive export/restore migration-plan guidance, `settings.manage`-gated maintenance cleanup for crash reports and retained exports, users, complete seeded role catalog, scoped RBAC, delegations with `starts_at`/`legal_basis`, sessions, API-key principals, guest/minimal read redaction for entity, registry, book, act, and imported-document metadata, step-up re-auth, password/recovery controls with hardened verifier-storage regression tests, and guarded non-destructive archive disposal execution evidence with ledger audit are implemented. | Tenant/group model, broader privacy/redaction lifecycle beyond read-response redaction, live SQLCipher/at-rest DB encryption proof, actual encryption migration/rotation execution workflow, ZK, sync/connectors, actual physical deletion, broader retention/disposal and incident/transfer control automation, GDPR erasure, and complete data lifecycle policies remain. | None specific beyond legal review for access/redaction policies. |
| spec/06 Workflows (WFL) | PARTIAL | Book/act lifecycle, sealing with structured rule-pack/profile metadata and explicit UI acknowledgement before sealing non-blocking compliance warnings, retification, document generation, closed-book read-only enforcement for pre-existing act patch/advance/seal/archive/convening-dispatch mutations, convening `evidence_reference` capture in act editing/patching, qualified-signature status, dashboard data including fiscal-year-aware profile-derived annual-calendar reminders with i18n-backed alert copy, actionable open-follow-up reminders, compact activity summaries, and active legal-hold/sealed-not-archived archive lifecycle alerts with advisory next steps, backup/restore, book import/export, historical paper-book validation plus non-canonical preservation/list/download with source page/original-number range metadata and continuation recommendations, start-over/reset workflows, bounded external-signer invite links with token-gated safe working copies, and accepted-invite signed-PDF technical evidence upload are present. | Full legal-calendar preset depth, OCR/reviewed canonical conversion workflows for preserved paper-book packages, external signer legal/qualified completion beyond technical evidence upload, richer dashboard feeds beyond the current reminders/activity/archive lifecycle alert slices, and family-specific workflow depth remain. | Provider credentials for live qualified signing. |
| spec/07 Architecture (ARC) | PARTIAL | Durable store, hot backup/restore, encrypted backup envelopes, recovery mode, `/api/v1` integration alias with JSON 404 namespace guards, persisted API-key lifecycle with bearer principal resolution, HTTP rate limiting, and attenuation tests for creator downgrade/deactivation/scope loss, MCP stdio server with tools, resources, static prompt discovery, and a secret-free `chancela://mcp/status` operability resource, platform service status/control endpoints with settings-backed API/MCP desired state, strict app/API/MCP log-level policy, audit tail, `/v1/platform/logs?service_id=&level=&tail=` for a bounded API-owned structured platform log tail gated by `settings.read`, data-dir persistence to `platform-logs.json` when `CHANCELA_DATA_DIR` is configured with a 512-entry bound and in-memory fallback otherwise, structured log entries from platform service status/control paths, honest supervisor/restart-required outcomes, data status/cleanup endpoints, Docker build/runtime smoke, persistent container data path, hardened Docker Compose deployment profiles, release version-consistency guard, tag/manual package-artifact workflow, package manifests/checksums with package artifact integrity checking, release-trust metadata validation for package declarations and local/production Docker declarations with stricter production Docker metadata anchors, package `sourceProvenance` manifest validation against current `HEAD`, web unit-test coverage thresholds in CI, CI dependency SBOM generation/checking, report-only npm/Cargo/Docker vulnerability artifacts with an enforced manual mode, Docker OCI metadata/security artifacts, a documented SQLCipher Windows feature lane, feature-gated SQLCipher keyed-open foundation, optional `CHANCELA_DB_KEY` / `CHANCELA_DB_KEY_FILE` startup wiring that fails closed when unsupported/invalid, secret-free key-ops status with operator action text and startup refusal for direct plaintext-to-encrypted keyed open, structured export/restore migration-plan guidance, and Tauri desktop shell are in tree. | Sync, storage connectors, HA profiles, real supervisor-backed API/MCP process lifecycle, supervisor-forwarded MCP process logs, historical stdout/stderr tailing, broader durable/live structured log sinks and reload/process logging beyond the API-owned tail, live SQLCipher encryption verification, executed plaintext-to-encrypted migration/export-restore flow, key rotation/ops workflow, sidecar encryption strategy, repo-level ZK, coverage thresholds beyond web unit tests, broader browser E2E coverage, live provider/hardware integration tests beyond compile-only seams, actual release signing/notarization, actual Docker image signing/attestation and registry-publication verification beyond metadata-anchor checks, production-grade HA/orchestration profiles, and mobile builds remain. | SQLCipher feature verification on this Windows host is blocked by vendored OpenSSL requiring a Windows-compatible Perl rather than the available Cygwin Perl. |
| spec/08 Documents & Archive (DOC) | PARTIAL | Template rendering, frozen `DocumentModel`, deterministic PDF/A-2u writer with embedded fonts and ToUnicode maps, conservative accessibility/PDF-UA blocker reporting without false PDF/UA identification, report-side alt-text/decorative metadata modeling, minimal tagged PDF structure with MCIDs, `StructTreeRoot`, `RoleMap`, `ParentTree`, page `StructParents`, `MarkInfo` true, and artifact marking, seal/book document generation, render-context exposure for convening `evidence_reference`, document bundle endpoint with structured technical validation reports for consistency/fixity/canonical-PDF/signed-document evidence, `validation_report.evidence_index`, and explicit non-certification flags, signed-document endpoint, external-invite uploaded signed-PDF technical evidence served through the signed-document path, Arquivo PDF/A export from ledger filters, working-copy Markdown/TXT/HTML/RTF/ODT/DOCX exports with API matrix coverage and browser export/save E2E coverage, read-only candidate import validation with fixity, preservation-review policy metadata for imported-document candidates and stored imported documents, persisted imported-document operator review state/notes, web review controls that retain original bytes only, and focused browser regression coverage for conservative imported-document review messaging/PATCH behavior, legacy DOC/OLE-CFB recognition, signed-PDF/PAdES structural status, local arbitrary-PDF signature validation for structure/ByteRange/PAdES/DSS/DocTimeStamp evidence, persisted non-canonical imported-document evidence including legacy DOC bytes with retained bytes/metadata-only ledger events and UI, expanded imported-document evidence families, guest redaction for imported-document filename/digest/importer/download metadata, web pre-persistence import validation evidence/refusal findings for legacy DOC/OLE-CFB candidates, historical paper-book validation plus persisted non-canonical package preservation/list/download with source page/original-number range metadata, paper-book OCR draft review metadata with explicit false canonical/signature creation fields, retained-export maintenance cleanup with export-only dry-run/minimum-age/keep-latest guardrails, deterministic internal preservation ZIPs with archive evidence reports including DocTimeStamp/imprint evidence and a technical archive package `evidence/index.json`, archive package tamper-failure tests, validator corpus raw-report sidecar preservation metadata, evidence attachment metadata projection, and evidence-indexing metadata, inventory preflight/self-validation, DGLAB-aligned internal preservation metadata with explicit non-certification flags, export-time legal-hold marking, persisted book-level legal hold, disposal eligibility/dry-run status, dashboard archive lifecycle alerts for active holds and sealed-not-archived acts, and guarded non-destructive disposal execution evidence are implemented. | Deeper imported-document preservation review workflow beyond the current status/note decisions and focused browser regression, OCR execution, full PDF/UA delivery beyond minimal tagged structure, richer structure trees/tagging/role maps/marked artifacts, canonical conversion/PDF/A generation or legal acceptance for legacy DOC/paper-book evidence, production/legal signed-import validation beyond local structural/PAdES checks and technical uploaded evidence, populated external-validator report attachments in runtime archive/document-bundle indexes beyond the current metadata paths, official DGLAB interchange/certification, retained-export policy depth beyond the current cleanup guardrails, actual physical deletion, broader disposal/retention policy automation, GDPR erasure linkage, and legal acceptance/certification remain incomplete. | Legal review of generated template content/thresholds. |
| spec/09 AI & MCP (AI) | PARTIAL | MCP server and API bridge exist, with tools mapped to `/api/v1` including Mermaid chronology, working-copy, archive package, ledger archive, trust catalog, law tools, exact AI-11 `prepare_archive_export` and `validate_signature_bundle` tools, `draft_minutes`, and AI-11 compatibility aliases (`list_companies`, `get_company_timeline`, `search_legal_texts`); live API bearer tests cover the bridge. MCP now requires both the local MCP switch and a tenant AI gate (`settings.ai.enabled` / `CHANCELA_AI_ENABLED`), advertises tools/resources/prompts, exposes a secret-free `chancela://mcp/status` resource, and exposes a static `draft_minutes_human_review_checklist` prompt that accepts no arguments and performs no hidden calls. Draft tools return an explicit non-authoritative `ai_draft` provenance envelope with top-level `source_provenance`, statement-source entries, human verification required, allowed pending/accepted/rejected checkpoint vocabulary, and fail closed on sealed/non-draft API shapes. MCP draft-act/draft-minutes calls also inject bounded `ai_provenance` into the act draft request, and the act API persists that provenance with a human-verification record; AI-assisted acts cannot advance from TextApproved to Signing until human review is recorded as accepted. `validate_signature_bundle` wraps the existing signature endpoint as technical evidence only with no legal-validation claim, and the web settings/platform surface can manage the tenant gate and display AI/MCP assurances for gates, API-key RBAC, draft status, and signature-bundle scope without exposing secrets. Law corpus search/browse endpoints and registry import support provenance-adjacent workflows. | AI drafting/extraction/comparison/summarization depth, workflow-level provenance panels beyond MCP output/status resources/static prompts, persisted act provenance, and the settings/platform assurance panel, richer MCP prompt/resource breadth, non-stdio MCP transports, and any assessment of AI quality or legal validity remain. | None specific. |
| spec/10 UX & Design (UX) | PARTIAL | Web shell, 14-locale i18n runtime and catalog completeness checks, onboarding/auth gate, password-policy checklist, settings, Settings-only users/RBAC/delegation/API-key/recovery/privacy/UI platform-operations UI with AI/MCP assurance copy, settings-managed app/API/MCP logging controls, Data Management storage telemetry and cleanup UI, privacy breach-playbook and transfer-control register panels, Ata editor convening evidence-reference controls, law corpus citation pin/copy shelf preserving Verified/Pending labels, imported-document evidence UI including pre-persistence validation/refusal evidence for non-canonical legacy DOC/OLE-CFB imports and operator review status/note controls, focused browser regression coverage for imported-document review conservative messaging and status/note submission, paper-book import list/download UI, document preview, PDF/Markdown/TXT/HTML/RTF/ODT/DOCX working-copy downloads with browser export/save E2E coverage, signature evidence with local B-LT/B-LTA technical labels, external-invite UI, external-invite landing page, Ferramentas external-signing workflow tool, browser E2E for signed-act external invite boundaries, dashboard reminders/work queue with localized alert keys, active legal-hold and sealed-not-archived alerts, and activity-summary polish, persisted notification triage with read/dismiss/acknowledge/restore controls, explicit seal-warning acknowledgement modal, compliance source/reference rendering, registered-entity primary filters that wrap without horizontal scrolling, collapsed accordion-style advanced filters that expand into wrapped multi-line controls, fixed/clamped registered-entity table cells with up-to-two-line text where needed, concise Type/Last Activity visible summaries with tooltips, improved template primary/advanced filters, Arquivo UI, Trust/TSL/TSA catalog UI with truncated/copyable digests, a PDF signature validator tool UI, bundled PDF fonts, button hover/leather active states, storage-tab spacing polish, and desktop window controls/smoke coverage are present. | Mobile UX, PDF/UA delivery beyond the bounded tagged-structure slice, richer dashboard ergonomics beyond the current reminders/activity/archive lifecycle alert slices, broader table ergonomics beyond the entities/templates/storage slices, broader imported-document browser coverage beyond the focused review regression, and broader legal-source/provenance linking beyond the citation shelf remain. | None specific. |
| spec/11 Template Catalog (TPL) | PARTIAL | `chancela-templates` loads 83 JSON template assets; API exposes `GET /v1/templates`, previews, on-demand generation, seal/book hooks, catalog summary metadata for channels, signature policy hints, rule-pack IDs, and bounded `law_references` derived from rule-pack IDs plus threshold references, with Pending status and source provenance. Template tests now validate required authored asset metadata, duplicate IDs, rule-pack law-reference anchors, and derived law-reference presence without claiming legal authority. The web catalog can search/filter by those metadata fields, keeps search/family/stage as primary controls, moves locale/channel/signature/rule-pack filters into a collapsed advanced area, and shows metadata in summary/detail views. | Template market parity, legally verified threshold values, broader statute-overlay depth, exhaustive/verified law-reference mapping, and full family/rule-pack semantic validation are not complete. | Legal review before any template wording, law reference, or threshold is treated as authoritative. |

---

## Recent Coverage Added

- **Bounded ASiC-S signing support:** `chancela-signing` can now create and validate bounded
  single-payload ASiC-S/CAdES containers for the supported local signing envelope path. This is not
  XAdES, arbitrary ASiC profile processing, embedded LT/LTA evidence, or a legal
  qualified-signature claim.
- **Bounded ASiC-E/CAdES manifest support:** `chancela-signing` can now create and validate a
  bounded ASiC-E ZIP shape with one ASiCManifest, one referenced detached CAdES signature over that
  manifest, and SHA-256 `DataObjectReference` checks against the packaged payload members. This is
  CAdES-backed manifest support only; it is not XAdES, ASiC-XAdES, multiple signatures, manifest
  extensions, embedded LT/LTA evidence, ETSI profile completeness, or legal validity assessment.
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
  targets and byte counts without broad deletion semantics. Retained-export cleanup now has
  export-only dry-run, minimum-age, and keep-latest policy controls; those options are rejected for
  crash cleanup. Data Management renders the same status with refresh, copy-path, scan-error,
  browser-safe open-folder-disabled states, and cleanup controls. This does not add durable log
  retention, SQLCipher production enablement, storage migration tooling, arbitrary deletion, GDPR
  erasure, legal disposal approval, legal retention execution, physical deletion guarantees beyond
  the bounded cleanup behavior, or complete data lifecycle automation.
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
- **Law citation resolver and corpus citation shelf:** `POST /v1/law/citations/resolve`
  normalizes up to 32 selected corpus article references into copyable citation metadata gated by
  `law.read@Global`. The resolver carries `verification`, `source_complete`, source URL/digest
  fields where available, and an explicit legal notice; the Legislação reader can pin/copy those
  citations while keeping Pending entries visibly pending. This is reference assistance only: it
  does not persist legal bases, certify the copied citations, promote DRE-sourced articles to
  Verified, or replace official publication/legal review.
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
- **Roles, delegations, guest/minimal redaction:** The seeded role catalog now covers Owner, Gestor,
  Signatário, Leitor, Platform Administrator, Tenant Administrator, Auditor, Guest, and API Client.
  Delegations carry `starts_at` and optional `legal_basis` evidence, persist to `delegations.json`,
  and remain non-redelegable. Minimal guest/read-only callers now get redacted entity and registry
  views plus book purpose/signatory/predecessor metadata, act free text/participant/evidence
  metadata, and imported-document filename/digest/importer/download metadata. This is read-response
  minimization, not anonymization, erasure, or full privacy lifecycle completion.
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
- **Breach playbook and transfer-control registers:** `GET|POST|PATCH
  /v1/privacy/breach-playbooks` and `GET|POST|PATCH /v1/privacy/transfer-controls` maintain
  bounded privacy-control registers with JSON sidecar durability, strict risk/status validation,
  sensitive-credential marker rejection, create/update audit events, and Settings privacy-tab
  create/edit/filter controls. These are register and review surfaces only; they do not execute an
  incident response, notify an authority or data subject, approve an international transfer, or
  certify GDPR compliance.
- **Retention policy register:** `GET|POST|PATCH /v1/privacy/retention-policies` and
  `POST /v1/privacy/retention-policies/dry-run` maintain bounded retention policy records with
  JSON sidecar durability, strict enum validation, sensitive-marker rejection, and create/update
  audit events. Dry-run reports only applicability and always returns `would_execute: false`;
  deletion/anonymization/archival execution remains out of scope. The dry-run surface now accepts an
  optional execution request and records an audit-only execution evidence object with actor,
  requested policy, matched-record summary, legal-hold blockers, operator notes/evidence, and
  `would_execute: false`; destructive, stale, missing-policy, and legal-hold cases remain blocked.
  Execution request evidence is now also persisted to `privacy-retention-executions.json` in
  data-dir mode and listed through `GET /v1/privacy/retention-executions` for authorized
  operators. This is retention execution history only: it still performs no deletion,
  anonymization, archive disposal, or legal-retention certification.
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
  a non-canonical import. The report now includes a preservation policy object with review state,
  operator-review requirement, OCR-review requirement for image evidence, original-byte preservation
  status, canonical-conversion status, and false canonical/acceptance flags. Malformed/truncated
  ByteRange data, duplicate ByteRange markers, ambiguous OLE/PDF claims, invalid PAdES/CAdES
  validation, and declared size/digest mismatches fail closed. Legacy DOC imports are accepted only
  as preserved non-canonical evidence: no macro execution, conversion, or canonical PDF/A generation
  is performed. `POST /v1/documents/import`,
  `GET /v1/documents/imported`, `GET /v1/documents/imported/{id}`, and
  `GET /v1/documents/imported/{id}/bytes` persist and expose validated non-canonical imported
  evidence through store schema v5. The `document.imported` ledger event carries metadata only; raw
  bytes remain in the store. Stored imported-document views and ledger metadata carry the same
  preservation-review policy and still mark `canonical_conversion_performed`,
  `canonical_pdfa_generated`, and `legal_acceptance_claimed` false. The document panel now validates
  candidates before persistence, renders legacy DOC/OLE-CFB evidence or refusal findings, exposes
  import/list/metadata/original-byte download controls, and keeps all copy explicit that imported
  documents are non-canonical evidence. Focused browser E2E route-stubs the imported-document review
  flow and pins the conservative review messaging plus review PATCH request/response behavior. This
  does not replace preserved canonical documents, run OCR, convert legacy Word/image/text/bundle
  files, create PDF/A, or prove legal/signature validity.
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
- **Convening evidence reference path:** the core `Convening` model, DTO/API patch shape, durable
  act JSON store, document rendering context, and Ata editor now carry `evidence_reference` as a
  bounded operator reference to external proof such as a document id, archive path, or tracking set.
  The field preserves the reference through editing and rendering context, but it does not ingest,
  validate, certify, or retain the underlying evidence object by itself.
- **External signer invitation tracking:** sealed acts can create/list/revoke external signer
  invite records under `/v1/acts/{id}/signature/external-invites`. Tokens are returned exactly once,
  stored hashed/redacted, and audit events are appended; this is tracking/envelope infrastructure,
  not completed remote signing. Unauthenticated token-body lookup/respond endpoints expose only safe
  invite/act/document metadata while the token is live, record accepted/declined acknowledgement
  events, and never return token material or canonical PDF/signed-PDF downloads. A token-body-only
  public endpoint can return a non-canonical Markdown working copy for sealed acts; it is explicitly
  non-evidentiary and not a qualified signature. The signing panel exposes create/list/revoke plus
  one-time token display, and `/assinatura-externa` is the token landing page.
- **External invite signed-PDF technical evidence:** accepted external invite responses can now
  carry an optional base64 signed PDF. The API requires the act to be sealed, validates the upload
  as a signed PAdES PDF, checks it is bound to the sealed PDF bytes, stores the exact signed bytes
  through the signed-document path as `ExternalSignerHandoff` /
  `ExternalSignedPdfTechnicalEvidence`, and exposes `signed_artifact` to the token holder plus the
  ordinary signature status/download endpoints. The status remains technical evidence only:
  `trusted_list_status` stays null, qualified/legal status is not claimed, and
  `require_qualified_for_seal` still keeps finalization non-qualified.
- **External signing workflow tool:** Ferramentas now includes an External Signing tool at
  `/ferramentas?tool=external-signing` for operational tracking. It lists redacted invite records,
  summarizes response/status state, handles same-origin token links, looks up public envelope
  metadata, and uses localized copy. This is still invite/envelope tracking and safe working-copy
  access, not legal signing completion, qualified-signature validation, or canonical signed-PDF
  delivery.
- **AMA/CMD evidence pack generator:** `docs/compliance/ama-cmd` now includes a generator,
  source metadata, templates, and generated pack material for collecting implementation evidence,
  authority-review notes, application/certificate placeholders, app-video evidence, and test
  evidence. The generated material is deliberately framed with no-approval-claim wording; it is
  not production CMD approval, a legal certification, or proof that AMA/SCMD credentials and
  production certificates are available.
- **Signing trust failure matrix:** API tests now cover fail-closed CMD/CC/TSA trust and
  timestamping cases, including path-backed or unsupported timestamp inputs. This improves
  regression coverage for deterministic trust failures; it does not exercise live CMD, physical CC
  hardware, or production QTSP/TSA operation.
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
  report material without transcribing a broader legal pass/fail claim. The same validator-corpus
  evidence metadata now declares archive package `evidence/index.json` and document-bundle
  `validation_report.evidence_index` indexing locations for external-validator report metadata.
  These fixtures and indexes improve technical interoperability evidence but do not replace live
  qualified validation, trust-list validation, legal acceptance, or authority approval.
- **Signing provider status and XAdES/ASiC honesty:** settings now include read-only provider-mode
  metadata for CMD/SCMD, CC, CSC/QTSP, and local PKCS#12 so operators can distinguish configured,
  blocked, and local-only paths without entering secrets in the UI. `chancela-signing` now has
  focused signing/validation tests and docs that keep XAdES unsupported while recognizing the
  bounded ASiC-S/CAdES and ASiC-E/CAdES manifest slices. ASiC-XAdES, XAdES generation/validation,
  ASiC-E profiles beyond one CAdES-signed manifest binding payload digests, embedded LT/LTA
  evidence, and legal qualified-signature claims remain explicitly out of scope.
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
  beside the official PDF/A download with localized labels and warning copy. API tests now cover the
  working-copy export matrix, and browser E2E covers the export/save flow for repeated canonical
  PDF/A download, separate review-copy downloads, preservation ZIP, signing fallback UI, and ledger
  archive PDF/A export.
- **Imported document evidence families:** the imported-document contract/API/UI test surface now
  distinguishes additional evidence families for retained bytes, metadata-only records, and signed
  PDF/PAdES structural status. These are preservation/evidence classifications, not legal
  acceptance of non-canonical files or production signed-import validation.
- **Dashboard reminders:** `GET /v1/dashboard` includes advisory annual-calendar reminders from
  encoded profile calendar presets. Commercial SA/Lda-like entities, associations, foundations, and
  cooperatives are covered where a profile preset defines a fiscal-year offset; unsupported or stale
  profile data emits no false reminder. Due dates use the entity's recorded fiscal-year end when
  valid, fall back explicitly to the default calendar-year model when absent/invalid, clamp leap-day
  edge cases deterministically, suppress reminders when a sealed/archive act already provides a
  recent calendar signal, and now carry i18n keys so the web notification/dashboard copy is resolved
  through the locale catalog. The reminder remains advisory and bounded by current calendar preset
  data.
- **Dashboard activity summaries:** the dashboard now presents more concise visible activity
  summaries, with localized copy and regression coverage for the summary rendering. This improves
  scanning of existing workflow signals; it is not a complete dashboard analytics or operational
  reporting layer.
- **Dashboard archive lifecycle alerts:** `GET /v1/dashboard` now emits active legal-hold
  (`book.legal_hold.active`) and sealed-not-archived (`act.archive.pending`) alerts with category,
  severity, target links, i18n keys, and recommended next steps; the web work queue renders them as
  localized routed items. These are advisory operational prompts to review a hold or archive a
  sealed act when preservation evidence is ready, not legal certification, disposal approval, or
  proof of archive completion.
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
  top-level `source_provenance`, per-field statement-source entries, source endpoint/tool, actor,
  allowed checkpoint statuses (`pending_human_verification`, `accepted_by_human`,
  `rejected_by_human`), timestamp, and null model/provider placeholders; sealed or non-draft API shapes are refused
  instead of presented as drafts. MCP draft calls now inject bounded act-level `ai_provenance`;
  the API persists that provenance, records accepted/rejected human-review decisions through a
  ledgered endpoint, and blocks AI-assisted acts from advancing to Signing until human review is
  accepted. This is a durable human-review gate and provenance injection path only, not legal
  validity, AI-quality review, or a complete provenance UI. The signature-bundle tool wraps the
  existing signature status endpoint as technical evidence only and refuses to claim legal
  validation. The server is still off by default and now additionally refuses to serve unless the
  tenant AI gate is enabled; settings UI exposes that default-off tenant gate to managers.
- **E2E / CI / desktop coverage:** CI now includes multi-OS Rust format/clippy/tests, web
  format/lint/tests/build on Node 20 and 24, web unit tests with enforced Vitest/V8 coverage
  thresholds, composed server E2E, opt-in Playwright browser E2E with artifacts, Docker server image
  build on main, and opt-in Windows Tauri desktop smoke with artifacts. API tests now cover the
  working-copy export matrix, archive package tamper failures, hardened password verifier storage,
  and signing trust failure cases. A separate tag/manual
  release workflow builds Linux/Windows/macOS package artifacts and uploads package
  manifests/checksums without claiming signing/notarization. Local scripts include
  `npm run test:e2e`, `npm run check:versions`, Docker smoke, and `apps/desktop` smoke helpers.
  Static-serving E2E now covers encoded/odd API paths so integration clients receive JSON 404s
  rather than the SPA shell. Archive package E2E now covers persisted legal hold after restart and
  blocked disposal with no partial state change. Browser E2E now covers disabled pre-seal document
  downloads, repeated canonical PDF/A download, separate non-evidentiary Markdown/TXT/HTML/RTF/ODT/DOCX
  working-copy downloads, preservation ZIP download, signing fallback UI, ledger archive PDF/A export,
  signed-act external invite boundaries, and a focused route-stubbed imported-document review
  regression. The web
  production build explicitly splits stable React/router/query/Tauri vendor chunks from the app
  bundle, keeping the main application chunk under the default Vite large-chunk warning threshold.
  Current audit caveats remain: browser E2E is not exhaustive, coverage thresholds outside the web
  unit-test lane are not broadly enforced, live signature/provider seams are compile-only, release
  packages are not signed or notarized, and Docker images are not signed or attested.
- **Docker deployment profiles:** the Docker compose/deployment material now distinguishes local,
  demo, and reverse-proxy/TLS-facing profile guidance with persistent data paths and smoke-script
  hardening. These are deployment profiles and checks, not HA architecture, managed operations, or
  signed/attested image publication.
- **Recent-landed checkpoint:** `npm run test:checkpoint:recent-landed` and the GitHub Actions
  `recent-landed` job pin the cross-cutting recent work: paper import API tests, archive package and
  DocTimeStamp evidence tests, web contract/dashboard/i18n tests, validator corpus sidecar validation, and
  desktop lockfile metadata. The static mode catches accidental removal of the mapped files and
  fixture markers without running the full commands.
- **Release trust metadata guard:** `scripts/check-release-trust.mjs` validates explicit package
  `releaseTrust` metadata and Docker signing-status metadata in the current `unsigned-dev` /
  `local-ci` paths and in production declarations, with a CI self-test and release/Docker workflow
  checks that reject production signing, notarization, publication, or attestation claims without
  matching metadata anchors. Docker production metadata must include anchors such as image/artifact
  digests, HTTPS workflow/run URLs, signing identity or certificate fingerprint, and attestation
  predicate metadata. This guards metadata honesty only; it does not sign, notarize, attest,
  publish, verify a registry push, or prove artifact provenance.
- **Package source provenance guard:** `scripts/package.sh` and `scripts/package.ps1` now write
  `manifest.sourceProvenance` with commit SHA, source-tree state, and `buildMode=release`.
  `scripts/check-package-artifacts.mjs` requires that provenance, mirrors it against
  `manifest.gitCommit`, and rejects fixture/package manifests whose commit does not match current
  `HEAD`; `scripts/check-release-trust.mjs` also cross-checks release summary `source.sha` against
  the manifest. This is source-traceability metadata only; it does not sign, attest, notarize,
  publish, or prove a clean-room/reproducible build.
- **Release and store hardening foundations:** packaging now stages `manifest.json` and `SHA256SUMS`
  with artifact metadata/checksums, checks generated package artifact integrity, and includes the
  host CLI plus operator scripts when present.
  CI now generates and validates a CycloneDX dependency SBOM from npm/Cargo lockfiles, uploads
  npm/Cargo advisory reports, can make scans blocking on manual `enforce_security_scans=true`
  dispatches, and records Docker image inspect/Syft/Trivy/signing-status artifacts without claiming
  registry publication, signing, attestation, or notarization.
  `chancela-store` has a feature-gated SQLCipher keyed-open foundation with typed unavailable and
  rejected-key errors while preserving default plaintext behavior. API/server startup now resolves
  `CHANCELA_DB_KEY` / `CHANCELA_DB_KEY_FILE`, rejects ambiguous/empty/unreadable key config without
  logging secrets, refuses configured encryption on no-SQLCipher builds before creating a plaintext
  database, and preserves plaintext startup when unset. The store now exposes a secret-free key-ops
  status/preflight that classifies configured/empty/missing key state, SQLCipher build availability,
  database file header format, the bounded operation plan, rotation readiness only for the
  non-plaintext `OpenEncryptedStore` plan, and operator action text without exposing key material.
  Store/API startup use that preflight to refuse direct plaintext-to-encrypted keyed open and point
  operators toward an explicit backup/export-restore migration path. The key-ops status now also
  serializes a non-secret `migration_plan` with evidence and ordered non-destructive
  backup/export, fresh encrypted-store, restore/verify, and cutover-hold steps. This is a guard,
  status, and operator-plan surface only: it does not prove live SQLCipher encryption,
  decryptability, key rotation, or at-rest encryption completion, and it does not perform
  migration. Plaintext-to-encrypted migration execution, key rotation workflow, and sidecar
  encryption remain follow-up work.

---

## Remaining Blockers

### Local product work

- Legal/product depth: per-family rule-pack completeness, legally verified
  threshold values, exhaustive/verified template/citation law references, guest/privacy redaction
  coverage beyond the current read-response slices, destructive/automated DSR execution workflows
  beyond bounded evidence, and DPIA/breach/transfer-control documentation depth.
- Data lifecycle/storage: the cleanup endpoint covers crash reports and retained exports only, with
  retained-export dry-run/minimum-age/keep-latest guardrails, and archive disposal execution is
  non-destructive evidence only; actual physical deletion, broader retention/disposal policy
  automation, GDPR erasure, export-retention policy controls beyond the current cleanup guardrails,
  incident-response/transfer-control automation beyond registers, executed storage
  migration/export-restore and key rotation tooling beyond the current key-ops guard/plan, and
  legal-hold/disposal operator workflows beyond the dashboard advisory prompts remain implementable
  next slices before any data-lifecycle compliance claim.
- Documents/archive: deeper imported-document preservation-review workflow depth beyond the current
  bounded status/note transition, production/legal signed-import validation beyond the local
  structural/PAdES checks and technical uploaded evidence, full PDF/UA delivery beyond the bounded
  tagged-structure slice, richer structure trees/tagging/role maps/marked artifacts, OCR execution
  and reviewed canonical/legal conversion for preserved legacy DOC and historical paper-book
  evidence, official DGLAB interchange/certification, actual physical deletion, broader
  disposal/retention policy automation, GDPR erasure linkage, legal acceptance/certification, and
  long-term signature evidence packaging beyond the implemented sidecars, archive package
  `evidence/index.json`, document-bundle `validation_report.evidence_index`, and technical metadata
  projections.
- Trust/signing depth: production/legal B-LT/B-LTA, XAdES/ASiC-XAdES, ASiC-E coverage beyond the
  bounded CAdES-signed manifest/digest-binding path, embedded ASiC LT/LTA evidence,
  PKCS#11/operator certificate workflows, multi-signature/archive timestamp renewal depth,
  production provider-management flows, actual operator validator report collection for the corpus,
  populated runtime evidence-index attachments beyond the declared external-validator metadata
  paths, AMA/CMD production approval beyond generated evidence-pack material, and external signer
  legal completion beyond invite/envelope tracking plus uploaded technical signed-PDF evidence.
- Workflow breadth: legal-calendar preset depth beyond the advisory dashboard reminder, OCR
  execution, deeper operator review, and canonical-conversion flows for preserved paper-book
  packages beyond current non-authoritative OCR draft metadata, external signer
  document-gated/legal completion flows, dashboard depth beyond the current
  reminders/activity/archive alert slices, groups/tenancy,
  sync/connectors, live SQLCipher/at-rest DB encryption verification plus migration/rotation
  operations, ZK, HA, and mobile builds.
- AI feature layer: drafting/extraction/compare/summarize, workflow-level provenance panels beyond
  the MCP envelope/source-provenance object, persisted act provenance, durable human-review gate,
  status resource, static human-review prompt, and settings/platform assurance panel, broader MCP
  prompt/resource coverage, additional MCP transports, and any legal-validity or AI-quality
  assessment.
- CI/release assurance: broaden browser E2E for critical workflows beyond the current focused
  signed-invite, export/save, and imported-document review regressions, add or explicitly waive
  coverage thresholds beyond the web unit-test lane, convert
  compile-only live signature seams into controlled integration lanes where credentials/hardware
  exist, harden package provenance beyond manifest/checksum/source metadata and release-trust
  metadata-anchor guards, move Docker profiles toward production HA/ops where required,
  sign/notarize release packages, and sign/attest Docker images with verified publication evidence.

### External / provider / legal blockers

- **CMD:** production use depends on AMA/SCMD onboarding credentials, the prod field-encryption
  certificate, and authority approval. The generated evidence pack and offline tests do not prove
  live SCMD operation or production CMD approval.
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
  Pending, including when those articles are copied through the citation shelf. Generated
  templates, exposed template/citation law references, and threshold values need legal review before
  they are treated as authoritative or complete.
- **Qualified-signature requirements:** CMD/legal-signature copy must stay explicit that there is no
  legal shortcut around qualified provider, qualified certificate, hardware, and onboarding
  requirements.
- **Release trust chain:** package manifests, checksums, integrity checks, and release-trust
  metadata validation are not signing or notarization; Docker profiles, OCI metadata, and
  signing-status metadata-anchor checks are not image signing or attestation and do not verify an
  actual registry push. Release packages are not signed/notarized and Docker images are not
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
- The generated AMA/CMD evidence pack is a documentation scaffold for collecting evidence and
  review inputs; it is not production CMD approval, legal certification, or proof of live AMA/SCMD
  credentials.
- The Trust/TSL catalog is a visibility surface, not a purchase workflow and not proof of qualified
  trust production readiness.
- External signing workflow screens and public envelope lookup are operational tracking surfaces;
  accepted/declined invite responses and uploaded signed PDFs are not legal signing completion,
  trust-list validation, or qualified-signature validation.
- MCP draft human-verification states are exposed in output envelopes, and AI-origin act drafts now
  have persisted provenance plus accepted/rejected human-review decisions that gate the Signing
  transition. That gate records human review only; it is not legal certification, AI output-quality
  validation, a provider call, hidden signing/trust operation, full provenance UI panel, or
  acceptance of draft text as final minutes. The MCP status resource is a local operability
  snapshot, and the MCP human-review prompt is static guidance.
- Local B-LT/B-LTA labels report technical evidence observed in the file; they are not production
  or legal long-term-validation claims.
- Bounded ASiC-E/CAdES support signs and validates one ASiCManifest/digest-binding container shape;
  it is not XAdES, ASiC-XAdES, embedded LT/LTA evidence, broad ETSI profile completeness, or legal
  validity assessment.
- Template law references are bounded Pending provenance links derived from current rule-pack and
  threshold metadata; they are not exhaustive, legally verified, or a substitute for reviewing the
  generated template wording.
- Template catalog metadata validation is regression coverage for required fields, duplicate IDs,
  and law-reference anchors; it is not legal review of template wording, thresholds, or cited law.
- The law citation resolver and corpus pin/copy UI preserve corpus verification status; copied
  Pending citations are not DRE-verified law text, legal bases, or legal advice.
- Guest/minimal redaction hides selected read-response metadata for current entity, registry, book,
  act, and imported-document views; it is not full anonymization, destructive erasure, or
  certification of access-control/privacy policy completeness.
- Database key-ops status/preflight is a secret-free configuration/build/header classification and
  startup guard. It does not prove live SQLCipher encryption, decryptability, key rotation,
  completed at-rest encryption, or a production migration path, and it does not convert plaintext
  SQLite stores into encrypted stores.
- The database key migration plan is operator guidance attached to key-ops status; it does not run
  backup/export-restore, verify a live encrypted restore, rotate keys, or retire plaintext data.
- Imported-document preservation review policy and UI record review requirements, reviewer metadata,
  and conservative original-byte/canonical-conversion decisions for non-canonical evidence. They do
  not run OCR, convert documents to PDF/A, create canonical records, certify legal acceptance, or
  validate legal effect.
- Paper-book OCR draft review metadata records non-authoritative review status and explicit false
  canonical/signature creation flags. It does not execute OCR, create canonical minutes, create
  documents, sign anything, or accept historical scans as legally converted digital records.
- Validator corpus sidecars, projected evidence metadata, archive package `evidence/index.json`,
  document-bundle `validation_report.evidence_index`, and evidence-indexing metadata preserve
  technical external report context and paths only. They are not live trust-list decisions, legal
  validity conclusions, qualified signature validation, DGLAB certification, or authority
  acceptance.
- Accessibility metadata and bounded tagged structure are not PDF/UA delivery; the writer still
  keeps `pdf_ua_claimed: false` and reports limited tagged structure rather than certification.
- Privacy breach-playbook and transfer-control registers are operator tracking/control registers;
  they do not execute incident response, perform authority/data-subject notification, approve
  transfers, or certify GDPR compliance.
- Data cleanup is bounded storage maintenance for crash reports and retained exports. Retained-export
  dry-run, minimum-age, and keep-latest options are policy controls for that cleanup target only.
  Guarded archive disposal execution is non-destructive ledger/audit evidence only; these surfaces
  are not GDPR erasure, legal disposal approval, legal retention certification, certification of
  data-lifecycle compliance, or physical deletion guarantees beyond the existing bounded cleanup
  behavior.
- Retention execution history records requests and outcomes for audit/review; it is not retention
  execution, anonymization, physical deletion, legal disposal approval, or GDPR erasure.
- Dashboard legal-hold and sealed-not-archived alerts are advisory operational next steps; they do
  not certify legal-hold handling, approve disposal, or prove archival completion.
- The persisted platform log tail covers API-owned structured events only and is bounded to 512
  entries; it is not stdout/stderr capture, MCP child-process logging, complete historical logging,
  or a general observability sink.
- CI and E2E coverage improve release confidence, and web unit tests now enforce coverage
  thresholds, but the current browser suite is not exhaustive, the signed-invite/export/save/imported
  review browser slices are focused regressions, and other lanes do not have broad coverage
  thresholds.
- SBOMs, checksums, package manifests, source provenance metadata, release-trust metadata
  validation, Docker signing-status metadata-anchor checks, and Docker OCI metadata are not
  substitutes for package signing, notarization, Docker signing, attestation, registry-publication
  verification, or reproducible-build proof; package artifact integrity checks and metadata guards
  are regression checks, not a release trust chain.
- Docker deployment profiles are operational configuration examples, not HA, managed production
  operations, image signing, or attestation.
- `/api/v1` API keys are an implemented integration feature, but a bearer key is still an
  attenuated RBAC principal, not an interactive user session or step-up credential.
