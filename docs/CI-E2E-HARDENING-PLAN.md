# CI and E2E Hardening Plan

Updated 2026-07-12 from the current CI configuration and head `869e02f`,
including coverage notes for the bounded PAdES DSS validation-time, PDF/UA v6
structural-depth, retention due-candidate explicit evidence states, bounded
archive/no-action evidence UI, duplicate-review guard/status surfacing, and
prior bounded execution suppression with active/suppressed candidate counts plus
retention execution review closure,
recovery-drill custody
receipt and optional-key contract tolerance, paper-book OCR conversion-dossier UI
and reviewed conversion execution artifact evidence,
CSC quota/delegation/revocation and standalone agenda-item template parity,
retained-export cleanup dry-run planning, post-act template sealed-provenance lint,
external-signing workflow-only envelope UI, workflow reminder policy, and
structured platform-log forwarded-ingest/failure-audit slices, plus data-status
sidecar classification, read-only local DGLAB interchange manifest API
scaffolding and BookDetail JSON download,
raw-byte per-book import preflight operator preview,
richer Ata editor AI statement-source provenance rendering, explicit external-validator raw
report upload UI guardrails, the raw external-validator raw-report byte download
API, the MCP workflow provenance and draft-vs-signed comparison review aids,
dashboard guest recent-events redaction, generated-document by-id download route,
condominium absent-owner communication auto-generation, and operator-supplied
dispatch-evidence recording with dashboard reminder surfacing,
document-bundle/archive generated dispatch-evidence metadata preservation,
imported-document review receipt UI, trust catalog identifier-match explanations,
password-required account creation/session hardening,
route-stubbed richer entity chronology visualization over existing structured
graph evidence as source-linked technical visualization evidence only,
plus local ASiC inspection endpoint and ASiC ZIP decompression-bound coverage,
plus release workflow static
assurance for the unsigned/local-only trust posture and production-package
manifest-required validation. This plan is the build and
test operating checklist for driving Chancela toward release confidence.

## Goals

- Keep fast PR feedback for common defects.
- Keep heavy browser, Docker, and desktop checks available without making every
  PR impractical.
- Exercise the real server, real web bundle, and real desktop shell at least in
  opt-in or main-branch paths.
- Prefer deterministic local fixtures over live network, provider, card-reader,
  TSL, TSA, CMD, or QTSP dependencies.
- Test failure and edge paths, not only the happy path.

## Current CI Shape

- CI runs on pushes to `main`, pull requests, and manual `workflow_dispatch`.
- Rust format, clippy, and workspace tests run on Linux, Windows, and macOS.
- A dedicated SQLCipher feature lane runs on Windows, pins Strawberry Perl ahead
  of vendored OpenSSL, and runs
  `cargo test -p chancela-store --locked --features sqlcipher sqlcipher`.
- Web format, ESLint, Vitest/V8 coverage thresholds, and Vite build run on Node
  20 and Node 24; the web CI test command is
  `npm run test:coverage --workspace apps/web`.
- Supply-chain CI generates and validates a CycloneDX dependency SBOM from
  `package-lock.json` plus `cargo metadata --locked`, uploads npm/Cargo advisory
  reports, and can make those reports blocking only on manual runs with
  `enforce_security_scans=true`.
- Composed server e2e runs `cargo test -p chancela-server --features e2e --locked`
  on Linux and Windows for every push and PR.
- Live seam compile checks run `cargo test ... --no-run` for the existing
  `network-tests` and `hardware-tests` feature gates, without touching live
  providers, networks, or card readers.
- Browser core e2e builds release `chancela-server`, builds the web app,
  installs Chromium, and runs the stable smoke/session/first-launch/journey
  Playwright specs on every push and PR.
- Browser full e2e remains a heavier Chromium lane for pushes to `main`, manual
  dispatches, or PRs labeled `run-browser-tests`; the explicit
  release-candidate `test:browser:matrix` command runs the same Playwright suite
  across Chromium, Firefox, WebKit, and mobile Chromium when full browser
  coverage is needed.
- Browser e2e is useful smoke/edge coverage, not exhaustive product coverage.
  Web unit coverage is enforced separately with Vitest/V8 thresholds in
  `apps/web/vite.config.ts` (statements 90, branches 78, functions 83, lines
  90).
- Docker server image build plus runtime smoke runs on pushes to `main` and
  manual dispatches; the smoke starts the container with `CHANCELA_DATA_DIR`,
  polls `/health`, and asserts durable persistence from the JSON body.
- The Docker lane applies OCI image labels and uploads image inspect metadata,
  report-only Syft/Trivy artifacts, and an explicit JSON status saying the local
  CI image was not pushed, signed, or attested.
- The release-trust self-test statically verifies workflow wiring for the
  unsigned/local-only trust posture: metadata checks, Docker no-push/local-load
  `local-ci` status, package `unsigned-dev` / `not_attested` metadata, and SBOM
  package linkage. This is static assurance only, not signing, notarization,
  registry publishing, Docker attestation, or a production trust claim.
- Package/release artifacts carry manifests and checksums where configured, but
  current release packages are not signed or notarized.
- Windows desktop smoke runs on pushes to `main` or PRs labeled
  `run-desktop-tests`.

## 2026-07-10 Audit Note

- Current browser e2e coverage is smoke/edge oriented rather than exhaustive.
  The enforced coverage thresholds are Vitest/V8 web-unit thresholds, so they do
  not prove browser, desktop, Docker, or live-provider coverage.
- Live signature/provider seams are compile-only checks; they do not exercise
  live CMD, CSC/QTSP, CC hardware, production TSL, or production TSA paths.
- Release packages are unsigned/not notarized, and Docker images are not
  signed/attested.
- The current Data Management slice adds `settings.manage`-gated cleanup for
  crash reports and retained exports plus SQLite logical usage estimates,
  including per-table logical payload entries surfaced in the web UI. Treat it
  as storage maintenance coverage, not legal data-lifecycle certification.
  The retained-export action now uses export-only dry-run planning for the
  Settings preview: `would_delete_*` counters and a server-bound `preview_token`
  are reported while `deleted_*` counters stay zero, and the preview copy states
  that no files were removed. The cleanup execution control is disabled until
  that tokened dry-run exists; the shared confirmation modal then posts the
  `preview_token`, the API rejects missing/stale/mismatched tokens, and execution
  deletes only the server-selected preview manifest before rendering results from
  `deleted_*` counters. Treat this as retained local export file cleanup only, not GDPR
  erasure, legal disposal, archive deletion, certification, or full data
  deletion.
- Data-status filesystem classification now groups `platform-logs.json` as
  `platform_logs` and `backup-recovery-drills.json` as
  `backup_recovery_drills` while preserving durable permission/status behavior.
  Treat this as telemetry classification only, not cleanup, retention execution,
  deletion, legal custody proof, or data-lifecycle certification.
- The current password-required auth slice makes `POST /v1/users` require a
  password, enforce policy, hash with the existing verifier seed, and recheck
  stale bootstrap requests under the users write lock. Non-bootstrap signed-out
  creates reject before password policy/hash work. `POST /v1/session` requires a
  password, rejects wrong/missing credentials and legacy no-hash users, and the
  no-hash path does not insert a session token. `DELETE /v1/users/{id}/secret`
  now returns `409` after authorization and preserves the password hash and
  attestation key; the web hides the remove-password action. This is local
  password-required account/session hardening only, not SSO, legal identity
  proof, tenant model, email verification, credential recovery completion, broad
  Playwright-browser-suite proof, or browser-matrix proof.
- The current restore preflight slice is non-destructive evidence only: API/store
  verify the archive manifest, every manifest-listed member digest, and ledger
  integrity, then materialize the DB plus sidecars in a unique temp workspace to
  prove isolated open/load/readback, sidecar file/byte readback, and temp cleanup,
  while the web UI exposes bounded manifest/evidence before destructive restore.
  Treat these checks as restore material screening, not live restore execution,
  live DB swap, live sidecar staging, `ledger.restored` append, DR readiness,
  custody proof, SQLCipher-at-rest proof, or legal archive certification.
- The current backup recovery-drill slice records preflight-only receipts through
  `POST`/`GET /v1/backup/recovery-drills`. The API calls the existing restore
  preflight path, persists only bounded evidence (archive reference, preflight
  ok/ready/encrypted, ledger verified, manifest counts/bytes/schema/ledger
  length, `isolated_restore_verified`, `isolated_restore_verification`, optional
  operator notes/custody location), rejects true overclaim flags, and the web
  action clears the transient passphrase while preserving exact bytes on submit.
  Treat this as operator receipt evidence, not live restore, DB swap, sidecar
  staging, ledger restore append, data deletion, SQLCipher-at-rest proof,
  off-site custody proof, RPO/RTO certification, production backup policy, FULL
  coverage, or legal archive certification.
- Release and package builds now opt into SQLCipher features by default where the
  supported package scripts and CI metadata require it. Treat this as encrypted
  build-default coverage, not proof of operator key custody, migration success,
  or deployed encrypted data at rest.
- Platform operations expose API-owned structured status/control/logging
  contracts plus `POST /v1/platform/logs/forwarded` for bounded structured
  forwarded entries. The ingest route is gated by non-meta
  `platform.logs.write@Global`, seeded freshly only to Owner and Platform
  Administrator while API Client remains excluded by default, and older
  customized Platform Administrator roles may need an explicit admin update
  after upgrade because persisted non-Owner seeded roles are not forcibly
  reconciled on load. It reuses the platform log ring, threshold/off
  suppression, persistence/retention, and GET tail behavior. Accepted retained
  forwarded entries append sanitized `platform.log.forwarded.accepted` ledger
  events with retained log id/seq/timestamp, service_id, level, target, message
  length/SHA-256, and context key count/serialized size when context is present;
  raw message/context/stdout/stderr/body/secrets stay out of the ledger event.
  Authenticated RBAC denial, malformed JSON, rejected structured payloads, and
  threshold/global/service-off suppression append sanitized
  `platform.log.forwarded.denied`, `.rejected`, or `.suppressed` route-outcome
  audits, while missing or invalid bearer requests remain unaudited. Failure
  audits carry no raw body, message, context keys, parse errors, stdout, stderr,
  tokens, secrets, or user strings, and the accepted audit remains single.
  Internal logging callers still ignore the returned `Option`. Treat it as
  structured ingress plus bounded accepted/failure audit markers only:
  no process lifecycle control, no stdout/stderr tailing/capture, no production
  supervisor/SIEM/HA/observability guarantee, no generalized observability sink,
  no log retention/deletion semantics, and no legal/compliance claim.
- The current template slice expands the embedded catalog to 101 JSON assets
  (101 total / 41 CSC) with standalone representation/proxy instruments,
  `ponto-ordem-trabalhos/v1` Convocatoria standalone agenda-item templates, and
  book-transport continuation terms for all supported families, including the
  company carta de representacao boundary, plus
  `csc-ata-divisao-quotas/v1` and `csc-ata-unificacao-quotas/v1` matching the
  sibling CSC quota Ata channels, rule-pack, signature-policy hint, and majority
  threshold marker, plus `csc-ata-delegacao-poderes/v1` and
  `csc-ata-revogacao-poderes/v1` as proposed-resolution text only with no new
  threshold marker. It also normalizes notice-template rendering of
  TPL-20 dispatch proof fields from `convening.recipients` across all supported
  families and pins all-family attendance-list rendering of structured attendee
  and proxy evidence, including CSC capital and condominium permilagem markers.
  Treat the focused `chancela-templates` tests and recent-landed static markers
  as catalog consistency checks only, not legal review of template wording,
  thresholds, law references, channel suitability, quota legal sufficiency,
  delegation/revocation legal sufficiency or authority verification, dispatch or
  attendance sufficiency, agenda-item legal sufficiency, registry submission,
  signing-process effect, external registry/provider behavior, or book-transport
  legal effect. The quota template law references remain Pending/non-authoritative;
  no DRE verification, legally verified threshold value, external registry/provider,
  signing-process, or new law-source claim is added.
  Current post-act semantic lint also requires `Certidao`/`Extrato` authored
  `BlockSpec` template references to sealed-act `ata_number` and
  `payload_digest`; this is a test/build-time consistency guard only and does
  not change asset wording or add legal-effect claims.
- The current external-validator slice adds bounded digest-verified raw report
  byte attachments to technical metadata capture/list/download, document-bundle
  indexes, archive package evidence members, and the Ferramentas operator UI.
  The UI keeps manual JSON metadata upload working, computes filename/type/size/
  digest/provenance locally when a raw report file is selected, does not upload
  on selection, and sends `raw_report.content_base64` plus `content_type`,
  `size_bytes`, `sha256`, and safe `source_filename` only on explicit upload.
  The follow-on raw-report byte API exposes `GET
  /v1/external-validator-reports/{case_id}/{validator_family}/raw-report` to
  `settings.read` actors only, returns retained raw bytes with attachment
  headers, returns 404 for missing or manifest-only reports, and fails closed for
  unsafe identities, malformed sidecars, and duplicate/ambiguous identities.
  List/create remain redacted and the web UI does not render raw bytes.
  Treat the API/archive/web tests and static markers as preservation/fixity
  coverage only, not external-validator legal acceptance, certification,
  PDF/UA/PAdES certification, compliance proof, live trust validation, or full
  report replay.
- The current MCP workflow provenance slice adds the static
  `workflow_provenance_review_checklist` prompt and
  `chancela://mcp/workflow-provenance-review` resource as offline review aids.
  They accept no arguments, include no secrets, make no bridge/API/provider
  calls, and keep legal-validity, source-certification, provider, trust,
  external, archive-certification, and signature-qualification flags false. Treat
  them as human review guidance only, not AI/MCP completion, source
  certification, trust validation, or provider/legal assurance.
- The current MCP draft-vs-signed comparison slice adds the static
  `draft_signed_comparison_review_checklist` prompt and
  `chancela://mcp/draft-signed-comparison-review` resource. With no arguments
  the resource returns static review guidance; with `arguments.draft` and
  `arguments.signed` objects it returns a deterministic local comparison report
  over caller-supplied metadata, IDs, digests, lifecycle/status fields,
  artifact references, timestamps, and provenance fields. It exposes no
  secrets, makes no bridge/API/AI-provider/hidden-provider calls, and keeps
  `legal_validity: false`, `source_certification: false`, `provider: false`,
  `trust: false`, `external_validation: false`, and
  `signature_qualification: false`. The spec-09 resource keeps AI-01 and full
  AI/MCP completion false. Treat this as technical comparison signal only with
  human review still required, not legal validity, source certification, trust
  validation, external validation, signature validation, signature
  qualification, provider assurance, signed-artifact certification, or AI/MCP
  completion.
- The current dashboard guest redaction slice returns `recent_events: []` from
  `GET /v1/dashboard` for guest/minimal redaction callers, while Owner and
  `Leitor` sessions keep recent events. Guest still lacks `GET /v1/ledger/events`.
  Treat this as response redaction only: no permission grants, no broader
  anonymization/redaction completion, and no access-control completeness claim.
- The current generated-document by-id download and dispatch-evidence slice returns
  `/v1/documents/generated/{document_id}` for on-demand generated post-act docs,
  gates the download through `act.read` on the owning act, and covers both
  durable and in-memory modes while keeping `/v1/acts/{act_id}/document` as the
  sealed Ata route. Sealing a condominium act with absent attendees also
  auto-generates `condominio-comunicacao-ausentes/v1`, keeps the canonical act
  document as the Ata, stores the communication for generated-document by-id
  retrieval in durable and in-memory modes, and emits honest pending dispatch
  evidence (`required_pending`, `evidence_attached=false`,
  `dispatch_completed=false`) that server E2E re-checks after restart. The same
  backend slice exposes `POST`/`GET`
  `/v1/documents/generated/{document_id}/dispatch-evidence` for
  operator-supplied dispatch evidence, stores it in
  `generated_document_dispatch_evidence`, returns exact retries idempotently,
  records selected absent-recipient evidence coverage, updates only
  evidence-attached/status headers while keeping
  `x-chancela-dispatch-completed=false`, and emits
  `absent_owner_communication.dispatch_evidence_recorded` with false/no-claim
  flags. Document bundles now keep the canonical bundle `document` and
  `/v1/acts/{act_id}/document` download as the sealed Ata while adding generated
  absent-owner dispatch metadata under
  `validation_report.evidence_index.generated_dispatch_evidence`. Archive
  package exports add metadata-only JSON sidecars at
  `evidence/generated-dispatch/{document_id}.json`, reference them from
  `evidence/index.json`, and register those sidecars as `EvidenceReport`
  metadata entries with `act_id` only and no `document_id`, so generated
  evidence sidecars are not promoted into top-level/canonical
  `manifest.document_ids`. The projection excludes `operator_note`,
  `idempotency_key`, note-derived stable fingerprints, generated communication
  bytes, and imported proof bytes; includes safe status/coverage fields,
  recipients, channel, reference, evidence locator, `imported_document_id`, and
  timestamps; and keeps `proof_bytes_included=false`, `bytes_included=false`,
  `operator_note_included=false`, `dispatch_completed=false`,
  legal-notice/legal-sufficiency, provider, registry, DGLAB, and legal-archive
  acceptance flags false. Focused preservation tests are
  `archive_package_indexes_generated_absent_owner_dispatch_evidence_metadata_only`
  and
  `document_bundle_indexes_generated_absent_owner_dispatch_evidence_without_replacing_ata`.
  The web follow-on slice covers `listGeneratedDocuments`, generated PDF
  fetch, `getGeneratedDocumentDispatchEvidence`,
  `recordGeneratedDocumentDispatchEvidence`, generated absent-owner
  communication listing, stored evidence rows, permission-gated metadata-only
  evidence recording, `operator_evidence_*` statuses, and
  `documents.generated.noClaim.*` copy. Dashboard and notification actions use
  generated-document deep links with `generated_document_id`,
  `focus=dispatch-evidence`, and `#generated-dispatch-evidence`; the Ata route
  resolves them through `actDocumentPanelTargetFromLocation`, and
  `ActDocumentPanel` selects/focuses the dispatch-evidence form once for
  operator evidence recording. Treat this as navigation and focus support for
  operator evidence recording only: it does not send mail/email/SMS/provider
  messages, prove delivery, mark dispatch complete, complete legal notice, add
  legal sufficiency/legal-effect claims, sign, archive, or certify legal
  validity. It also makes no DGLAB certification or legal archive acceptance
  claim.
- The current imported-document receipt/history slice projects a `Recibo de
  revisão` panel and bounded technical review history from the imported-document
  view. Pending rows show no fake receipt, while reviewed rows show latest
  status, reviewer, time, note, required and acknowledged guardrails, ordered
  prior decisions, plus no-claim rows for OCR, conversion, canonical PDF/A
  replacement, signed artifact creation/validation, signature validation, seal,
  PDF/UA, certification, and legal acceptance. Treat this as metadata-only
  review history for non-canonical evidence: no downloads, OCR, conversion,
  canonical replacement, signed artifact, signature validation, seal, PDF/UA,
  certification, legal validity, or legal acceptance.
- The current trust catalog identifier-match slice adds optional
  `identifier_match` fields to identifier-filtered TSL/TSA rows and renders
  technical match explanations in Ferramentas while preserving strict complete
  SHA-256/SKI lookup behavior and full-value copy actions. Treat this as
  technical catalog visibility only, not legal validity, certificate trust,
  provider approval, external validation, qualified-status, or trust-list
  certification.
- The current local DGLAB interchange slice exposes read-only `GET
  /v1/books/{id}/archive/local-dglab-interchange-manifest`, gated by
  `book.export@Book`, to derive a deterministic local
  `LocalDglabInterchangeManifest` JSON scaffold from an existing internal
  preservation `PackageManifest`. It keeps official-DGLAB/certification/approval/
  legal-archive/destructive-disposal flags forced false. BookDetail adds a local
  JSON save action that calls the same GET endpoint and saves `.json` metadata
  without calling the package/export/archive mutation paths. Treat this as local
  metadata scaffold coverage only: no official DGLAB export, government filing,
  ZIP sidecar member, import flow, package validation change, persisted package
  bytes, ledger event, disposal path, legal archival certification,
  PDF/A/PAdES/PDF-UA certification, authority approval, or legal archive claim.
- The current per-book import preflight slice exposes raw-byte `POST
  /v1/books/import/preflight?policy=...` as a preview-only import step. It
  checks the bundle evidence currently available before import and current
  collision state, returns operator preview fields without `import_id`, and the
  store/API tests pin no `ledger.imported`, no `imported_books`, no retained
  imported bundle bytes, and no live-record mutation. The web recovery panel
  requires selected file -> preflight preview -> explicit confirm import, and
  ignores stale preflight responses when the selected file or policy changes.
  Treat this as operator-safety preview coverage only: no legal archive
  certification, no DGLAB/legal acceptance, no production signed-import
  validation beyond existing import checks, and no final protection from
  concurrent confirm-time collision or IO/persistence failure.
- The current paper-book OCR conversion-dossier slice exposes the existing
  API/store flow on BookDetail: accepted OCR drafts can create/list
  non-canonical metadata-only dossiers, existing dossiers render without a
  duplicate create affordance, creation is operator-triggered only for accepted
  OCR drafts without a dossier, mutable draft-act creation remains separate,
  no-claim flags/notices render, and raw OCR text is not shown from dossier
  responses. Treat it as review metadata UI evidence only, with no automatic
  POST and no canonical paper-book conversion, act/document/PDF/signature/seal/
  archive creation, or legal-validity claim.
- The current external signer linked-invite/UI slice lets operators list and
  create workflow-only external-signing envelopes from SigningPanel, with order
  policy, signer slots, slot labels/statuses, identity requirements, completion
  summary, and the backend no-legal/no-qualified notice. Invite creation can
  optionally link to an envelope slot, sends `external_envelope_id` /
  `external_slot_id` only when selected, preserves the tracking-only payload
  when unselected, and renders later sequential-slot 409s as safe operational
  messages without raw backend/token-like detail, including after slot selection
  changes. SigningPanel also displays stored slot evidence metadata and records
  operator-supplied technical evidence for pending/initiated slots through
  `PATCH /v1/external-signing/envelopes/{id}` with a `slots` payload that omits
  `complete:true`; identity-requirement-tagged evidence rows are required before
  submit when configured. Ferramentas maps `workflow: external_envelope` to
  localized copy in rows and token lookup. Treat this as operational tracking
  and operator-supplied technical slot evidence only, not provider signing,
  PIN/OTP/passphrase collection, provider calls, trust-list checks, QES/
  qualified status, legal validity, provider completion, act finalization,
  envelope legal completion, or public token exposure.
- The current ASiC inspection slice exposes `POST /v1/signature/asic/inspect`
  for read-only local technical profile inspection of a base64 ASiC ZIP with
  optional filename, declared size, and declared SHA-256. Focused API and
  signing-crate tests pin fixity/base64/malformed-ZIP/unsafe-path validation,
  profile shape, bounded profile, blockers, member paths, manifest diagnostics,
  signature diagnostics, no-claim fields, `technical_validation` projected from
  `validate_asic_container` across CAdES, XAdES, mixed ASiC-E signatures, and
  archive timestamp imprint/reference consistency, plus the legacy bounded
  `cades` compatibility report. Actual decompressed-size caps cover payloads,
  manifests, CAdES signatures, XAdES signatures, unsupported `META-INF`, and
  other non-directory members. Treat this as local technical inspection only:
  no signing, storage, archive mutation, live provider calls, TSA/TSL/OCSP/CRL
  fetching, trust anchoring, legal validity, QES, B-LT/B-LTA, eIDAS
  legal-effect, or production ASiC/XAdES conformance claim.

## Last Broad Local Verification Snapshot

Recorded on 2026-07-09 from a then-current dirty working tree after the
privacy/archive/signing integration wave and before the later document-import/MCP
worker wave was integrated. Retained as historical context; it is not a current
full-green claim for head `c54fc0e`:

- `cargo fmt --all -- --check` passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings` passed.
- `cargo test --workspace --locked` passed.
- `cargo test -p chancela-server --features e2e --locked` passed.
- `npm run format:check --workspace apps/web` passed.
- `npm run lint --workspace apps/web` passed.
- `npm run test --workspace apps/web` passed.
- `npm run build --workspace apps/web` passed after vendor chunk splitting.
- `npm run test:browser --workspace apps/web -- e2e/hardening-edge.spec.ts`
  passed, 3/3 Playwright tests, covering API-key boundary behavior plus TSL/TSA
  structured search/filter empty states without live trust-network calls.
- Earlier in the same 2026-07-09 recovery batch, before the latest hardening
  spec was added, `npm run test:browser --workspace apps/web` passed, 22/22
  Playwright tests, and `docker build -f docker/Dockerfile.server -t
chancela-server:local .` passed. Re-run the full heavy gates after the current
  document-import/MCP worker wave lands.

Windows Playwright runs can leave a nonfatal temporary SQLite cleanup warning when
the web server releases the DB handle slowly; `CHANCELA_E2E_STRICT_CLEANUP=1`
turns that cleanup warning into a failure when needed.

## Optimization Plan

1. Keep dependency resolution locked everywhere.
   - Cargo commands use `--locked`.
   - Node commands use `npm ci`.
   - Desktop Rust tests use the Tauri manifest with `--locked`.

2. Split fast and heavy jobs.
   - Fast PR path: Rust unit/integration, web unit/build, Linux/Windows
     composed server e2e, live seam compile-only gates, and Chromium core
     browser e2e.
   - Heavy path: full Playwright browser, Docker build+smoke, desktop smoke.
   - Use PR labels only for the heavy browser/desktop jobs, while `main` still
     exercises them.

3. Keep cache boundaries predictable.
   - Use `Swatinem/rust-cache` per Rust job and desktop workspace.
   - Use setup-node npm cache keyed from the root lockfile and desktop lockfile.
   - Avoid sharing mutable generated outputs between jobs.
   - Keep Vite vendor chunking explicit so stable React/router/query/Tauri code
     is cache-separated from the application bundle.

4. Make browser tests self-contained.
   - Build the release server and web bundle in the job.
   - Run against temporary data dirs only.
   - Keep all registry, CAE, TSL, TSA, and signing fixtures local.

5. Make failure artifacts useful.
   - Upload Playwright traces, screenshots, videos, and reports on browser
     failure.
   - Upload desktop smoke logs, temp data, and Windows binaries on desktop
     failure.
   - Keep server e2e logs in test output with enough request/route context.

## Required Local Verification Loop

Run these after each integration batch:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
npm run format:check --workspace apps/web
npm run lint --workspace apps/web
npm run test:coverage --workspace apps/web
npm run build --workspace apps/web
node scripts/release-supply-chain.mjs sbom --output dist/supply-chain/chancela-dependency-sbom.cdx.json
node scripts/release-supply-chain.mjs check --input dist/supply-chain/chancela-dependency-sbom.cdx.json
cargo test -p chancela-server --features e2e --locked
cargo test -p chancela-cae --features network-tests --locked --no-run
cargo test -p chancela-cmd --features network-tests --locked --no-run
cargo test -p chancela-csc --features network-tests --locked --no-run
cargo test -p chancela-law --features network-tests --locked --no-run
cargo test -p chancela-registry --features network-tests --locked --no-run
cargo test -p chancela-tsa --features network-tests --locked --no-run
cargo test -p chancela-tsl --features network-tests --locked --no-run
cargo test -p chancela-smartcard --features hardware-tests --locked --no-run
```

Run these before declaring a release candidate:

```powershell
npm run test:browser --workspace apps/web -- e2e/smoke.spec.ts e2e/session.spec.ts e2e/first-launch-onboarding.spec.ts e2e/journey.spec.ts
npx playwright install --with-deps chromium firefox webkit
npm run test:browser:matrix
npm run build:docker
cd apps/desktop
npm run test:rust
npm run build:no-bundle
npm run test:smoke -- -DataDir <temp-data-dir>
```

The root scripts `test:browser`, `test:browser:matrix`, `build:docker`,
`test:desktop:rust`, and `test:desktop:smoke` are thin aliases for those
heavier release-candidate gates. `test:browser` stays Chromium-only for the
bounded core browser gate; use `test:browser:matrix` for full browser coverage.

## E2E Edge-Case Matrix

### Onboarding and Auth

- First-launch path creates the organization, first admin user, password,
  recovery phrase, and settings record in one pass.
- User creation and bootstrap sign-in submit the same operator password; no
  passwordless create/sign-in path is a supported browser workflow.
- Current-user switching prompts for a password before posting `POST
  /v1/session`.
- Refresh during onboarding does not skip mandatory recovery phrase display.
- Existing users but no session routes to sign-in, not onboarding.
- Expired or invalid sessions fail closed without exposing protected routes.
- API-key bearer requests cannot satisfy session-only or step-up routes.
- API-key bearer requests can use only granted `/api/v1` integration routes and
  remain refused for interactive session inspection.

### RBAC and Delegation

- Guest/read-only users see redacted entity and registry data.
- API-key principals inherit only their scoped grants.
- Delegations respect `starts_at`, `expires_at`, non-redelegable behavior, and
  legal-basis evidence.
- Permission-denied UI states render useful blocked actions without leaking
  adjacent privileged data.

### Settings and Data Lifecycle

- Settings autosave preserves unrelated sections and handles stale responses.
- Dirty settings navigation does not silently discard typed changes.
- API-key create/rotate shows plaintext exactly once and never after reload.
- Recovery reset and start-over flows require step-up proof.
- AI/MCP tenant gate defaults off and must be enabled before MCP can serve.
- Platform service controls show unsupported and supervisor-required outcomes
  exactly as returned by the backend; the UI must not present API self-restart or
  MCP stdio start as if Chancela directly controls those processes.
- The focused `e2e/platform-operations.spec.ts` browser proof is route-stubbed:
  it renders API/MCP service rows, posts only the MCP desired-state `start`
  action, shows `supervisor_required`, autosaves a log-level override, and does
  not prove live supervisor or process lifecycle control.
- Global logging level `off` suppresses service log output even if stale
  per-service overrides remain stored; explicit service overrides take effect
  only when the global/area level allows logging.
- `POST /v1/platform/logs/forwarded` accepts only `service_id`, non-`off`
  `level`, `target`, `message`, and bounded optional `context`; rejects unknown
  services, unknown fields, raw `stdout`/`stderr` fields, blank/oversized values
  or context, and stream or secret-like context keys; writes accepted entries
  only when global/service thresholds allow them; and appends sanitized ledger
  events only for accepted retained entries.
- Storage cleanup presents crash reports and retained exports as separate
  bounded maintenance rows, rejects unknown cleanup targets, and preserves
  permission/usage diagnostics after a failed cleanup. Retained-export dry-run
  preview reports `would_delete_*` plus a server-bound `preview_token`, keeps
  `deleted_*` at zero, and must not delete files or accept those policy fields
  for crash cleanup. Retained-export execution is UI-gated by that tokened
  preview plus the shared confirmation modal, posts the `preview_token`, rejects
  missing/stale/mismatched tokens, executes only the server-selected preview
  manifest, and renders `deleted_*` execution counts.
- SQLCipher package defaults are checked statically, and plaintext development
  paths remain explicit so local tests do not silently claim production
  encrypted deployment.

### Dashboard and Ledger

- Dashboard recent feed is newest-first and capped at 10 rows.
- Duplicate timestamps are ordered deterministically by sequence.
- Metric cards remain stable with six cards on one desktop row.
- General Arquivo uses additive `GET /v1/ledger/events/page` for newest-first
  lazy loading with numeric `before_seq` cursor pagination, default page size
  100, and normalized 1..250 limits, while `GET /v1/ledger/events` remains
  bare-array compatible.
- Ledger archive list/export share server-backed chain, scope/search, kind,
  actor, date-range, and limit filters. The web UI keeps Livro-style filters,
  an icon-only accessible clear-filters control, and export choices for
  canonical PDF/A plus JSON/TXT/CSV/HTML audit/interchange formats. Only PDF/A
  is the canonical preserved evidence export; the other formats are review or
  interchange aids.
- Ledger archive paging coverage now spans 1000+ in-memory log events and
  SQL-backed persisted store pages after reopen/reload and memory clear via
  `Store::ledger_events_page`. Ledger archive export preserves active filters,
  shares limit normalization with the paged list, and refuses unauthorized
  downloads. This does not make non-PDF/A exports preserved evidence or certify
  legal archive compliance, DGLAB acceptance, or production custody.
- Export actions that create user-owned files open the desktop/browser save
  prompt when available, return a visible cancellation state when the user backs
  out, and fall back to a safe browser download only when direct save APIs are
  unavailable.
- Download filenames preserve the legal/evidentiary distinction: working copies
  remain labeled as non-canonical, retained export ZIPs remain archive packages,
  and signed/canonical PDFs are not renamed into ambiguous draft files.
- Corrupt ledger/recovery mode shows degraded state without crashing the shell.

### Documents, Archive, and Legal Hold

- Working-copy Markdown download is labeled non-evidentiary and never mutates
  sealed PDF/A bytes.
- Preservation package includes manifest fixity, PDF/A members, evidence
  reports, signatures, and timestamp sidecars when present.
- Export-time legal hold rejects blank reasons.
- Persisted legal hold automatically appears in retention metadata and evidence
  sidecars.
- Clearing legal hold records an audit event and removes package hold metadata
  on later exports.

### Signing and Trust

- CMD, CC, and CSC setup paths stay explicit about provider/hardware/onboarding
  requirements.
- Local/co-located CC batch signing is represented in the web UI for sealed acts
  through the desktop/local CC path and `POST /v1/signature/cc/batch-sign`,
  with optional transient PIN submission, per-document results, auth-mode/event
  reporting, and declared signer-capacity evidence display. This checkpoint is
  local CC batch UI evidence only: not CMD batch signing, not CSC/QTSP remote
  batch signing, not provider-certified remote batch signing, and not
  SCAP-verified representative authority or legal-capacity proof.
- `chancela-signing` core exposes repeated per-document remote-session
  orchestration helpers over the existing `RemoteSigningSource`
  initiate/confirm one-digest flow. Each document still opens and confirms its
  own remote session/activation. This is core-only: no API route, no web UI;
  not provider-certified remote batch, not single OTP/PIN/SAD authorizing
  multiple documents, not CMD multiple-sign, not CSC/QTSP multi-hash/SAD batch,
  and not SCAP/legal-capacity proof.
- `GET /v1/acts/{id}/signature` returns additive pending-session provider
  metadata so the web can resume already-open CMD or CSC/QTSP sessions after
  reload and call the matching confirm endpoint. This is reload
  adoption/routing only. Focused route-stubbed browser proof is
  `npm run test:browser --workspace apps/web --
  e2e/remote-signing-pending-session.spec.ts`, covering provider-specific
  remote confirm for CSC/QTSP pending sessions and dedicated CMD confirm for
  legacy CMD pending sessions after reload, with fake activation/OTP values.
  No production provider approval, live CSC readiness, trust-list/legal
  validation, SCAP/legal-capacity verification, remote batch,
  qualified-signature certification, act finalization, or legal-validity claim
  is made.
- Trust policy rejects unknown, withdrawn, stale, or invalid TSL states before
  signing.
- TSA diagnostics use offline fixtures in CI and do not make live timestamp
  network calls.
- B-T timestamp evidence is included when configured; local B-LT/B-LTA planning
  and DSS/VRI evidence remain technical status only unless live trust validation,
  policy validation, and legal review are actually present.
- Arbitrary-PDF validation handles multiple signatures, missing ByteRange,
  mismatched DSS/VRI entries, future DocTimeStamp values, and tampered DSS-only
  evidence without turning local diagnostics into a qualified-signature decision.
- ASiC inspection accepts only a bounded base64 ASiC ZIP envelope, checks
  declared size/SHA-256, malformed ZIPs, and unsafe member paths, reports local
  profile/member/manifest/signature diagnostics, projects `technical_validation`
  from `validate_asic_container` for CAdES, XAdES, mixed ASiC-E signatures, and
  archive timestamp consistency, keeps the legacy bounded `cades` compatibility
  field, and enforces actual decompressed-size limits without making live trust,
  legal, or production ASiC/XAdES conformance claims.

### Imports and Search

- CAE and law search handle accents, case differences, empty queries, no
  matches, and exact-code lookup.
- TSL/TSA catalog search handles provider/service names, qualified-service
  filters, stale cache, invalid XML signature, and empty result states.
- TSL/TSA catalog browser coverage exercises accent-insensitive search,
  service-type/status/history/supply filters, URL params, fixture-only TSA
  records, and no-live-timestamp-call behavior.
- Certidao import masks access codes and never returns raw secrets.
- Registry auto-update jobs honor disabled schedules, expired access codes,
  malformed e-mail/contact fields, and per-entity conflict review before
  overwriting locally curated profile data.
- MCP `draft_minutes` creates only draft act records, rejects missing/unknown
  arguments before HTTP, injects deterministic `ai_provenance.statement_sources[]`
  rows into MCP/API draft creation, and never treats generated text as legal
  minutes. API persistence clamps unsafe statement-row human-verified,
  authoritative-source, and legal-validity claims false, and the Ata editor AI
  review panel renders grouped counts by `source_type`, row path/type/label/
  status, conservative false/no-claim flags, and missing/null fallbacks as
  review evidence only.
- Core weighted-voting checks cover complete capital/permilage attendance
  metadata, mismatched aggregate tallies, partial-weight warnings, and
  unweighted fallback paths.

### Resilience

- Browser reload after each primary workflow preserves durable state.
- Server restart with the same data dir preserves users, books, ledger, API
  keys, settings, legal holds, and DSR records.
- Concurrent writes to the same ledger chain produce deterministic conflict or
  sequence behavior.
- Static SPA fallback returns index for app routes but JSON 404 for unknown API
  routes.

## Exit Criteria

- All fast PR checks pass locally and in CI.
- Chromium core browser e2e passes as a normal PR/push gate.
- Full browser e2e passes at least once on the release branch.
- Web Vitest/V8 coverage thresholds pass in CI and in the local release loop;
  any coverage threshold waiver is explicit and release-scoped.
- Docker image builds and passes the runtime `/health` persistence smoke from a
  clean checkout.
- Release metadata artifacts include a validated dependency SBOM, package
  manifest, and SHA-256 checksums.
- Vulnerability scans have either passed in an enforced manual run or their
  report-only findings are triaged and explicitly accepted for the release.
- Package signing/notarization and Docker image signing are not claimed unless
  the release workflow actually performs those steps.
- Desktop smoke passes on Windows with a temporary data dir.
- The remaining failures, if any, are documented as external blockers such as
  live CMD, QTSP, CC hardware, production TSL/TSA network, or legal review.

## Focused Gate Snapshot Through `3e72e08`

Historical focused checks from the active director loop, refreshed on
2026-07-10 for current head `3e72e08`. This is not an exhaustive current
green-run claim; browser, Docker, desktop, package signing/notarization, image
signing/attestation, and live-provider limits above still apply.

- `actionlint .github/workflows/ci.yml`, `npx prettier --check
.github/workflows/ci.yml`, and `git diff --check -- .github/workflows/ci.yml
docs/CI-E2E-HARDENING-PLAN.md`: passed after the CI hardening workflow
  update.
- `cargo test -p chancela-server --features e2e --locked --no-run` plus the
  compile-only live seam gates for `chancela-cae`, `chancela-cmd`,
  `chancela-csc`, `chancela-law`, `chancela-registry`, `chancela-tsa`,
  `chancela-tsl`, and `chancela-smartcard`: passed.
- `cargo test -p chancela-mcp --locked`: passed at head `c54fc0e` after the MCP
  status resource landed, with 68 unit tests plus 2 live API integration tests.
- `cargo test -p chancela-core --locked`: passed 76 unit tests plus 7
  back-compat integration tests.
- `cargo clippy -p chancela-core --all-targets --locked -- -D warnings`:
  passed.
- `npm run test --workspace apps/web -- CompliancePanel.test.tsx`: passed 8
  tests after the source-reference link narrowing fix.
- `npm run test --workspace apps/web -- DashboardPage.test.tsx`: passed 5
  tests after the operator work queue and i18n wiring.
- `npm run test --workspace apps/web -- i18n.test.ts`: passed 9 tests across
  all locale catalogs after the dashboard work-queue strings were added.
- `npm run test --workspace apps/web -- ActDocumentPanel.test.tsx`: passed 13
  tests after the imported-document UI worker landed.
- `npm run test --workspace apps/web -- src/contracts/contracts.test.ts`:
  passed 39 contract fixture tests after adding web-side pins for
  `retention.policies.json` and `paper-book.import.json`.
- `npm run test --workspace apps/web -- SettingsPage.test.tsx users.test.tsx`:
  passed 46 tests after redirecting the legacy `/utilizadores*` routes into
  the canonical Settings users section.
- `npm run build --workspace apps/web`: passed after the contract pinning and
  Settings-only user-management cleanup.
- `npm run lint --workspace apps/web`: passed.
- `npm run test --workspace apps/web`: passed 55 test files / 390 tests. Vitest
  emitted a nonfatal jsdom navigation-not-implemented stderr from an anchor test,
  but the command exited green.
- `npm run format:check --workspace apps/web` and `npm run build --workspace
apps/web`: passed after dashboard formatting and the CompliancePanel
  TypeScript fix.
- `npm run test:browser --workspace apps/web -- e2e/operator-edge.spec.ts`:
  passed 6 Playwright tests through the official script; the Windows temp DB
  cleanup warning was nonfatal.
- `cargo test -p chancela-doc --locked`: passed 11 unit tests plus 4 PAdES
  roundtrip integration tests after the accessibility/PDF-UA honesty slice.
- `cargo fmt -p chancela-doc -- --check`: passed.
- Additional 2026-07-09 director-loop focused checks after the next fan-out:
  `cargo test -p chancela-tsl --locked` passed after the TSL/TSA record-search
  module landed; `cargo test -p chancela-api redaction --lib --locked`,
  `cargo test -p chancela-api --test privacy retention --locked`,
  `cargo test -p chancela-api --test paper_import --locked`,
  `cargo test -p chancela-api --locked books_import_preflight`,
  `cargo test -p chancela-api router_walk_every_route_is_classified --locked`,
  and `cargo test -p chancela-api --test external_signing_envelopes --locked`
  passed after route classification and parser-detail assertion repair.
  `cargo test -p chancela-core --locked` and
  `cargo clippy -p chancela-core --locked --all-targets -- -D warnings`
  passed after the condominium rule-depth slice.
- Web/Docker focused checks from the same wave passed: dashboard unit tests,
  Ferramentas trust unit tests for truncated/copyable TSA hashes, direct
  Playwright smoke 6/6, Playwright cleanup-proof wrapper lint/prettier/help, and
  Docker image build plus `/health` persistence smoke.
- Follow-up focused checks also passed after the provider/document/release/test
  lanes landed: `npm run check:versions`, `actionlint .github/workflows/ci.yml`,
  `node --check scripts/check-versions.mjs`, `cargo test -p chancela-signing
--locked`, `cargo clippy -p chancela-signing --all-targets --locked --
-D warnings`, `cargo test -p chancela-server --features e2e --locked --test
e2e_static_serving`, `cargo test -p chancela-api
router_walk_every_route_is_classified --locked`, `cargo test -p chancela-api
settings --locked`, `cargo test -p chancela-api document_import --lib
--locked`, `cargo test -p chancela-api --test apikey_auth --locked`, and
  `npm run test --workspace apps/web -- SettingsPage.test.tsx
settingsDefaults.test.ts contracts.test.ts`.
- Additional edge-case E2E checks landed after that: external-signer public URL
  safety passed in Playwright (`e2e/external-signer-public-safety.spec.ts`),
  and composed-server backup/restore E2E passed 2/2 after adding invalid-restore
  no-partial-apply coverage. Browser degraded-mode coverage passed 9/9 in
  `e2e/resilience-edge.spec.ts`, covering degraded banner/no-crash behavior,
  blocked create/archive flows, and the recovery link to Settings integrity.
- Packaging/release-hardening checks from the same wave passed: `npm run package`
  produced the Windows tarball with `manifest.json`, `SHA256SUMS`, `chancela.exe`,
  `chancela-server.exe`, and operator scripts; package checksum verification passed.
- Store hardening checks: `cargo test -p chancela-store --locked` passed after
  the feature-gated SQLCipher keyed-open foundation. The SQLCipher feature test
  (`cargo test -p chancela-store --locked --features sqlcipher sqlcipher`) now
  has a Windows CI lane that installs pinned Strawberry Perl before Rust/Cargo so
  vendored OpenSSL sees a Windows-native Perl first on `PATH`.
- Recent 2026-07-10 focused checks through `783538c`: `npm run
  check:encrypted-build-defaults`, `cargo metadata --locked --format-version 1
  --features "chancela-server/sqlcipher chancela-cli/sqlcipher" --no-deps`,
  desktop Tauri SQLCipher metadata, and Windows `cargo check -p
  chancela-server -p chancela-cli --locked --features
  "chancela-server/sqlcipher chancela-cli/sqlcipher"` passed with Strawberry
  Perl pinned.
- Recent platform/service checks through `5a79f1e`: `cargo fmt -p
  chancela-api -- --check`, `cargo test -p chancela-api platform_ --locked`,
  `cargo check -p chancela-api --locked`, and `cargo clippy -p chancela-api
  --locked --all-targets -- -D warnings` passed.
- Current working-tree structured platform-log ingestion checks: focused
  `cargo test -p chancela-api --locked platform_logs_forwarded` coverage pins
  `POST /v1/platform/logs/forwarded` route behavior, write-permission auth,
  tail visibility, data-dir persistence/reload, global/service `off`
  suppression without sidecar writes, and strict request validation for unknown
  services, `off`, unknown fields, raw `stdout`/`stderr`, blank/oversized
  values/context, and secret-like context keys, plus sanitized
  `platform.log.forwarded.accepted` ledger events for accepted retained forwards
  and sanitized `platform.log.forwarded.denied`, `.rejected`, and `.suppressed`
  ledger audits for authenticated RBAC denial, rejected structured/malformed
  payloads, and threshold/global/service-off suppression. Missing/invalid bearer
  requests stay unaudited, accepted retained forwards still produce one accepted
  audit, and the audit payloads avoid raw body/message/context keys/parse errors/
  stdout/stderr/tokens/secrets/user strings. Focused `cargo test -p
  chancela-authz --locked platform_log_write_is_seeded_only_to_owner_and_platform_admin`
  coverage pins fresh seeded `platform.logs.write` defaults for Owner and
  Platform Administrator only, excluding API Client. This remains a bounded API
  log-tail ingress check only: no lifecycle control, stdout/stderr capture,
  production supervisor/SIEM/HA/observability proof, generalized observability
  sink, log retention/deletion semantics, or legal/compliance claim is
  implemented.
- Recent web focused checks through `3f19872`: books, notification popup/page,
  storage settings, ESLint, Prettier, `npm run check:spec-coverage`,
  `node --check scripts/checkpoint-recent-landed.mjs`, and `npm run
  test:checkpoint:recent-landed:static` passed.
- Recent notification footer checks through `938b61e`: the focused
  `NotificationBell.test.tsx` coverage, Prettier, and ESLint passed for the
  icon-only popup footer action.
- Recent web focused checks through `5aad733`: onboarding first-user email,
  Settings user create/edit email, Ata signatory email, and Data Management
  cleanup-row/retained-export target coverage are the focused UI checks for the
  latest web slices, alongside Prettier and ESLint.
- Current working-tree retained-export cleanup UX checks: focused API/core
  markers pin export dry-run `would_delete_files`, `would_delete_directories`,
  and `would_delete_bytes` planning with `deleted_files`, `deleted_directories`,
  and `deleted_bytes` all zero, a server `preview_token`, and retained files
  preserved. Focused Settings Data Management markers pin the preview-only
  `{ target: "exports", dry_run: true, minimum_age_days: 30, keep_latest: 5 }`
  payload, no-files-removed result copy, disabled execution button until a
  tokened preview exists, shared-modal confirmation gate, execution payload with
  that `preview_token`, token-required/stale-mismatch rejection, server-selected
  preview manifest deletion, and execution copy based on `deleted_*` counters. Crash cleanup
  continues to reject export policy fields. This is retained local export file
  cleanup coverage only, not GDPR erasure, legal disposal, archive deletion,
  certification, anonymization/redaction completion, full data deletion,
  retention execution, deletion outside the bounded server-selected manifest, or
  a broad deletion claim.
- Recent trust-source provider checks through `fa57352`: focused
  `SettingsPage.test.tsx` trust-source/TSA-provider coverage, i18n locale
  catalog validation, Prettier, and ESLint are the focused web checks for
  settings-backed TSL/TSA provider management.
- Recent trust catalog display checks through `c3d874b`: focused Ferramentas
  trust tests pin the `trust-accepted-hash` wrapper, copyable truncated accepted
  TSA hash behavior, and labelled `Registos TSA` result grouping without making
  live trust-network calls.
- Current working-tree PDF accessibility checks: focused document tests pin
  accessibility report JSON version 9, structure-tree diagnostics, explicit
  role-map target entries, marked-content coverage counts, bounded local
  topology facts, and marked-artifact target/operator evidence for
  writer-owned decorative rule artifacts emitted as PDF artifacts. The default
  fixture no longer reports
  `no_alt_text_model` for only writer-owned decorative artifacts, page breaks
  stay excluded through
  `accessibility_page_breaks_do_not_require_decorative_accounting`, and
  `accessibility_non_text_accounting_covers_current_block_variants` keeps
  `DocumentBlock` accounting exhaustive for future caller-owned non-text
  variants. `LimitedTaggedStructure` remains machine-visible while
  `pdf_ua_claimed` stays false and no PDF/UA certification claim or `pdfuaid`
  metadata is emitted. This is blocker reduction only, not PDF/UA conformance,
  validator evidence, legal sufficiency, or signed-PDF accessibility
  certification.
- Recent export-save checks through `ff1823a`: focused browser E2E pins
  `installCancelledBrowserSavePicker`, the visible `Guardar cancelado` result,
  preserved save-picker options, no browser-download fallback, and no mutation
  when a sealed-act PDF save prompt is cancelled.
- Recent dashboard density checks through `2ffae33`: focused dashboard unit
  coverage pins the six-card stats order, `desktop-six` density marker, and
  compact summary CSS for the desktop metrics row.
- Recent SQLite logical-usage checks through `2187a67`: data-status coverage
  pins `sqlite_logical_table`, `sqlite_table_*` logical payload entries,
  `sqlite_logical_payload` basis, and the API test that rejects the old
  "sqlite logical usage not reported" placeholder.
- Recent browser export-save gate checks through `fd70ca0`: the focused books
  and entities CSS tests now dynamically import `node:fs` inside runtime CSS
  assertions instead of statically importing it, and the focused books/entities
  test run passed 34 tests alongside eslint/prettier. The browser export-save
  lane then passed 4 Chromium tests with
  `npm run test:browser --workspace apps/web -- e2e/export-save-hardening.spec.ts`.
- Recent web SQLite table-usage checks through `c1c57fe`: focused
  `GestaoDadosSection` coverage passed 13 tests after adding optional
  `DataUsageConcern.kind`, contract tolerance, `sqlite_logical_table` fixture
  rows, `data-status-sqlite-table-list` / row DOM and CSS markers, plus
  prettier/eslint and scoped `git diff --check`.
- Current working-tree data-status sidecar classification checks: focused API
  markers pin `data_status_concern_classification_covers_known_roots` and
  `/v1/data/status` filesystem concerns for `platform-logs.json` as
  `platform_logs` and `backup-recovery-drills.json` as
  `backup_recovery_drills`. These checks preserve durable permission/status
  behavior and classify sidecar usage only; they do not add deletion, retention
  execution, legal custody proof, or data-lifecycle certification.
- Recent keyed PAdES VRI `/TU` checks through `76fc229`: worker validations
  passed `cargo fmt`, `cargo test -p chancela-pades`,
  `cargo test -p chancela-api pdf_signature`,
  `cargo test -p chancela-api signature_evidence_status`,
  `cargo check -p chancela-signing`, `cargo check -p chancela-api`, and
  `git diff --check`. The checks pin `vri_tu_keys`,
  `has_vri_tu_for_key`, keyed API signature/PDF validation payloads, and
  multi-signature renewal planning for the specific VRI key without claiming
  production/legal PAdES-LT/LTA completion.
- Current working-tree PAdES DSS validation-time checks: focused
  `cc_signing` and `chancela-pades` tests pin caller-supplied
  `validation_time` on local DSS attach, DSS VRI `/TU` emission from local
  caller-supplied evidence, malformed-time rejection without digest or audit
  mutation, and local renewal-plan movement to document timestamp and
  `monitor_timestamp_renewal` states when bounded local inputs are present.
  These are technical evidence markers only; they do not fetch live OCSP, CRL,
  TSA, or TSL material and do not claim legal B-LT/B-LTA, production long-term
  profile, QES, qualified status, or legal LTV.
- Recent compact notification/entity filter checks through `2c88b90`: worker
  validations passed 20 notification tests, 4 export-save browser-gate Chromium
  tests, 21 entities tests, plus prettier/eslint/diff checks. These pin compact
  notification list rows, title-folded tags, bell badge z-index/pointer-events
  assertions, entity primary-filter nowrap desktop/mobile-wrap CSS, and
  advanced-filter no-overflow grid assertions.
- Recent compact template-filter checks through `5db121a`: focused Minutas
  markers pin search/family/stage as compact primary controls, locale/channel/
  signature/rule-pack as a collapsed advanced filter area, clear-filter behavior,
  and no-overflow CSS declarations for the primary row, advanced grid, and action
  button.
- Current working-tree agenda-item template checks: focused
  `cargo test -p chancela-templates --locked` coverage pins
  `catalog_includes_agenda_item_template_for_every_supported_family`, the five
  `ponto-ordem-trabalhos/v1` Convocatoria assets for CSC, condominium,
  association, foundation, and cooperative families, channel-neutral metadata,
  rule-pack/signature-policy hints, and the 101 total / 41 CSC catalog census.
  The same lane still pins `csc-ata-divisao-quotas/v1` and
  `csc-ata-unificacao-quotas/v1` quota parity plus the unresolved
  `csc.deliberacao.maioria_qualificada` majority threshold marker, and
  `csc-ata-delegacao-poderes/v1` / `csc-ata-revogacao-poderes/v1` proposed
  resolution text without adding threshold markers. These are local catalog
  parity/rendering checks only; law references remain Pending/non-authoritative
  with no DRE verification, guessed threshold, authority verification,
  registry submission, external registry/provider integration, signing-process
  claim, legal sufficiency, or new law-source claim.
- Current working-tree post-act template semantic-lint checks: focused
  `cargo test -p chancela-templates --locked` coverage pins the authored
  catalog guard that `Certidao` and `Extrato` `BlockSpec` template strings bind
  sealed-act `ata_number` and `payload_digest`, plus a synthetic missing-binding
  regression proving the guard applies only to post-act stages. This is
  test/build-time catalog consistency only; no asset wording changes, DRE
  verification, Verified law references, legal thresholds, or legal-effect
  claims are implemented.
- Recent compliance tooling checks through `3e72e08`: focused markers pin
  structured book termo signatories with email and legacy string compatibility,
  the Settings retention execution review queue and `/v1/privacy/retention-executions`
  status filter, backend database-encryption key-source status with fail-closed
  `hardware_derived_fallback`, and the PDF verifier UI for DSS/VRI `/TU`,
  DocTimeStamp, local renewal evidence, and explicit no-live-trust/no-legal-claim
  guardrails. These remain review/status/UI markers only; they do not claim
  destructive retention execution, hardware-key custody, production SQLCipher
  completion, live trust validation, PDF/UA, or legal validity.
- Current retention evidence checks through `869e02f`: API and Settings markers
  pin read-only `GET /v1/privacy/retention-due-candidates` for closed-book
  archive/document candidates selected from active retention policies, closing
  date plus supported retention periods, legal-hold blockers, required
  approvals, unsupported-period findings, and explicit false
  destructive/full-erasure flags. The evidence state surface is explicit and
  non-destructive: `review_queued`, `blocked`, `bounded_archive_recorded`,
  `bounded_no_action_recorded`, and `prior_bounded_evidence_available`.
  Settings renders the candidates without creating execution, disposal, or
  erasure records on page load, and exposes candidate-row actions that post a
  dry-run `execution_request` with forced/default `review_only` for review
  queues or `execute_supported` for bounded evidence recording, then refresh
  due-candidate and execution-history queries after an execution record.
  Duplicate `review_only` requests for the same candidate/policy, including
  concurrent duplicates, reuse the existing `awaiting_review` execution record
  and do not append another history record or ledger event. Due-candidate GET
  remains read-only while surfacing existing queued review status/id/time, and
  Settings shows that queued state instead of posting again. Due-candidate
  reads can also derive prior safe bounded `executed` archive/no-action
  evidence for the same candidate/policy with no write, audit, policy, or
  legal-hold mutation; suppression requires bounded executor evidence, acted
  targets, and false destructive/full-erasure flags. That evidence omits rows
  from the active candidate list by derived evidence only: `candidate_count`
  reports active unsuppressed rows, `suppressed_candidate_count` and
  `suppressed_by_bounded_evidence_count` report bounded-evidence omissions, and
  optional `suppression_summary` explains that execution history remains
  queryable for review. Settings can initiate the dry-run-backed
  `execute_supported` path only for eligible `disposal_action === archive` or
  `disposal_action === no_action` due-candidates: concrete record id,
  non-destructive, no blockers or legal holds, no queued review, no prior
  execution, and no suppressed evidence state. That UI payload remains scoped to
  the dry-run endpoint, candidate/policy identifiers, and
  `execution_mode: "execute_supported"`; ineligible rows remain review-only,
  disabled, queued-review, or existing-evidence badge paths.
  `POST /v1/privacy/retention-executions/{id}/review-closure` records separate
  review closure fields for an existing execution record without changing
  `execution_status` or `outcome`. Focused API coverage pins review-only,
  bounded, and blocked closure decisions, idempotent same-closure repeats,
  conflict on different closure evidence, authorization/unknown-field/unsafe
  claim rejection, data-dir persistence, and due-candidate reads that stay
  non-mutating after closure. Contract/client/Settings coverage pins
  `review_closure_decision`, note/evidence, closed actor/time, the
  `closeRetentionExecutionReview` client route, false destructive/full-erasure/
  legal-hold/policy-mutation flags, outcome-category decision mapping, closure
  history rendering, and hidden closure actions for already closed records.
  Route-mocked browser coverage proves the operational closure action posts only
  the review-closure endpoint, keeps due-candidate counts stable, keeps closure
  copy non-legal/non-destructive, and makes no dry-run, destructive, disposal,
  erasure, policy, or legal-hold mutation calls. This remains non-destructive
  scanner/review/bounded archive/no-action evidence UI plus operational closure
  only: no physical deletion, anonymization, redaction completion, destructive
  GDPR erasure, full erasure, legal disposal completion, legal approval,
  disposal execution, persisted resolved flag, legal-hold/policy mutation,
  candidate disposal, or FULL coverage is implemented.
- Current working-tree AI provenance checks: MCP/API draft creation now carries
  deterministic `ai_provenance.statement_sources[]` rows, the API persists those
  rows while clamping unsafe row-level human-verified, authoritative-source, and
  legal-validity claims false, and the Ata editor AI review panel renders a
  bounded local provenance panel with deterministic local summary counts,
  grouped provenance summary counts by `source_type`, grouped review-status
  counts, statement-source row path/type/label/status, conservative `human_verified`,
  `authoritative_source_claimed`, and `legal_validity_claimed` flags, and
  missing/null field fallbacks plus explicit false no-claim markers
  (`legal_validity: false`, `source_certification: false`, `provider: false`,
  `trust: false`, `external_validation: false`, and
  `signature_qualification: false`) while keeping accept/reject unchanged. This
  remains deterministic persistence/rendering and offline/static review guidance
  coverage only: no bridge/API/AI-provider/hidden-provider calls, no secrets,
  no model accuracy or AI quality assessment, no legal advice or legal-validity
  claim, no source certification, no provider assurance, no trust validation,
  no external validation, no new provider/network or non-stdio MCP behavior, no
  unreviewed finalization, no automated
  draft-vs-signed comparison execution, and broader extraction/compare/summarize
  remains incomplete.
- Current working-tree MCP workflow provenance review checks: focused
  `cargo test -p chancela-mcp --locked` coverage pins the static
  `workflow_provenance_review_checklist` prompt, the
  `chancela://mcp/workflow-provenance-review` resource, offline/static
  resource flags, no arguments, no bridge/API/provider calls, no secrets, review
  category coverage, and false legal/source/provider/trust/external claim flags.
  This is review guidance only: no AI or MCP completion claim, no legal validity,
  no source certification, no provider assurance, no trust validation, and no
  external validation.
- Current working-tree MCP draft-vs-signed comparison review checks: focused
  `cargo test -p chancela-mcp --locked` coverage pins the static
  `draft_signed_comparison_review_checklist` prompt, the
  `chancela://mcp/draft-signed-comparison-review` resource, local-json/static
  guidance mode, deterministic local comparison report mode for
  `arguments.draft` and `arguments.signed`, changed digest/status/reference
  detection, missing/unknown/unmapped field reporting, no extra resource params,
  no bridge/API/AI-provider/hidden-provider calls, no secrets, false
  legal/source/provider/trust/external-validation/signature-qualification claim
  flags, and false AI-01/full AI/MCP completion flags in the spec-09 resource.
  This is technical comparison signal only with human review still required: no
  AI or MCP completion claim, no legal validity, no source certification, no
  provider assurance, no trust validation, no external validation, no signature
  validation, no qualified signature status, and no signed-artifact
  certification.
- Current working-tree dashboard guest recent-events redaction checks: focused
  `cargo test -p chancela-api --locked dashboard_recent_events_redacts_guest_feed_but_keeps_owner_and_reader_feed`
  coverage pins `recent_events: []` for guest/minimal dashboard readers, Owner
  and `Leitor` recent-event visibility, and continued Guest refusal from
  `/v1/ledger/events`. This is response redaction only: no permission grants,
  full anonymization, destructive erasure, or policy-completeness claim.
- Current working-tree generated-document by-id download, dispatch-evidence, and
  dashboard absent-owner reminder checks: focused
  `cargo test -p chancela-api --locked on_demand_generate_persists_a_chosen_document_and_emits_the_event`
  and
  `cargo test -p chancela-api --locked in_memory_generated_document_download_uses_returned_url_and_keeps_canonical_ata`
  plus
  `cargo test -p chancela-server --test e2e_act_document_persistence --locked condominium_absent_owner_communication_auto_generates_and_keeps_canonical_ata`
  plus `cargo test -p chancela-api --locked absent_owner_dispatch_evidence_`
  and
  `cargo test -p chancela-store --test store --locked generated_document_dispatch_evidence`
  coverage pins `/v1/documents/generated/{document_id}`, route classification,
  `act.read` gating by the owning act, durable and in-memory lookup, and
  preservation of `/v1/acts/{act_id}/document` as the sealed Ata bytes. It also
  pins automatic condominium absent-owner communication generation after seal,
  generated-document by-id retrieval of that communication, pending dispatch
  evidence status, restart persistence, `POST`/`GET`
  `/v1/documents/generated/{document_id}/dispatch-evidence`,
  `generated_document_dispatch_evidence`, operator-supplied dispatch evidence
  with exact-retry idempotency, selected absent-recipient evidence coverage,
  evidence-attached/status headers, no dispatch-completed header claim, and the
  bounded
  `absent_owner_communication.dispatch_evidence_recorded` event false flags.
  The `cargo test -p chancela-api --locked reminder_` lane also pins
  `GET /v1/dashboard` absent-owner dispatch-evidence reminders for
  `required_pending` and `operator_evidence_partial`, suppresses
  `operator_evidence_covered`, keeps no-date reminders `Pending`/`Advisory`,
  routes them to
  `/atas/{act_id}?generated_document_id={document_id}&focus=dispatch-evidence#generated-dispatch-evidence`,
  points `api_href` to `/v1/documents/generated/{document_id}/dispatch-evidence`,
  and keeps valid dated reminders ahead of no-date reminders before `dashboard_limit`
  truncation through
  `reminder_generated_absent_owner_no_due_date_does_not_evict_dated_reminders_before_limit`.
  Focused web coverage is
  `npm run test --workspace apps/web -- src/api/client.test.ts src/contracts/contracts.test.ts src/features/dashboard/DashboardPage.test.tsx src/features/documents/ActDocumentPanel.test.tsx src/i18n/i18n.test.ts`;
  it pins `listGeneratedDocuments`, `getGeneratedDocumentDispatchEvidence`,
  `recordGeneratedDocumentDispatchEvidence`, generated absent-owner
  communication listing, generated PDF fetch, stored evidence rows,
  permission-gated metadata-only evidence recording, `operator_evidence_*`
  status display, `documents.generated.noClaim.*` localized copy, dashboard
  localized deep-link routing, notification deep-link routing, one-time
  ActDocumentPanel dispatch-evidence selection/focus, advisory absent-owner
  reminder copy, and the `contracts/dashboard.json` pending no-due-date
  generated absent-owner fixture.
  Focused route-stubbed browser proof is
  `npm run test:browser --workspace apps/web -- e2e/absent-owner-dispatch-evidence.spec.ts`;
  it pins the advisory dashboard reminder opening the generated-document
  dispatch-evidence form, generated `condominio-comunicacao-ausentes/v1`
  visibility/download, metadata-only evidence recording, resulting operator
  evidence row display, and no send/delivery/legal-notice completion claims.
  This is generated-document retrieval, dashboard/notification navigation, and
  operator-recorded dispatch-evidence metadata only: no sealed act, canonical
  Ata, or generated-byte mutation; no mail, email, SMS, or provider sending; no
  delivery, legal notice completion, legal sufficiency, legal effect, provider
  execution, registry filing, signing, bundle readiness, template legal review,
  threshold correctness, law verification claim, dashboard ledger-event append,
  archive action, legal validity certification, or dispatch-complete claim.
- Current working-tree external-validator raw-report checks: focused API,
  archive-package, and web Ferramentas tests now pin bounded
  `raw_report.content_base64` acceptance only when declared byte length and
  SHA-256 match, fail-closed digest mismatch rejection, create/list response
  redaction of embedded bytes, document-bundle evidence-index summaries, archive
  package embedding of verified raw report files under the external-validator
  evidence path, manual JSON metadata upload continuity, raw report file
  selection with local filename/type/size/digest/provenance summary, no automatic
  upload on selection, explicit submit payload fields (`content_base64`,
  `content_type`, `size_bytes`, `sha256`, safe `source_filename`), backend
  summary rendering, and raw byte/content redaction from the DOM. These are
  technical preservation/fixity checks only, not legal validator acceptance,
  trust-list validation, authority/legal validation, report replay
  certification, external certification, PDF/UA/PAdES certification, compliance
  proof, or provider approval.
- Current working-tree raw external-validator report download checks: focused
  API/static markers pin `GET
  /v1/external-validator-reports/{case_id}/{validator_family}/raw-report`,
  `settings.read` gating, retained raw byte output with attachment headers,
  create/list redaction of `content_base64`, 404 for missing or manifest-only
  reports, and fail-closed unsafe identity, malformed sidecar, and
  duplicate/ambiguous identity behavior. There is no auto-upload, no UI raw
  rendering, and no validator, legal, certification, trust, external-validation,
  or provider-approval claim.
- Current working-tree imported-document review receipt/history checks: focused
  `npm run test --workspace apps/web -- src/features/documents/ActDocumentPanel.test.tsx`
  coverage pins the review-depth summary, `Recibo de revisão` group, and
  `Histórico técnico de revisão` group, pending `Sem recibo de revisão` without
  fake reviewer/time/note/guardrail details, neutral/not-indicated copy when
  preservation status is missing, latest reviewed status/reviewer/time/note plus
  required and acknowledged guardrails, ordered prior decisions, explicit
  no-claim rows for OCR/conversion/PDF-A replacement/signed artifact/signature
  validation/seal/PDF-UA/certification/legal acceptance, and no accidental
  bytes/archive/signed-document/external-validator/trust/OCR/conversion calls.
  This is imported-document metadata rendering and bounded review-history
  projection only, with no download, OCR, conversion, PDF/A replacement, signed
  PDF, signature validation, seal, PDF/UA, certification, or legal acceptance
  behavior.
- Current working-tree trust catalog identifier-match checks: focused
  `cargo test -p chancela-api trust --locked` and `npm run test --workspace
  apps/web -- src/features/ferramentas/trust.test.tsx` coverage pins optional
  `identifier_match` on identifier-filtered TSL/TSA rows, omission without
  identifier filters, strict complete SHA-256/SKI matching, no loose partial-hash
  inference, technical-only match explanation copy, truncated display, and full
  hash/SKI copy actions. These are catalog explanation checks only, not legal
  validity, certificate trust, provider approval, external validation,
  qualified-status, or trust-list certification.
- Current working-tree local DGLAB interchange manifest API checks: focused
  `archive_package` API tests plus `chancela-archive` markers pin read-only
  `GET /v1/books/{id}/archive/local-dglab-interchange-manifest`,
  `book.export@Book` gating, `LocalDglabInterchangeManifest`,
  `chancela-local-dglab-interchange-manifest/v1`,
  `build_local_dglab_interchange_manifest`, deterministic/sorted file entries,
  `validate_local_dglab_interchange_manifest` source-manifest validation,
  rejection of true official-DGLAB/certification/approval/legal-archive/
  destructive-disposal flags, no ZIP member, no persisted package/manifest bytes,
  and no ledger event. This is local scaffold JSON coverage only; no official
  DGLAB export, government filing, UI, import flow, package validation change,
  disposal execution, PDF/A/PAdES/PDF-UA certification, authority approval, or
  legal archive claim is implemented.
- Current working-tree paper-book OCR conversion-dossier and execution-artifact
  checks: focused `cargo test -p chancela-store --test store --locked
  paper_book_ocr_conversion`, `cargo test -p chancela-api --test paper_import
  --locked paper_book_ocr_conversion`,
  `npm run test --workspace apps/web -- src/contracts/contracts.test.ts`, and
  `npm run test --workspace apps/web -- src/features/books/books.test.tsx`
  coverage pins accepted matching draft requirements, metadata-only response
  fields, idempotent duplicate dossier creation without another ledger event,
  v14 `paper_book_ocr_conversion_execution_artifacts` storage, accepted
  OCR-to-mutable-Draft act artifact creation, optional dossier binding,
  `conversion_execution_artifact` and `conversion_execution_artifacts` response
  shapes, raw OCR text redaction from responses, ledger events, artifact
  payloads, and dossier UI, false canonical/document/PDF-A/PDF-UA/signature/
  seal/archive/legal flags, the derived OCR/dossier review-depth summary with
  fallbacks for no OCR draft/no accepted draft/no dossier, existing-dossier
  rendering without duplicate creation, accepted-draft gating, operator-only
  creation with no automatic POST, separate mutable draft-act creation, reviewed
  conversion execution evidence rendering, and no document/signature/seal/archive
  endpoint calls from the dossier UI. This is metadata-only/reviewed execution
  evidence for mutable drafting only; no legal archive certification, official
  DGLAB acceptance/export, PDF/UA delivery, OCR accuracy certification,
  canonical minutes/legal conversion, signed artifact validity, or legal-validity
  claim is implemented.
- Current working-tree external-signing envelope UI checks: focused
  `external_signer_invites` coverage pins optional envelope/slot request fields,
  first sequential slot initiation, later sequential slot 409 refusal without
  token/storage, parallel slot initiation, public lookup redaction, and
  accept-response tracking that leaves signature status unsigned. Linked invite
  accept with a validated signed PDF now pins the technical evidence-only path:
  it stores act-scoped signed-PDF evidence, can mark only the linked external
  envelope slot signed when that slot has no identity requirements, updates the
  normal envelope read/list completion summary (`signed_required_slot_count` and
  blocking slot IDs), refuses identity-required slots with a bounded blocked
  reason, and replays idempotently without duplicate signed documents, slot
  evidence, or update events. The public invite upload path is bounded before
  frontend file read and by the backend body-limit envelope. The web
  external-signing evidence slice now also pins `updateExternalSigningEnvelope`
  on `PATCH /v1/external-signing/envelopes/{id}`,
  `useUpdateExternalSigningEnvelope(actId)`, `SlotEvidenceMetadata` rendering,
  `slotCanRecordTechnicalEvidence`, `buildSlotEvidenceRows`, and
  `identity_requirement: requirement` rows. `SigningPanel.test.tsx` covers
  identity-tagged operator evidence submission with no `complete:true`, stored
  evidence metadata display, and pending/initiated-only evidence actions;
  `client.test.ts` covers the client PATCH route/payload, and
  `external_signing_envelopes.rs` pins that signed slot evidence without
  `complete:true` leaves the workflow envelope open. Focused route-stubbed
  browser proof in `external-signing-operator-evidence.spec.ts` now covers the
  signed-in operator path, exact `PATCH /v1/external-signing/envelopes/{id}`
  `slots` payload that omits `complete:true`, identity-requirement-tagged
  evidence rows, stored slot evidence metadata after the update, browser
  no-secret boundary for PIN, OTP, CAN, credential, token, password, passphrase,
  and private-key material, and no provider calls, trust-list checks,
  QES/qualified status, legal validity, provider completion, act finalization,
  or full envelope legal completion. Focused web coverage in
  `SigningPanel.test.tsx`, `client.test.ts`, and
  `ExternalSigningWorkflowsPage.test.tsx` also pins workflow-only envelope
  list/create UI, order policy and signer-slot payloads, optional linked-slot
  invite payloads (`external_envelope_id` / `external_slot_id`), tracking-only
  payloads when no slot is selected, safe sequential 409 messaging without raw
  backend/token-like detail after slot selection changes, and localized
  Ferramentas `workflow: external_envelope` labels. `ExternalSignerInvitePage.test.tsx`
  and `i18n.test.ts` also pin that upload/result copy is technical evidence only
  and that non-pt locale keys do not leak Portuguese source text. The focused
  web command is
  `npm run test --workspace apps/web -- src/api/client.test.ts
  src/contracts/contracts.test.ts
  src/features/signing/ExternalSignerInvitePage.test.tsx
  src/features/ferramentas/ExternalSigningWorkflowsPage.test.tsx
  src/features/signing/SigningPanel.test.tsx src/i18n/i18n.test.ts`; run the
  browser proof with `npm run test:browser --workspace apps/web --
  e2e/external-signing-operator-evidence.spec.ts`. This is
  invite/envelope tracking plus linked no-identity-slot technical evidence
  status and operator-supplied workflow slot evidence only; it is not provider
  signing, PIN/OTP/passphrase collection, provider calls, trust-list checks,
  QES/qualified status, legal validity, provider completion, act finalization,
  full envelope legal completion, or public token exposure.
- Current working-tree official signed-PDF handoff browser checks: focused
  route-stubbed Playwright proof is `npm run test:browser --workspace apps/web
  -- e2e/official-signed-handoff.spec.ts`. It pins the sealed-act browser UI for
  importing a PDF already signed outside Chancela as technical signed-PDF
  evidence only, requires guardrail acknowledgement before import, asserts the
  exact official import guardrail IDs and client-declared trace context only
  (`provider`/`source`/`filename`), verifies collecting no PIN, OTP, CAN,
  credential, token, password, passphrase, or private-key material, rejects live
  provider/trust/signing route calls, and checks the imported evidence result
  plus no-claim copy that Chancela does not perform trust-list validation, claim
  qualified status, or complete legal signing acceptance. Treat this as local
  browser proof only, not live
  Autenticacao.gov/CC/CMD/CSC/QTSP execution, provider-backed signing,
  trust-list/provider validation, qualified-signature status, legal
  validity/effect/sufficiency, act finalization, or legal signing acceptance.
- Current working-tree ASiC inspection/decompression checks: focused `cargo
  test -p chancela-api --test asic_signature_validation --locked` coverage pins
  `POST /v1/signature/asic/inspect`, base64 ASiC ZIP envelopes with optional
  filename/declared size/declared SHA-256, fixity/base64/malformed-ZIP/
  unsafe-path refusals, profile shape, bounded profile, blockers, member paths,
  manifest diagnostics, signature diagnostics, no-claim fields,
  `technical_validation` projected from `validate_asic_container` for CAdES,
  XAdES, mixed ASiC-E signatures, and archive timestamp consistency, plus the
  legacy bounded `cades` compatibility field. Focused `cargo test -p
  chancela-signing --test roundtrip --locked asic_` coverage pins actual
  decompressed-size accounting for payloads, manifests, CAdES signatures, XAdES
  signatures, unsupported `META-INF`, and other non-directory members, including
  underdeclared entries that must still produce inspection blockers. This is
  local technical inspection only: no signing, storage, archive mutation, live
  provider calls, TSA/TSL/OCSP/CRL fetching, trust anchoring, legal validity,
  QES, B-LT/B-LTA, eIDAS legal-effect, or production ASiC/XAdES conformance
  claim is implemented.
- Current working-tree TSL XML-DSig checks: focused `chancela-tsl` coverage now
  pins bounded P-256 ECDSA-SHA256 verification only when the embedded signer
  certificate matches a configured trust anchor and only for XML-DSig's
  fixed-width raw `r||s` signature value, with DER ECDSA encodings rejected.
  This remains technical trust-list parsing evidence only; it is not real C14N,
  certificate path/revocation/policy validation, broad ECDSA support, legal
  trust certification, production trust-list validity, multiple-reference
  support, or transform-chain support.
- Current working-tree trust/import/static hardening checks: focused API
  coverage pins TSL/TSA outbound URL policy that rejects unsafe schemes plus
  localhost, loopback, private, link-local, reserved, and unspecified ranges
  including `0.0.0.0/8`; validates resolved addresses before runtime fetch;
  pins the resolved address into `reqwest`; and disables redirects plus system
  proxy use. The loopback allowance is debug/test-only, exact-origin scoped,
  RAII-dropped, and has no env-var production bypass. TSL import from invalid
  signature/trust-anchor XML fails closed and does not promote or replace the
  cache; unsafe URL imports fail before fetching or cache replacement. Settings
  rejects private/loopback/metadata TSL/TSA URLs. Timestamping and signing trust
  policy fail before network/PDF work for unsafe sources. `/v1/books/import`
  has route-level and handler-level body limits and rejects oversized bodies
  before staging. Static SPA fallback/assets and API responses get security
  headers including CSP `frame-ancestors 'none'`. The pinned tests are
  `outbound_url_policy_rejects_reserved_ipv4_zero_eight`,
  `local_trust_url_test_allowance_is_scoped_to_registered_origin`,
  `settings_put_rejects_private_loopback_metadata_tsl_tsa_urls`,
  `trust_policy_url_backed_tsl_source_rejects_unsafe_url_before_fetch`,
  `timestamp_unsafe_tsa_url_fails_before_network_or_pdf_processing`,
  `import_from_file_with_invalid_signature_persists_failure_without_replacing_cache`,
  `import_from_unsafe_url_persists_failure_without_fetching_or_cache`,
  `books_import_rejects_body_above_route_limit_before_staging`,
  `security_headers_apply_to_static_spa_fallback_and_assets`,
  `trust_refresh_rejects_unsafe_tsl_source_without_replacing_cache`, and
  `cc_sign_rejects_real_tsl_source_with_invalid_signature`. This remains
  defensive request-boundary/cache/static-header coverage only; it does not
  exhaustively prove hostile DNS/rebinding resistance, production qualified
  trust, legal validity, live provider readiness, DGLAB certification, or full
  release hardening.
- Current working-tree backup recovery-drill receipt checks: focused
  `backup_recovery_drill` API coverage pins `POST`/`GET
  /v1/backup/recovery-drills`, restore-preflight-only execution, durable
  `backup-recovery-drills.json` persistence, bounded manifest evidence,
  `isolated_restore_verified` and `isolated_restore_verification` receipt fields,
  isolated DB materialization/open/load, ledger/readback counts, sidecar
  materialized file/byte counts, temp cleanup evidence, passphrase/hash/
  member-name/app-version redaction, no live DB rewrite, no sidecar replacement,
  no `ledger.restored` append, and 422 refusal for true overclaim flags. Web/
  contract coverage pins the receipt fixture, nullable manifest handling, exact
  transient passphrase submit/clear behavior, the explicit operator-triggered
  drill action, rendered isolated verification evidence, and no calls to either
  live restore or the separate restore-preflight modal route from the Data
  Management drill action. Contract coverage now treats `operator_notes` /
  `custody_location` as optional receipt keys, matching the API wire contract and
  fixing the optional key build check without making those fields required. This
  remains custody receipt evidence only; no destructive restore success, live DB
  swap, sidecar staging, ledger restore append, data deletion, SQLCipher-at-rest
  proof, off-site custody proof, RPO/RTO certification, production backup policy,
  FULL coverage, or legal archive certification is implemented or proven.
- Current working-tree workflow reminder policy checks: focused `cargo test -p
  chancela-api --locked reminder_` coverage pins `workflow.reminders` defaults
  (enabled, dashboard limit 5, due-soon 45 days, attendance lookahead 45 days,
  all sources enabled), dashboard policy application to the existing
  profile-calendar, act-follow-up, and attendance-hygiene advisory reminder
  families, `enabled=false` suppression of reminder output without removing
  other dashboard current-work data, per-source suppression limited to the
  matching local reminder family, numeric limit/window behavior, and absolute
  calendar-day reminder status across year boundaries. Focused `cargo test -p
  chancela-api --locked profile_calendar_` coverage pins the new
  profile-calendar metadata. Profile-calendar
  coverage/status metadata now distinguishes supported local-rule presets from
  unsupported pending/no-date presets while keeping legal-authority, external
  delivery/calendar-sync/webhook, compliance-status, and workflow-completion
  claim flags false. Focused
  `settingsDefaults.test.ts` and `SettingsPage.test.tsx` coverage pins the web
  defaults and compact Gestão controls for the master switch, limit, due-soon
  window, attendance lookahead, and three source toggles. This remains local
  advisory policy coverage only: no new legal-calendar rules, law-source
  authority, threshold verification, external delivery/email/ICS/CalDAV/webhook,
  workflow completion, attendance proof, compliance gate, or legal sufficiency
  claim is implemented.
- Current working-tree release workflow static-guard checks: `node
  scripts/check-release-trust.mjs self-test` pins the CI metadata lane
  release-trust self-test, SBOM package-linkage self-test, and package
  provenance fixture checks; the Docker no-push/local-load job with `local-ci`
  trust status, `--expect-mode local-ci`, and nested
  `releaseTrust.imagePublication/signing/notarization/attestation.status`
  context; and the release package job's package integrity check,
  `--require-clean-source`, `releaseTrust.mode = unsigned-dev`,
  `attestation.status = not_attested`, `--expect-mode unsigned-dev`, and SBOM
  package linkage. Production package validation also requires `--manifest` when
  either package mode or expected mode is `production`, with self-tests covering
  those signals independently. `check-package-artifacts --require-clean-source`
  fails `dirty` and `unknown` source states. This is static workflow/package
  metadata assurance only; it does not add signing, notarization, attestation,
  registry publishing, reproducible-build proof, or production trust claims.
- Current working-tree seeded role drift diagnostic checks: focused
  `chancela-api` coverage pins read-only
  `seeded_role_drift.missing_default_permissions` and
  `requires_manual_review` on editable seeded roles, while preserving the
  customized persisted role permissions. Focused RBAC UI coverage renders the
  manual-review warning and missing-permission list. This is diagnostic only; it
  does not auto-reconcile roles, grant permissions, or weaken authorization.
- Current working-tree archive readability/ZK caveat checks: focused
  `chancela-archive` coverage pins manifest-only `readability_caveats`, old v1
  conservative defaults when the caveat block is missing, rejection of unknown
  caveat fields such as decryption/custody/import claims, and refusal of true
  overclaim flags. This adds no keys, decryption material, connectors, custody
  proof, ZK repository guarantee, GDPR shortcut, or legal archive claim.
- Current working-tree template family/channel guard checks: focused
  `chancela-templates` metadata validation pins `FamilyChannelMismatch` for
  family/channel drift and keeps narrow current-catalog compatibility carve-outs
  for already-authored assets. This is test-only catalog consistency coverage;
  no asset wording, legal threshold, provider behavior, law-reference authority,
  or legal effect changes are claimed.
- Current working-tree MCP discoverability checks: focused `chancela-mcp`
  coverage pins `search_trust_catalog` structured filter schema fields and the
  read-only, `settings.read`, closed no-arg
  `list_external_validator_reports` summary tool. The MCP catalog rejects raw
  report/upload arguments and contains no `raw-report`, `content_base64`, or
  upload path/schema exposure. This is discoverability and redacted summary
  access only, not raw report download, provider execution, legal validation,
  trust validation, or certification.
- Current working-tree password-required auth checks: focused static markers pin
  `create_user_requires_password_and_persists_hardened_hash`,
  `create_user_rejects_missing_or_weak_password_with_policy_errors`,
  `create_user_rejects_unauthenticated_non_bootstrap_before_password_policy`,
  `create_user_stale_unauthenticated_bootstrap_is_rejected_at_insert_recheck`,
  `create_session_requires_password_for_hashed_user`,
  `create_session_rejects_legacy_no_hash_user_409`, the no-token/no-session
  legacy no-hash assertions, and the remove-secret `409` preservation assertions.
  Web markers pin onboarding password create/sign-in ordering, no password skip,
  sign-in password prompts, current-user password switching, settings-hosted user
  creation with password, hidden remove-password action, and E2E helpers using a
  configured operator password. Focused Playwright auth proof pins
  `settings-created users require passwords and switch current user with that
  password` in `apps/web/e2e/session.spec.ts` and `fresh install requires strong
  password onboarding, recovery phrase, then opens the app` in
  `apps/web/e2e/first-launch-onboarding.spec.ts` via `npm run test:browser
  --workspace apps/web -- e2e/session.spec.ts e2e/first-launch-onboarding.spec.ts`.
  Treat the static/unit/focused markers as the pinned slice, not broad
  Playwright-browser-suite or browser-matrix proof; the browser suite is not exhaustive.
- Current checkpoint metadata/static checks through `869e02f`
  bounded slice markers passed: `node
  --check scripts/checkpoint-recent-landed.mjs`, `npm run
  test:checkpoint:recent-landed:static`, `npm run check:spec-coverage`, and
  `git diff --check -- SPEC-COVERAGE.md docs\CI-E2E-HARDENING-PLAN.md
  docs\CI-CHECKPOINTS.md scripts\checkpoint-recent-landed.mjs
  scripts\check-release-trust.mjs`. These pin the spec snapshot,
  hardening-plan head, PDF table-structure semantics, export save-prompt
  routing, dashboard dates tab, notification footer icon-only action, and
  clarified platform operations UI, user/signatory email capture, and compact
  Data Management cleanup controls, retained-export dry-run planning with
  `would_delete_*`/zero-`deleted_*` counters and preview-only no-files-removed
  Settings payload markers, plus SettingsPage/i18n trust-source
  provider markers, trust-accepted-hash/Registos TSA grouping, decorative
  page-break accounting, export-save cancellation, dashboard desktop-six
  density, SQLite logical table payload markers, browser dynamic-import gate
  markers, web SQLite table-usage rows, keyed VRI `/TU` evidence markers,
  compact notification/bell badge assertions, and entity filter nowrap/mobile
  wrap markers, compact template filter markers, structured book termo signatory
  markers, retention execution review-queue and review-closure markers, retention due-candidate
  bounded archive/no-action evidence and explicit evidence-state markers,
  backend database-encryption
  key-source/hardware-fallback markers, and PDF verifier DSS/VRI `/TU` plus
  local-renewal/legal-boundary markers, plus raw external-validator report
  attachment parser, size-bound, redaction, archive-package, document-bundle, web
  contract markers, and Ferramentas file-selection/no-auto-upload/explicit-submit/
  summary-only/no-claim UI markers, raw-report byte download route, settings.read,
  attachment-header, 404, fail-closed, and redaction markers, plus MCP workflow
  provenance review prompt/resource offline/no-call/no-claim markers, imported-document
  review receipt/history pending/reviewed/no-claim markers, trust catalog
  identifier-match explanation/copy-safe strict lookup markers, trust/import/static
  URL/body/header fail-closed markers, plus local DGLAB interchange manifest API
  route, book.export gate, schema, builder,
  deterministic sorted file entries, source validation, false-claim-flag
  rejection, and metadata-only/no-ZIP-member/no-persisted-bytes/no-ledger/
  no-certification markers, plus
  deterministic AI statement-source persistence, clamp, grouped source-type
  counts, path/type/label/status rows, false/no-claim flags, missing/null
  fallback, and unchanged accept/reject review markers, plus TSL P-256
  ECDSA-SHA256 raw
  `r||s` XML-DSig acceptance/rejection markers, plus read-only retention
  due-candidate API, contract, Settings render, unsupported-period, non-mutating
  page-load, review-only dry-run `execution_request`, query refresh, no
  policy/legal-hold/disposal/erasure mutation, duplicate review-only reuse,
  concurrent duplicate guard, queued review status/id/time UI surfacing, and
  false destructive/full-erasure markers, plus PAdES DSS caller validation-time, malformed-time refusal, VRI
  `/TU`, document-timestamp local renewal planning, and monitor-state markers,
  plus PDF accessibility JSON version 9, structural-depth evidence,
  structure-tree diagnostics, explicit role-map target entries,
  marked-content coverage counts, writer-owned marked-artifact accounting,
  bounded topology self-check,
  `LimitedTaggedStructure`, no-PDF/UA/no-`pdfuaid` markers, plus all-family
  agenda-item template IDs/counts/rendering markers,
  CSC quota template IDs/Pending-law-reference markers, CSC
  delegation/revocation template IDs/rendering/no-new-threshold markers, and
  post-act `Certidao`/`Extrato` sealed-provenance semantic lint markers,
  plus metadata-only
  paper-book OCR conversion-dossier route/store/redaction/idempotency, reviewed
  conversion execution artifact store/API/contract markers, and BookDetail UI
  accepted-draft/existing-dossier/reviewed-artifact/no-automatic-POST/
  no-endpoint guardrail markers,
  and external signer linked-invite sequential/parallel slot-policy,
  workflow-only envelope list/create UI, safe sequential 409 rendering,
  tracking-only response markers, stored slot evidence display,
  operator technical evidence PATCH/no-`complete:true` payload markers, and
  identity-requirement-tagged row markers, release workflow unsigned/local-only
  static guard, clean-source provenance gate, and production-package manifest-required
  markers, plus local CC BatchSigningPanel UI, `useCcBatchSign`,
  `/v1/signature/cc/batch-sign`, transient PIN clear/no-storage and route-reset
  tests, per-document result rendering, auth-mode reporting, declared capacity
  evidence display, local-CC-only boundary copy markers, and focused
  route-stubbed Playwright proof in
  `apps/web/e2e/local-cc-batch-signing.spec.ts` for the mounted
  local/co-located Cartao de Cidadao batch-signing UI,
  `POST /v1/signature/cc/batch-sign`, optional transient PIN request/clear/
  no-storage behavior, blank PIN omission, per-document results,
  server-returned `single_auth` or `per_document_auth` accounting, declared
  signer-capacity evidence, and the no-live-provider route boundary. This is
  local CC batch UI evidence only and route-stubbed local browser proof only:
  no live Autenticacao.gov/CC middleware, card reader, PKCS#11, hardware, CMD,
  CSC/QTSP, SCAP, TSA/TSL, or provider execution; no live CC batch signing,
  qualified batch signing, legal/qualified/provider-certified batch,
  provider-certified remote batch, single OTP/PIN/SAD authorization for
  multiple remote documents, CMD multiple-sign, CSC/QTSP multi-hash/SAD batch,
  SCAP-verified representative authority, legal-capacity proof,
  trust-list/provider validation, legal validity/effect/sufficiency, or act
  finalization/legal signing acceptance, plus
  `chancela-signing` repeated remote-session helper/types/tests for per-document
  `RemoteSigningSource` initiate/confirm activation and core-only no-batch-claim
  boundary markers, plus pending-session provider identity bridge markers for
  additive `GET /v1/acts/{id}/signature` provider metadata and reload
  CMD/CSC-QTSP confirm routing, including route-stubbed Playwright browser
  proof for reload adoption/routing only, plus ASiC inspect
  route/base64/fixity/
  malformed-ZIP/unsafe-path checks, bounded profile/member/manifest/signature
  diagnostics, `technical_validation` from `validate_asic_container` across
  CAdES/XAdES/mixed signatures and archive timestamps, legacy bounded `cades`
  compatibility markers, no-claim fields, and actual decompressed-size
  blocker markers for underdeclared payload/signature/unsupported-META-INF
  members, plus backup recovery-drill route, contract,
  optional receipt-key tolerance, bounded-manifest receipt, isolated
  restore/readback receipt evidence, overclaim-refusal, no-restore/no-DB-swap,
  no sidecar staging, no ledger append, exact-passphrase submit/clear,
  nullable-manifest, and custody/legal-certification false-flag markers, plus
  workflow reminder policy/default/UI/dashboard/source-toggle and
  year-boundary status markers, plus platform forwarded-log route,
  `platform.logs.write` seed-default, missing/invalid-bearer unaudited,
  validation,
  global/service-off suppression, data-dir persistence/reload, no-stdout/stderr,
  accepted-retained `platform.log.forwarded.accepted` ledger-audit, sanitized
  RBAC-denied/rejected/suppressed audit markers, payload
  digest/length/context-summary, and redaction markers for auth/off/invalid
  paths, plus data-status `platform_logs` /
  `backup_recovery_drills` filesystem classification markers, plus seeded role
  drift read-only manual-review markers, archive readability/ZK manifest-only
  caveat markers, template `FamilyChannelMismatch` compatibility markers, and
  MCP structured trust-catalog filter plus redacted external-validator summary
  markers, plus generated-document by-id route, absent-owner dispatch-evidence
  route/store/idempotency/selected-recipient coverage/evidence-attached/
  no-completion/no-claim markers and focused generated absent-owner evidence
  web client/panel/i18n/dashboard/notification deep-link/focus/contract markers,
  plus document-bundle
  `generated_dispatch_evidence` metadata and archive
  `evidence/generated-dispatch/{document_id}.json` sidecar/index markers,
  plus Arquivo paged ledger route/default-limit/cursor markers,
  1000+ event first-page/load-more tests, `Store::ledger_events_page`
  persisted-pager tests, API after-reload/memory-clear store-pager markers,
  shared list/export search (`q`), chain/scope filter, and limit normalization
  markers, numeric `next_cursor` typing, Livro-style filter and
  icon-only clear-control markers, and JSON/TXT/CSV/HTML export-format markers
  with canonical-only PDF/A evidence boundaries.

Full workspace format/clippy should be rerun before commit. The prior
`paper_import.rs` compile blocker, retention dead-code warning set, TSL `record`
compile break, external-signing route-classification blocker, document-import
dead-code warning, and `/api` namespace route-classification miss have been
cleared.
