# CI and E2E Hardening Plan

Updated 2026-07-24 from the current CI configuration, clean base `d2a4df1`,
and implementation snapshot `baf9f41`,
including coverage notes for the mobile companion foundation docs/scripts,
destructive erasure preflight/approve/execute route wiring plus local gate
evidence, append-only rectification/restriction ledger annotation routes and
remedy classification framing, tenant-chain ledger membership and
authorization-chain integration evidence, the
mkdocs navigation drift capture for the mobile companion docs, XAdES C14N
vector-test formatting, command-signing environment-race test determinism, the
settled PDF/UA v12 gated-claim lane, XAdES
C14N/digest-agility/B/T/LT/ASiC evidence, archive PDF accessibility
propagation, the MCP document/archive PDF accessibility v12
identifier/count/blocker alignment, fixture report version 12, the Ata editor
workflow provenance review panel, generated-document coverage fixture alignment,
CI coverage-waiver debt guard, and the full ignored Postgres store backend sweep with
per-test child database isolation, child database cleanup, logical restore
JSON text-to-jsonb binding, and backend-only SCAP-backed signer-capacity evidence
persistence for local PKCS#12 signing, revocation cache graceful offline
fallback, full-chain PAdES DSS evidence assembly from validated chains plus
revocation material, live LOTL trust bootstrap, live end-entity signer-path
validation, TSL-resolved revocation trust-decision reporting, API B-LT/B-LTA
technical status surfacing, and offline PAdES LTV CA-link verification,
wp23 user-template authoring groundwork
for store CRUD, `template.manage`, strict authoring validation, API
CRUD/export/import, merged catalog contracts, i18n key coverage, and Minutas
create/edit/import/export/delete UI actions, plus composed-server template
fixture E2E wiring, the
real-backend generated-convening
dispatch-evidence browser proof, full composed-server E2E local pass after auth
harness alignment, focused composed-server generated-convening
dispatch-evidence E2E coverage, generated-convening dispatch-evidence
metadata-only generated-document recording, convening recipient contact metadata before local
dispatch evidence stamping, route-stubbed convening dispatch browser proof,
convening dispatch evidence capture UI,
convocation reminder guidance routing,
missing-meeting-date convocation reminders, convocation act-review guidance and
convocation-notice local WFL/legal-calendar advisory reminders, condominium
annual local advisory Jan 15 profile-calendar
depth, dashboard annual profile-calendar reminder localization,
automated-review dashboard contract surfacing, archive active-filter count
refinement, all-filtered archive export streaming/caps,
automated-review law corpus evidence and UI tier surfacing, MCP workflow
provenance local JSON/text summary,
key-custody readiness UI/contract surfacing,
data key-rotation receipt history,
bounded PAdES DSS validation-time, PDF/UA v12
blocker-delta and scoped table-header evidence, retention due-candidate explicit evidence states,
bounded archive/no-action evidence UI, duplicate-review guard/status surfacing, and
prior bounded execution suppression with active/suppressed candidate counts plus
retention execution review closure,
recovery-drill custody
receipt and optional-key contract tolerance, paper-book OCR conversion-dossier UI,
local OCR/canonical rehearsal report, and reviewed conversion execution artifact evidence,
dashboard backup recovery freshness advisory surfacing,
CSC quota/delegation/revocation and standalone agenda-item template parity,
retained-export cleanup preview-token/manifest-gated execution evidence,
compliance legal-basis internal corpus deep links, first-class template catalog metadata lint,
deterministic local template law-reference corpus audit coverage,
automated-review law-corpus vendoring for 39 of 40 previously Pending
DRE-sourced articles without human-Verified promotion,
bounded platform-log sidecar cleanup target coverage,
remote signing provider readiness manifests,
external-signing workflow-only envelope UI, workflow reminder policy, and
structured platform-log forwarded-ingest/failure-audit slices, ROL-02 seeded
role archetype explicitness, Postgres store runtime write/read marker coverage,
Postgres logical backup/restore/recovery marker coverage,
Postgres per-book export/import/start-over plus restore-preflight marker coverage,
local advisory-lock cluster write gating and fail-closed promotion handoff markers,
full ignored `postgres_backend` local Docker/Postgres sweep proof with per-test
child database isolation and `10 passed`,
SQLite-default feature/config-gated backend selection, DPIA template/guidance
checkpoint coverage,
plus data-status
sidecar classification and backend-neutral durability/sidecar telemetry,
read-only local DGLAB interchange manifest API
scaffolding and BookDetail JSON download,
local sync/handoff preflight readiness reporting over existing evidence only
plus Data Management local JSON export of the already-loaded report,
archive filter reset icon-only clear-control coverage,
raw-byte per-book import preflight operator preview,
richer Ata editor AI statement-source provenance rendering and deterministic
AI provenance review-packet copy, explicit external-validator raw
report upload UI guardrails, the raw external-validator raw-report byte download
API, the MCP workflow provenance, draft-vs-signed comparison, privacy-control,
and document/archive review aids,
dashboard guest/minimal contract fixture and web parsing coverage for existing
recent-event redaction, generated-document by-id download route,
sealed post-act certidao/extrato template generation UI,
condominium absent-owner communication auto-generation, and operator-supplied
absent-owner/generated-convening dispatch-evidence recording with dashboard reminder surfacing,
document-bundle/archive generated dispatch-evidence metadata preservation,
imported-document review receipt UI, trust catalog identifier-match explanations,
imported-document review dashboard reminders and review-form deep-link focus routing,
password-required account creation/session hardening,
additive hardened Dockerfile/Compose/operator documentation validation,
written-resolution evidence receipt local browser proof,
route-stubbed richer entity chronology visualization over existing structured
graph evidence and local sealed-act chronology projection over sealed/archived
acts as source-linked technical visualization evidence only,
plus local ASiC inspection endpoint and ASiC ZIP decompression-bound coverage,
plus release workflow static
assurance for the unsigned/local-only trust posture, production-package
manifest-required validation, and release summary binding to the actual package
tarball basename/SHA-256, opt-in release signing workflow hooks and truthful
status artifacts, rustls Postgres TLS connector / `sslmode=prefer` live store
round-trip evidence, observability probes and route-template metrics/request-id
coverage, runtime HTTP/session hardening with HSTS, single-node in-memory
per-IP rate limiting, absolute session lifetime cap enforcement, reset/reload
cleanup, and CurrentAttestor cap handling, synthetic seed dataset integration coverage
over API-created entity/book/act/ledger/dashboard/RBAC/delegation paths, and
RBAC ledger verification regression coverage for user-role, delegation, and
role-catalog audit events. This
plan is the build and
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
- A dedicated Postgres store backend lane runs the ignored
  `runtime_reads_and_writes_roundtrip_on_postgres` and
  `sslmode_verify_full_opens_and_roundtrips_on_postgres` tests against a disposable
  GitHub Actions PostgreSQL 18.4 database configured with an ephemeral CA and
  hostname-verified server certificate. The runtime test uses the backend's
  secure default and the TLS test supplies `sslmode=verify-full` explicitly:
  `cargo test -p chancela-store --features postgres --locked --test
  postgres_backend <test-name> -- --ignored --test-threads=1`. This proves the
  live store/TLS path but remains limited to the store integration test binary;
  API seed, logical restore, cluster/failover/feed, sidecar, HA, and migration
  coverage remain outside this CI lane. Historical full ignored
  `postgres_backend` sweeps are pinned below as local Docker/Postgres store-backend proof,
  not as broadened default CI.
- Web format, ESLint, Vitest/V8 coverage thresholds, and Vite build run on Node
  24; the web CI test command is
  `npm run test:coverage --workspace apps/web`.
- `npm run check:ci-assurance-waivers` enforces the explicit
  `ci.coverage.thresholds.non_web_unit` debt record. browser/desktop/Docker/live-provider
  coverage thresholds remain explicit waiver debt outside the apps/web
  Vitest/V8 unit-test lane; the guard does not add those thresholds.
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
  manual dispatches; the direct smoke starts the container with
  `CHANCELA_DATA_DIR`, polls `/health`, and asserts durable persistence from
  the JSON body. The Docker job also renders the actual Compose profiles
  `single-node`, `worker`, and `postgres`, then runs the `single-node` Compose
  runtime-hardening smoke against the locally loaded image. That smoke inspects
  the Compose-created server container for read-only rootfs, `cap_drop: ALL`,
  `no-new-privileges`, a non-root user, `/tmp` tmpfs, and a persistent
  `/var/lib/chancela` mount before the same `/health` persistence assertion.
- The Docker lane applies OCI image labels and uploads image inspect metadata,
  report-only Syft/Trivy artifacts, and an explicit JSON status saying the local
  CI image was not pushed, signed, or attested.
- The release-trust self-test statically verifies workflow wiring for the
  unsigned/local-only trust posture: metadata checks, Docker no-push/local-load
  `local-ci` status, package `unsigned-dev` / `not_attested` metadata, and SBOM
  package linkage. The release workflow also passes the collected package path
  so the validator recomputes the tarball basename and SHA-256 before accepting
  the release summary. This is static/package metadata assurance only, not signing, notarization,
  registry publishing, Docker attestation, or a production trust claim.
- Package/release artifacts carry manifests and checksums where configured, but
  current release packages are not signed or notarized.
- Windows desktop smoke runs on pushes to `main` or PRs labeled
  `run-desktop-tests`.

## 2026-07-10 Audit Note

- Current browser e2e coverage is smoke/edge oriented rather than exhaustive.
  The enforced coverage thresholds are Vitest/V8 web-unit thresholds, so they do
  not prove browser, desktop, Docker, or live-provider coverage. The
  `ci.coverage.thresholds.non_web_unit` waiver keeps that gap explicit in CI; it
  does not add those thresholds.
- Live signature/provider seams are compile-only checks; they do not exercise
  live CMD, CSC/QTSP, CC hardware, production TSL, or production TSA paths.
- Release packages are unsigned/not notarized, and Docker images are not
  signed/attested.
- The current Data Management slice adds `settings.manage`-gated cleanup for
  crash reports, the local platform-log sidecar, and retained exports plus SQLite logical usage estimates,
  including per-table logical payload entries surfaced in the web UI. Treat it
  as storage maintenance coverage, not legal data-lifecycle certification.
  Platform-log cleanup uses the `platform_logs` target, is constrained to the
  canonical configured data directory, removes only the `platform-logs.json`
  sidecar selected by the data-status classifier, clears the current API ring,
  and leaves ledger/audit/domain records, stdout/stderr, SIEM/log shipping,
  legal retention, disposal, and compliance claims out of scope.
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
- The current sync/handoff preflight slice is read-only local evidence
  composition through `GET /v1/sync/handoff-preflight`, gated by
  `ledger.recover@Global`. It summarizes durable data status, untrusted
  backup-directory candidates, verified recovery-drill manifest/member/isolated
  snapshot evidence when present, book bundle export/import preflight route
  availability, archive/local DGLAB evidence counts, blockers, missing-evidence
  items, operator actions, and explicit no-claim flags. It
  accepts no target path, scans only the configured data directory's existing
  `backups` folder, and does not call providers, networks, connectors, uploads,
  downloads, imports, background jobs, or mutating record paths. Data Management
  can save the already-loaded report as local JSON through the browser save
  picker only; that export makes no extra request and performs no remote
  upload/download/import, sync, connector, evidence refresh, or record mutation.
  Treat this as
  operator handoff review evidence only, not active sync, connector protocol
  compatibility, production sync readiness, legal validity, DGLAB/archive
  certification, signing/notarization/attestation, deployment readiness, or
  external-system readiness.
- Release and package builds now opt into SQLCipher features by default where the
  supported package scripts and CI metadata require it. Treat this as encrypted
  build-default coverage, not proof of operator key custody, migration success,
  or deployed encrypted data at rest.
- Data Management now renders the existing
  `persistence.database_encryption` readiness object for SQLCipher build
  availability, keyed-store state, key source class, fail-closed hardware
  fallback status, database format, key-ops plan, key-config class, plaintext
  migration pending/blocked flags, and migration-plan summary/steps. Treat this
  as secret-free UI/contract surfacing of backend readiness only: it does not
  execute migration or rekey, expose keys/hash/fingerprint/env secrets, prove
  production SQLCipher-at-rest encryption, complete production key custody or
  hardware-derived defaults, retire plaintext stores, or certify legal/GDPR
  lifecycle completion.
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
- The current template slice expands the embedded catalog to 104 JSON assets
  (104 total / 44 CSC) with standalone representation/proxy instruments,
  `ponto-ordem-trabalhos/v1` Convocatoria standalone agenda-item templates, and
  book-transport continuation terms for all supported families, including the
  company carta de representacao boundary, plus
  `csc-ata-divisao-quotas/v1` and `csc-ata-unificacao-quotas/v1` matching the
  sibling CSC quota Ata channels, rule-pack, signature-policy hint, and majority
  threshold marker, plus `csc-ata-delegacao-poderes/v1` and
  `csc-ata-revogacao-poderes/v1` as proposed-resolution text only with no new
  threshold marker, plus `csc-ata-fusao/v1`, `csc-ata-cisao/v1`, and
  `csc-ata-liquidacao/v1` as local CSC structural-change Ata templates for the
  merger, demerger, and liquidation-step minutes named by spec/11. It also
  normalizes notice-template rendering of
  TPL-20 dispatch proof fields from `convening.recipients` across all supported
  families and pins all-family attendance-list rendering of structured attendee
  and proxy evidence, including CSC capital and condominium permilagem markers.
  Treat the focused `chancela-templates` tests, the
  `template_catalog_metadata_lint` command, and recent-landed static markers as
  catalog consistency checks only, not legal review of template wording,
  verified thresholds, law references, channel permissibility, quota legal
  sufficiency, delegation/revocation legal sufficiency or authority verification,
  structural-change legal sufficiency or authority verification, dispatch or
  attendance sufficiency, agenda-item legal sufficiency, exhaustive law mapping,
  DRE/source authority, registry submission, signing correctness, external
  registry/provider behavior, or book-transport legal effect. The quota and
  structural-change template law references remain Pending/non-authoritative; no
  DRE verification, legally verified threshold value, external registry/provider,
  signing-process, or new law-source claim is added.
  Current post-act semantic lint also requires `Certidao`/`Extrato` authored
  `BlockSpec` template references to sealed-act `ata_number` and
  `payload_digest`; this is runnable embedded-catalog metadata consistency lint
  only and does not change asset wording or add legal-effect claims.
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
- The current MCP workflow provenance slice keeps the static
  `workflow_provenance_review_checklist` prompt and
  `chancela://mcp/workflow-provenance-review` resource as offline review aids.
  With no arguments the resource returns static guidance; with
  `arguments.workflow_evidence` as caller-supplied JSON object/array or text, it
  returns deterministic aggregate workflow lifecycle counts, human-review
  decision status counts, missing human-review decision counts, evidence-marker
  counts, and raw-content/contact/secret-like warning counts. It echoes no raw
  workflow text, uploaded bytes, contacts, credentials, secrets, access codes,
  reviewer values, identifiers, digests, or caller payloads; makes no
  bridge/API/AI-provider/legal-service/provider calls; and keeps
  legal-validity, source-certification, workflow-completion,
  provider-assurance, trust, external-validation, archive-certification,
  signature-qualification, extraction-accuracy, AI-completion, and
  MCP-completion flags false. Treat it as human review guidance only, not
  AI/MCP completion, source certification, trust validation, extraction
  certification, or provider/legal assurance.
- The current Ata editor workflow provenance panel is browser-side local review
  UI only. It derives deterministic aggregate workflow lifecycle,
  AI-human-review, evidence-marker, missing/unknown, and compliance counts from
  already loaded act/compliance state, then copies a sanitized
  `arguments.workflow_evidence` payload for
  `chancela://mcp/workflow-provenance-review`. It does not echo raw IDs,
  names, emails, titles, deliberations, access codes, document labels,
  reviewer notes, payload or attachment digests, or raw caller payloads; the
  browser does not call MCP, the API bridge, AI providers, hidden providers,
  legal services, registries, trust services, or external validators. Treat it
  as local aggregate review/copy evidence only: no AI-01, AI-02, full AI/MCP,
  source-certification, extraction-accuracy, workflow-completion, legal,
  provider, trust, non-stdio transport, or release-readiness claim is made.
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
- The current MCP privacy-control review summary slice adds the read-only
  `chancela://mcp/privacy-control-review-summary` resource. With no arguments
  it returns local input-shape guidance and no-claim boundaries; with
  `arguments.privacy_controls` it returns deterministic aggregate counts only
  for local processors, DPIAs, breach playbooks, transfer controls, retention
  policies, retention executions, DSR requests, optional
  `retention_due_candidates` reports, and optional
  `retention_candidate_resolutions` records. It buckets due-candidate
  status/outcome/evidence-state labels, bounded-suppression counts, latest
  resolution presence/dispositions, candidate-resolution dispositions,
  blocker/approval presence, evidence-only flags, and false/no-claim
  observations without echoing record names, ids, notes, legal bases,
  recipients, subjects, data categories, raw evidence text, or secrets. It
  makes no bridge/API/AI-provider/legal-service/provider calls; and keeps legal
  approval/completion, notification, transfer execution, DPIA
  filing/completion, compliance certification, privacy/GDPR completion,
  destructive disposal, deletion, anonymization, redaction, erasure,
  legal-hold mutation, retention-policy mutation, and full-erasure claims
  false. Treat this as caller-supplied local JSON review signal only, not
  privacy/GDPR compliance completion, legal approval, notification, transfer
  execution, DPIA filing/completion, disposal, deletion, redaction,
  anonymization, erasure, legal-hold mutation, retention-policy mutation,
  AI/MCP completion, or provider/legal-service assurance.
- The current MCP document/archive review summary slice adds the read-only
  `chancela://mcp/document-archive-review-summary` resource. With no arguments
  it returns local input-shape guidance and no-claim boundaries; with
  `arguments.document_archive` it returns deterministic aggregate counts for
  validation report/status, digest/fixity fields, signed-document metadata,
  external-validator attachment statuses, the `pdf_accessibility_v12` checkpoint,
  `pdf_accessibility_v12_summary`, `v12_report_count`, PDF accessibility v12
  report/blocker and row/column table-header evidence, archive/evidence-index path
  markers, no-claim flag observations, and missing-evidence blockers including
  `pdf_accessibility_v12_report_missing`. Fixture coverage uses
  `report_version: 12` plus nested `accessibility_report_json.version: 12`,
  `limited_tagged_structure` known blockers, `other` buckets for unrecognized
  caller blocker text, and row-header/column-header count and scope fields. It echoes no raw
  reports, digest values, path values, IDs, notes, raw PDF bytes, or secrets;
  makes no bridge/API/AI-provider/legal-service/HTTP/SSE/provider calls; and
  keeps PDF/UA conformance, DGLAB certification, legal validity, signature
  validity, archive certification, provider validation, external-validator
  success, trust validation, and legal-review claims false. Treat this as
  caller-supplied local JSON review signal only, not PDF/UA conformance, DGLAB
  certification, legal validity, signature validity, archive certification,
  provider validation, external-validator success, trust validation, legal
  review, full archive completion, AI/MCP completion, spec completion, or
  provider/legal assurance.
- The current MCP meeting metadata extraction review slice adds the read-only
  `chancela://mcp/meeting-metadata-extraction-review` resource. With no
  arguments it returns static human-review guidance; with
  `arguments.meeting_document` as caller-supplied JSON or text metadata it
  returns deterministic local candidate counts, bounded channel classification,
  evidence-reference presence, blockers, warnings, and false no-claim flags. It
  makes no bridge/API/AI-provider/legal-service/HTTP/SSE/provider calls; echoes
  no raw document text, uploaded bytes, names, contacts, emails, phone numbers,
  access codes, credentials, secrets, agenda text, digests, or caller IDs; and
  requires human verification. Treat this as local review signal only, not legal
  validity, source certification, workflow completion, meeting legality, notice
  sufficiency, extraction accuracy certification, AI-01 completion, full AI/MCP
  completion, or provider/model assurance.
- The current dashboard guest redaction slice now has a
  `contracts/dashboard.guest.json` fixture and web contract parser coverage for
  the existing `GET /v1/dashboard` response boundary: guest/minimal callers get
  `recent_events: []`, owner-only ledger event fields/values are absent from
  the fixture, Owner and `Leitor` sessions keep recent events, and Guest still
  lacks `GET /v1/ledger/events`. Treat this as response redaction only: no
  permission grants, no broader anonymization/redaction completion, no
  production privacy compliance, and no access-control completeness claim.
- The current generated-document by-id download and dispatch-evidence slice returns
  `/v1/documents/generated/{document_id}` for on-demand generated docs,
  gates the download through `act.read` on the owning act, and covers both
  durable and in-memory modes while keeping `/v1/acts/{act_id}/document` as the
  sealed Ata route. Sealing a condominium act with absent attendees also
  auto-generates `condominio-comunicacao-ausentes/v1`, keeps the canonical act
  document as the Ata, stores the communication for generated-document by-id
  retrieval in durable and in-memory modes, and emits honest pending dispatch
  evidence (`required_pending`, `evidence_attached=false`,
  `dispatch_completed=false`) that server E2E re-checks after restart.
  Generated Convocatoria documents now reuse the same generated-document
  dispatch-evidence path when the generated template is a `Convocatoria` stage
  template and the act has persisted convening recipients. The same backend
  slice exposes `POST`/`GET`
  `/v1/documents/generated/{document_id}/dispatch-evidence` for
  operator-supplied dispatch evidence for absent-owner communications and
  generated Convocatoria documents, stores it in
  `generated_document_dispatch_evidence`, returns exact retries idempotently,
  records selected absent/convening-recipient evidence coverage, updates only
  evidence-attached/status headers while keeping
  `x-chancela-dispatch-completed=false`, and emits
  `absent_owner_communication.dispatch_evidence_recorded` or
  `generated_document.dispatch_evidence_recorded` with false/no-claim
  flags. Document bundles now keep the canonical bundle `document` and
  `/v1/acts/{act_id}/document` download as the sealed Ata while adding generated
  absent-owner and generated Convocatoria dispatch metadata under
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
  `document_bundle_indexes_generated_absent_owner_dispatch_evidence_without_replacing_ata`,
  plus
  `archive_package_indexes_generated_convening_notice_dispatch_evidence_metadata_only`
  and
  `document_bundle_indexes_generated_convening_notice_dispatch_evidence_without_replacing_ata`.
  The web follow-on slice covers `listGeneratedDocuments`,
  `generateActDocument`, generated PDF fetch,
  `getGeneratedDocumentDispatchEvidence`,
  `recordGeneratedDocumentDispatchEvidence`, sealed post-act `Certidao` and
  `Extrato` plus Convocatoria template discovery/generation/download, generated absent-owner
  communication listing, stored evidence rows, permission-gated metadata-only
  evidence recording, `operator_evidence_*` statuses, and
  `documents.generated.noClaim.*` copy. Dispatch evidence forms render for
  generated rows with `dispatch_evidence_status`; generated certidao/extrato
  rows keep null status and do not fetch or render dispatch-evidence forms.
  Dashboard and notification actions use
  generated-document deep links with `generated_document_id`,
  `focus=dispatch-evidence`, and `#generated-dispatch-evidence`; the Ata route
  resolves them through `actDocumentPanelTargetFromLocation`, and
  `ActDocumentPanel` selects/focuses the dispatch-evidence form once for
  operator evidence recording. Treat this as sealed-act generated-document UI
  plumbing plus navigation/focus support for operator evidence recording only:
  it does not replace the canonical Ata, send mail/email/SMS/provider messages,
  prove delivery, mark dispatch complete, complete legal notice, add legal
  sufficiency/legal-effect claims, submit to an external registry, sign,
  complete signing, archive, certify legal validity, or perform legal review of
  generated template wording. It also makes no DGLAB certification or legal
  archive acceptance claim.
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
  bounded operator-supplied legal-basis evidence for new grants while legacy
  missing-basis records remain readable.
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
- Storage cleanup presents crash reports, platform logs, and retained exports as separate
  bounded maintenance rows, rejects unknown cleanup targets, and preserves
  permission/usage diagnostics after a failed cleanup. Retained-export dry-run
  preview reports `would_delete_*` plus a server-bound `preview_token`, keeps
  `deleted_*` at zero, and must not delete files or accept those policy fields
  for crash cleanup. Retained-export execution is UI-gated by that tokened
  preview plus the shared confirmation modal, posts the `preview_token`, rejects
  missing/stale/mismatched tokens, executes only the server-selected preview
  manifest, and renders `deleted_*` execution counts.
  Platform-log cleanup is a direct `platform_logs` maintenance target only for
  the local `platform-logs.json` sidecar/current API ring; it does not clean
  stdout/stderr, SIEM/log shipping, audit/ledger records, domain records, or
  any legal-retention/disposal surface.
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
  a collapsed advanced-filter summary with a compact active-filter count badge,
  an icon-only accessible clear-filters control backed by the shared
  `FilterClear` funnel/clear glyph, and export choices for canonical PDF/A plus
  JSON/TXT/CSV/HTML audit/interchange formats. Only PDF/A is the canonical
  preserved evidence export; the other formats are review or interchange aids.
- Ledger archive paging coverage now spans 1000+ in-memory log events and
  SQL-backed persisted store pages after reopen/reload and memory clear via
  `Store::ledger_events_page`. Ledger archive export preserves active filters,
  shares limit normalization with the paged list, and refuses unauthorized
  downloads. Focused route-stubbed Playwright proof in
  `apps/web/e2e/ledger-archive-boundedness.spec.ts` now pins the mounted
  `/arquivo` browser path: first load requests only
  `/v1/ledger/events/page?limit=100&order=desc`, renders only those first-page
  rows, keeps an older tail event absent until load-more, sends
  `before_seq=<next_cursor>&limit=100&order=desc` for older events, serializes
  current filters with `limit=50&order=desc`, and exports through
  `/v1/ledger/archive/document` with format/current filters and no `before_seq`.
  This does not make non-PDF/A exports preserved evidence, does not claim an
  all-record export, and does not make any archive certification, DGLAB/legal
  archive certification, filing/legal acceptance, signature validation,
  signing/legal evidence, ledger mutation, or production custody claim.
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
- Provider credentials now have encrypted, entry-bound storage and operator
  management UI coverage for CMD, CSC/QTSP, SCAP, and local PKCS#12 entries.
  The API/UI evidence is write-only for secrets, priority ordered, and fail-closed
  for missing key source, strict non-confidential protection, malformed sidecars,
  incomplete stored records, disabled stored records, or authorization-mode
  mismatches. It does not prove production credential custody, provider approval,
  live provider readiness, or legal sufficiency.
- Backend local PKCS#12 signing now accepts optional `scap_capacity_evidence`
  and persists resolved signer-capacity evidence for the upload path and stored
  PKCS#12 delegation. No-SCAP requests keep `not_checked_by_scap`; preprod/mock
  SCAP stays `declared_capacity_by_provider`; `verified_by_scap` is reachable
  only through prod HTTP SCAP after a `Granted` decision, with current proof
  limited to a local HTTP fixture. Mismatched declared capacity versus SCAP
  attribute fails 422 before artifact/event persistence. This is backend-only
  evidence persistence: no UI picker rollout, no live SCAP credentials/network
  proof, no production SCAP availability claim, no representative-authority or
  legal-capacity completion, and no qualified-signature/legal-validity claim.
- Local/co-located CC batch signing is represented in the web UI for sealed acts
  through the desktop/local CC path and `POST /v1/signature/cc/batch-sign`,
  with optional transient PIN submission, per-document results, auth-mode/event
  reporting, and declared signer-capacity evidence display. This checkpoint is
  local CC batch UI evidence only: not CMD batch signing, not CSC/QTSP remote
  batch signing, not provider-certified remote batch signing, and not
  SCAP-verified representative authority or legal-capacity proof.
- `POST /v1/signature/remote/{provider}/batch-initiate` exposes the repeated
  per-document remote-session helper through the API and SigningPanel UI. Each
  valid act opens its own pending remote session/activation and returns
  `auth_mode: "per_document_activation"`; later activation/confirmation still
  happens through the normal single-document CMD or CSC/QTSP confirm route.
  Invalid act preconditions are isolated into redacted per-document error rows,
  while duplicate IDs and over-cap requests fail before provider or pending-row
  creation. Focused proof spans `cargo test -p chancela-api --test
  remote_signing --locked`, `client.test.ts`, `SigningPanel.test.tsx`, and
  route-stubbed `apps/web/e2e/remote-signing-pending-session.spec.ts` coverage
  for per-document pending rows without credential echo. This is not
  provider-certified remote batch, not provider-native multi-document
  authorization, not single OTP/PIN/SAD authorizing multiple documents, not CMD
  multiple-sign, not CSC/QTSP multi-hash/SAD batch, and not SCAP/legal-capacity
  proof.
- `GET /v1/acts/{id}/signature` returns additive pending-session provider
  metadata so the web can resume already-open CMD or CSC/QTSP sessions after
  reload and call the matching confirm endpoint. This is reload
  adoption/routing only. Focused route-stubbed browser proof is
  `npm run test:browser --workspace apps/web --
  e2e/remote-signing-pending-session.spec.ts`, covering provider-specific
  remote confirm for CSC/QTSP pending sessions and dedicated CMD confirm for
  legacy CMD pending sessions after reload, with fake activation/OTP values.
  No production provider approval, live CSC readiness, trust-list/legal
  validation, SCAP/legal-capacity verification, provider-native remote batch,
  qualified-signature certification, act finalization, or legal-validity claim
  is made.
- `GET /v1/signature/providers` now includes a local-only readiness manifest for
  CMD and configured CSC/QTSP rows. Static/API/web coverage pins readiness,
  environment/sandbox, `production_blocked`, missing local config,
  authorization mode, ordinary single initiate/confirm and repeated
  per-document initiation capabilities, false provider-native/single-auth batch
  claims, false live-provider/provider-approval/legal/qualified/trust-list
  listing claims, and evidence basis from local settings/env/protected
  credential metadata only. This is provider-listing metadata and UI copy only:
  no live CMD/CSC/QTSP/CC call, no provider approval, no provider-native batch,
  no TSL/trust-list validation at listing, no legal or qualified-signature
  claim, and no secret values.
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
- Docker image builds and passes the direct runtime `/health` persistence smoke
  plus the `single-node` Compose runtime-hardening smoke from a clean checkout.
- Release metadata artifacts include a validated dependency SBOM, package
  manifest, and SHA-256 checksums.
- Vulnerability scans have either passed in an enforced manual run or their
  report-only findings are triaged and explicitly accepted for the release.
- Package signing/notarization and Docker image signing are not claimed unless
  the release workflow actually performs those steps.
- Desktop smoke passes on Windows with a temporary data dir.
- The remaining failures, if any, are documented as external blockers such as
  live CMD, QTSP, CC hardware, production TSL/TSA network, or legal review.

## Focused Gate Snapshot Through `baf9f41`

Historical focused checks from the active director loop, refreshed on
2026-07-10 for head `3e72e08` and checkpoint-promoted on 2026-07-15 for
current implementation head `baf9f41`. This is not an exhaustive current
green-run claim; the full-server E2E claim below is limited to local
`chancela-server --features e2e` after auth harness alignment, and browser,
Docker, desktop, production package signing/notarization, production image
signing/attestation, live `verify-full` CA proof, production TLS/HSTS
deployment proof, HA/distributed rate-limiting proof, and live-provider limits
above still apply.

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
  `cargo test -p chancela-api --test api-archive-privacy --locked -- privacy::retention`,
  `cargo test -p chancela-api --test api-records --locked -- paper_import`,
  `cargo test -p chancela-api --locked books_import_preflight`,
  `cargo test -p chancela-api router_walk_every_route_is_classified --locked`,
  and `cargo test -p chancela-api --test api-signatures --locked -- external_signing_envelopes`
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
--locked`, `cargo test -p chancela-api --test api-auth --locked -- apikey_auth`, and
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
- Current `9ddced8` Postgres store runtime, backend-selection, logical
  recovery, cluster write-gating, and covered follower-feed checks: static/source markers pin the off-by-default `postgres`
  feature, `PostgresBackend::open`, advisory-locked single writer, boot `load`
  replay, request-serving `Tx` write methods, runtime `Store` read projections,
  `CHANCELA_DB_BACKEND`, `DATABASE_URL_FILE`, `resolve_backend_selection`,
  `Store::open_backend`, API/server feature gates, default-SQLite parsing, and
  fail-closed selector tests. The wp15 markers also pin
  `chancela-pg-logical-backup/v1`, `verify_pg_backup_bundle`,
  `PostgresBackend::logical_restore`, `Store::pg_backup`,
  `execute_recovery_batch`, pure `pg_backup` fixity/cross-backend/rollback
  checks, and ignored `DATABASE_URL` tests for runtime round trips, logical
  backup/restore, recovery/start-over, corrupt-restore refusal, and
  SQLite-bundle refusal. The wp16 P0 markers pin the local advisory-lock
  cluster write gate and fail-closed promotion handoff: `cluster_assert_writable`
  before durable append, `write_gate_allows` keeping a promoted node read-only
  until handoff, `cluster_promotion_handoff` reloading and re-verifying durable
  state, `NotLeader` to HTTP 503 mapping, and ignored live Postgres election /
  failover tests gated by `DATABASE_URL`. The wp16 P1 markers pin the
  `LISTEN chancela_ledger`/seq-poll follower feed, verified-prefix delta apply,
  aggregate snapshot publish gate, full-reload fallback, nullable
  `/health.cluster` covered-feed lag scope, store tail/notify helper contracts,
  and ignored live LISTEN/NOTIFY scaffolding gated by `DATABASE_URL`. This is
  marker/static coverage plus local advisory-lock/fail-closed gating, covered
  read-model feed coverage, and opt-in live-test scaffolding only;
  The wp21 markers from `9ddced8` additionally pin Postgres per-book
  export/import/imported-bundle/start-over portability through pooled reads and
  backend-agnostic transaction writers, plus non-destructive logical-bundle
  `restore_preflight` verification; ignored live-Postgres tests cover
  export/import round-trip, tamper quarantine, collision-refuse atomicity,
  start-over coherence, and bad-bundle preflight refusal. SQLite remains the
  default, Postgres selection is feature/config gated, and the current live
  Postgres CI lane is limited to the store runtime write/read round-trip test
  against a disposable `chancela_store_ci` database. The `628b613` local
  Docker/Postgres proof runs the full ignored `postgres_backend` store test
  binary with per-test child database isolation and `10 passed`, covers runtime,
  persist/reload, logical restore, per-book, recovery/start-over, and bad-bundle
  paths, drops child databases during cleanup so successful sweeps leave no
  per-test child DBs behind, and fixes logical restore row insertion with
  `$1::text::jsonb` before `jsonb_populate_record`. Only direct SQLite
  internals remain fail-closed on Postgres. It is not production Postgres
  readiness, global read-freshness certification for settings/users/roles/
  sidecars, broad API/product live DB validation beyond the store backend sweep,
  API Postgres CI, migration completeness, production HA
  readiness, consensus correctness, split-brain impossibility, live failover
  certification, cloud deployment readiness, live `verify-full` CA/hostname
  proof, production TLS/remote PG readiness,
  multi-node operational certification, backup-policy/RPO/RTO certification,
  legal/DR certification, or external sync readiness.
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
- Mobile P1 API base URL checks through `842b7f2`: focused
  `apps/web/src/api/baseUrl.test.ts`, `apps/web/src/api/client.test.ts`, and
  `apps/web/src/shell/mobileShell.test.ts` coverage pins relative browser/Tauri
  defaults, `VITE_CHANCELA_API_BASE_URL`, runtime `__CHANCELA_CONFIG__`,
  `__CHANCELA_MOBILE_SHELL__` API base URL injection, and Capacitor/Cordova/
  ReactNative/WKWebView shell detection. This is frontend API base URL
  indirection and shell detection only: no native mobile build, iOS/Android
  package, offline sync, production connector readiness, or spec-completion
  claim is made.
- Mobile companion foundation checkpoint through `d43b82a`: desktop package
  scripts expose inert Android companion entry points and `docs/mobile.md`
  records the external prerequisites and backend exposure boundaries. This is
  documentation/script scaffolding only: no Rust desktop host change, native APK
  build, iOS/Android packaging proof, store submission, offline sync, production
  connector readiness, or mobile spec-completion claim is made.
- GDPR/API subject-DEK secret-store binding through `33e70bb`: focused local
  `crates/chancela-api/src/secretstore.rs` coverage pins subject-DEK crypto
  construction from the resolved credential secret-store CMK using dedicated
  HKDF salt/info, subject/field/key-version AAD binding, empty wrapped-DEK blob
  erase failure, randomized wrapped blobs, and cross-store unwrap failure. This
  is API secret-store crypto evidence only: no wired destructive erasure
  workflow, physical deletion/anonymization, backup/archive rewrite, legal GDPR
  completion, production key-custody proof, or spec-completion claim is made.
- GDPR erasure API workflow checkpoint through `67952f7`: focused privacy tests
  pin the destructive erasure preflight/approve/execute route wiring, workflow
  persistence, ledger verification advancement across a real erasure, test
  subject user row removal, and destroyed subject-DEK unwrap failure. This is
  local API gate evidence only: no physical deletion, anonymization, backup or
  archive rewrite, legal GDPR compliance/completion, legal disposal approval,
  production key custody, or spec-completion claim is made.
- GDPR sealed-record annotation/remedy checkpoint through `6093e7e`: focused
  API tests pin `58b7e55` append-only subject rectification and
  processing-restriction annotation routes/kinds plus preflight
  `remedy=annotation` classification for statutory-retention cases, preserving
  prior sealed/signed event bytes, hashes, and payload digests while
  verification advances. The current snapshot documents the retained-record remedy framing.
  This is append-only privacy remedy evidence only: no deletion, anonymization,
  mutation of sealed/signed historical events, legal GDPR compliance/completion,
  legal disposal approval, or spec-completion claim is made.
- Tenant-chain integration checkpoint through `6093e7e`: focused implementation
  evidence adds tenant-chain ledger membership, tenant-aware archive chain
  labeling, tenant scope handling in entity activity indexing, and tenant scope
  preservation through role/authorization resolution paths. This is tenant-chain
  and authorization plumbing evidence only: no full multi-tenancy isolation
  certification, full tenant authorization proof, legal-capacity validation,
  broad security certification, or spec-completion claim is made; the spec
  matrix remains `PARTIAL=11`.
- Snapshot drift/test-determinism checkpoint through `c9cf2cb`: `fafb8ad`
  records mkdocs navigation drift capture for the mobile companion docs,
  `b951895` formats the XAdES C14N vector test, and `c9cf2cb` isolates
  command-signing environment state in the API test harness. This is docs
  config and test determinism evidence only: no production signing, XAdES
  conformance, CMD approval, legal validity, or spec-completion claim is made;
  the spec matrix remains `PARTIAL=11`.
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
- Current PDF accessibility checks: focused document tests pin accessibility
  report JSON version 12, deterministic `pdf_ua_blocker_delta` evidence with
  local basis, cleared blockers, remaining blockers, cleared count of 13,
  remaining count of 0 for the conforming fixture, scoped row/column
  table-header evidence, structure-tree diagnostics, explicit role-map target
  entries, marked-content coverage counts, bounded local topology facts, and
  marked-artifact target/operator evidence for writer-owned decorative rule
  artifacts emitted as PDF artifacts. The default fixture no longer reports
  `no_alt_text_model` for only writer-owned decorative artifacts, page breaks
  stay excluded through
  `accessibility_page_breaks_do_not_require_decorative_accounting`, and
  `accessibility_non_text_accounting_covers_current_block_variants` keeps
  `DocumentBlock` accounting exhaustive for future caller-owned non-text
  variants. The conforming fixture now sets `pdf_ua_claimed: true`, emits the
  PDF/UA-1 XMP identifier plus extension schema, and passes the enforced
  self-check gate; skipped-heading and fallback-metadata fixtures still decline
  the claim. This is a gated pre-signature document claim only, not DGLAB
  certification, legal archive certification, validator evidence, legal
  sufficiency, universal PDF/UA completion, or signed-PDF accessibility
  certification.
- Current PDF accessibility evidence projection checks: focused
  API/archive tests project the deterministic `chancela-doc` accessibility
  report JSON v12 into document bundle validation reports and archive package
  `evidence/pdf-accessibility/{document_id}.json` sidecars. Act-owned documents
  are derived from the persisted render model, and `99d15a4` preserves the
  generated report's `pdf_ua_claimed` value into bundle/archive evidence.
  Book-level or unsupported model cases remain explicit
  `pdf_accessibility_report_unavailable` sidecars with `pdf_ua_claimed: false`.
  The bundle and archive indexes expose path pointers while keeping
  `dglab_certification_claimed` and `legal_validity_claimed` false. This is
  technical blocker/fixity metadata, not DGLAB certification, legal validity,
  external certification, universal PDF/UA completion, or signed-PDF
  accessibility certification.
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
- Current `bac4337` data-status sidecar classification and backend-neutral
  durability telemetry checks: focused API
  markers pin `data_status_concern_classification_covers_known_roots` and
  `/v1/data/status` filesystem concerns for `platform-logs.json` as
  `platform_logs` and `backup-recovery-drills.json` as
  `backup_recovery_drills`, plus active durable backend family,
  sidecar-storage mode, durable-store-open permission status,
  backend-neutral logical payload rows, and DB-backed sidecar logical
  rows/labels where sidecars are database-backed. These checks preserve durable
  permission/status behavior and classify sidecar usage only; they do not add
  file-to-DB migration, backup/restore execution, production RPO/RTO proof,
  destructive operation semantics, external service dependency, legal custody
  proof, or data-lifecycle certification.
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
  rule-pack/signature-policy hints, and the 104 total / 44 CSC catalog census.
  The same lane still pins `csc-ata-divisao-quotas/v1` and
  `csc-ata-unificacao-quotas/v1` quota parity plus the unresolved
  `csc.deliberacao.maioria_qualificada` majority threshold marker, and
  `csc-ata-delegacao-poderes/v1` / `csc-ata-revogacao-poderes/v1` proposed
  resolution text without adding threshold markers. It also pins
  `csc-ata-fusao/v1`, `csc-ata-cisao/v1`, and `csc-ata-liquidacao/v1` as local
  CSC structural-change Ata templates with Pending rule-pack and majority
  threshold law-reference anchors. These are local catalog parity/rendering
  checks only; law references remain Pending/non-authoritative with no DRE
  verification, guessed threshold, authority verification, registry submission,
  external registry/provider integration, signing-process claim, legal
  sufficiency, structural-change legal sufficiency, or new law-source claim.
- Current working-tree post-act template semantic-lint checks: focused
  `cargo test -p chancela-templates --locked` coverage plus
  `cargo run -p chancela-templates --bin template_catalog_metadata_lint --locked`
  pins the authored catalog guard that `Certidao` and `Extrato` `BlockSpec`
  template strings bind sealed-act `ata_number` and `payload_digest`, plus a
  synthetic missing-binding regression proving the guard applies only to
  post-act stages. This is runnable embedded-catalog metadata consistency lint
  only; no asset wording changes, DRE verification, Verified law references,
  verified thresholds, channel permissibility, registry/provider integration,
  signing correctness, or legal-effect claims are implemented.
- Current local legal-reference corpus audit checks: focused
  `cargo test -p chancela-api --test api-records --locked -- law_reference_coverage` coverage
  builds a deterministic local audit report from the embedded template registry
  and embedded law corpus. It pins template `law_references` source IDs against
  local corpus diplomas, single-article references resolving to corpus articles
  or explicit blockers, corpus Verified/Pending status preservation, Pending
  corpus/template references staying unresolved, threshold-backed references
  staying blocked as `legal threshold value pending`, and `LEGAL_THRESHOLDS`
  entries remaining `value: None` with only pending rendered markers. This is a
  local static/corpus audit only: no network, DRE, EUR-Lex, registry, provider,
  legal-service, or authority calls; no Pending-to-Verified promotion; no
  threshold value completion; and no legal review, legal validity, template
  sufficiency, cited-law correctness, or threshold correctness claim.
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
- Current `5911fe0` AI provenance checks: MCP/API draft creation now carries
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
  `signature_qualification: false`) while keeping accept/reject unchanged. It
  also copies a deterministic pretty-JSON review packet generated from
  `act.ai_provenance`, with `schema_version`, `generated_from`, source/tool
  presence, human-review presence booleans, counts/status/missing/pending/claim
  rows, and false `no_claim_flags`, without raw statement labels, operator
  instruction, reviewer identity, or review notes. This
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
  `chancela://mcp/workflow-provenance-review` resource, offline/static guidance,
  `arguments.workflow_evidence` local JSON/text summary mode, aggregate
  workflow/human-review/evidence-marker/warning counts, no raw echo, no
  bridge/API/AI-provider/provider calls, no secrets, review category coverage,
  and false legal/source/workflow/provider/trust/external/signature/extraction
  claim flags. This is review guidance only: no AI or MCP completion claim, no
  legal validity, no source certification, no workflow completion, no provider
  assurance, no trust validation, no external validation, and no extraction
  accuracy certification.
- Current `2d84112` Ata editor workflow provenance panel checks: focused web
  tests passed for
  `apps/web/src/features/acts/workflowProvenanceReviewPacket.test.ts` and
  `apps/web/src/features/acts/AtaEditorStructured.test.tsx` as part of the
  implementation validation, alongside web lint/build, MCP resource tests, and
  `git diff --check`. These tests pin the local
  `chancela://mcp/workflow-provenance-review` copy payload, deterministic
  aggregate lifecycle/human-review/evidence-marker/missing/compliance counts,
  visible panel rows, i18n keys, no raw ID/name/email/title/deliberation/access
  code/digest echo, false no-claim flags, and no browser MCP/API/AI-provider
  call path. This remains a route/local-state web proof only: no provider/live
  AI calls, non-stdio MCP transport, workflow completion, source certification,
  extraction accuracy, legal validity, release readiness, AI-01, AI-02, or full
  AI/MCP completion.
- Current `0954b53` generated-document fixture alignment checks: the
  CompliancePanel/Ata editor test fixture now stubs
  `/v1/acts/{id}/documents/generated`, matching the generated-document query
  path so `npm run test:web:coverage` is green again. This restores the
  apps/web Vitest/V8 coverage gate only; it does not add browser, desktop,
  Docker, live-provider, or release-coverage threshold breadth.
- Current working-tree law corpus automated-review checks: focused local corpus
  coverage now has a third `AutomatedReview` tier for automatically vendored
  statutory text that is complete enough to render but explicitly not
  human-Verified. The gate keeps complete-source/body requirements for those
  articles, keeps the DRE human approval manifest untouched, leaves the oversized
  amending article Pending, and does not claim legal certification, human legal
  approval, DRE source-authority verification, template sufficiency, legal
  validity, or spec completion.
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
- Current working-tree MCP privacy-control review summary checks: focused
  `cargo test -p chancela-mcp --locked privacy_control_review_summary` coverage
  pins the read-only `chancela://mcp/privacy-control-review-summary` resource,
  static no-argument input guidance, deterministic aggregate report mode for
  `arguments.privacy_controls`, local JSON only, secret/no-echo coverage,
  no extra resource params, no bridge/API/AI-provider/legal-service/provider
  calls, aggregate counts for privacy records, advisory review status,
  review/drill receipts, missing advisory review, no-claim flags, retention
  execution status/outcome/evidence state, DSR type/status/outcome,
  caller-supplied retention due-candidate status/outcome/evidence-state
  buckets, bounded suppression counts, latest-resolution presence and
  disposition buckets, candidate-resolution disposition buckets,
  blocker/approval presence counts, evidence-only flags, and missing/unknown
  optional input behavior, plus false legal approval/completion, notification,
  transfer, DPIA, compliance, disposal, deletion, anonymization, redaction,
  erasure, legal-hold mutation, retention-policy mutation, full-erasure,
  provider, and legal-service claims. Unknown labels are counted as
  `other`/`missing` and sensitive ids, notes, legal bases, subjects,
  recipients, data categories, and raw evidence text are not echoed. This is
  caller-supplied local JSON review signal only: no privacy/GDPR compliance
  completion, no legal approval, no notification, no transfer execution, no
  DPIA filing/completion, no disposal, no deletion, no redaction, no
  anonymization, no erasure, no legal-hold or retention-policy mutation, no
  provider/legal-service assurance, and no AI or MCP completion claim.
- Current working-tree DPIA template/guidance checks: focused
  `cargo test -p chancela-api --test api-archive-privacy --locked -- privacy::dpia` coverage pins
  `GET /v1/privacy/dpia-template` as a static local/offline guidance artifact
  with structured processing-description, necessity/proportionality, risk,
  safeguards, consultation/escalation, evidence-boundary, no-claim, and
  operator-action fields. Web contract and Settings tests pin
  `contracts/privacy.dpia-template.json`, `api.getDpiaTemplate()`, the
  Settings > Privacidade `Modelo DPIA local` panel, and no-echo/no-mutation
  behavior. This is distinct from `GET|POST|PATCH /v1/privacy/dpias`: no raw
  register contents, names, recipients, subject identifiers, notes,
  subprocessors, legal bases, personal data, or secrets are echoed. It does not
  add CNPD/EDPB or other authority filing/approval, legal review acceptance,
  DPIA completion/certification, external delivery/validation, compliance
  certification, transfer approval/execution, notification, external calls,
  register mutation, automated legal decision, or risk-scoring authority, and
  it keeps the spec matrix at `PARTIAL=11`.
- Current `92de3e7` MCP document/archive PDF accessibility v12 alignment checks: focused
  `cargo test -p chancela-mcp --locked document_archive_review_summary` coverage
  pins the read-only `chancela://mcp/document-archive-review-summary` resource,
  static no-argument input guidance, deterministic aggregate report mode for
  `arguments.document_archive`, local JSON only, raw-report/no-echo coverage,
  no extra resource params, no bridge/API/AI-provider/legal-service/HTTP/SSE/
  provider calls, aggregate counts for validation report/status, digest/fixity
  fields, signed-document state, external-validator attachments/statuses,
  `pdf_accessibility_v12`, `pdf_accessibility_v12_summary`,
  `v12_report_count`, `pdf_accessibility_v12_report_missing`, fixture
  `report_version: 12`, nested `accessibility_report_json.version: 12`, known
  `limited_tagged_structure` blockers, `other` buckets for unrecognized caller
  blocker text, row/column table-header counts and scope flags,
  archive/evidence-index path markers, no-claim observations, and
  missing-evidence blockers, plus false PDF/UA conformance, DGLAB
  certification, legal validity, signature validity, qualified-signature,
  archive-certification, provider-validation, external-validator-success,
  trust-validation, and legal-review claims. This is caller-supplied local JSON
  review signal only: no PDF/UA conformance, no DGLAB certification, no legal
  validity, no signature validity, no archive certification, no provider
  validation, no external-validator success, no trust validation, no legal
  review, no full archive completion, no spec completion, no provider/legal
  assurance, and no AI or MCP completion claim.
- Current working-tree sealed-act chronology projection checks: focused API/UI
  evidence pins `sealed_act_projection` on `GET /v1/entities/{id}/chronology`
  for local sealed or archived acts, including provenance rows, local nodes and
  edges, retification/correction edges, and false `legal_validity_claimed` and
  `authority_certified_claimed` flags. The Entity chronology panel renders the
  projection as local act chronology with source labels and no-claim copy. This
  is read-only local sealed-act projection evidence only: no registry/provider
  certification, legal validity claim, archive or act mutation, user/editor
  authoritative graph claim, live provider call, or ownership/relationship
  determination is made.
- Current `b8c1ccf` dashboard guest/minimal recent-events redaction checks:
  focused
  `cargo test -p chancela-api --locked dashboard_recent_events_redacts_guest_feed_but_keeps_owner_and_reader_feed`
  coverage pins the existing API behavior, and
  `npm run test --workspace apps/web -- src/contracts/contracts.test.ts` now
  covers `contracts/dashboard.guest.json` through the web parser with
  `recent_events: []` plus absent owner-only ledger event fields/values. Owner
  and `Leitor` keep recent-event visibility, and Guest still gets refusal from
  `/v1/ledger/events`. This is response redaction contract coverage only: no
  permission grants, full anonymization, destructive erasure, production
  privacy compliance, or policy-completeness claim.
- Current `3795016` generated-convening real-backend browser proof checkpoint:
  `npm run test:browser --workspace apps/web -- e2e/generated-convening-dispatch-evidence-real.spec.ts --project=chromium`
  passed for the release-server/built-SPA/E2E-backend path. It follows the
  dashboard generated-convening dispatch-evidence reminder deep link to
  `/atas/{act_id}?generated_document_id={document_id}&focus=dispatch-evidence#generated-dispatch-evidence`,
  records operator metadata through real `POST`/`GET`
  `/v1/documents/generated/{document_id}/dispatch-evidence`, and verifies the
  persisted operator evidence row plus `operator_evidence_covered` status
  rendering. This validates UI/backend integration for generated Convocatoria
  dispatch-evidence metadata only: no send/delivery/legal-notice completion,
  restart-persistence, bundle/archive preservation, full browser matrix,
  provider/legal/registry proof, or spec completion is claimed.
- Current `364cb4b` composed-server auth-aligned E2E checkpoint:
  `cargo test -p chancela-server --features e2e --locked` passed locally after
  the server E2E auth helpers were aligned with the current password-required
  `/v1/users` and `/v1/session` public contracts. Legacy passwordless
  degraded-recovery coverage is preserved only through a test-only e2e-feature
  session seed file consumed at server startup; public account/session
  semantics remain unchanged, and public session creation still rejects no-hash
  users. Focused recovery E2E also passed with
  `cargo test -p chancela-server --features e2e --locked --test e2e_recovery_data_mgmt -- --nocapture`,
  web contract tests passed with
  `npm run test --workspace apps/web -- src/contracts/contracts.test.ts` (57),
  and `cargo fmt --all --check` plus `git diff --check` passed. This full
  server E2E pass validates the generated-convening composed-server slice under
  the full suite only; it does not claim full spec completion, live provider
  proof, legal proof, public auth weakening, or browser/Desktop/Docker matrix
  completion.
- Current `212a1b2` generated-document by-id download, dispatch-evidence, and
  dashboard absent-owner/generated-convening reminder checks: focused
  `cargo test -p chancela-api --locked on_demand_generate_persists_a_chosen_document_and_emits_the_event`
  and
  `cargo test -p chancela-api --locked in_memory_generated_document_download_uses_returned_url_and_keeps_canonical_ata`
  plus
  `cargo test -p chancela-server --test e2e_act_document_persistence --locked condominium_absent_owner_communication_auto_generates_and_keeps_canonical_ata`
  plus `cargo test -p chancela-api --locked absent_owner_dispatch_evidence_`
  and
  `cargo test -p chancela-api --locked generated_convening_notice_dispatch_evidence`
  and
  focused composed-server real-binary checks
  `cargo test -p chancela-server --features e2e --locked --test e2e_act_document_persistence generated_convening -- --nocapture`
  and
  `cargo test -p chancela-server --features e2e --locked --test e2e_archive_package generated_convening -- --nocapture`
  plus
  `cargo test -p chancela-store --test store --locked generated_document_dispatch_evidence`
  coverage pins `/v1/documents/generated/{document_id}`, route classification,
  `act.read` gating by the owning act, durable and in-memory lookup, and
  preservation of `/v1/acts/{act_id}/document` as the sealed Ata bytes. It also
  pins automatic condominium absent-owner communication generation after seal,
  generated-document by-id retrieval of that communication, pending dispatch
  evidence status, restart persistence, generated Convocatoria dispatch evidence
  for persisted convening recipients, `POST`/`GET`
  `/v1/documents/generated/{document_id}/dispatch-evidence`,
  `generated_document_dispatch_evidence`, operator-supplied dispatch evidence
  with exact-retry idempotency, selected absent/convening-recipient evidence coverage,
  evidence-attached/status headers, no dispatch-completed header claim, and the
  bounded
  `absent_owner_communication.dispatch_evidence_recorded` and
  `generated_document.dispatch_evidence_recorded` event false flags.
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
  `npm run test --workspace apps/web -- src/api/client.test.ts src/contracts/contracts.test.ts src/features/dashboard/DashboardPage.test.tsx src/features/documents/ActDocumentPanel.test.tsx src/features/notifications/notifications.test.ts src/i18n/i18n.test.ts`;
  it pins `listGeneratedDocuments`, `getGeneratedDocumentDispatchEvidence`,
  `recordGeneratedDocumentDispatchEvidence`, generated absent-owner
  communication listing, generated Convocatoria generation/evidence form,
  generated PDF fetch, stored evidence rows,
  permission-gated metadata-only evidence recording, `operator_evidence_*`
  status display, `documents.generated.noClaim.*` localized copy, dashboard
  localized deep-link routing, dashboard generated-convening reminder routing,
  notification deep-link routing, one-time
  ActDocumentPanel dispatch-evidence selection/focus, advisory absent-owner
  reminder copy, and the `contracts/dashboard.json` pending no-due-date
  generated absent-owner fixture.
  Focused route-stubbed browser proof is
  `npm run test:browser --workspace apps/web -- e2e/absent-owner-dispatch-evidence.spec.ts`
  and `npm run test:browser --workspace apps/web -- generated-convening-dispatch-evidence.spec.ts --project=chromium`;
  it pins the advisory dashboard reminder opening the generated-document
  dispatch-evidence form, generated `condominio-comunicacao-ausentes/v1` and
  generated Convocatoria visibility/download, metadata-only evidence recording,
  resulting operator evidence row display, and no send/delivery/legal-notice
  completion claims.
  Real-backend browser proof is
  `npm run test:browser --workspace apps/web -- e2e/generated-convening-dispatch-evidence-real.spec.ts --project=chromium`;
  it uses the E2E backend for the dashboard deep link, real
  `/v1/documents/generated/{document_id}/dispatch-evidence` `POST`/`GET`, and
  persisted operator evidence row/status rendering while keeping the
  metadata-only no-claim boundary.
  This is generated-document retrieval, dashboard/notification navigation, and
  operator-recorded dispatch-evidence metadata only: no sealed act, canonical
  Ata, or generated-byte mutation; no mail, email, SMS, or provider sending; no
  delivery, legal notice completion, legal sufficiency, legal effect, provider
  execution, registry filing, signing, bundle readiness, template legal review,
  threshold correctness, law verification claim, dashboard ledger-event append,
  archive action, legal validity certification, or dispatch-complete claim.
  The composed-server commands are focused generated-convening E2E filters only;
  this checkpoint does not claim that the full
  `cargo test -p chancela-server --features e2e --locked` suite or API
  regression suite was rerun in the final pass.
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
- Current working-tree written-resolution evidence receipt browser checks:
  focused route-stubbed Playwright proof is
  `npm run test:browser --workspace apps/web --
  e2e/written-resolution-evidence.spec.ts`. It pins the mounted Ata editor path
  for a WrittenResolution act, local evidence receipt form fill/submit, exact
  act `PATCH` body scoped to `written_resolution_evidence`, preservation of
  existing checklist/history metadata, all proof/legal/authority claim flags
  false, and updated receipt/history/no-claim rendering after the stubbed
  response. Treat this as metadata-only local browser proof: no live provider,
  legal acceptance, legal sufficiency, written-consent/quorum/identity proof,
  external validation, legal-validity or authority certification, act
  finalization, signing, seal, or archive completion.
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
  checks, plus local OCR/canonical rehearsal report checks: focused
  `cargo test -p chancela-store --test store --locked
  paper_book_ocr_conversion`, `cargo test -p chancela-api --test api-records
  --locked -- paper_import::paper_book_ocr_conversion`,
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
  conversion execution evidence rendering, the read-only
  `/v1/books/paper-import/{id}/ocr-canonical-rehearsal` report shape,
  readiness/blocker/no-claim summaries, confidence known/unknown buckets, digest
  and page-span evidence counts, the `paper-book.ocr-canonical-rehearsal.json`
  contract fixture, and the BookDetail compact local report panel, with no
  document/signature/seal/archive endpoint calls from the dossier UI. This is
  metadata-only/reviewed execution/local rehearsal evidence for mutable drafting
  only; no mutation, external OCR/provider/validator/legal-service call, legal
  archive certification, official DGLAB acceptance/export, PDF/UA delivery, OCR
  accuracy certification, canonical minutes/legal conversion, signed artifact
  validity, or legal-validity claim is implemented.
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
  test -p chancela-api --test api-signatures --locked -- asic_signature_validation` coverage pins
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
- Current `33e70bb` TSL XML-DSig checks: focused `chancela-tsl` coverage now
  pins real C14N-backed SignedInfo/reference digest candidate handling while
  preserving the already-canonical fast path, plus bounded P-256 ECDSA-SHA256
  verification only when the embedded signer certificate matches a configured
  trust anchor and only for XML-DSig's fixed-width raw `r||s` signature value,
  with DER ECDSA encodings rejected. This remains technical trust-list parsing
  evidence only; the broader `chancela-xades` lane below is the current
  XML-signing implementation surface. It is not certificate path/revocation/
  policy validation, legal trust certification, production trust-list validity,
  multiple-reference support for the TSL importer, or transform-chain support
  for the TSL importer.
- `63df508` signing trust validation checkpoint: static markers pin
  the prior `8bbe944` live EU LOTL/member-state bootstrap, `6292d75`
  revocation cache and graceful offline fallback, `ead1aaa` full-chain PAdES
  DSS evidence assembly from validated chain plus revocation material,
  `9be5e00` live end-entity signer-path validation with TSL-resolved
  revocation trust-decision reporting, `93175c0` public signer trust
  validation export, `4de850b` live LOTL trust bootstrap, `119d91c`
  full-chain signer trust plus B-LT/B-LTA technical status surfacing in the
  API, and `63df508` cryptographic CA-link verification in the offline PAdES
  LTV verifier. This is bounded technical validation evidence only: it is not
  production trust-list validity, legal certificate path/revocation policy
  sufficiency, qualified-status determination, eIDAS/QES compliance, legal
  trust certification, live provider approval, or full trust implementation.
- Current `50854dd` XAdES reconciliation checks: `chancela-xades` now pins real
  in-crate XML C14N against W3C REC-derived vectors, duplicate-`Id` fail-closed
  guards, multiple-reference XML-DSig packaging, SHA-384/512 digest agility for
  P-384/P-521 at the XAdES layer, XAdES-B/T/LT validation material, and ASiC-S
  plus ASiC-E XAdES technical evidence including `sign_asic_e_xades_lt`. This
  is shipped technical XML-signing evidence only: no XAdES-LTA, live
  xmlsec1/EU-DSS run, trusted-list/provider/legal completion, QES, or eIDAS
  legal-effect claim is made.
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
- Current `6d0c3ec` backup recovery freshness advisory checks: API coverage pins
  `backup.recovery.freshness_advisory` only for actors with `LedgerRecover` or
  `DataBackup` authority, using existing stored receipt freshness states
  (`no_receipt`, `stale`, `failed`) and omitting receipt IDs, archive paths,
  manifests, findings, and live restore markers. Web notification/dashboard
  coverage pins localized work-queue and notification copy,
  `/configuracoes?sec=dados` routing, and fallback-sanitized rendering. This
  remains local advisory surfacing over stored receipt metadata only; it does
  not create a backup, execute a restore, mutate archives or live data, certify
  RPO/RTO or production backup policy, prove DR readiness, or complete
  compliance coverage.
- Current working-tree sync/handoff preflight readiness checks: focused
  `cargo test -p chancela-api --locked --lib sync_handoff_preflight` coverage pins the
  read-only `GET /v1/sync/handoff-preflight` report, `ledger.recover@Global`
  authz classification, in-memory blockers, untrusted backup-directory
  candidates, verified recovery-drill receipt evidence projection, rejection of
  malformed/unverified recovery receipts, book bundle/import-preflight route
  availability, archive/local DGLAB evidence counts, and false no-claim flags.
  Web contract coverage pins `sync.handoff-preflight.json` and the typed
  client/hook shape, while the Data Management panel renders a local report
  card with a browser save-picker JSON export for the already-loaded report only
  and no target-path, remote upload/download/import, connector, or mutation
  control. This remains local handoff
  review evidence only: no active sync, connector protocol, background job,
  remote upload/download/import, record mutation, production sync readiness, external
  connector compatibility, legal validity, DGLAB/archive certification,
  signing/notarization/attestation, deployment readiness, or external-system
  readiness is implemented or proven.
- Recent `baad7b4` archive filter refinement checks: focused
  `npm run test --workspace apps/web -- LedgerPage.test.tsx` coverage pins the
  Arquivo icon-only clear-filters button with tooltip/accessibility label, empty
  text content, disabled state, `Icon.FilterClear` funnel/clear SVG paths, and
  absence of the generic close-icon paths. It also pins collapsed
  `details.ledger-advanced-filters.filter-advanced` by default, the compact
  active-filter count badge in the advanced-filter summary once filters are
  active, and responsive summary/body CSS. `LedgerPage.tsx` continues to use
  `Icon.FilterClear`, the export dropdown remains `pdfa`/`txt`/`json`/`csv`/
  `html`, server-backed filters and lazy newest-first paging remain intact, and
  archive-document export remains bounded to the current filtered first page
  with no `before_seq`. This remains archive UI clarity/accessibility and
  bounded current-page export regression coverage for `baad7b4`; the later
  `a7125b3`/`040ce48` slices cover opt-in all-filtered export and
  streaming/cap boundaries. No non-PDF/A evidence
  preservation, archive certification, legal acceptance, signature validation,
  ledger mutation, or production custody claim is implemented or proven.
- Current `040ce48` all-filtered archive export checks: focused
  `cargo test -p chancela-api arquivo --locked`, `cargo test -p chancela-api
  --lib ledger_archive_document --locked`, `npm run test --workspace apps/web
  -- LedgerPage.test.tsx client.test.ts i18n.test.ts`, `npm run build
  --workspace apps/web`, and `npx playwright test
  e2e/ledger-archive-boundedness.spec.ts --project=chromium` coverage pins
  explicit archive `export_scope`, default bounded current-page export,
  `all_filtered` server-side walking of filtered newest-first records in
  250-record internal chunks, streamed JSON/TXT/CSV/HTML audit/interchange
  exports with `streamed`, `streaming_mode`, and `record_cap` metadata,
  buffered all-filtered PDF/A capped at 1,000 records with over-cap rejection
  and no truncation, continued `before_seq` rejection on archive export,
  preservation of `pdfa`, `txt`, `json`, `csv`, and `html` formats, UI help
  copy for the streamed formats/PDF/A cap, and UI/browser behavior where
  all-filtered export does not load older records into the table. This remains
  filtered ledger export coverage only: JSON/TXT/CSV/HTML are
  audit/interchange exports rather than preserved evidence, PDF/A remains
  buffered and capped, and there is no DGLAB/legal archive certification,
  expanded PDF/A/signature validity, production custody proof, legal
  acceptance, ledger mutation, or full archive completion claim.
- Current `3a41187` workflow reminder/calendar checks: focused `cargo test -p
  chancela-core --locked profile_calendar`, `cargo test -p chancela-api
  --locked profile_calendar`, and `cargo test -p chancela-api --locked
  reminder_` coverage pins `workflow.reminders` defaults
  (enabled, dashboard limit 5, due-soon 45 days, attendance lookahead 45 days,
  all sources enabled), dashboard policy application to the existing
  profile-calendar, act-follow-up, and attendance-hygiene advisory reminder
  families, `enabled=false` suppression of reminder output without removing
  other dashboard current-work data, per-source suppression limited to the
  matching local reminder family, numeric limit/window behavior, and absolute
  calendar-day reminder status across year boundaries, plus the deterministic
  condominium `condominio-annual` local fixed Jan 15 advisory date. The typed
  local advisory profile-calendar plan
  distinguishes rule kind, support/review/source status, due-rule shape,
  evaluated fiscal-year or fixed-date basis, and explicit no-claim flags for
  supported local-rule presets and unsupported pending/no-date presets.
  Structural law
  references remain Pending/unverified metadata, not verified law sources or
  legal authority; legal-authority, external delivery/calendar-sync/webhook,
  compliance-status, and workflow-completion claim flags remain false. Focused
  `settingsDefaults.test.ts` and `SettingsPage.test.tsx` coverage pins the web
  defaults and compact Gestão controls for the master switch, limit, due-soon
  window, attendance lookahead, and three source toggles. Web
  contracts/dashboard/notification tests plus `npm run build --workspace
  apps/web` passed for the fixed-date condominium reminder surface. This
  remains local advisory policy/calendar coverage only: no legal-calendar
  authority, law-source authority, threshold verification, external
  delivery/email/ICS/CalDAV/webhook,
  workflow completion, attendance proof, compliance gate, or legal sufficiency
  claim is implemented.
- Current `711c7a4` dashboard annual reminder localization checks: focused
  `npm run test --workspace apps/web --
  src/features/dashboard/DashboardPage.test.tsx` coverage pins work-queue
  localized titles, shared annual advisory body copy, localized entity action,
  entity routes, due dates, source metadata, and raw fallback suppression for
  `csc-art376-annual`, `assoc-annual`, `fundacao-annual`, and
  `cooperativa-annual`, while preserving `condominio-annual` behavior. `npm run
  build --workspace apps/web` passed with the existing ConfirmActionModal Rollup
  warnings. This is frontend dashboard display and workflow/calendar UI coverage
  only: no backend/calendar policy, contract, provider, legal/compliance, DRE
  source-authority, external delivery/calendar-sync/webhook, workflow completion,
  or legal-effect claim is implemented.
- Current `982cc9a` convocation-notice advisory checks: focused
  `cargo test -p chancela-core --locked convocation_notice`, `cargo test -p
  chancela-api --locked convocation_notice`, `npm run test --workspace apps/web
  -- DashboardPage.test.tsx notifications.test.ts`, `npm run build --workspace
  apps/web`, `cargo fmt --check`, and `git diff --check` coverage pins local
  statute/convening advisory depth only. Core compares
  `Entity.statute.convocation_notice_days` with `Act.convening`
  antecedence/dispatch metadata, warning for missing/unverifiable evidence or
  too-short notice and suppressing the warning when evidence satisfies the
  configured day count. The API dashboard emits `act-convening-notice` open-act
  reminders with `meeting_date`, computed `notice_due_date`, dispatch/antecedence
  params, empty `law_refs`, localized
  `notifications.reminder.act.conveningNotice.*` copy, and false
  legal-sufficiency/external-delivery/workflow-completion claim params; web
  dashboard and notification tests pin localized act routing and raw-backend
  fallback suppression. Residual limitation: dashboard reminder emission needs
  `meeting_date` to compute `notice_due_date`, and core still emits advisory
  warnings for missing or unverifiable convening evidence. This adds no
  legal-authority, legal-sufficiency, provider, certification, external
  delivery, workflow-completion, DRE/source-authority, registry acceptance,
  legal effect, or legal/compliance completion claim.
- Current `daf8288` convening recipient contact metadata checks: focused core,
  API, template, AtaEditor convening, route-stubbed browser, web build, and
  whitespace checks passed before this checkpoint. `ConveningRecipient.contact`
  is additive optional recipient contact metadata distinct from dispatch
  proof/tracking `reference`; the Ata editor exposes separate `Contacto` and
  `Referência de expedição` inputs, persists contact through the existing
  `updateAct` / `UpdateActBody.convening` path, filters blank-name rows from
  the saved payload, and does not migrate legacy ambiguous `reference` values
  into `contact`. Local dispatch evidence stays disabled until recipient names
  exist in persisted act state, so UI-created recipients must be saved before
  dispatch evidence can stamp proof `reference` / `dispatched_at`; stamping
  preserves existing `contact`. Convocatoria templates render contact and proof
  reference distinctly. This remains local workflow metadata/template/evidence
  capture only: no email/SMS sending, provider delivery, delivery confirmation,
  legal sufficiency, compliance completion, workflow completion, legal effect,
  registry/DRE/provider acceptance, or legal/compliance completion claim is
  added.
- Current `caae1bf` convening dispatch evidence capture checks: focused
  `npm run test --workspace apps/web -- AtaEditorStructured.test.tsx`, `npm
  run test --workspace apps/web -- client.test.ts`, `npm run build --workspace
  apps/web`, `cargo test -p chancela-api --locked dispatch_`, and `git diff
  --check` coverage pins local workflow evidence capture through the existing
  `POST /v1/acts/{id}/convening/dispatch` endpoint. The Ata editor builds the
  dispatch body from existing `act.convening` recipients, required
  `dispatched_at`, and optional channel/reference metadata, then records local
  provenance and updates matching convening recipient stamps from the returned
  `ActView`; no backend changes were needed. This does not create recipients,
  send email/SMS, confirm external delivery, compute legal sufficiency, complete
  the workflow, or claim registry/DRE/provider acceptance, legal effect, or
  legal/compliance completion.
- Current `0c539ae` convening dispatch browser proof checks: focused
  route-stubbed Playwright evidence passed with `npm run test:browser
  --workspace apps/web -- e2e/convening-dispatch-evidence.spec.ts` (1 Chromium
  test), plus `git diff --check` and `git diff --cached --check` before commit.
  It pins the dashboard `act-convening-notice` reminder link to
  `/atas/{id}#convening-guidance`, the existing guidance/no-claim browser copy,
  and the local `POST /v1/acts/{id}/convening/dispatch` body for required
  `dispatched_at`, optional channel/reference, and existing recipient names.
  This is route-stubbed local browser evidence only: no real delivery, provider,
  registry/DRE acceptance, legal sufficiency/effect, workflow completion, or
  legal/compliance completion claim is added.
- Current `82d3554` convocation reminder guidance routing checks: focused
  `npm run test --workspace apps/web -- DashboardPage.test.tsx
  notifications.test.ts AtaEditorStructured.test.tsx` passed 64 tests, `npm
  run build --workspace apps/web` passed, and `git diff --check` passed. The
  dashboard and notification actions for `open_act_convening_notice` /
  `act-convening-notice` now route to `/atas/{act-id}#convening-guidance`, and
  the Ata editor maps that stable hash to the existing convocatória/convening
  guidance card with a post-load scroll effect after async act data resolves.
  This is local workflow UI routing depth only: no backend route, contract,
  archive, legal authority, legal sufficiency, legal deadline computation,
  external delivery, workflow completion, registry/DRE/provider acceptance,
  legal effect, or legal/compliance completion claim is added.
- Prior `3dc31e3` missing-meeting-date convocation reminder checks: focused
  `cargo test -p chancela-api --locked convocation_notice`, `npm run test
  --workspace apps/web -- DashboardPage.test.tsx notifications.test.ts`, `npm
  run test --workspace apps/web -- i18n.test.ts`, `npm run build --workspace
  apps/web`, and `git diff --check` pin the API and web behavior for a statute
  convocation-notice day count when `meeting_date` is absent. The API dashboard
  now emits the same `act-convening-notice` local advisory route with blank
  `due_date`, blank `meeting_date`, blank `notice_due_date`,
  `evidence_status=missing_meeting_date`,
  `notice_due_date_computable=false`,
  `notice_due_date_blocked_by=missing_meeting_date`,
  `local_deadline_computed=false`, empty `law_refs`, and false no-claim params
  for legal sufficiency, legal deadline computation, external delivery,
  workflow completion, registry acceptance, DRE acceptance, and provider
  acceptance. Web dashboard and notification copy choose the
  missing-meeting-date body and state that the local notice due date cannot be
  computed until the meeting date is recorded; the existing recorded-meeting
  short/missing dispatch path still computes and displays `notice_due_date` as
  before. This is local advisory workflow/calendar depth only: no legal
  authority, legal sufficiency, compliance completion, external delivery,
  workflow completion, registry/DRE/provider acceptance, legal deadline
  computation, legal effect, or legal/compliance completion claim is added.
- Current `87ec6aa` convocation act-review guidance checks: focused
  `npm run test --workspace apps/web -- AtaEditorStructured.test.tsx
  CompliancePanel.test.tsx` passed 38 tests, `npm run build --workspace
  apps/web` passed with the existing ConfirmActionModal warnings, and `git diff
  --check HEAD~1 HEAD` passed. The Ata editor now shows compact local guidance
  when the recorded meeting date or convening dispatch/channel/antecedence/
  evidence reference is missing, and the CompliancePanel now shows next-record
  guidance for missing or below-threshold convocation-notice advisories. This is
  local WFL/legal-calendar usability depth only: no backend/dashboard contract
  change, legal sufficiency, compliance determination, delivery, workflow
  completion, registry, DRE/source-authority, provider, legal effect, or spec
  completion claim is implemented. Dashboard reminder due-date computation
  still depends on recorded `meeting_date`; missing-date dashboard reminders are
  non-computed local advisories.
- Current imported-document review reminder checks: focused `cargo test -p
  chancela-api --lib --locked imported_document_review_reminder` coverage pins
  metadata-only dashboard reminder emission for act-scoped imports whose review
  status is still `operator_review_required`, `ocr_review_required`, or
  `canonical_conversion_review_required`, while skipping global/unattached and
  terminally reviewed imports. Focused web tests in `DashboardPage.test.tsx`,
  `notifications.test.ts`, `AtaEditorStructured.test.tsx`, and
  `ActDocumentPanel.test.tsx` pin the dashboard/notification route to
  `/atas/{act_id}?imported_document_id={id}&focus=import-review#imported-documents`,
  act-page query parsing, and one-time selection/focus of the existing imported
  review form. This remains advisory workflow routing only: no OCR, conversion,
  PDF/A/PDF/UA generation, signed-import legal validation, dashboard review
  mutation, raw imported bytes, filenames, digests, notes, imported-by details,
  DGLAB/legal/provider/trust/GDPR completion, or compliance-completion claim is
  implemented.
- Current working-tree release workflow static-guard checks: `node
  scripts/check-release-trust.mjs self-test` pins the CI metadata lane
  release-trust self-test, SBOM package-linkage self-test, and package
  provenance fixture checks; the Docker no-push/local-load job with `local-ci`
  trust status, `--expect-mode local-ci`, and nested
  `releaseTrust.imagePublication/signing/notarization/attestation.status`
  context; and the release package job's package integrity check,
  `--require-clean-source`, `releaseTrust.mode = unsigned-dev`,
  `attestation.status = not_attested`, `--expect-mode unsigned-dev`, collected
  `--package` path validation, tarball basename/SHA-256 recomputation, and SBOM
  package linkage. Production package validation also requires `--manifest` when
  either package mode or expected mode is `production`, with self-tests covering
  those signals independently. `check-package-artifacts --require-clean-source`
  fails `dirty` and `unknown` source states. This is static workflow/package
  metadata assurance only; it does not add signing, notarization, attestation,
  registry publishing, reproducible-build proof, or production trust claims.
- Current `ef3270a` opt-in release-signing checks: reviewed
  `.github/workflows/release-signing.yml`,
  `scripts/release-signing-status.mjs`, and `docs/release-signing.md`. The
  workflow is manual/secret-gated and inert by default, can push/sign a target
  container image with cosign and attach a CycloneDX SBOM attestation only when
  the required target and identity are configured, can code-sign/notarize
  desktop artifacts only when platform credentials exist, and always uploads
  status artifacts recording unsigned/not-pushed/not-attested/not-notarized
  outcomes when evidence is absent. This is hook/status-artifact coverage only:
  it does not prove production signing success, secret availability, package
  trust certification, registry publication, or completed notarization.
- Current `f4047b5` observability checks: focused API coverage pins `/metrics`,
  `/livez`, `/readyz`, `/api/metrics`, `/api/livez`, `/api/readyz`,
  `x-request-id` echo/replacement, Prometheus text output, and matched route
  labels that avoid raw path IDs in metrics. `/metrics` is intentionally
  unauthenticated for scraper compatibility and must stay internal-network or
  allowlist protected. `/readyz` is degraded-mode readiness only and does not
  prove database, Redis, remote-signing, trust-list, or cluster dependency
  readiness. This is probe/metrics/tracing plumbing only, not production
  observability, SIEM, alerting, HA, retention, or compliance completion.
- Current `22bb23d` runtime HTTP/session hardening checks: focused API coverage
  pins `Strict-Transport-Security` on API/static responses,
  per-client-IP token-bucket 429 responses with `Retry-After`, liveness probe
  rate-limit exemption, absolute session lifetime cap rejection/eviction,
  reload/factory-reset cleanup of `session_issued_at` and `rate_limit_buckets`,
  and CurrentAttestor refusal/eviction before exposing an unlocked signing key
  for an over-age session. Server source markers also pin
  `into_make_service_with_connect_info::<SocketAddr>()` for real TCP peer IPs
  and the plaintext durable-SQLite warning. This is local in-memory single-node
  runtime HTTP/session hardening only, not TLS termination, production HSTS
  proof, cluster-wide/distributed rate limiting, HA, SQLCipher-at-rest proof,
  external deployment proof, legal/DR/security certification, or spec
  completion.
- Current working-tree seeded role drift diagnostic checks: focused
  `chancela-api` coverage pins read-only
  `seeded_role_drift.missing_default_permissions` and
  `requires_manual_review` on editable seeded roles, while preserving the
  customized persisted role permissions. Focused RBAC UI coverage renders the
  manual-review warning and missing-permission list. Focused route-stubbed
  browser proof is `npm run test:browser --workspace apps/web --
  e2e/seeded-role-drift.spec.ts`; it pins no initial reconciliation `POST`,
  explicit `Rever defaults` review `GET`, add-only/defaults UI for
  `platform.logs.write`, empty `{}` apply body, retained customized
  permissions, unchanged Owner/custom rows, and disabled review without
  `role.manage`. This is diagnostic and explicit-admin-apply evidence only; it
  does not auto-reconcile roles, grant permissions, or weaken authorization; it
  grants nothing on load and does not complete
  tenant/sync/ZK/archive/retention/compliance work.
- Current working-tree ROL-02 seeded role archetype checks: focused
  `cargo test -p chancela-authz --locked` pins the seeded catalog at 15 roles,
  preserving the stable Owner/Gestor/Signatário/Leitor/platform/tenant/auditor/
  guest/api-client ids while adding explicit Company Owner, Corporate Secretary,
  Legal Counsel, Records Manager, Signatory, and Reviewer ids. New archetype
  permission tests pin explicit permission arrays and deny meta/delegation,
  `user.manage`, `settings.manage`, `platform.logs.write`, `ledger.recover`,
  `data.wipe`, and `data.start_over`. Focused API coverage is
  `cargo test -p chancela-api --locked seeded_role`, proving missing seeded
  roles insert without clobbering customized seeded API Client/non-Owner roles.
  This is local RBAC seed/default coverage only; it does not prove legal
  capacity, tenant/group policy, HR authority, access-policy certification,
  sync/ZK, retention/disposal, or encryption completion.
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
- Recent `7ab3ab7` automated-review law corpus UI checks: focused API,
  contract, and web markers pin `DashboardLawReference.review_method` /
  `review_note`, `law_verification_wire` emitting the `automated_review` serde
  wire value, `LawSourceView` review metadata, per-diploma
  `automated_review_count`, contract fixtures where automated-review articles
  keep real body text and `verified === false`, and Legislação rendering with a
  separate info-toned automated-review badge, help caveat, non-Pending article
  body display, and localized automated-review label/caveat copy. The underlying
  UI implementation landed in `72df5c0`; `7ab3ab7` pins the focused badge/caveat
  assertions. This is honest
  automated-review provenance surfacing only: no human legal approval,
  Pending-to-Verified promotion, DRE authority verification, legal correctness,
  dashboard legal guidance completion, or legal validity/effect claim is
  implemented or proven.
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
- Current working-tree synthetic seed dataset integration checks: focused
  `cargo test -p chancela-api --test seed_dataset --locked` coverage builds a
  fictional dev/test dataset through the real API router and validates entity,
  book, act lifecycle, sealed-document readback, ledger integrity, dashboard
  aggregate, scoped RBAC, active delegation, deterministic-shape, scale-up, and
  SQLite backup/restore fixity evidence. The ignored feature-gated Postgres
  lane reuses the same validation shape only when a live `DATABASE_URL` is
  supplied. This is synthetic integration test evidence only; it is not
  production seed data, external-provider coverage, legal-validity proof,
  legal-capacity proof, production backup-policy certification,
  RBAC/delegation completion, broad dashboard/business completeness, or spec
  completion.
- Current working-tree RBAC ledger verification regression checks: focused
  `cargo test -p chancela-api --test api-records --locked -- rbac_ledger_verify` coverage
  drives user-role assignment/unassignment, delegation grant/revoke, and role
  catalog create/update/delete paths through the real API router, then verifies
  `/v1/ledger/verify`, `/v1/ledger/integrity`, direct `Ledger::verify()`, shared
  `application` audit-chain scoping, and no accidental `company:` chain minting
  for RBAC audit events. This is focused regression coverage only; it is not
  full RBAC/delegation-policy completion, tenant authorization proof,
  legal-capacity verification, broad security certification, or spec
  completion.
- Current `35ddb1f` wp23 template-authoring groundwork checks: focused
  package and web gates passed with
  `cargo test -p chancela-templates --locked`,
  `cargo test -p chancela-authz --locked`,
  `cargo test -p chancela-api --locked`,
  `cargo test -p chancela-server --features e2e --locked --test e2e_contracts`,
  `npm run build --workspace apps/web`,
  `npm run test --workspace apps/web -- src/i18n/i18n.test.ts src/contracts/contracts.test.ts src/features/templates/TemplatesCatalogPage.test.tsx src/features/documents/ActDocumentPanel.test.tsx`,
  `cargo fmt --all -- --check`, and `git diff --check`. These pin
  `user_templates` document-row CRUD, `template.manage` permission coverage,
  strict `validate_user_template` authoring validation with nested
  unknown-field rejection, user-template API create/update/delete,
  export/import, merged built-in plus user catalog summaries, refreshed
  `TemplateSummary` / `TemplateImportVerdict` / `template.export.json`
  contracts, client/hooks, 14-locale i18n key coverage, and the Minutas
  user-template editor/import dialog/catalog actions, and composed-server
  contract E2E wiring for `template.summary`, `template.import-verdict`, and
  `template.export` fixtures. The `fae8fd7` commit in this stack is
  locale-only; the API and contract implementation comes from the preceding
  wp23 commits, `2530693` adds the UI layer, and `35ddb1f` adds server E2E
  fixture wiring. This is authoring infrastructure only and does not complete
  the template catalog, replace legal review, verify thresholds or law
  references, certify provider/registry/DRE behavior, claim production
  Postgres CI, or move the spec matrix beyond `PARTIAL=11`.
- Current `628b613` full ignored Postgres store sweep checks: local
  Docker/Postgres validation passed targeted logical restore, persist/reload,
  and runtime store tests, then passed
  `cargo test -p chancela-store --features postgres --locked --test postgres_backend -- --ignored --test-threads=1`
  with the full ignored `postgres_backend` suite at `10 passed`, followed by
  `cargo fmt -p chancela-store -- --check` and `git diff --check`. The
  implementation creates a per-test child database from `DATABASE_URL`, points
  each ignored store-backend test at that child URL, and drops the child
  database during cleanup so successful sweeps leave no per-test child DBs
  behind. It also fixes logical restore row insertion by casting exported JSON
  text through `$1::text::jsonb` before `jsonb_populate_record`. This is store
  backend live Postgres coverage only: it does not broaden default CI beyond
  the targeted `71fc536` store runtime lane, does not add API Postgres CI, and
  does not claim production Postgres readiness, live `verify-full` CA/hostname
  proof, production TLS readiness, HA readiness, migration completeness, RPO/RTO certification, split-brain prevention,
  failover certification, legal/DR certification, or spec completion.
- Current Postgres TLS checks supersede the older opportunistic-TLS checkpoint.
  Source markers pin `CHANCELA_PG_SSLMODE` precedence over `DATABASE_URL`,
  default `verify-full`, rejection of `disable`/`prefer`/`require`,
  `verify-ca` hardening to verify-full, and fail-closed root loading. CI creates
  an ephemeral CA and hostname-valid server certificate, verifies PostgreSQL
  with `psql sslmode=verify-full`, and runs the ignored live store test
  `sslmode_verify_full_opens_and_roundtrips_on_postgres`. This proves the CI
  connector/CA/hostname path, not production CA custody, remote-Postgres
  readiness, HA/failover, migration completeness, RPO/RTO, or legal/DR
  certification.
- Current `03784e5` hardened Docker checks: reviewed
  `Dockerfile.hardened`, `docker-compose.hardened.yml`, and
  `docs/security/hardened-docker.md`, then validated
  `git diff --check 5f0281e..HEAD -- Dockerfile.hardened docker-compose.hardened.yml docs/security/hardened-docker.md`,
  `docker compose -f docker-compose.hardened.yml --profile single-node config --quiet`,
  `docker compose -f docker-compose.hardened.yml --profile postgres config --quiet`
  with ignored temporary secret files removed afterward, and
  `docker build -f Dockerfile.hardened --check .`. This pins the additive
  hardened image/compose/operations-documentation lane only: no full image build,
  production-readiness, TLS/key-custody, vulnerability-free scan, SBOM,
  signature/attestation, HA/failover/RPO/RTO, legal/DR certification, cloud
  deployment readiness, or spec-completion claim is made.
- Current checkpoint metadata/static checks through `baf9f41`
  bounded slice markers passed: `node
  --check scripts/checkpoint-recent-landed.mjs`, `npm run
  test:checkpoint:recent-landed:static`, `npm run check:spec-coverage`, and
  `git diff --check -- SPEC-COVERAGE.md docs/CI-CHECKPOINTS.md
  docs/CI-E2E-HARDENING-PLAN.md scripts/checkpoint-recent-landed.mjs
  scripts/check-spec-coverage.mjs`.
  These pin the spec snapshot,
  hardening-plan head, LOTL/member-state bootstrap markers, mobile API base
  URL/shell-detection markers, subject DEK
  secret-store binding markers, opt-in
  release signing hooks/status artifacts, Postgres
  rustls TLS `sslmode=verify-full` CI proof and no-production-readiness
  boundary, observability `/metrics`/`/livez`/`/readyz` request-id/route-label
  markers, runtime HSTS, single-node in-memory rate-limiting, absolute session
  lifetime, reset/reload cleanup, and CurrentAttestor cap markers, MCP
  document/archive PDF accessibility v12 identifiers
  and counts, `pdf_accessibility_v12_summary`, `v12_report_count`,
  `pdf_accessibility_v12_report_missing`, fixture report version 12,
  browser workflow provenance review panel and sanitized local MCP payload
  markers, generated-document coverage fixture alignment,
  CI coverage-waiver static debt guard, backend-only SCAP-backed local PKCS#12
  `scap_capacity_evidence` persistence, `not_checked_by_scap` fallback,
  preprod/mock `declared_capacity_by_provider`, prod-fixture
  `verified_by_scap`, mismatched declared-capacity 422 refusal, local
  `Granted` fixture boundaries, no live SCAP credentials/network proof, no UI
  picker rollout, and no legal-capacity/full-spec completion claim,
  wp23 user-template authoring groundwork markers for `user_templates` store
  CRUD, `template.manage`, strict `validate_user_template` unknown-field
  rejection, user-template CRUD/export/import routes, merged catalog contracts,
  `TemplateSummary`, `TemplateImportVerdict`, `template.export.json`, web
  client/hooks, i18n locale-key coverage, TemplateEditorForm,
  TemplateImportDialog, catalog create/edit/import/export/delete UI actions,
  and e2e_contracts template summary/import-verdict/export fixture markers,
  real-backend generated-convening dispatch-evidence
  browser proof, focused composed-server generated-convening E2E evidence,
  generated-convening dispatch evidence metadata-only
  generated-document recording, convening recipient contact metadata, route-stubbed
  convening dispatch browser proof, convening dispatch evidence capture,
  convocation
  reminder guidance routing, convocation act-review guidance, convocation-notice
  advisory reminders, dashboard annual
  reminder localization, automated-review
  dashboard contract surfacing, Arquivo advanced-filter count badge,
  all-filtered archive export streaming/cap scope, MCP meeting
  metadata extraction review resource, PDF table-structure semantics, export save-prompt
  routing, dashboard dates tab, notification footer icon-only action, and
  clarified platform operations UI, user/signatory email capture, and compact
  Data Management cleanup controls, platform-log cleanup target/row markers,
  retained-export dry-run planning with
  `would_delete_*`/zero-`deleted_*` counters and preview-only no-files-removed
  Settings payload markers, retained-export preview-token/manifest-gated
  execution markers with `deleted_*` result counters and no deletion outside the
  bounded server-selected manifest, plus SettingsPage/i18n trust-source
  provider markers, trust-accepted-hash/Registos TSA grouping, decorative
  page-break accounting, export-save cancellation, dashboard desktop-six
  density, SQLite logical table payload markers, browser dynamic-import gate
  markers, web SQLite table-usage rows, keyed VRI `/TU` evidence markers,
  compact notification/bell badge assertions, and entity filter nowrap/mobile
  wrap markers, compact template filter markers, structured book termo signatory
  markers, DPIA/breach/transfer privacy-control review reminder dashboard and
  browser markers under `workflow.reminders.sources.privacy_control_reviews`,
  retention execution review-queue and review-closure markers, retention due-candidate
  bounded archive/no-action evidence and explicit evidence-state markers,
  backend database-encryption
  key-source/hardware-fallback markers, key-custody readiness UI/contract
  markers for `persistence.database_encryption` SQLCipher availability,
  keyed-store state, key source, fail-closed hardware fallback, database format,
  key-ops plan, plaintext migration pending/blocked flags, migration-plan
  summary/steps, readiness gaps, and no key/hash/fingerprint/env-secret/
  production-custody/legal-GDPR claim boundaries, data key-rotation receipt
  history markers for the bounded receipt file, `/v1/data/status` projection,
  contract fixture, Data Management rendering, no-secret/no-path/no-fingerprint
  false flags, and no-success-receipt forbidden/plaintext refusal paths, and PDF verifier DSS/VRI `/TU` plus
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
  plus PDF accessibility JSON version 12, deterministic `pdf_ua_blocker_delta`,
  gated `pdf_ua_claimed` true/false paths, cleared/remaining blocker counts,
  scoped table-header evidence,
  structural-depth evidence, structure-tree diagnostics, explicit role-map
  target entries,
  marked-content coverage counts, writer-owned marked-artifact accounting,
  bounded topology self-check, PDF/UA-1 XMP/self-check gate markers,
  no-DGLAB/no-legal/no-universal-PDF/UA markers, plus all-family
  agenda-item template IDs/counts/rendering markers,
  CSC quota template IDs/Pending-law-reference markers, CSC
  delegation/revocation template IDs/rendering/no-new-threshold markers, and
  CSC structural-change template IDs/Pending-law-reference/local-rendering
  markers, and
  post-act `Certidao`/`Extrato` sealed-provenance semantic lint markers,
  Postgres store runtime/logical recovery source/test markers,
  local advisory-lock cluster write-gate and fail-closed promotion handoff
  markers, full ignored `postgres_backend` 10-test local Docker/Postgres sweep
  proof, per-test child database isolation and cleanup markers,
  `$1::text::jsonb` logical restore binding markers, SQLite-default
  feature/config-gated backend selector markers, and
  no-production-readiness/API-Postgres-CI/HA-readiness caveats,
  delegation legal-basis requirement, trimmed storage, legacy missing-basis
  display, compliance-panel `legal_basis` internal Legislação corpus deep links,
  and no legal/HR/SCAP/access-policy certification or legal-verification
  upgrade caveats,
  deterministic local template law-reference corpus audit markers for embedded
  registry/corpus coverage, Verified/Pending preservation, unresolved Pending
  references, legal-threshold blockers, no network/provider/legal-service
  calls, no DRE/EUR-Lex verification claim, no threshold value completion, and
  no Pending-to-Verified upgrade,
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
  static guard, clean-source provenance gate, package tarball trust binding, and production-package manifest-required
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
  encrypted provider-credential entry storage and management UI markers for
  sidecar plaintext absence, entry-bound AEAD authentication, write-only create
  and response payloads, Settings priority/reorder/enable/delete controls,
  stored CMD/CSC runtime resolution, stored SCAP prod resolution, stored-only
  PKCS#12 priority/failover and wrong-identity fail-safe markers, plus
  `chancela-signing` repeated remote-session helper/types/tests for per-document
  `RemoteSigningSource` initiate/confirm activation and API/UI
  `POST /v1/signature/remote/{provider}/batch-initiate` markers for
  per-document pending-session initiation, `per_document_activation`,
  duplicate/over-cap no-pending-row guards, redacted per-document errors, and
  no credential echo, plus pending-session provider identity bridge markers for
  additive `GET /v1/acts/{id}/signature` provider metadata and reload
  CMD/CSC-QTSP confirm routing, including route-stubbed Playwright browser
  proof for reload adoption/routing only plus route-stubbed remote
  batch-initiate browser proof for per-document pending rows without credential
  echo, plus ASiC inspect
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
  markers, plus generated-document by-id route, absent-owner/generated-convening dispatch-evidence
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
  plus the dedicated `FilterClear` glyph/no-close-icon regression markers, with
  canonical-only PDF/A evidence boundaries, plus the route-stubbed
  `apps/web/e2e/ledger-archive-boundedness.spec.ts` browser proof for bounded
  first-page rendering, cursor request serialization, filtered `limit=50`
  query serialization, archive-document export without `before_seq`, and no
  all-record/certification/signature/ledger-mutation claim.

Full workspace format/clippy should be rerun before commit. The prior
`paper_import.rs` compile blocker, retention dead-code warning set, TSL `record`
compile break, external-signing route-classification blocker, document-import
dead-code warning, and `/api` namespace route-classification miss have been
cleared.
