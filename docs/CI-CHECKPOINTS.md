# CI Checkpoints

## Spec Coverage Status

`npm run check:spec-coverage` parses `SPEC-COVERAGE.md` and fails if the
top-level spec table no longer covers all 11 spec documents, uses an unknown
status, loses the implementation snapshot marker, points it at a non-local
commit, lets snapshot/checkpoint markers drift from the declared implementation snapshot,
lets a non-checkpoint HEAD or commit chain claim an older snapshot, or drops the required
blocker and "Do Not Overstate" boundary sections. Use
`node scripts/check-spec-coverage.mjs --json` when a machine-readable summary is
needed for release notes or an operator review packet.

This is an honesty gate for the implementation tracker. It does not certify
legal completeness, external-provider readiness, or spec completion.

## Live Provider Assurance

`npm run check:live-provider-assurance` is a cheap static guard for the live CMD,
CSC/QTSP, TSA, and smartcard seams. It checks that the live-provider test files
keep their top-level feature gates, `#[ignore]` manual-test markers, no-CI and
credential/operator boundary copy, and that CI still compiles those seams with
`cargo test ... --no-run`.

This is static/compile-time assurance only. It does not use credentials, make
network calls, touch card readers, or run live tests, and it does not prove live
provider validity or authority approval.

## Recent Landed Areas

`npm run test:checkpoint:recent-landed` is a focused local and CI guard for
recently landed work that crosses Rust API tests, data key preflight guards,
guardrail acknowledgements, written-resolution evidence status binding and
browser receipt proof, trust
parsing, declared signer-capacity evidence preservation, live-provider static
assurance, MCP resource/prompt coverage including workflow provenance review
guidance, draft-vs-signed comparison review guidance, and the
`chancela://mcp/meeting-metadata-extraction-review` local review aid over
caller-supplied meeting JSON/text metadata, the bounded local
provenance panel with deterministic local counts, no bridge/API/AI-provider/hidden-provider
calls, no raw text/contact/secret/access-code echo, no secrets, and false legal/source/workflow/provider/trust/external/signature-qualification
flags, web fixtures, ASiC
inspect `technical_validation` and structural diagnostic markers, registry chronology
graph markers, sealed-act chronology projection markers for local sealed/archived
acts, provenance, retification edges, and false no-claim flags, PDF writer spacing
and PDF/UA blocker-decomposition markers,
archive timestamp append markers, raw-byte per-book import preflight markers for
no-mutation operator previews,
paper-book OCR API/UI markers including accepted OCR draft to mutable draft-act
creation, reviewed conversion execution artifacts, conversion-dossier binding,
and focused paper-book OCR review browser workflow markers,
retention explicit evidence-state markers (`review_queued`, `blocked`,
`bounded_archive_recorded`, `bounded_no_action_recorded`,
`prior_bounded_evidence_available`), duplicate review-only request guards,
queued-review status surfacing, prior bounded execution suppression, and eligible
bounded archive/no-action evidence UI, plus active/suppressed candidate counts
and suppression-summary copy for safe bounded evidence omissions, retention
review-closure route/client/contract/Settings/browser markers with separate
closure fields and false mutation flags,
retained-export cleanup preview-token/manifest gating, compliance legal-basis
internal Legislação corpus deep links, forwarded platform-log sanitized
accepted/denied/rejected/suppressed audit markers, the first-class
`template_catalog_metadata_lint` command for post-act template
sealed-provenance lint, all-family standalone agenda-item templates,
recovery/document/dashboard/notification
UI, dashboard guest recent-events redaction, Ferramentas external-validator
metadata UI, raw-report byte download API, imported-document review receipt UI,
imported-document review dashboard reminder/deep-link routing,
web shell accessibility/focus markers for the skip link to `#main-content`,
route-change main landmark focus, route-crash `main#main-content`
preservation, PageHeader h1 rendering, and modal focus-trap behavior,
password-required account creation/session static markers,
trust identifier-match explanations, trust/import/static request-boundary
hardening, and read-only local DGLAB interchange
manifest API and BookDetail JSON-download markers, generated-document by-id
download route plus sealed post-act certidao/extrato template generation UI,
absent-owner communication dispatch-evidence recording, and generated
absent-owner evidence UI and dashboard absent-owner dispatch-evidence reminders,
compact validator-report actions, template provenance UI, release clean-source
provenance gating, local CC batch-signing UI markers for BatchSigningPanel,
`useCcBatchSign`, `POST /v1/signature/cc/batch-sign`, optional transient PIN
clearing/no-storage, per-document results, auth-mode reporting, declared
signer-capacity evidence display, local-CC-only no-claim boundary copy, and
focused route-stubbed Playwright proof in
`apps/web/e2e/local-cc-batch-signing.spec.ts` for the mounted
local/co-located Cartao de Cidadao batch-signing UI, optional transient PIN
request/clear/no-storage behavior, blank PIN omission, per-document results,
server-returned `single_auth` or `per_document_auth` accounting, declared
signer-capacity evidence, and the no-live-provider route boundary. This is
local CC batch UI evidence only and route-stubbed local browser proof only:
no live Autenticacao.gov/CC middleware, card reader, PKCS#11, hardware, CMD,
CSC/QTSP, SCAP, TSA/TSL, or provider execution; no live CC batch signing,
qualified batch signing, legal/qualified/provider-certified batch,
provider-certified remote batch, single OTP/PIN/SAD authorization for multiple
remote documents, CMD multiple-sign, CSC/QTSP multi-hash/SAD batch,
SCAP-verified representative authority, legal-capacity proof,
trust-list/provider validation, legal validity/effect/sufficiency, or act
finalization/legal signing acceptance,
encrypted provider-credential entry storage and Settings management markers for
CMD, CSC/QTSP, SCAP, and local PKCS#12, including write-only secret responses,
sidecar plaintext absence, entry-bound AEAD authentication, priority/reorder/
enable/delete flows, strict non-confidential-store blocking, stored CMD/CSC
runtime credential resolution, stored SCAP prod resolution, stored-only PKCS#12
priority/failover and wrong-identity fail-safe markers,
manual-signature original-reference metadata markers for core required-before-mutation
and immutable seal metadata coverage, API guest/minimal redaction coverage,
focused Ata editor manual seal validation tests, `act.sealed` contract coverage,
and focused Playwright browser coverage in
`apps/web/e2e/manual-signature-original-reference.spec.ts` plus the shared seal
helper for requiring, capturing, and preserving `manual_signature_original_reference`.
This is validation/redaction-backed custody metadata only: no qualified/eIDAS/legal
signature validity, provider-backed signing, PAdES/PDF-A certification, or legal
archive certification,
`chancela-signing` core repeated per-document remote-session orchestration
markers for `RemoteSigningSource` initiate/confirm one-digest flow,
per-document activation, helper/types/tests, API/UI
`POST /v1/signature/remote/{provider}/batch-initiate` markers for
per-document pending-session initiation, `per_document_activation`, redacted
per-document errors, duplicate/over-cap no-pending-row guards, and no
credential echo, with no provider-certified remote batch / provider-native
multi-document authorization / single OTP/PIN/SAD / CMD multiple-sign /
CSC/QTSP multi-hash/SAD / SCAP/legal-capacity claim,
pending-session provider identity bridge markers for additive
`GET /v1/acts/{id}/signature` metadata (`provider_id`, `family`, and optional
`activation_hint`) plus web reload adoption routing to the dedicated CMD
confirm path or generic CSC/QTSP remote confirm path, including the focused
route-stubbed browser proof
`apps/web/e2e/remote-signing-pending-session.spec.ts`,
seeded role drift diagnostics, archive readability/ZK caveat
metadata, template family/channel rule guards, MCP trust-catalog filter
discoverability, redacted external-validator report summary tools, external
invite signed-PDF technical evidence markers including linked no-identity slot
completion, identity-required refusal, replay idempotency, upload body limits,
i18n leakage guards, external-signing stored slot evidence rendering,
operator technical evidence form submission, identity-requirement-tagged
evidence rows, `PATCH` slot payloads that omit `complete:true`, validator
fixtures, off-by-default Postgres store runtime write/read markers, Postgres
logical backup/restore/recovery source and test markers, local advisory-lock
cluster write-gate and fail-closed promotion handoff markers, ignored
`DATABASE_URL` live tests, and remaining `UnsupportedOnPostgres` per-book
portability plus `restore_preflight` boundaries, SQLite-default
feature/config-gated database backend selection markers, and the standalone
desktop Cargo workspace.

The synthetic seed dataset integration markers prove that
`cargo test -p chancela-api --test seed_dataset --locked` builds a fictional
dev/test dataset only through the real in-process API router, then validates
entity, book, act lifecycle, sealed-document readback, ledger integrity,
dashboard aggregate, scoped RBAC, active delegation, deterministic-shape,
scale-up, and SQLite backup/restore fixity evidence. The feature-gated ignored
Postgres lane reuses the same validation shape only when a live `DATABASE_URL`
is supplied. These markers do not seed production data, use real records, call
external providers, prove legal validity or legal capacity, certify dashboard
or backup-policy completeness, complete RBAC/delegation policy, or make any
spec area complete.

The RBAC ledger verification regression markers prove that `cargo test -p
chancela-api --test rbac_ledger_verify --locked` drives user-role assignment
and unassignment, delegation grant and revoke, and role-catalog
create/update/delete mutations through the real in-process API router, then
asserts `GET /v1/ledger/verify`, `GET /v1/ledger/integrity`, direct
`Ledger::verify()`, shared `application` audit-chain scoping, and no spurious
`company:` chains after RBAC audit events. These markers are focused
ledger-integrity regression coverage only. They do not complete RBAC,
delegation policy, tenant authorization, legal-capacity validation, broad
security certification, or any spec area.

The Postgres store, backend-selection, logical recovery, and local
advisory-lock/fail-closed cluster write gate and promotion handoff markers prove
source/test coverage for the off-by-default backend runtime paths, API/server
selector, app-level logical backup/restore/recovery paths, pre-append
write-gate refusal, promotion handoff reloading/re-verification, and HTTP 503
`NotLeader` mapping only. The `bac4337` data-status refresh reports the active
durable backend family and sidecar storage mode, adds backend-neutral logical
payload and DB-backed sidecar telemetry labels where sidecars are database-backed,
and preserves SQLite-specific rows for compatibility. SQLite remains the
default backend; Postgres selection is feature/config gated through
`CHANCELA_DB_BACKEND=postgres` plus
exactly one `DATABASE_URL` or `DATABASE_URL_FILE` source; default CI still does
not run against a live Postgres database, and live PG election/failover tests
remain ignored unless `DATABASE_URL` points at a throwaway database. They do
not prove file-to-DB sidecar migration, backup/restore execution, production
Postgres readiness, live DB validation, migration completeness, production HA
readiness, consensus correctness, split-brain impossibility, live failover
certification, cloud deployment readiness, TLS/remote PG readiness, multi-node
operational certification, backup-policy/RPO/RTO certification, destructive
operation safety, legal/DR certification, external service dependency, or external sync
readiness.

It intentionally reuses existing test surfaces:

- API paper import: `cargo test -p chancela-api --test paper_import --locked`
  including the non-canonical canonical-conversion preflight guard and
  operator-configured local OCR run coverage, plus the accepted OCR draft to
  mutable draft-act endpoint, `conversion_execution_artifact` response/store
  binding, optional dossier binding, and refusal cases. Focused Playwright
  coverage for the non-canonical paper-book OCR review workflow is pinned
  statically here and executed in browser jobs.
- Store and contract paper-book conversion artifacts:
  `cargo test -p chancela-store --test store --locked paper_book_ocr_conversion`
  and
  `npm run test --workspace apps/web -- src/contracts/contracts.test.ts` pin the
  v14 `paper_book_ocr_conversion_execution_artifacts` table, idempotent
  import/draft/target-act binding, canonical-draft response artifact shape, and
  dossier `conversion_execution_artifacts` shape.
- API archive package and `/DocTimeStamp` evidence:
  `cargo test -p chancela-api --test archive_package --locked`
  including the read-only local DGLAB interchange manifest endpoint and
  `book.export@Book` gate.
- API per-book import preflight:
  `cargo test -p chancela-api --locked books_import_preflight`
  including raw-byte `POST /v1/books/import/preflight?policy=...`, current
  pre-import evidence/collision preview, no `import_id`, no `ledger.imported`,
  no `imported_books`, and no retained imported bundle bytes.
- Archive readability/ZK caveat metadata:
  `cargo test -p chancela-archive --locked readability_caveat`
  including manifest-only defaults, old v1 conservative defaults, unknown-field
  refusal, and false overclaim flags.
- Web BookDetail local DGLAB JSON download:
  `npm run test --workspace apps/web -- src/features/books/books.test.tsx`
  including the direct `GET /v1/books/{id}/archive/local-dglab-interchange-manifest`
  call, `.json` save behavior, and no ZIP/export/archive mutation.
- Web BookDetail paper-book conversion evidence:
  `npm run test --workspace apps/web -- src/features/books/books.test.tsx`
  also pins reviewed conversion execution evidence rendering, dossier-bound
  `conversion_execution_artifacts`, raw OCR text hiding, no-claim flags, and no
  document/signature/seal/archive calls from that UI.
- API external-validator report metadata, including raw metadata and raw-report
  byte downloads:
  `cargo test -p chancela-api --locked external_validator_report_metadata`
- Live-provider assurance static gate:
  `npm run check:live-provider-assurance`
- API local PKCS#12 signing:
  `cargo test -p chancela-api --test local_pkcs12_signing --locked`
- API stored CMD/CSC runtime resolution and remote batch initiation:
  `cargo test -p chancela-api --test remote_signing --locked` including
  stored CSC service/access-token runtime credentials, stored CMD
  batch-initiate configuration, per-document pending-session creation,
  invalid-act isolation, duplicate/over-cap no-pending-row guards, and
  signing-permission refusal before provider calls.
- API stored SCAP prod runtime credential resolution:
  `cargo test -p chancela-api --test scap --locked` including stored-over-env
  prod credentials, incomplete/disabled stored credential fail-closed behavior,
  and preprod mock behavior that ignores stored SCAP credentials and never
  verifies legal capacity.
- Web remote batch and provider credential management unit proof:
  `npm run test --workspace apps/web -- src/api/client.test.ts
  src/features/signing/SigningPanel.test.tsx` pins the encoded
  `POST /v1/signature/remote/{provider}/batch-initiate` client route,
  per-document pending/error rows without credential echo, stale-result
  clearing, and provider-bound credential clearing. The provider credential UI
  unit proof is `npm run test --workspace apps/web --
  src/features/settings/ProviderCredentialsSection.test.tsx`.
- API bounded retention execution:
  `cargo test -p chancela-api --test privacy --locked retention_`
  including explicit non-destructive evidence states, due-candidate prior
  bounded archive/no-action suppression, active `candidate_count`,
  `suppressed_candidate_count`, `suppressed_by_bounded_evidence_count`,
  optional `suppression_summary`, bounded archive/no-action
  `execute_supported` records, safe internal evidence gating, non-mutating GET
  behavior, queryable execution history without a persisted `resolved` flag, and
  review-closure coverage for `POST
  /v1/privacy/retention-executions/{id}/review-closure`: idempotent same
  closure, conflict on different closure evidence, outcome-category decision
  mapping, persistence, authorization/unknown-field/overclaim rejection, and
  due-candidate reads that stay non-mutating after closure.
- API dashboard guest event redaction:
  `cargo test -p chancela-api --locked dashboard_recent_events_redacts_guest_feed_but_keeps_owner_and_reader_feed`
  including guest `recent_events: []`, retained Owner/Leitor recent events, and
  continued guest denial from `/v1/ledger/events`.
- API generated-document by-id downloads, sealed post-act template generation
  UI, absent-owner dispatch evidence, and
  dashboard reminders:
  `cargo test -p chancela-api --locked on_demand_generate_persists_a_chosen_document_and_emits_the_event`
  and
  `cargo test -p chancela-api --locked in_memory_generated_document_download_uses_returned_url_and_keeps_canonical_ata`
  plus
  `cargo test -p chancela-server --test e2e_act_document_persistence --locked condominium_absent_owner_communication_auto_generates_and_keeps_canonical_ata`
  plus
  `cargo test -p chancela-api --locked absent_owner_dispatch_evidence_`
  plus
  `cargo test -p chancela-store --test store --locked generated_document_dispatch_evidence`
  plus
  `cargo test -p chancela-api --test archive_package --locked archive_package_indexes_generated_absent_owner_dispatch_evidence_metadata_only`
  plus
  `cargo test -p chancela-api --locked document_bundle_indexes_generated_absent_owner_dispatch_evidence_without_replacing_ata`
  plus the `cargo test -p chancela-api --locked reminder_` lane for
  `reminder_generated_absent_owner_dispatch_evidence_required_pending_routes_to_act_document_workflow`,
  `reminder_generated_absent_owner_dispatch_evidence_partial_routes_to_act_document_workflow`,
  `reminder_generated_absent_owner_dispatch_evidence_covered_is_suppressed`,
  and
  `reminder_generated_absent_owner_no_due_date_does_not_evict_dated_reminders_before_limit`
  plus route-classification coverage for
  `/v1/documents/generated/{document_id}` as a gated `act.read` route while the
  canonical `/v1/acts/{act_id}/document` endpoint remains the sealed Ata path,
  including automatic `condominio-comunicacao-ausentes/v1` generation after
  condominium seal with absent attendees, and `POST`/`GET`
  `/v1/documents/generated/{document_id}/dispatch-evidence` as gated
  operator-supplied evidence recording. The markers pin the separate
  `generated_document_dispatch_evidence` store table, exact-retry idempotency
  without a duplicate ledger event, selected absent-recipient evidence coverage,
  evidence-attached/status headers, `x-chancela-dispatch-completed=false`, and
  the `absent_owner_communication.dispatch_evidence_recorded` false/no-claim
  flags. Document-bundle markers pin
  `validation_report.evidence_index.generated_dispatch_evidence` while the
  bundle `document` and canonical download remain the sealed Ata. Archive
  package markers pin metadata-only `EvidenceReport` JSON sidecars at
  `evidence/generated-dispatch/{document_id}.json`, `evidence/index.json`
  references, `act_id` without `document_id` on sidecar manifest entries, and
  no promotion into top-level/canonical `manifest.document_ids`. Preservation
  markers pin safe status/coverage/recipient/channel/reference/evidence
  locator/imported-document/timestamp fields; exclusion of `operator_note`,
  `idempotency_key`, note-derived stable fingerprints, generated communication
  bytes, and imported proof bytes; and false `proof_bytes_included`,
  `bytes_included`, `operator_note_included`, `dispatch_completed`,
  legal-notice/legal-sufficiency, provider, registry, DGLAB, and legal-archive
  acceptance flags. Web/UI markers pin `listGeneratedDocuments`,
  `getGeneratedDocumentDispatchEvidence`,
  `recordGeneratedDocumentDispatchEvidence`, `generateActDocument`,
  sealed post-act `Certidao`/`Extrato` template discovery and
  generation/download, generated absent-owner communication listing, generated
  PDF fetch, stored evidence rows, metadata-only evidence form submission,
  `operator_evidence_*` statuses, `documents.generated.noClaim.*` copy,
  dispatch-evidence scope remaining limited to
  `condominio-comunicacao-ausentes/v1`, generated-document deep-link
  `generated_document_id`, `focus=dispatch-evidence`,
  `#generated-dispatch-evidence`, `actDocumentPanelTargetFromLocation`, one-time
  dispatch-evidence selection/focus, and no send/delivery/legal-notice or
  dispatch-completion copy. Focused Playwright browser proof is guarded by
  `apps/web/e2e/absent-owner-dispatch-evidence.spec.ts` and pins the advisory
  dashboard reminder route into the generated-document dispatch-evidence form,
  generated `condominio-comunicacao-ausentes/v1` visibility and download,
  metadata-only evidence recording, resulting operator evidence row display,
  and no send/delivery/legal-notice completion claims. Dashboard markers pin `source_rule`
  `absent-owner-dispatch-evidence`, `source_profile`
  `condominium-generated-communication`, action kind
  `open_absent_owner_dispatch_evidence`, no-date `Pending`/`Advisory`
  semantics,
  `/atas/{act_id}?generated_document_id={document_id}&focus=dispatch-evidence#generated-dispatch-evidence`
  routing from dashboard reminders and notification popup actions,
  `/v1/documents/generated/{document_id}/dispatch-evidence` API hrefs,
  `operator_evidence_covered` suppression, dated-before-no-date
  `dashboard_limit` sorting, and the `contracts/dashboard.json` no-date
  fixture.
- API synthetic seed dataset integration:
  `cargo test -p chancela-api --test seed_dataset --locked` including
  API-created synthetic entities, books, act lifecycle rows, structured
  attendance/deliberations/convening evidence, sealed document readback, ledger
  verification/integrity, dashboard aggregate readback, scoped RBAC,
  delegation resolution, deterministic-shape/scale checks, and SQLite
  backup/restore fixity. The ignored Postgres variant is live-DB gated and is
  not default CI evidence.
- API RBAC ledger verification:
  `cargo test -p chancela-api --test rbac_ledger_verify --locked` including
  role assignment/unassignment, delegation grant/revoke, role-catalog mutation,
  `/v1/ledger/verify`, `/v1/ledger/integrity`, direct `Ledger::verify()`,
  application-chain audit scoping, and no accidental `company:` chain for RBAC
  audit events.
- API and web privacy control review reminders:
  `cargo test -p chancela-api --locked privacy_control_review_reminders_cover_missing_overdue_and_source_toggle`
  plus the focused web unit lane for
  `apps/web/src/features/dashboard/DashboardPage.test.tsx` and
  `apps/web/src/features/settings/SettingsPage.test.tsx`. Focused
  route-stubbed browser proof is guarded by
  `apps/web/e2e/privacy-control-review-reminders.spec.ts` and pins Settings >
  Privacidade rendering for breach/transfer/DPIA advisory review fixtures,
  local review badges/no-claim copy, dashboard work-queue reminders for
  `privacy-breach-playbook-review` and `privacy-transfer-control-review`, and
  Gestão suppression through
  `workflow.reminders.sources.privacy_control_reviews=false` without privacy
  record mutation. These markers remain local advisory reminder evidence only:
  they do not notify authorities or data subjects, approve or execute
  transfers, file or complete DPIAs, complete legal approval, deliver
  provider/calendar/email/webhooks, or certify privacy compliance.
- DPIA template/guidance pack:
  `cargo test -p chancela-api --test privacy --locked dpia` plus
  `apps/web/src/contracts/contracts.test.ts` and
  `apps/web/src/features/settings/SettingsPage.test.tsx` pin
  `GET /v1/privacy/dpia-template`, `contracts/privacy.dpia-template.json`,
  `api.getDpiaTemplate()`, the Settings > Privacidade `Modelo DPIA local`
  panel, structured template sections/checklists/operator actions, false
  no-claim flags, and no live register/sensitive echo. This is static
  local/offline guidance only: no mutation route, external call, authority/CNPD/
  EDPB filing or approval, legal review acceptance, DPIA completion,
  certification, external delivery, compliance certification, transfer
  approval/execution, notification, automated legal decision, or risk-scoring
  authority claim. The spec matrix remains `PARTIAL=11`.
- Written-resolution evidence receipt browser proof:
  `npm run test:browser --workspace apps/web -- e2e/written-resolution-evidence.spec.ts`
  pins a route-stubbed WrittenResolution act editor path for filling a local
  evidence receipt, submitting only `written_resolution_evidence` through
  `PATCH /v1/acts/{id}`, preserving existing checklist/history metadata,
  keeping proof/legal/authority claim flags false, and rendering updated
  receipt/history/no-claim copy after the stubbed response. This is metadata-only
  local browser evidence; it is not live provider evidence, legal acceptance,
  legal sufficiency, written-consent/quorum/identity proof, external validation,
  legal-validity or authority certification, act finalization, signing, seal, or
  archive completion.
- API retained-export cleanup preview-token/manifest execution:
  `cargo test -p chancela-api --locked data_cleanup_`
- API data key operations:
  `cargo test -p chancela-api --test data_key_ops --locked`
- API seeded role drift diagnostic:
  `cargo test -p chancela-api --locked customized_seeded_platform_admin_reports_missing_defaults_without_granting_them`
- Seeded role drift browser proof:
  `npm run test:browser --workspace apps/web -- e2e/seeded-role-drift.spec.ts`
  loads `/configuracoes?sec=funcoes` with route-stubbed API calls and
  proves no initial reconciliation `POST`, explicit `Rever defaults` review `GET`,
  add-only/defaults UI for `platform.logs.write`, empty `{}` apply body,
  retained customized permissions, unchanged Owner/custom rows, and disabled
  review without `role.manage`. This is local browser evidence for explicit
  admin apply only; it is not auto-privilege mutation, tenant/sync/ZK/archive,
  retention, or compliance completion evidence.
- API official signed-PDF handoff guardrail acknowledgement:
  `cargo test -p chancela-api --test official_signature_import --locked official_import_requires_guardrail_acknowledgement_without_artifact_or_event`
- Official signed-PDF handoff browser proof:
  `npm run test:browser --workspace apps/web -- e2e/official-signed-handoff.spec.ts`
  pins the sealed-act browser path for importing a PDF already signed outside
  Chancela as technical signed-PDF evidence only. The route-stubbed proof checks
  the guardrail acknowledgement gate, exact required guardrail IDs,
  client-declared trace context only (`provider`/`source`/`filename`),
  collecting no PIN, OTP, CAN, credential, token, password, passphrase, or
  private-key material, no live provider/trust/signing route calls, the imported
  evidence result display, and copy stating that Chancela does not perform
  trust-list validation, claim qualified status, or complete legal signing
  acceptance.
- TSL XML-DSig hardening: `cargo test -p chancela-tsl --locked`
- API trust/import/static hardening markers: the static map pins
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
  `cc_sign_rejects_real_tsl_source_with_invalid_signature`. These pin unsafe
  TSL/TSA URL refusal before runtime fetch/network/PDF work, resolved-address
  validation and `reqwest` pinning with redirects/system proxy disabled,
  debug/test-only exact-origin loopback allowance with RAII drop and no env-var
  production bypass, fail-closed invalid TSL XML import/cache behavior,
  `/v1/books/import` route and handler body limits before staging, and security
  headers on API responses plus static SPA fallback/assets including CSP
  `frame-ancestors 'none'`.
- MCP resource/prompt coverage: `cargo test -p chancela-mcp --locked`
  including the no-argument draft-signed comparison prompt/resource, the
  deterministic local comparison report for `arguments.draft` and
  `arguments.signed`, closed extra resource params, no
  bridge/API/AI-provider/hidden-provider calls, no secrets, and false
  legal/source/provider/trust/external-validation/signature-qualification
  claims, plus the read-only `chancela://mcp/chronology-review-summary`
  human-review resource for static chronology guidance and caller-supplied
  local aggregate counts only, plus
  `chancela://mcp/privacy-control-review-summary` static guidance and
  caller-supplied `arguments.privacy_controls` aggregate counts for
  processors, DPIAs, breach playbooks, transfer controls, retention policies,
  retention executions, DSR requests, caller-supplied retention due-candidate
  reports, and caller-supplied candidate-resolution records. The
  privacy-control resource is local JSON only, makes no
  bridge/API/AI-provider/legal-service/provider calls, echoes no names, ids,
  notes, legal bases, recipients, subjects, data categories, raw evidence text,
  or secrets, and keeps legal approval/completion, notification,
  transfer/DPIA/compliance, disposal, deletion, anonymization, redaction,
  erasure, legal-hold mutation, retention-policy mutation, and full-erasure
  claims false.
- Template catalog metadata/semantic lint:
  `cargo test -p chancela-templates --locked` and
  `cargo run -p chancela-templates --bin template_catalog_metadata_lint --locked`
  pin runnable embedded-catalog metadata consistency only, including required
  fields, duplicate IDs, family/stage/channel drift, local law-reference anchors,
  and `Certidao`/`Extrato` references to `ata_number` / `payload_digest`. This
  does not claim legal/template sufficiency, verified thresholds, channel
  permissibility, exhaustive law mapping, DRE/source authority, provider or
  registry integration, signing correctness, or legal effect.
- Web client/contract/books/dashboard/document/entity/Ferramentas/notification/recovery/settings/signing/templates/i18n/subnav
  matrix:
  `npm run test --workspace apps/web -- src/api/client.test.ts src/contracts/contracts.test.ts src/features/books/books.test.tsx src/features/dashboard/DashboardPage.test.tsx src/features/documents/ActDocumentPanel.test.tsx src/features/entities/entities.test.tsx src/features/ferramentas/ferramentas.test.tsx src/features/ferramentas/trust.test.tsx src/features/notifications/NotificationBell.test.tsx src/features/notifications/NotificationsPage.test.tsx src/features/recovery/GestaoDadosSection.test.tsx src/features/settings/SettingsPage.test.tsx src/features/signing/SigningPanel.test.tsx src/features/templates/TemplatesCatalogPage.test.tsx src/i18n/i18n.test.ts src/ui/SubNav.test.tsx`
- Web shell accessibility/focus unit tests:
  `npm run test --workspace apps/web -- src/app/layout.test.tsx src/app/router.test.tsx src/ui/PageHeader.test.tsx src/ui/useFocusTrap.test.ts`
  pin the skip-link `#main-content` target, pathname route-change focus to the
  main landmark, route-crash preservation of `main#main-content`, PageHeader h1
  coverage, and modal focus-trap activation/restore/wrap behavior. This is
  focused shell/navigation/modal regression evidence only, not complete UX,
  WCAG/legal accessibility certification, PDF/UA delivery, or exhaustive
  assistive-technology validation.
- Validator corpus manifest:
  `npm run test:validator-corpus`
- Desktop lockfile resolution:
  `cargo metadata --manifest-path apps/desktop/src-tauri/Cargo.toml --locked --no-deps --format-version 1`

The script also performs a cheap static map before running commands. That map
asserts the expected test files, fixture markers, data key preflight markers,
official-signature/imported-document guardrail acknowledgement markers,
official signed-PDF handoff browser proof markers for
`apps/web/e2e/official-signed-handoff.spec.ts`, the route-stubbed
`/v1/acts/${ACT_ID}/signature/official/import` path, the exact official import
guardrail IDs, the API acknowledgement notice, client-declared trace context
only, no PIN/OTP/CAN/credential/token/password/passphrase/private-key
collection, and no trust-list, qualified-status, or legal-signing-acceptance
claim copy,
written-resolution evidence status/binding markers and written-resolution
browser receipt proof markers for
`apps/web/e2e/written-resolution-evidence.spec.ts`, declared signer-capacity
evidence markers with `not_checked_by_scap` and
`declared_capacity_evidence_only`, local CC batch-signing UI markers for
BatchSigningPanel, `useCcBatchSign`, `POST /v1/signature/cc/batch-sign`,
transient PIN clear/no-storage tests, route/current-act reset behavior,
per-document result rendering, auth-mode reporting, and declared-capacity
evidence display, `chancela-signing` repeated remote-session helper/types/tests
for one `RemoteSigningSource::initiate` and one
`RemoteSigningSource::confirm` per document plus per-document activation
no-claim copy, pending-session provider bridge markers for `PendingInfo`,
`pending_provider_info`, `providerFromPending`, and reload confirm routing,
dashboard subtab markers,
dashboard/notification icon-only markers, web shell accessibility/focus
markers for the skip-link target, route-change main focus, route-crash main
target preservation, PageHeader h1 coverage, and modal focus-trap behavior,
template law-reference UI markers,
password-required account creation/session API and web markers,
structured registry chronology graph markers plus richer frontend chronology
visualization markers and local sealed-act chronology projection markers with
provenance, retification edges, and false legal-validity/authority-certified
flags as source-linked technical evidence only, not a legal registry certificate,
DRE verification, registry/provider authority verification, archive mutation,
legal validity, user/editor authoritative graph, or an authority-approved graph,
mapped PDF inter-word space,
PDF/UA blocker-decomposition markers, PDF accessibility report JSON v11,
deterministic `pdf_ua_blocker_delta`, cleared/remaining blocker counts,
marked-content coverage counts, `writer_owned_decorative_artifacts_accounted_for`, reduced default-fixture
`limited_tagged_structure` remaining blocker lists, exhaustive `DocumentBlock`
non-text-accounting coverage, ASiC structural profile-shape,
manifest/signature diagnostic, blocker-ID, `technical_validation`,
`validate_asic_container`, `AsicValidationReport`, `AsicSignatureValidation`,
and `AsicArchiveTimestampValidation` markers, local paper-book OCR
API/UI/contract markers, accepted OCR draft to mutable draft-act
API/UI/refusal markers, per-book import preflight route/no-mutation/API tests,
web preview-confirm flow markers, stale file/policy response guards,
focused paper-book OCR review browser workflow markers,
caller-supplied archive timestamp append API markers, dashboard current-work
summary caps/hidden-count markers, registered-entity single-line table and
filter no-overflow markers, books filter/table no-overflow markers, platform
service/control desired-state markers, encrypted-build-default markers, external-validator
metadata API durability markers, the settings.read raw metadata and raw-report
byte download
route/tests, Settings privacy retention-policy list/create/patch/dry-run UI,
retention due-candidate explicit evidence-state enum markers,
duplicate-review, queued-status, prior bounded evidence suppression,
active/suppressed candidate count fields, suppression-summary copy, eligible
bounded archive/no-action `execute_supported` UI markers, ineligible
review-only/badge paths, locale keys, and non-destructive payload assertions,
Ferramentas
panel/client/i18n markers including compact validator-report actions,
imported-document review-depth/receipt/history markers for technical review
history, neutral missing-preservation copy, pending/reviewed states, no-claim
OCR/conversion/PDF-A replacement/signed-PDF/signature-validation/seal/PDF-UA/
certification/legal acceptance copy, route-stubbed full imported-document
browser route contract markers for all four `acknowledged_guardrail_ids`, two
ordered `review_history` entries, pending receipt/history before
acknowledgement, canonical `/v1/acts/{id}/document` PDF export, and no
accidental imported-byte/OCR/conversion behavior,
trust identifier-match explanation/copy-safe hash and
SKI markers, trust/import/static URL/body/header fail-closed markers,
retained-export `would_delete_*`/zero-`deleted_*` dry-run planning markers,
preview-only Settings payload/no-files-removed markers, retained-export
preview-token/manifest-gated execution markers without certification of physical
deletion outside the bounded server-selected retained-export manifest, post-act
`Certidao`/`Extrato` `ata_number`/`payload_digest` template lint markers,
standalone agenda-item template IDs, rendering markers, and the 101-template
census, CSC delegation/revocation template IDs/rendering markers, forwarded
platform-log missing/invalid-bearer unaudited markers, authenticated
RBAC-denied/rejected/malformed/suppressed sanitized audit markers, local DGLAB
manifest route/permission/read-only/no-persisted-bytes/no-ZIP-member/no-ledger
markers plus BookDetail JSON-save markers,
release clean-source provenance gate markers, seeded role drift API/UI markers,
archive readability/ZK caveat markers, template `FamilyChannelMismatch` markers,
MCP trust-catalog structured-filter and redacted external-validator summary
markers, MCP draft-vs-signed comparison review prompt/resource plus deterministic
local comparison report/no-call/no-claim markers, dashboard guest
`recent_events: []` redaction and no-permission-grant
markers, privacy control review reminder source-rule/dashboard/browser markers,
generated-document by-id route, sealed post-act certidao/extrato generation UI,
dispatch-evidence route, `act.read`/`document.generate` gates,
durable/in-memory, canonical Ata preservation,
absent-owner communication auto-generation, communication-template-scoped dispatch-evidence store,
idempotency, selected-recipient evidence coverage, evidence-attached headers,
no dispatch completion, web client/hooks/panel/i18n metadata-only evidence UI,
generated-document deep-link query/hash focus routing, one-time
ActDocumentPanel dispatch-evidence selection/focus, no send/delivery/
legal-notice copy, no-claim markers, and dashboard reminder/notification
source/action/deep-link/no-date ordering/fixture markers, plus document-bundle
`generated_dispatch_evidence` metadata and archive
`evidence/generated-dispatch/{document_id}.json` sidecar/index markers,
live-provider assurance markers, validator manifest,
Arquivo paged-ledger route/default-limit/cursor markers, 1000+ event first-page
and load-more coverage, `Store::ledger_events_page` persisted-pager markers,
API after-reload/memory-clear store-pager coverage, shared list/export search
(`q`), chain/scope filter, and limit normalization markers, numeric
`next_cursor` typing, Livro-style filters, icon-only clear-control markers,
JSON/TXT/CSV/HTML export-format markers, and canonical-only PDF/A evidence
boundaries, plus route-stubbed `/arquivo` browser proof in
`apps/web/e2e/ledger-archive-boundedness.spec.ts` for bounded first-page rows,
older-tail absence before load-more, cursor request serialization, filtered
`limit=50&order=desc` list queries, and archive-document export with current
filters and no `before_seq`, backup recovery-drill `isolated_restore_verified` /
`isolated_restore_verification` receipt markers, isolated DB material/readback,
sidecar materialized file/byte counts, temp-cleanup evidence, no live-restore/
no `ledger.restored` markers, external-signing slot evidence
metadata rendering, pending/initiated slot operator evidence actions,
identity-requirement-tagged row builders, no-`complete:true` PATCH payloads,
and desktop `Cargo.lock` are present, so accidental deletion or rename of the
checkpoint targets fails with a direct message. It also statically pins the
imported-document review notification/export browser E2E marker plus the
guardrail acknowledgement payload, ordered review-history rendering, and
canonical act-document download assertions; Playwright execution remains in the
browser jobs so this recent-landed lane stays focused.

Imported-document review reminder markers pin the API dashboard reminder unit
coverage for act-scoped imports still in `operator_review_required`,
`ocr_review_required`, or `canonical_conversion_review_required`, dashboard and
notification action routes to
`/atas/{act_id}?imported_document_id={id}&focus=import-review#imported-documents`,
act-page query parsing, and one-time ActDocumentPanel selection/focus of the
existing imported-document review form. These markers are advisory routing and
metadata-minimization coverage only: no raw imported bytes, filenames, digests,
notes, imported-by details, OCR, conversion, PDF/A/PDF/UA generation,
signed-import legal validation, review mutation from dashboard load, DGLAB,
provider/trust, GDPR-erasure, or compliance-completion claim is pinned.

Password-required auth markers pin the current security slice only: `POST
/v1/users` requires a password, enforces policy after auth for non-bootstrap
creates, stores a hardened `password_hash`, and rechecks stale bootstrap
requests under the users write lock; `POST /v1/session` requires a password and
rejects legacy no-hash users without minting a token; `DELETE
/v1/users/{id}/secret` returns `409` after authorization while preserving the
password hash and attestation key; web onboarding, sign-in, current-user
switching, user creation, and E2E helpers all submit passwords. These markers
include focused Playwright auth proof in `apps/web/e2e/session.spec.ts` and
`apps/web/e2e/first-launch-onboarding.spec.ts`; the broad browser suite/matrix
remains unclaimed. They are not SSO, legal identity proof, tenant model, email
verification, credential recovery completion, or broad Playwright-browser-suite
proof.
Static markers are deletion/rename guards only; the retention archive/no-action
markers pin explicit non-destructive evidence states, bounded evidence UI
copy/payload shape, active/suppressed candidate counts, and suppression-summary
copy. Review-closure markers pin separate operational closure fields and false
destructive/full-erasure/legal-hold/policy-mutation flags only. They are not
physical deletion, anonymization, GDPR erasure, legal disposal completion, legal
approval, legal-hold mutation, policy mutation, persisted resolution, or
candidate disposal execution.
The backup recovery-drill markers pin isolated preflight material/readback
evidence only: DB snapshot materialized/opened/loaded, ledger/readback counts,
sidecar materialized file/byte counts, cleanup verification, redaction, and
false live-restore flags. They do not prove live restore execution, live DB
swap, live sidecar staging, `ledger.restored` append, SQLCipher-at-rest proof,
RPO/RTO, off-site custody, production backup policy, legal archive
certification, or FULL coverage.
They do not certify legal validity, legal retention schedules or approvals,
retention deletion or anonymization/redaction execution, retention execution
completion, destructive GDPR erasure, full erasure, template legal effect, DRE
verification, verified law references, legal thresholds, external
registry/provider behavior, signing-process behavior, official DGLAB export,
government filing, DGLAB/legal-archive/PDF-A/PAdES/PDF-UA certification, PDF/UA
conformance, validator evidence, signed-PDF accessibility certification,
production XAdES/ASiC conformance, ASiC trust/LTV
or legal validity, production B-LT/B-LTA, SCAP verification, representative
authority, live provider validity, canonical OCR conversion, imported-document
OCR, imported-document conversion, imported-document PDF/A replacement, imported-document
signed-PDF creation or signature validation, imported-document seal/PDF-UA, imported-document
legal acceptance, per-book import preflight legal archive certification, DGLAB/legal acceptance,
production signed-import validation beyond existing confirm checks, confirm-time collision/IO
finality, raw external-validator legal/trust/certification validation,
trust-list legal validity, hostile DNS/rebinding proof, production qualified trust,
provider approval, live provider readiness, DGLAB certification, full release
hardening, raw MCP report-byte exposure,
auto-role reconciliation, permission grants, archive custody/decryption material,
AI-01/full AI completion, MCP draft-signed legal/source/trust/external
certification or signed-artifact validity, MCP meeting metadata extraction legal/source/workflow
certification, generated-document signing, bundle readiness, template legal
review, threshold correctness, law verification, provider execution, registry
filing, legal-effect claims, mail/email/SMS/provider sending, provider
dispatch-sent proof, dispatch completion from operator evidence, delivery proof,
legal notice completion, generated communication legal sufficiency,
promotion of generated dispatch-evidence metadata sidecars into canonical documents,
canonical paper-book conversion,
paper-book canonical act/document/archive-package creation, paper-book PDF/A/PDF-UA,
paper-book signature/seal creation, paper-book OCR/conversion behavior beyond the
bounded reviewed metadata/execution-artifact slices, legal effect for mutable
draft acts created from accepted OCR drafts, provider-native CMD batch
signing, provider-native CSC/QTSP multi-hash/SAD batch signing,
provider-certified remote batch signing, single OTP/PIN/SAD authorizing
multiple documents, CMD multiple-sign, SCAP-verified representative authority,
legal-capacity proof, production/live remote batch readiness, or legal effect
for local CC or repeated remote batch-initiate UI evidence. The
Arquivo markers prove bounded UI/API/browser paging, persisted-store SQL paging
after reload/memory clear, and filtered first-page export behavior only; export
remains bounded to the current filtered newest-first page after limit
normalization. They do not turn non-PDF/A exports into preserved evidence,
make any archive certification or DGLAB/legal archive certification claim,
prove filing or legal acceptance, claim all-record export, add signing/legal
evidence, validate signatures, or mutate the ledger. The external invite
signed-PDF markers prove act-scoped technical signed evidence and the linked
no-identity external slot status path only. The operator-supplied
external-signing slot evidence markers prove stored technical evidence display
and PATCH recording for pending/initiated slots with required identity-tagged
rows and no `complete:true`. The focused browser proof is
`npm run test:browser --workspace apps/web --
e2e/external-signing-operator-evidence.spec.ts`; it route-stubs the signed-in
operator path, captures the `PATCH /v1/external-signing/envelopes/{id}`
`slots` payload that omits `complete:true`, verifies the browser no-secret
boundary for PIN, OTP, CAN, credential, token, password, passphrase, and
private-key material, and keeps the envelope open as operator-supplied
technical workflow evidence only; they do not prove provider calls, trust-list
checks, QES/qualified status, legal validity, provider completion, act
finalization, provider-backed slot signing, or full envelope legal completion.
The remote batch-initiate markers prove only repeated per-document
pending-session initiation through
`POST /v1/signature/remote/{provider}/batch-initiate`: each valid act gets its
own pending session, activation hint, expiry, and later single-document
CMD/CSC-QTSP confirm path. They do not prove provider-certified remote batch,
provider-native multi-document authorization, one OTP/PIN/SAD for multiple
documents, CMD multiple-sign, CSC/QTSP multi-hash/SAD batch, production
provider approval, SCAP/legal-capacity verification, act finalization, or legal
validity. The focused route-stubbed browser proof for that slice is in
`apps/web/e2e/remote-signing-pending-session.spec.ts` and asserts
per-document pending rows without credential echo.
The pending-session provider identity bridge markers prove only that additive
pending-session metadata can route an already-open CMD or CSC/QTSP session
after reload to the matching confirm endpoint; they do not prove production
provider approval, live CSC readiness, trust-list/legal validation,
SCAP/legal-capacity verification, qualified-signature certification, act
finalization, or legal-validity.
Focused browser execution for that slice is
`npm run test:browser --workspace apps/web -- e2e/remote-signing-pending-session.spec.ts`;
it is route-stubbed reload adoption/routing only and uses fake activation/OTP
values.
Run only that static portion with
`npm run test:checkpoint:recent-landed:static`.

The GitHub Actions job is `recent-landed` in `.github/workflows/ci.yml`. Keep
this lane focused: add only short-running commands that prove the named landed
areas still resolve together. Broader workspace clippy, full Rust tests,
browser E2E, Docker, and Windows desktop smoke remain in their dedicated jobs.
The `3f19872` refresh documents compact notification/storage UI, honest
platform service controls, encrypted package-build defaults, and books
filter/table density in `SPEC-COVERAGE.md` and the static checkpoint map without
claiming stdout/stderr, MCP process logs, supervisor lifecycle coverage,
hardware-ID-derived key security, production key custody, legal validity, or
complete UX/spec coverage.

Settings platform operations now also has a focused route-stubbed browser proof:
`npm run test:browser --workspace apps/web -- e2e/platform-operations.spec.ts`.
It verifies API/MCP row rendering, the MCP `start` desired-state POST returning
`supervisor_required`, and settings autosave for an MCP log override only. It
does not prove live supervisor integration, process start/stop/restart control,
stdout/stderr capture, MCP child-process logging, or production observability.

## Release Hardening Artifacts

The CI `supply-chain` job now generates and validates a CycloneDX dependency
SBOM from the committed npm and Cargo lockfiles. It uploads that SBOM together
with npm and Cargo vulnerability reports under `chancela-supply-chain-reports-*`.

`node scripts/check-release-trust.mjs self-test` statically verifies that the CI
metadata lane keeps release-trust, SBOM package-linkage, and package provenance
fixture checks; that the Docker job stays no-push/local-load with `local-ci`
trust status and `--expect-mode local-ci`; and that the release workflow runs
package integrity, emits `releaseTrust.mode = unsigned-dev` and
`attestation.status = not_attested`, validates `--expect-mode unsigned-dev`, and
runs SBOM package linkage. Production package validation now requires
`--manifest` whenever either the package mode or expected mode is `production`;
the self-test covers both signals independently. The Docker trust JSON checks
preserve nested path context for
`releaseTrust.imagePublication/signing/notarization/attestation.status`.
`node scripts/check-package-artifacts.mjs --fixture --skip-dist` is also part of
the cheap CI metadata lane; its fixture coverage proves
`--require-clean-source` rejects `dirty` and `unknown` source states. `npm run
check:encrypted-build-defaults` remains in that lane; it statically checks that
release package, Docker server, and desktop package builds opt into the existing
`sqlcipher` feature while dev/test commands remain explicit plaintext/no-SQLCipher
paths. Release packaging then validates each generated
`*-release-artifact.json` plus package manifest in explicit `unsigned-dev` mode,
including a source SHA cross-check against
`manifest.sourceProvenance.commitSha`. Docker CI validates
the actual Compose profiles `single-node` and `validation-worker`, runs
`bash scripts/docker-smoke.sh --compose-profile chancela-server:ci` after the
local image load, and validates `chancela-server-signing-status.json` in
explicit `local-ci` mode. The Compose smoke inspects the `single-node`
Compose-created server container for read-only rootfs, `cap_drop: ALL`,
`no-new-privileges`, non-root user, `/tmp` tmpfs, and persistent
`/var/lib/chancela` data mount before the durable `/health` assertion;
`validation-worker` remains config-validated only in this checkpoint. The
release-trust metadata checks remain static workflow assurance only; switch
those checks to `production` only when signing, notarization, registry
publication, and attestation evidence are actually generated. The Compose
smoke does not claim HA, a dedicated worker image, registry publication, image
signing, attestation, notarization, vulnerability remediation, or production
deployment certification.

After `npm run package`, run `npm run test:package-integrity` to validate the
generated `dist/chancela-*.tar.gz` archive and staged package directory. The
check enforces safe archive member paths, matching manifest entries, valid
`SHA256SUMS` digests, explicit code-signing/notarization status, and package
source provenance in `manifest.json`. The provenance check requires a Git commit
SHA, source tree state, `buildMode=release`, and a commit that matches current
HEAD when the check runs inside a Git checkout.

Normal CI treats vulnerability scans as report-only so missing advisory tooling
or newly reported findings do not silently break unrelated PRs. Manual
`workflow_dispatch` runs can set `enforce_security_scans=true` to make the npm,
Cargo, and Docker vulnerability scan statuses blocking. See
`docs/CI-RELEASE-HARDENING.md` for the current enforced/report-only boundary.
