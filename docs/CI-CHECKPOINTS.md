# CI Checkpoints

## Spec Coverage Status

`npm run check:spec-coverage` parses `SPEC-COVERAGE.md` and fails if the
top-level spec table no longer covers all 11 spec documents, uses an unknown
status, loses the implementation snapshot marker, or drops the required blocker
and "Do Not Overstate" boundary sections. Use
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
guardrail acknowledgements, written-resolution evidence status binding, trust
parsing, declared signer-capacity evidence preservation, live-provider static
assurance, MCP resource/prompt coverage including workflow provenance review
guidance and draft-vs-signed comparison review guidance, web fixtures, ASiC
inspect `technical_validation` and structural diagnostic markers, registry chronology
graph markers, PDF writer spacing and PDF/UA blocker-decomposition markers,
archive timestamp append markers, raw-byte per-book import preflight markers for
no-mutation operator previews,
paper-book OCR API/UI markers including accepted OCR draft to mutable draft-act
creation plus focused paper-book OCR review browser workflow markers,
retention duplicate review-only request guards, queued-review status surfacing,
prior bounded execution projection, and eligible no-action bounded evidence UI,
retained-export cleanup preview-token/manifest gating, forwarded platform-log sanitized
accepted/denied/rejected/suppressed audit markers, post-act template
sealed-provenance lint, all-family standalone agenda-item templates,
recovery/document/dashboard/notification
UI, dashboard guest recent-events redaction, Ferramentas external-validator
metadata UI, raw-report byte download API, imported-document review receipt UI,
password-required account creation/session static markers,
trust identifier-match explanations, trust/import/static request-boundary
hardening, and read-only local DGLAB interchange
manifest API and BookDetail JSON-download markers, generated-document by-id
download route plus absent-owner dispatch-evidence recording and generated
absent-owner evidence UI and dashboard absent-owner dispatch-evidence reminders,
compact validator-report actions, template provenance UI, release clean-source
provenance gating, local CC batch-signing UI markers for BatchSigningPanel,
`useCcBatchSign`, `POST /v1/signature/cc/batch-sign`, optional transient PIN
clearing/no-storage, per-document results, auth-mode reporting, declared
signer-capacity evidence display, and local-CC-only no-claim boundary copy,
`chancela-signing` core repeated per-document remote-session orchestration
markers for `RemoteSigningSource` initiate/confirm one-digest flow,
per-document activation, helper/types/tests, core-only no-API/no-web boundary,
and no provider-certified remote batch / single OTP/PIN/SAD / CMD
multiple-sign / CSC/QTSP multi-hash/SAD / SCAP/legal-capacity claim,
pending-session provider identity bridge markers for additive
`GET /v1/acts/{id}/signature` metadata (`provider_id`, `family`, and optional
`activation_hint`) plus web reload adoption routing to the dedicated CMD
confirm path or generic CSC/QTSP remote confirm path,
seeded role drift diagnostics, archive readability/ZK caveat
metadata, template family/channel rule guards, MCP trust-catalog filter
discoverability, redacted external-validator report summary tools, external
invite signed-PDF technical evidence markers including linked no-identity slot
completion, identity-required refusal, replay idempotency, upload body limits,
i18n leakage guards, external-signing stored slot evidence rendering,
operator technical evidence form submission, identity-requirement-tagged
evidence rows, `PATCH` slot payloads that omit `complete:true`, validator
fixtures, and the standalone desktop Cargo workspace.

It intentionally reuses existing test surfaces:

- API paper import: `cargo test -p chancela-api --test paper_import --locked`
  including the non-canonical canonical-conversion preflight guard and
  operator-configured local OCR run coverage, plus the accepted OCR draft to
  mutable draft-act endpoint and refusal cases. Focused Playwright coverage for
  the non-canonical paper-book OCR review workflow is pinned statically here and
  executed in browser jobs.
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
- API external-validator report metadata, including raw metadata and raw-report
  byte downloads:
  `cargo test -p chancela-api --locked external_validator_report_metadata`
- Live-provider assurance static gate:
  `npm run check:live-provider-assurance`
- API local PKCS#12 signing:
  `cargo test -p chancela-api --test local_pkcs12_signing --locked`
- API bounded retention execution:
  `cargo test -p chancela-api --test privacy --locked retention_`
  including due-candidate prior bounded archive/no-action projection, safe
  internal evidence gating, non-mutating GET behavior, and canonical
  `prior_execution.next_step` text.
- API dashboard guest event redaction:
  `cargo test -p chancela-api --locked dashboard_recent_events_redacts_guest_feed_but_keeps_owner_and_reader_feed`
  including guest `recent_events: []`, retained Owner/Leitor recent events, and
  continued guest denial from `/v1/ledger/events`.
- API generated-document by-id downloads, absent-owner dispatch evidence, and
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
  `recordGeneratedDocumentDispatchEvidence`, generated absent-owner
  communication listing, generated PDF fetch, stored evidence rows,
  metadata-only evidence form submission, `operator_evidence_*` statuses,
  `documents.generated.noClaim.*` copy, generated-document deep-link
  `generated_document_id`, `focus=dispatch-evidence`,
  `#generated-dispatch-evidence`, `actDocumentPanelTargetFromLocation`, one-time
  dispatch-evidence selection/focus, and no send/delivery/legal-notice or
  dispatch-completion copy. Dashboard markers pin `source_rule`
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
- API retained-export cleanup dry-run:
  `cargo test -p chancela-api --locked data_cleanup_`
- API data key operations:
  `cargo test -p chancela-api --test data_key_ops --locked`
- API seeded role drift diagnostic:
  `cargo test -p chancela-api --locked customized_seeded_platform_admin_reports_missing_defaults_without_granting_them`
- API official signed-PDF handoff guardrail acknowledgement:
  `cargo test -p chancela-api --test official_signature_import --locked official_import_requires_guardrail_acknowledgement_without_artifact_or_event`
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
  including the no-argument draft-signed comparison prompt/resource, closed
  resource params, no bridge/API/provider calls, no secrets, and false
  legal/source/trust/external-validation/signature-qualification claims.
- Template catalog metadata/semantic lint:
  `cargo test -p chancela-templates --locked`
- Web client/contract/books/dashboard/document/entity/Ferramentas/notification/recovery/settings/signing/templates/i18n/subnav
  matrix:
  `npm run test --workspace apps/web -- src/api/client.test.ts src/contracts/contracts.test.ts src/features/books/books.test.tsx src/features/dashboard/DashboardPage.test.tsx src/features/documents/ActDocumentPanel.test.tsx src/features/entities/entities.test.tsx src/features/ferramentas/ferramentas.test.tsx src/features/ferramentas/trust.test.tsx src/features/notifications/NotificationBell.test.tsx src/features/notifications/NotificationsPage.test.tsx src/features/recovery/GestaoDadosSection.test.tsx src/features/settings/SettingsPage.test.tsx src/features/signing/SigningPanel.test.tsx src/features/templates/TemplatesCatalogPage.test.tsx src/i18n/i18n.test.ts src/ui/SubNav.test.tsx`
- Validator corpus manifest:
  `npm run test:validator-corpus`
- Desktop lockfile resolution:
  `cargo metadata --manifest-path apps/desktop/src-tauri/Cargo.toml --locked --no-deps --format-version 1`

The script also performs a cheap static map before running commands. That map
asserts the expected test files, fixture markers, data key preflight markers,
official-signature/imported-document guardrail acknowledgement markers,
written-resolution evidence status/binding markers, declared signer-capacity
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
dashboard/notification icon-only markers, template law-reference UI markers,
password-required account creation/session API and web markers,
structured registry chronology graph markers, mapped PDF inter-word space,
PDF/UA blocker-decomposition markers, PDF accessibility report JSON v7,
`writer_owned_decorative_artifacts_accounted_for`, reduced default-fixture
`limited_tagged_structure` blocker lists, exhaustive `DocumentBlock`
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
retention due-candidate duplicate-review, queued-status, prior-execution
projection, projected-row duplicate-action suppression, eligible no-action
`execute_supported` UI markers, ineligible review-only/badge paths, locale keys,
and non-destructive payload assertions, Ferramentas
panel/client/i18n markers including compact validator-report actions,
imported-document review-depth/receipt markers for metadata-derived summaries,
neutral missing-preservation copy, pending/reviewed states, no-claim OCR/
conversion/PDF-A replacement/signed-PDF/signature-validation/seal/PDF-UA/legal
acceptance copy, and no-extra-route behavior, trust identifier-match explanation/copy-safe hash and
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
markers, MCP draft-vs-signed comparison review prompt/resource/no-call/no-claim
markers, dashboard guest `recent_events: []` redaction and no-permission-grant
markers, generated-document by-id route, dispatch-evidence route, `act.read`/
`document.generate` gates, durable/in-memory, canonical Ata preservation,
absent-owner communication auto-generation, dispatch-evidence store,
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
boundaries, external-signing slot evidence
metadata rendering, pending/initiated slot operator evidence actions,
identity-requirement-tagged row builders, no-`complete:true` PATCH payloads,
and desktop `Cargo.lock` are present, so accidental deletion or rename of the
checkpoint targets fails with a direct message. It also statically pins the
imported-document review notification/export browser E2E marker; Playwright
execution remains in the browser jobs so this recent-landed lane stays focused.

Password-required auth markers pin the current security slice only: `POST
/v1/users` requires a password, enforces policy after auth for non-bootstrap
creates, stores a hardened `password_hash`, and rechecks stale bootstrap
requests under the users write lock; `POST /v1/session` requires a password and
rejects legacy no-hash users without minting a token; `DELETE
/v1/users/{id}/secret` returns `409` after authorization while preserving the
password hash and attestation key; web onboarding, sign-in, current-user
switching, user creation, and E2E helpers all submit passwords. These markers
are not SSO, legal identity proof, tenant model, email verification, credential
recovery completion, or broad Playwright-browser-suite proof.
Static markers are deletion/rename guards only; the retention no-action markers
pin bounded evidence UI copy and payload shape, not legal disposal completion.
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
certification, generated-document signing, bundle readiness, template legal
review, threshold correctness, law verification, provider execution, registry
filing, legal-effect claims, mail/email/SMS/provider sending, provider
dispatch-sent proof, dispatch completion from operator evidence, delivery proof,
legal notice completion, generated communication legal sufficiency,
promotion of generated dispatch-evidence metadata sidecars into canonical documents,
canonical paper-book conversion,
paper-book canonical act/document/archive-package creation, paper-book PDF/A/PDF-UA,
paper-book signature/seal creation, paper-book OCR/conversion behavior, legal
effect for mutable draft acts created from accepted OCR drafts, CMD batch
signing, CSC/QTSP remote batch signing, provider-certified remote batch signing,
single OTP/PIN/SAD authorizing multiple documents, CMD multiple-sign,
CSC/QTSP multi-hash/SAD batch, SCAP-verified representative authority,
legal-capacity proof, API/web coverage for the core-only repeated
remote-session helper, or legal effect for local CC batch UI evidence. The
Arquivo markers prove bounded UI/API paging, persisted-store SQL paging after
reload/memory clear, and filtered export behavior only; they do not turn
non-PDF/A exports into preserved evidence or certify legal archive/DGLAB
acceptance. The external invite
signed-PDF markers prove act-scoped technical signed evidence and the linked
no-identity external slot status path only. The operator-supplied
external-signing slot evidence markers prove stored technical evidence display
and PATCH recording for pending/initiated slots with required identity-tagged
rows and no `complete:true`; they do not prove provider calls, trust-list
checks, QES/qualified status, legal validity, provider completion, act
finalization, provider-backed slot signing, or full envelope legal completion.
The pending-session provider identity bridge markers prove only that additive
pending-session metadata can route an already-open CMD or CSC/QTSP session
after reload to the matching confirm endpoint; they do not prove production
provider approval, live CSC readiness, trust-list/legal validation,
SCAP/legal-capacity verification, remote batch, qualified-signature
certification, act finalization, or legal-validity.
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
`chancela-server-signing-status.json` in explicit `local-ci` mode. This is
static workflow assurance only; switch those checks to `production` only when
signing, notarization, registry publication, and attestation evidence are
actually generated.

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
