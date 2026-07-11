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
structural diagnostic markers, registry chronology
graph markers, PDF writer spacing and PDF/UA blocker-decomposition markers,
archive timestamp append markers,
paper-book OCR API/UI markers including accepted OCR draft to mutable draft-act
creation plus focused paper-book OCR review browser workflow markers,
retention duplicate review-only request guards, queued-review status surfacing,
and prior bounded execution projection,
retained-export cleanup dry-run planning, forwarded platform-log sanitized
accepted/denied/rejected/suppressed audit markers, post-act template
sealed-provenance lint, all-family standalone agenda-item templates,
recovery/document/dashboard/notification
UI, dashboard guest recent-events redaction, Ferramentas external-validator
metadata UI, raw-report byte download API, imported-document review receipt UI,
trust identifier-match explanations, and read-only local DGLAB interchange
manifest API and BookDetail JSON-download markers, generated-document by-id
download route plus condominium absent-owner communication auto-generation,
compact validator-report actions, template provenance UI, release clean-source
provenance gating, seeded role drift diagnostics, archive readability/ZK caveat
metadata, template family/channel rule guards, MCP trust-catalog filter
discoverability, redacted external-validator report summary tools, external
invite signed-PDF technical evidence markers including linked no-identity slot
completion, identity-required refusal, replay idempotency, upload body limits,
i18n leakage guards, validator fixtures, and the standalone desktop Cargo
workspace.

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
- API generated-document by-id downloads:
  `cargo test -p chancela-api --locked on_demand_generate_persists_a_chosen_document_and_emits_the_event`
  and
  `cargo test -p chancela-api --locked in_memory_generated_document_download_uses_returned_url_and_keeps_canonical_ata`
  plus
  `cargo test -p chancela-server --test e2e_act_document_persistence --locked condominium_absent_owner_communication_auto_generates_and_keeps_canonical_ata`
  plus route-classification coverage for
  `/v1/documents/generated/{document_id}` as a gated `act.read` route while the
  canonical `/v1/acts/{act_id}/document` endpoint remains the sealed Ata path,
  including automatic `condominio-comunicacao-ausentes/v1` generation after
  condominium seal with absent attendees and pending dispatch evidence status.
- API retained-export cleanup dry-run:
  `cargo test -p chancela-api --locked data_cleanup_`
- API data key operations:
  `cargo test -p chancela-api --test data_key_ops --locked`
- API seeded role drift diagnostic:
  `cargo test -p chancela-api --locked customized_seeded_platform_admin_reports_missing_defaults_without_granting_them`
- API official signed-PDF handoff guardrail acknowledgement:
  `cargo test -p chancela-api --test official_signature_import --locked official_import_requires_guardrail_acknowledgement_without_artifact_or_event`
- TSL XML-DSig hardening: `cargo test -p chancela-tsl --locked`
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
`declared_capacity_evidence_only`, dashboard subtab markers,
dashboard/notification icon-only markers, template law-reference UI markers,
structured registry chronology graph markers, mapped PDF inter-word space,
PDF/UA blocker-decomposition markers, PDF accessibility report JSON v7,
`writer_owned_decorative_artifacts_accounted_for`, reduced default-fixture
`limited_tagged_structure` blocker lists, exhaustive `DocumentBlock`
non-text-accounting coverage, ASiC structural profile-shape,
manifest/signature diagnostic, and blocker-ID markers, local paper-book OCR
API/UI/contract markers, accepted OCR draft to mutable draft-act
API/UI/refusal markers,
focused paper-book OCR review browser workflow markers,
caller-supplied archive timestamp append API markers, dashboard current-work
summary caps/hidden-count markers, registered-entity single-line table and
filter no-overflow markers, books filter/table no-overflow markers, platform
service/control desired-state markers, encrypted-build-default markers, external-validator
metadata API durability markers, the settings.read raw metadata and raw-report
byte download
route/tests, Settings privacy retention-policy list/create/patch/dry-run UI,
retention due-candidate duplicate-review, queued-status, prior-execution
projection, and projected-row duplicate-action suppression UI markers,
locale keys, and non-destructive payload assertions, Ferramentas
panel/client/i18n markers including compact validator-report actions,
imported-document review-depth/receipt markers for metadata-derived summaries,
neutral missing-preservation copy, pending/reviewed states, no-claim OCR/
conversion/PDF-A replacement/signed-PDF/signature-validation/seal/PDF-UA/legal
acceptance copy, and no-extra-route behavior, trust identifier-match explanation/copy-safe hash and
SKI markers,
retained-export `would_delete_*`/zero-`deleted_*` dry-run planning markers,
preview-only Settings payload/no-files-removed markers, retained-export
execution payload/modal-gate/deleted-counter markers, post-act
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
markers, generated-document by-id route, `act.read` gate, durable/in-memory,
canonical Ata preservation, absent-owner communication auto-generation, and
pending dispatch evidence markers, live-provider assurance markers, validator manifest,
Arquivo paged-ledger route/default-limit/cursor markers, 1000+ event first-page
and load-more coverage, shared list/export filter and limit normalization
markers, numeric `next_cursor` typing, Livro-style filters, icon-only
clear-control markers, JSON/TXT/CSV/HTML export-format markers, and
canonical-only PDF/A evidence boundaries,
and desktop `Cargo.lock` are present, so accidental deletion or rename of the
checkpoint targets fails with a direct message. It also statically pins the
imported-document review notification/export browser E2E marker; Playwright
execution remains in the browser jobs so this recent-landed lane stays focused.
Static markers are deletion/rename guards only; they do not certify legal
validity, legal retention schedules or approvals, retention deletion or
anonymization/redaction execution, retention execution completion,
GDPR erasure, template legal effect, DRE
verification, verified law references, legal thresholds, external
registry/provider behavior, signing-process behavior, official DGLAB export,
government filing, DGLAB/legal-archive/PDF-A/PAdES/PDF-UA certification, PDF/UA
conformance, validator evidence, signed-PDF accessibility certification,
XAdES validation, ASiC trust/LTV
or legal validity, production B-LT/B-LTA, SCAP verification, representative
authority, live provider validity, canonical OCR conversion, imported-document
OCR, imported-document conversion, imported-document PDF/A replacement, imported-document
signed-PDF creation or signature validation, imported-document seal/PDF-UA, imported-document
legal acceptance, raw external-validator legal/trust/certification validation,
trust-list legal validity, provider approval, raw MCP report-byte exposure,
auto-role reconciliation, permission grants, archive custody/decryption material,
AI-01/full AI completion, MCP draft-signed legal/source/trust/external
certification, generated-document signing/bundle/template/threshold/law/provider/
registry/legal-effect claims, dispatch-sent proof, dispatch completion,
generated communication legal sufficiency, canonical paper-book conversion,
paper-book canonical act/document/archive-package creation, paper-book PDF/A/PDF-UA,
paper-book signature/seal creation, paper-book OCR/conversion behavior, or legal effect for mutable draft acts created from
accepted OCR drafts. The Arquivo markers prove bounded UI/API paging and
filtered export behavior only; they do not prove persistent-store boot-time SQL
paging or turn non-PDF/A exports into preserved evidence. The external invite
signed-PDF markers prove act-scoped technical signed evidence and the linked
no-identity external slot status path only; they do not prove provider calls,
trust-list checks, QES/qualified status, legal validity, provider completion,
act finalization, or full envelope legal completion.
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
