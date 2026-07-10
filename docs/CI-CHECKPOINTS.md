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
assurance, MCP resource/prompt coverage, web fixtures, ASiC structural
diagnostic markers, registry chronology graph markers, PDF writer spacing and
PDF/UA blocker-decomposition markers, archive timestamp append markers,
paper-book OCR API/UI markers including accepted OCR draft to mutable draft-act
creation plus focused paper-book OCR review browser workflow markers,
recovery/document/dashboard/notification
UI, Ferramentas external-validator metadata UI and compact validator-report
actions, template provenance UI, validator fixtures, and the standalone desktop
Cargo workspace.

It intentionally reuses existing test surfaces:

- API paper import: `cargo test -p chancela-api --test paper_import --locked`
  including the non-canonical canonical-conversion preflight guard and
  operator-configured local OCR run coverage, plus the accepted OCR draft to
  mutable draft-act endpoint and refusal cases. Focused Playwright coverage for
  the non-canonical paper-book OCR review workflow is pinned statically here and
  executed in browser jobs.
- API archive package and `/DocTimeStamp` evidence:
  `cargo test -p chancela-api --test archive_package --locked`
- API external-validator report metadata, including raw metadata download:
  `cargo test -p chancela-api --locked external_validator_report_metadata`
- Live-provider assurance static gate:
  `npm run check:live-provider-assurance`
- API local PKCS#12 signing:
  `cargo test -p chancela-api --test local_pkcs12_signing --locked`
- API bounded retention execution:
  `cargo test -p chancela-api --test privacy --locked retention_`
- API data key operations:
  `cargo test -p chancela-api --test data_key_ops --locked`
- API official signed-PDF handoff guardrail acknowledgement:
  `cargo test -p chancela-api --test official_signature_import --locked official_import_requires_guardrail_acknowledgement_without_artifact_or_event`
- TSL XML-DSig hardening: `cargo test -p chancela-tsl --locked`
- MCP resource/prompt coverage: `cargo test -p chancela-mcp --locked`
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
structured registry chronology graph markers, mapped PDF inter-word space and
PDF/UA blocker-decomposition markers, ASiC structural profile-shape,
manifest/signature diagnostic, and blocker-ID markers, local paper-book OCR
API/UI/contract markers, accepted OCR draft to mutable draft-act
API/UI/refusal markers,
focused paper-book OCR review browser workflow markers,
caller-supplied archive timestamp append API markers, dashboard current-work
summary caps/hidden-count markers, registered-entity single-line table and
filter no-overflow markers, external-validator
metadata API durability markers, the settings.read raw metadata download
route/tests, Settings privacy retention-policy list/create/patch/dry-run UI,
locale keys, and non-destructive payload assertions, Ferramentas
panel/client/i18n markers including compact validator-report actions,
live-provider assurance markers, validator manifest,
and desktop `Cargo.lock` are present, so accidental deletion or rename of the
checkpoint targets fails with a direct message. It also statically pins the
imported-document review notification/export browser E2E marker; Playwright
execution remains in the browser jobs so this recent-landed lane stays focused.
Static markers are deletion/rename guards only; they do not certify legal
validity, legal retention schedules or approvals, retention deletion or
anonymization execution, GDPR erasure, PDF/UA, XAdES validation, ASiC trust/LTV
or legal validity, production B-LT/B-LTA, SCAP verification, representative
authority, live provider validity, canonical OCR conversion, or legal effect for
mutable draft acts created from accepted OCR drafts.
Run only that static portion with
`npm run test:checkpoint:recent-landed:static`.

The GitHub Actions job is `recent-landed` in `.github/workflows/ci.yml`. Keep
this lane focused: add only short-running commands that prove the named landed
areas still resolve together. Broader workspace clippy, full Rust tests,
browser E2E, Docker, and Windows desktop smoke remain in their dedicated jobs.
The `f58019c` refresh documents API-owned structured platform log threshold
enforcement and paper-import clippy cleanup in `SPEC-COVERAGE.md` without adding
new recent-landed commands or claiming stdout/stderr, MCP process logs, or
supervisor lifecycle coverage.

## Release Hardening Artifacts

The CI `supply-chain` job now generates and validates a CycloneDX dependency
SBOM from the committed npm and Cargo lockfiles. It uploads that SBOM together
with npm and Cargo vulnerability reports under `chancela-supply-chain-reports-*`.

`node scripts/check-release-trust.mjs self-test` and
`node scripts/check-package-artifacts.mjs --fixture --skip-dist` are part of
the cheap CI metadata lane. `npm run check:encrypted-build-defaults` is also in
that lane; it statically checks that release package, Docker server, and desktop
package builds opt into the existing `sqlcipher` feature while dev/test commands
remain explicit plaintext/no-SQLCipher paths. Release packaging then validates
each generated `*-release-artifact.json` plus package manifest in explicit
`unsigned-dev` mode, including a source SHA cross-check against
`manifest.sourceProvenance.commitSha`. Docker CI validates
`chancela-server-signing-status.json` in explicit `local-ci` mode. Switch those
checks to `production` only when signing, notarization, registry publication,
and attestation evidence are actually generated.

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
