# CI and E2E Hardening Plan

Updated 2026-07-10 from the current CI configuration and head `2c88b90`. This
plan is the build and test operating checklist for driving Chancela toward
release confidence.

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
- Release and package builds now opt into SQLCipher features by default where the
  supported package scripts and CI metadata require it. Treat this as encrypted
  build-default coverage, not proof of operator key custody, migration success,
  or deployed encrypted data at rest.
- Platform operations expose API-owned structured status/control/logging
  contracts. They do not prove real supervisor-backed start/stop/restart,
  historical stdout/stderr tailing, or child-process log forwarding.

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
- Global logging level `off` suppresses service log output even if stale
  per-service overrides remain stored; explicit service overrides take effect
  only when the global/area level allows logging.
- Storage cleanup presents crash reports and retained exports as separate
  bounded maintenance rows, rejects unknown cleanup targets, and preserves
  permission/usage diagnostics after a failed cleanup.
- SQLCipher package defaults are checked statically, and plaintext development
  paths remain explicit so local tests do not silently claim production
  encrypted deployment.

### Dashboard and Ledger

- Dashboard recent feed is newest-first and capped at 10 rows.
- Duplicate timestamps are ordered deterministically by sequence.
- Metric cards remain stable with six cards on one desktop row.
- Ledger archive export preserves active filters and refuses unauthorized
  downloads.
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
  arguments before HTTP, and never treats generated text as legal minutes.
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

## Focused Gate Snapshot Through `2c88b90`

Historical focused checks from the active director loop, refreshed on
2026-07-10 for current head `2c88b90`. This is not an exhaustive current
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
- Recent trust-source provider checks through `fa57352`: focused
  `SettingsPage.test.tsx` trust-source/TSA-provider coverage, i18n locale
  catalog validation, Prettier, and ESLint are the focused web checks for
  settings-backed TSL/TSA provider management.
- Recent trust catalog display checks through `c3d874b`: focused Ferramentas
  trust tests pin the `trust-accepted-hash` wrapper, copyable truncated accepted
  TSA hash behavior, and labelled `Registos TSA` result grouping without making
  live trust-network calls.
- Recent PDF accessibility checks through `fdb9376`: focused document tests pin
  `accessibility_page_breaks_do_not_require_decorative_accounting` and the
  `emits_decorative_artifact_block` boundary so page breaks no longer require
  decorative artifact accounting while `pdf_ua_claimed` stays false.
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
- Recent keyed PAdES VRI `/TU` checks through `76fc229`: worker validations
  passed `cargo fmt`, `cargo test -p chancela-pades`,
  `cargo test -p chancela-api pdf_signature`,
  `cargo test -p chancela-api signature_evidence_status`,
  `cargo check -p chancela-signing`, `cargo check -p chancela-api`, and
  `git diff --check`. The checks pin `vri_tu_keys`,
  `has_vri_tu_for_key`, keyed API signature/PDF validation payloads, and
  multi-signature renewal planning for the specific VRI key without claiming
  production/legal PAdES-LT/LTA completion.
- Recent compact notification/entity filter checks through `2c88b90`: worker
  validations passed 20 notification tests, 4 export-save browser-gate Chromium
  tests, 21 entities tests, plus prettier/eslint/diff checks. These pin compact
  notification list rows, title-folded tags, bell badge z-index/pointer-events
  assertions, entity primary-filter nowrap desktop/mobile-wrap CSS, and
  advanced-filter no-overflow grid assertions.
- Recent checkpoint metadata/static checks through `2c88b90` passed: `node
  --check scripts/checkpoint-recent-landed.mjs`, `npm run
  test:checkpoint:recent-landed:static`, `npm run check:spec-coverage`, and
  `git diff --check -- SPEC-COVERAGE.md docs\CI-E2E-HARDENING-PLAN.md
  scripts\checkpoint-recent-landed.mjs`. These pin the spec snapshot,
  hardening-plan head, PDF table-structure semantics, export save-prompt
  routing, dashboard dates tab, notification footer icon-only action, and
  clarified platform operations UI, user/signatory email capture, and compact
  Data Management cleanup controls, plus SettingsPage/i18n trust-source
  provider markers, trust-accepted-hash/Registos TSA grouping, decorative
  page-break accounting, export-save cancellation, dashboard desktop-six
  density, SQLite logical table payload markers, browser dynamic-import gate
  markers, web SQLite table-usage rows, keyed VRI `/TU` evidence markers,
  compact notification/bell badge assertions, and entity filter nowrap/mobile
  wrap markers.

Full workspace format/clippy should be rerun before commit. The prior
`paper_import.rs` compile blocker, retention dead-code warning set, TSL `record`
compile break, external-signing route-classification blocker, document-import
dead-code warning, and `/api` namespace route-classification miss have been
cleared.
