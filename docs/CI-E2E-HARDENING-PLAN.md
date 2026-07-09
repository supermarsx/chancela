# CI and E2E Hardening Plan

Updated 2026-07-09 from the current working tree. This plan is the build and
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
- Web format, ESLint, Vitest, and Vite build run on Node 20 and Node 24.
- Composed server e2e runs `cargo test -p chancela-server --features e2e --locked`
  on Linux and Windows for every push and PR.
- Live seam compile checks run `cargo test ... --no-run` for the existing
  `network-tests` and `hardware-tests` feature gates, without touching live
  providers, networks, or card readers.
- Browser core e2e builds release `chancela-server`, builds the web app,
  installs Chromium, and runs the stable smoke/session/first-launch/journey
  Playwright specs on every push and PR.
- Browser full e2e remains a heavier Chromium gate for pushes to `main`, manual
  dispatches, or PRs labeled `run-browser-tests`.
- Docker server image build plus runtime smoke runs on pushes to `main` and
  manual dispatches; the smoke starts the container with `CHANCELA_DATA_DIR`,
  polls `/health`, and asserts durable persistence from the JSON body.
- Windows desktop smoke runs on pushes to `main` or PRs labeled
  `run-desktop-tests`.

## Current Local Verification Snapshot

Recorded on 2026-07-09 from the current dirty working tree after the
privacy/archive/signing integration wave and before the next document-import/MCP
worker wave is integrated:

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
npm run test --workspace apps/web
npm run build --workspace apps/web
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
npm run test:browser
npm run build:docker
cd apps/desktop
npm run test:rust
npm run build:no-bundle
npm run test:smoke -- -DataDir <temp-data-dir>
```

The root scripts `test:browser`, `build:docker`, `test:desktop:rust`, and
`test:desktop:smoke` are thin aliases for those heavier release-candidate gates.

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

### Dashboard and Ledger

- Dashboard recent feed is newest-first and capped at 10 rows.
- Duplicate timestamps are ordered deterministically by sequence.
- Metric cards remain stable with six cards on one desktop row.
- Ledger archive export preserves active filters and refuses unauthorized
  downloads.
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
- B-T timestamp evidence is included when configured; B-LT/B-LTA remains
  honestly reported as not implemented.

### Imports and Search

- CAE and law search handle accents, case differences, empty queries, no
  matches, and exact-code lookup.
- TSL/TSA catalog search handles provider/service names, qualified-service
  filters, stale cache, invalid XML signature, and empty result states.
- TSL/TSA catalog browser coverage exercises accent-insensitive search,
  service-type/status/history/supply filters, URL params, fixture-only TSA
  records, and no-live-timestamp-call behavior.
- Certidao import masks access codes and never returns raw secrets.
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
- Docker image builds and passes the runtime `/health` persistence smoke from a
  clean checkout.
- Desktop smoke passes on Windows with a temporary data dir.
- The remaining failures, if any, are documented as external blockers such as
  live CMD, QTSP, CC hardware, production TSL/TSA network, or legal review.

## Current Focused Gate Snapshot

Latest focused checks from the active director loop:

- `actionlint .github/workflows/ci.yml`, `npx prettier --check
.github/workflows/ci.yml`, and `git diff --check -- .github/workflows/ci.yml
docs/CI-E2E-HARDENING-PLAN.md`: passed after the CI hardening workflow
  update.
- `cargo test -p chancela-server --features e2e --locked --no-run` plus the
  compile-only live seam gates for `chancela-cae`, `chancela-cmd`,
  `chancela-csc`, `chancela-law`, `chancela-registry`, `chancela-tsa`,
  `chancela-tsl`, and `chancela-smartcard`: passed.
- `cargo test -p chancela-mcp --locked`: passed 60 unit tests plus 1 live API
  bearer test.
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
  (`cargo test -p chancela-store --locked --features sqlcipher sqlcipher`) is
  blocked on this Windows host because vendored OpenSSL rejects the available
  Cygwin Perl for MSVC builds; CI needs a Windows-compatible Perl/OpenSSL setup
  before this can be a required feature gate.

Full workspace format/clippy should be rerun before commit. The prior
`paper_import.rs` compile blocker, retention dead-code warning set, TSL `record`
compile break, external-signing route-classification blocker, document-import
dead-code warning, and `/api` namespace route-classification miss have been
cleared.
