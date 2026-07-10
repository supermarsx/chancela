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

## Recent Landed Areas

`npm run test:checkpoint:recent-landed` is a focused local and CI guard for
recently landed work that crosses Rust API tests, web fixtures, validator
fixtures, and the standalone desktop Cargo workspace.

It intentionally reuses existing test surfaces:

- API paper import: `cargo test -p chancela-api --test paper_import --locked`
- API archive package and `/DocTimeStamp` evidence:
  `cargo test -p chancela-api --test archive_package --locked`
- Web contract/dashboard/i18n matrix:
  `npm run test --workspace apps/web -- src/contracts/contracts.test.ts src/features/dashboard/DashboardPage.test.tsx src/i18n/i18n.test.ts`
- Validator corpus manifest:
  `npm run test:validator-corpus`
- Desktop lockfile resolution:
  `cargo metadata --manifest-path apps/desktop/src-tauri/Cargo.toml --locked --no-deps --format-version 1`

The script also performs a cheap static map before running commands. That map
asserts the expected test files, fixture markers, validator manifest, and
desktop `Cargo.lock` are present, so accidental deletion or rename of the
checkpoint targets fails with a direct message. Run only that static portion
with `npm run test:checkpoint:recent-landed:static`.

The GitHub Actions job is `recent-landed` in `.github/workflows/ci.yml`. Keep
this lane focused: add only short-running commands that prove the named landed
areas still resolve together. Broader workspace clippy, full Rust tests,
browser E2E, Docker, and Windows desktop smoke remain in their dedicated jobs.

## Release Hardening Artifacts

The CI `supply-chain` job now generates and validates a CycloneDX dependency
SBOM from the committed npm and Cargo lockfiles. It uploads that SBOM together
with npm and Cargo vulnerability reports under `chancela-supply-chain-reports-*`.

`node scripts/check-release-trust.mjs self-test` and
`node scripts/check-package-artifacts.mjs --fixture --skip-dist` are part of
the cheap CI metadata lane. Release packaging then validates each generated
`*-release-artifact.json` plus package manifest in explicit `unsigned-dev`
mode, including a source SHA cross-check against
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
