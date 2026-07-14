# CI Release Hardening

Updated 2026-07-14.

This page records the current supply-chain and release metadata behavior. It is
deliberately conservative: CI may upload reports and placeholders, but it must
not imply package notarization, code signing, container signing, or registry
publication unless those steps actually happened.

## Enforced in CI

- `metadata` runs `npm run check:versions` before heavier jobs.
- `metadata` runs `node scripts/check-release-trust.mjs self-test`, which proves
  the release-trust validator accepts explicit unsigned/local modes and rejects
  production claims without evidence.
- `metadata` runs `node scripts/check-package-artifacts.mjs --fixture
  --skip-dist`, which proves package manifests must carry source provenance and
  rejects a fixture manifest whose commit SHA does not match the current HEAD.
  The same fixture coverage proves `--require-clean-source` rejects `dirty` and
  `unknown` source tree states.
- `supply-chain` generates `dist/supply-chain/chancela-dependency-sbom.cdx.json`
  from `package-lock.json` and `cargo metadata --locked`, then validates that
  the CycloneDX SBOM includes the expected npm and Cargo ecosystems.
- The release workflow generates and validates the same dependency SBOM for
  each platform package metadata artifact.
- The release workflow writes a `releaseTrust` block into each
  `*-release-artifact.json` metadata file, then runs
  `node scripts/check-release-trust.mjs package --expect-mode unsigned-dev`
  against the package summary, copied package manifest, and collected package
  path. This intentionally passes only explicit unsigned package metadata today.
  The same check also confirms the release summary source SHA matches
  `manifest.sourceProvenance.commitSha` and recomputes the tarball basename and
  SHA-256 before accepting `release artifact.package` and
  `release artifact.packageSha256`.
- The release workflow runs `npm run test:package-integrity` against the staged
  package and tarball before upload, passing `--require-clean-source` so dirty or
  unknown source provenance fails the release package gate. The package manifest must include
  `sourceProvenance.commitSha`, `sourceProvenance.sourceTreeState`, and
  `sourceProvenance.buildMode=release`, with the commit matching current HEAD.
- The Docker lane, on `main` pushes and manual runs, still builds the server
  image locally, applies OCI labels, boots it, and checks `/health` for durable
  persistence.
- The Docker lane writes `chancela-server-signing-status.json` with
  `releaseTrust.mode=local-ci`, then runs
  `node scripts/check-release-trust.mjs docker --expect-mode local-ci`. The
  check fails if the local CI image claims push, signing, notarization, or
  attestation work that did not happen.

## Report-Only by Default

- `npm audit --omit=dev --audit-level=high --json` writes
  `npm-audit-prod.json`.
- `cargo audit --json` writes `cargo-audit.json` on `main`, manual runs, and
  PRs labeled `run-security-scans`. If `cargo-audit` cannot be installed, CI
  writes a skipped report instead of claiming a clean audit.
- The Docker lane uploads image inspect metadata, a Syft image SBOM when Syft
  succeeds, and a Trivy HIGH/CRITICAL vulnerability report when Trivy succeeds.
- These report-only scans do not fail normal PR or `main` CI. A manual
  `workflow_dispatch` run with `enforce_security_scans=true` makes the npm,
  Cargo, and Docker vulnerability scan statuses blocking.

## Not Yet Enforced or Claimed

- Release packages are uploaded with source provenance, manifests, and SHA-256
  checksums, and the release gate requires a clean source-tree state plus a
  matching package tarball basename/SHA-256, but there is no package code
  signing or notarization step configured.
- The Docker image is local-only in CI. It is not pushed to a registry, signed,
  attested, or notarized.
- The Docker security artifact includes
  `chancela-server-signing-status.json`, which records that no signing or
  notarization was performed.
- Actual production package or image publication should be added only after the
  registry, signing identity, notarization flow, provenance policy, and secret
  handling are configured. At that point, change the relevant
  `scripts/check-release-trust.mjs` call from `unsigned-dev` or `local-ci` to
  `production` and include concrete evidence anchors such as certificate
  fingerprints, attestation digests, workflow run URLs, or notarization ticket
  references.
