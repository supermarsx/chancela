# CI Release Hardening

Updated 2026-07-09.

This page records the current supply-chain and release metadata behavior. It is
deliberately conservative: CI may upload reports and placeholders, but it must
not imply package notarization, code signing, container signing, or registry
publication unless those steps actually happened.

## Enforced in CI

- `metadata` runs `npm run check:versions` before heavier jobs.
- `supply-chain` generates `dist/supply-chain/chancela-dependency-sbom.cdx.json`
  from `package-lock.json` and `cargo metadata --locked`, then validates that
  the CycloneDX SBOM includes the expected npm and Cargo ecosystems.
- The release workflow generates and validates the same dependency SBOM for
  each platform package metadata artifact.
- The Docker lane, on `main` pushes and manual runs, still builds the server
  image locally, applies OCI labels, boots it, and checks `/health` for durable
  persistence.

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

- Release packages are uploaded with manifests and SHA-256 checksums, but there
  is no package code signing or notarization step configured.
- The Docker image is local-only in CI. It is not pushed to a registry, signed,
  attested, or notarized.
- The Docker security artifact includes
  `chancela-server-signing-status.json`, which records that no signing or
  notarization was performed.
- Actual signed image publication should be added only after the registry,
  signing identity, provenance policy, and secret handling are configured.
