# CI Release Hardening

Updated 2026-07-26.

This page records the current supply-chain and release metadata behavior. It is
deliberately conservative: CI may upload reports, hooks, and placeholders, but
it must not imply package notarization, code signing, container signing, or
registry publication unless those steps actually happened and the matching
status artifact records concrete evidence.

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
- The pull-request-visible `packaging-contracts` job enforces the fixed
  Linux/locked search-projector dependency ceiling and forbidden-dependency
  boundary, Dockerfile contracts, rendered normal/hardened/cluster Compose
  security topology, secret initialization fixtures, and packaging shell
  syntax before the main-only image build lane.
- The Docker lane, on `main` pushes and manual runs, builds all three application
  images locally, applies OCI labels, checks server/worker health, and proves
  query-only SQLite and PostgreSQL servers can return records indexed by the
  isolated projector. The PostgreSQL smoke also provisions the exact restricted
  role, verifies the full ACL, and executes denied entity/event writes plus a
  denied provider-credential read before accepting publication.
- A focused hardened PostgreSQL smoke additionally starts the real hardened
  Compose profile with ephemeral validated Docker secrets, proves the
  preflight/runtime/role initializers complete, inspects read-only root filesystems,
  dropped capabilities, secret mounts, and edge/backend isolation, then
  stop/starts the API and projector and requires both to become healthy again.
- The Docker lane writes one `releaseTrust.mode=local-ci` status document per
  image, then validates each with
  `node scripts/check-release-trust.mjs docker --expect-mode local-ci`. The
  check fails if a local CI image claims push, signing, notarization, or
  attestation work that did not happen.
- The final `publish-ghcr` job depends on every required CI job and runs only for
  a push to `main`, so publication cannot begin before the normal CI graph
  succeeds. Running `main` pushes are never cancelled by a later push. It uses
  `GITHUB_TOKEN` (`packages: write`) to push server, worker, and isolated
  search-projector images by canonical digest before creating any named tag.
- `org.opencontainers.image.created` and `SOURCE_DATE_EPOCH` come from the
  source commit timestamp, never the workflow wall clock.
- A `sha-<full-commit>` tag is created only when absent. If it already exists,
  CI preserves its top-level digest and requires the exact source revision,
  commit-derived created label, and `linux/amd64` platform digest to equal the
  new build. This comparison intentionally ignores a different top-level index
  digest from run-specific provenance metadata. A mismatch fails closed.
- Normal CI does not publish a moving `latest` tag.
- All three published images are pinned to `linux/amd64` and carry maximum
  BuildKit SLSA v1 provenance (`mode=max,version=v1`) plus SBOM attestations.
  Their machine-readable status is validated as `published-unsigned`;
  publication and attestations do not imply a cosign signature. Publication and
  signature evidence bind the immutable tag digest; attestation evidence
  separately binds the exact `linux/amd64` platform digest that BuildKit
  attested, and records the matching
  `https://slsa.dev/provenance/v1` predicate.
- After all three full-SHA tags are read back and verified, CI writes
  `chancela-image-set.json` with each exact repository, tag digest, and platform
  digest. The workflow being green **and** that validated complete manifest
  being present is the completeness boundary. Deployments consume
  `repository@sha256:…` from the manifest, not a mutable tag.
- Each built, preserved, and final image index must expose exactly one
  non-attestation descriptor, and that descriptor must be `linux/amd64`.
  Unknown or additional runnable manifests are rejected. At least one
  attestation descriptor must exist, and every attestation descriptor must use
  the `unknown/unknown` attestation platform marker and reference that sole
  platform digest. Descriptor presence alone is not accepted as evidence: CI
  extracts and validates the actual `.Provenance.SLSA` and `.SBOM.SPDX`
  payloads from every built reference, preserved or newly published tag, and
  final tag reread. Provenance must use the BuildKit SLSA v1 structure and
  contain the `mode=max` LLB build definition; the SBOM must be a non-empty SPDX
  document describing at least one package or file.
- The publication trust artifact is named
  `ghcr-publication-trust-<commit>-<run-id>-<run-attempt>` so reruns cannot
  collide with earlier evidence. Its upload uses `if-no-files-found: error`;
  a green publication run therefore cannot silently omit the image-set and
  trust declarations. The signing workflow derives this exact name from the
  successful source run it selected.

The OCI Distribution tag-write API has no portable compare-and-set operation.
The workflow therefore serializes its own reruns for the same commit, checks
absence twice before its sole tag write, and reads the entire set back before
emitting the manifest. A registry administrator with independent write access
could still race that final check; keep GHCR package write access restricted to
the release workflow. Any later registry mutation invalidates the uploaded
manifest's digest contract rather than silently becoming a new release.

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

## Opt-In Signing Workflow

The separate `Release signing (opt-in)` workflow
(`.github/workflows/release-signing.yml`) is manual/tag-triggered and
secret-gated. With no signing credentials configured, it records honest
unsigned / not-pushed / not-attested / not-notarized status and does not create
a production trust claim.

- Container signing accepts no independently writable image target. When
  configured for cosign keyless OIDC or
  `COSIGN_PRIVATE_KEY`/`COSIGN_PASSWORD`, it resolves the exact successful
  `main` push CI run for the source commit, downloads and validates that run's
  complete three-image manifest, and signs/verifies the server, worker, and
  search-projector digest references. It performs no image build, image push,
  tag write, `imagetools` mutation, or replacement attestation.
- When more than one successful CI run exists for the exact source SHA, signing
  selects the newest run ID and then that run's newest attempt; an older
  high-attempt rerun cannot displace a newer successful run.
- Keyless and private-key signing are mutually exclusive and run in separate
  steps. Ambiguous dual configuration fails closed; the keyless step never
  receives the private key/password secrets.
- Desktop code-signing/notarization hooks are gated by platform-specific
  certificates and notarization credentials. Missing credentials leave artifacts
  unsigned with a status artifact rather than an implied success.
- `scripts/release-signing-status.mjs self-test` proves positive container,
  attestation, desktop signing, and macOS notarization claims require concrete
  evidence such as a digest, identity, predicate type, signer, certificate
  fingerprint, or notarization ticket.
- A release SBOM checks out the exact dispatch/tag-push release tag, verifies
  that it names an existing GitHub release and that `HEAD` is its commit, then
  embeds the source commit and tag in CycloneDX metadata before any
  `--clobber` attachment. Checkout does not persist credentials. Syft receives
  the checkout through a read-only mount and writes under `RUNNER_TEMP`, outside
  the scanned tree, with runtime networking disabled; only the source-bound
  result is copied to the artifact directory. Desktop downloads likewise
  validate the exact release before consuming its artifacts.

This checkpoint pins workflow wiring, documentation, and truthful status
artifacts only. It does not prove production signing success, secret
availability, package trust certification, registry publication, or completed
notarization. Those outcomes still require concrete hosted-run evidence; no
automatically published image is claimed to be signed.

## Not Yet Enforced or Claimed

- The normal release workflow uploads packages with source provenance,
  manifests, and SHA-256 checksums, and the release gate requires a clean
  source-tree state plus a matching package tarball basename/SHA-256. Production
  package signing and notarization remain unvalidated unless the separate
  opt-in workflow runs with configured credentials and emits signed/notarized
  status evidence.
- The normal Docker smoke lane remains local-only. After every required CI job
  succeeds on a `main` push, `publish-ghcr` automatically pushes server,
  worker, and search-projector images with BuildKit provenance and SBOM
  attestations, reconciles immutable full-SHA tags, and emits the complete
  digest-pinned image-set manifest. The images remain unsigned. The opt-in
  signing workflow can only sign the exact three digest references from that
  successful normal-CI image set when explicitly configured.
- The Docker security artifact includes server, worker, and search-projector
  signing-status documents, which record that no signing or notarization was
  performed.
- Actual production package signing or image signing should be claimed only
  after the signing identity, notarization flow, provenance policy, and secret
  handling are configured and a workflow run emits concrete evidence anchors.
  Automatic GHCR publication uses `published-unsigned`; only a genuinely signed
  workflow result may move image trust to `production`.
