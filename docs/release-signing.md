# Release signing, notarization & provenance

This page documents the **opt-in signing pipeline** for Chancela release
artifacts: the container image, the desktop/binary artifacts, and the release
SBOM.

The pipeline lives in
[`.github/workflows/release-signing.yml`](https://github.com/supermarsx/chancela/blob/main/.github/workflows/release-signing.yml)
and is deliberately **separate** from the default `ci.yml` and `release.yml`
pipelines. Those two build and package artifacts but never sign them; they always
record an honest `unsigned-dev` / `local-ci` trust status. The final `publish-ghcr`
job in `ci.yml` publishes the exact commit that passed every required CI job and
records `published-unsigned`: BuildKit provenance and SBOM attestations are
present, but no signature is claimed. `release-signing.yml` remains the single
place where signing is activated.

## Current default state

**By default, nothing is signed.** After a successful push to `main`, normal CI
publishes `chancela-server`, `chancela-worker`, and
`chancela-search-projector` to GHCR using `GITHUB_TOKEN`. Each image receives
an immutable `sha-<full-commit>` tag, with BuildKit provenance and SBOM
attestations; no moving `latest` tag is published. The complete
`chancela-image-set.json` artifact records the exact tag and `linux/amd64`
platform digests. Its trust declaration remains explicitly
`published-unsigned` and points to the exact preserved or newly published tag
digest. Publication and cosign signature evidence bind that tag digest, while
BuildKit provenance/SBOM attestation evidence binds the corresponding platform
digest that BuildKit actually attested. Normal CI explicitly requests
`provenance: mode=max,version=v1`, so the recorded provenance predicate
`https://slsa.dev/provenance/v1` matches the schema emitted by BuildKit rather
than relying on BuildKit's v0.2 default. The published index must contain
exactly one non-attestation descriptor, and it must be `linux/amd64`; every
attestation descriptor must use BuildKit's `unknown/unknown` platform marker and
link back to that platform digest. Extra runnable manifests, including a
descriptor that merely spoofs the attestation annotation on another platform,
fail publication. CI also extracts the actual `.Provenance.SLSA` and
`.SBOM.SPDX` payloads for every built reference, preserved or published tag,
and final tag reread. It refuses the positive `published-unsigned` trust
declaration unless provenance is BuildKit SLSA v1 with `mode=max` build
definition data and the SBOM is a non-empty SPDX document.

Separately, with no signing identity configured, the opt-in signing workflow:

- does **not** download a publication image set or write to GHCR,
- does **not** sign an image or produce a replacement attestation,
- does **not** code-sign or notarize desktop/binary artifacts,
- records an honest `unsigned` / `not_pushed` / `not_attested` / `not_notarized`
  status for every artifact.

Cosign signing happens **only** when you supply the real credentials below, and the
recorded `releaseTrust` reflects exactly what actually ran — it never claims an
artifact is signed, pushed, notarized, or attested unless the concrete evidence
(image digest, signing identity, attestation predicate, notarization ticket,
workflow run URL) is present. This is enforced in code by
[`scripts/release-signing-status.mjs`](https://github.com/supermarsx/chancela/blob/main/scripts/release-signing-status.mjs),
which refuses to emit a positive claim without its evidence, and cross-checked by
[`scripts/check-release-trust.mjs`](https://github.com/supermarsx/chancela/blob/main/scripts/check-release-trust.mjs).

Each signing step is guarded by an `if:` condition on the presence of its secret
or configuration variable, so a fork or a pull request that lacks the secrets
runs the workflow to a clean no-op rather than failing.

---

## What each signing path needs

Configure these under **Settings → Secrets and variables → Actions**. Repository
**variables** are non-secret toggles/names; **secrets** are sensitive material.

### 1. Digest-only container image signing (cosign)

Normal `main` publication needs no repository secret or variable: it uses
`GITHUB_TOKEN` with `packages: write` and does not invoke cosign. The settings
below apply only to the separate opt-in workflow when a signed image is needed.

The signing job does not accept an image repository and never builds, pushes,
or tags an image. It resolves the exact commit, finds a successful `main`
`push` run of `ci.yml` (the newest run ID, then its newest attempt), downloads
that run's
`ghcr-publication-trust-<commit>-<run-id>-<run-attempt>` artifact, and validates
its complete `chancela-image-set.json`. Including the run and attempt prevents a
rerun from colliding with or ambiguously replacing earlier evidence. Missing
publication files make the normal-CI upload fail. The signing workflow derives
the exact artifact name from the selected successful run, then signs and
verifies all three immutable `repository@sha256:…` references: server, worker,
and search projector. The BuildKit provenance and SBOM attestations were already
attached by normal CI; the signing workflow does not replace them.

Two mutually exclusive signing modes are supported:

| Setting                          | Type     | Purpose                                                                                                                      |
| -------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `RELEASE_SIGNING_COSIGN_KEYLESS` | variable | Set to `true` to sign **keyless** with GitHub OIDC (Fulcio/Rekor). No private key to manage. Recommended for GitHub Actions. |
| `COSIGN_PRIVATE_KEY`             | secret   | A cosign private key (PEM). Enables **key-based** signing when keyless is not turned on.                                     |
| `COSIGN_PASSWORD`                | secret   | Password for the cosign private key (if the key is encrypted).                                                               |

- **Keyless (recommended):** set `RELEASE_SIGNING_COSIGN_KEYLESS=true`. The
  workflow requests an OIDC token
  (`id-token: write`) and signs with the workflow's own identity.
- **Key-based:** add `COSIGN_PRIVATE_KEY` (and `COSIGN_PASSWORD` if encrypted).
  Generate a key pair with
  `cosign generate-key-pair`.

Configuration fails closed if both modes are enabled. Keyless and private-key
signing use separate workflow steps: the keyless process never receives
`COSIGN_PRIVATE_KEY` or `COSIGN_PASSWORD`, while the key-based process does not
request or consume a keyless identity; its OIDC request variables are explicitly
blanked.

The job needs `actions: read` to consume the normal-CI artifact and
`packages: write` because cosign signatures are stored as GHCR referrers.
`packages: write` is real registry-write capability and could support image/tag
mutation if the workflow invoked it. The safety boundary is therefore the
digest-only workflow plus its static/mutation checks, which reject image builds,
pushes, tag writes, `imagetools`, and replacement attestations.
The workflow fails closed when the exact successful main run or its image-set
artifact is absent, expired, incomplete, or bound to another commit. Publication
artifacts are retained for 30 days, so a later signing attempt requires a fresh
successful main CI run for that exact commit.

If neither mode is configured, the opt-in workflow records three honest
`local-ci`/unsigned status documents and performs no registry operation. This
does not upgrade the independently published normal-CI images to signed images.

### 2. Desktop / binary code signing

The `desktop` job downloads the artifacts of an existing release (the tag that
triggered the run, or the `release_tag` workflow input) and signs them per
platform.

**Windows Authenticode:**

| Secret                            | Purpose                                                                            |
| --------------------------------- | ---------------------------------------------------------------------------------- |
| `WINDOWS_CODE_SIGN_PKCS12_BASE64` | Base64-encoded PKCS#12 (`.pfx`) code-signing certificate. Enables Windows signing. |
| `WINDOWS_CODE_SIGN_PASSWORD`      | Password for the PKCS#12 file.                                                     |

When present, `signtool` signs each `*.exe` / `*.msi` with a SHA-256 digest and
RFC-3161 timestamp. When absent, the step is skipped and the artifact is recorded
as `unsigned`.

**macOS codesign + notarization:**

| Secret                        | Purpose                                                                              |
| ----------------------------- | ------------------------------------------------------------------------------------ |
| `APPLE_CERTIFICATE`           | Base64-encoded Developer ID Application certificate (`.p12`). Enables macOS signing. |
| `APPLE_CERTIFICATE_PASSWORD`  | Password for the `.p12`.                                                             |
| `APPLE_SIGNING_IDENTITY`      | The signing identity name, e.g. `Developer ID Application: Example (TEAMID)`.        |
| `APPLE_ID`                    | Apple ID used for notarization.                                                      |
| `APPLE_APP_SPECIFIC_PASSWORD` | App-specific password for `notarytool`.                                              |
| `APPLE_TEAM_ID`               | Apple Developer team identifier.                                                     |

When all are present, each `*.dmg` / `*.app.tar.gz` is `codesign`-ed (hardened
runtime, secure timestamp), submitted to `notarytool --wait`, and stapled. When
absent, the step is skipped and the artifact is recorded as `unsigned` /
`not_notarized`.

**Tauri native signing (alternative).** If you build the desktop bundles inside a
signing job rather than post-signing downloaded artifacts, Tauri consumes the
same identities natively during `tauri build`. Provide the `APPLE_*` environment
variables above, set `bundle.macOS.signingIdentity` and
`bundle.windows.certificateThumbprint` in
`apps/desktop/src-tauri/tauri.conf.json`, and — for updater signatures — set
`TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`. This
workflow does not edit `tauri.conf.json`; those fields are yours to add when you
adopt native bundle signing.

### 3. Release SBOM

The `sbom-release` job always generates a CycloneDX SBOM of the source tree with
[syft](https://github.com/anchore/syft) and, when the run has a release tag in
context, attaches `chancela-source-sbom.cdx.json` to that GitHub release. This
uses the built-in `GITHUB_TOKEN` (`contents: write`); no extra secret is needed.
For a manual dispatch, checkout uses the exact `release_tag` input; a tag push
uses its triggering tag. Before an attachment can replace the release asset, the
job proves that the tag exists, identifies an existing GitHub release, and
matches the checked-out commit. The CycloneDX metadata embeds
`chancela:source.commit` and `chancela:source.tag`, binding the attached SBOM to
that exact source. Checkout does not persist its write-capable token, and the
third-party Syft container sees the source tree read-only while writing into
`RUNNER_TEMP` outside the tree it scans; its runtime network is disabled. Only
the bound result is copied into the upload directory. Desktop artifact
downloads also validate the exact existing release tag before signing or
reattaching anything.

---

## Verifying signed artifacts

### Verify the container image signature (keyless)

```sh
cosign verify \
  --certificate-identity-regexp 'https://github.com/<owner>/chancela/.github/workflows/release-signing.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/<owner>/chancela-server@sha256:<digest>
```

### Verify the container image signature (key-based)

```sh
cosign verify --key cosign.pub ghcr.io/<owner>/chancela-server@sha256:<digest>
```

### Verify the normal-CI SBOM / provenance attestation

```sh
# BuildKit provenance / SBOM attestations attached by normal main CI
cosign download attestation ghcr.io/<owner>/chancela-server@sha256:<digest>
docker buildx imagetools inspect ghcr.io/<owner>/chancela-server@sha256:<digest>
```

### Verify desktop artifact signatures

```sh
# Windows Authenticode (on Windows)
signtool verify /pa /v Chancela_<version>_x64_en-US.msi

# macOS code signature + notarization (on macOS)
codesign --verify --deep --strict --verbose=2 Chancela.app
spctl --assess --type execute --verbose Chancela.app
```

Each run also uploads machine-readable server, worker, and search-projector
signing-status documents plus desktop status documents as workflow artifacts.
They record the publication run, signing run, exact digest, signer, and
image-set binding behind any positive claim. The status schema keeps the
publication/signature subject (`tagDigest`) distinct from the BuildKit
attestation subject (`platformDigest`).

Normal CI also uploads server, worker, and search-projector publication-status
documents. All three
declare `releaseTrust.mode=published-unsigned`; publication and BuildKit
attestations must never be read as evidence of a cosign signature. The workflow
is complete only when it is green and the validated `chancela-image-set.json`
artifact contains all three `repository@sha256:…` references.

---

## Design notes

- The default `ci.yml` (Docker build + smoke) and `release.yml` (packaging) jobs
  intentionally carry **no** signing commands and always record an honest
  unsigned status. The final `publish-ghcr` job depends on every required CI job
  and runs only for a successful `main` push. It publishes all three images with
  `published-unsigned` declarations using their exact verified tag digests.
  Builds are pushed by canonical digest first; full-SHA tags are reconciled only
  after all three builds exist, and an existing tag is preserved only when its
  source/platform contract matches. These contracts are enforced by a static
  guard in `scripts/check-release-trust.mjs`; signing remains isolated to the
  opt-in workflow.
- The signing workflow downloads the exact successful main-CI image-set
  artifact with a pinned `actions/download-artifact`, then signs all three
  digest references. It contains no image builder, image push, tag write,
  `imagetools`, or replacement `cosign attest` command.
- Action versions are pinned, including `sigstore/cosign-installer@v4.1.2`,
  `docker/login-action@v4.4.0`, and `actions/download-artifact@v8.0.1`.
- The recorded trust status is derived from what actually ran, not hardcoded. A
  missing identity yields a skipped step and an unsigned record — never a false
  signed claim.
