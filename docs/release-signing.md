# Release signing, notarization & provenance

This page documents the **opt-in signing pipeline** for Chancela release
artifacts: the container image, the desktop/binary artifacts, and the release
SBOM.

The pipeline lives in
[`.github/workflows/release-signing.yml`](https://github.com/supermarsx/chancela/blob/main/.github/workflows/release-signing.yml)
and is deliberately **separate** from the default `ci.yml` and `release.yml`
pipelines. Those two build and package artifacts but never sign them; they always
record an honest `unsigned-dev` / `local-ci` trust status. This workflow is the
single place where signing is activated.

## Current default state

**By default, nothing is signed.** With no signing identity configured, the
signing workflow:

- does **not** push the container image to any registry,
- does **not** sign the image or produce an attestation,
- does **not** code-sign or notarize desktop/binary artifacts,
- records an honest `unsigned` / `not_pushed` / `not_attested` / `not_notarized`
  status for every artifact.

Signing happens **only** when you supply the real credentials below, and the
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

### 1. Container image signing + SBOM attestation (cosign)

Signs the pushed image with [cosign](https://github.com/sigstore/cosign) and
attaches a CycloneDX SBOM attestation. The `docker/build-push-action` build also
emits build **provenance** and an **SBOM** attestation via BuildKit
(`provenance: true`, `sbom: true`).

Two mutually exclusive signing modes are supported. Both require a registry
target:

| Setting | Type | Purpose |
| --- | --- | --- |
| `RELEASE_IMAGE_REPOSITORY` | variable | Fully-qualified image repository to push to, e.g. `ghcr.io/<owner>/chancela-server`. Required to enable any push/sign. |
| `RELEASE_SIGNING_COSIGN_KEYLESS` | variable | Set to `true` to sign **keyless** with GitHub OIDC (Fulcio/Rekor). No private key to manage. Recommended for GitHub Actions. |
| `COSIGN_PRIVATE_KEY` | secret | A cosign private key (PEM). Enables **key-based** signing when keyless is not turned on. |
| `COSIGN_PASSWORD` | secret | Password for the cosign private key (if the key is encrypted). |
| `REGISTRY_USERNAME` / `REGISTRY_PASSWORD` | secrets | Registry credentials. Optional for GHCR — the built-in `GITHUB_TOKEN` (with `packages: write`) is used by default. |

- **Keyless (recommended):** set `RELEASE_IMAGE_REPOSITORY` and
  `RELEASE_SIGNING_COSIGN_KEYLESS=true`. The workflow requests an OIDC token
  (`id-token: write`) and signs with the workflow's own identity.
- **Key-based:** set `RELEASE_IMAGE_REPOSITORY` and add `COSIGN_PRIVATE_KEY`
  (and `COSIGN_PASSWORD` if encrypted). Generate a key pair with
  `cosign generate-key-pair`.

If neither mode is configured, the image is not pushed and the container status
is recorded as `unsigned` / `not_pushed` / `not_attested`.

### 2. Desktop / binary code signing

The `desktop` job downloads the artifacts of an existing release (the tag that
triggered the run, or the `release_tag` workflow input) and signs them per
platform.

**Windows Authenticode:**

| Secret | Purpose |
| --- | --- |
| `WINDOWS_CODE_SIGN_PKCS12_BASE64` | Base64-encoded PKCS#12 (`.pfx`) code-signing certificate. Enables Windows signing. |
| `WINDOWS_CODE_SIGN_PASSWORD` | Password for the PKCS#12 file. |

When present, `signtool` signs each `*.exe` / `*.msi` with a SHA-256 digest and
RFC-3161 timestamp. When absent, the step is skipped and the artifact is recorded
as `unsigned`.

**macOS codesign + notarization:**

| Secret | Purpose |
| --- | --- |
| `APPLE_CERTIFICATE` | Base64-encoded Developer ID Application certificate (`.p12`). Enables macOS signing. |
| `APPLE_CERTIFICATE_PASSWORD` | Password for the `.p12`. |
| `APPLE_SIGNING_IDENTITY` | The signing identity name, e.g. `Developer ID Application: Example (TEAMID)`. |
| `APPLE_ID` | Apple ID used for notarization. |
| `APPLE_APP_SPECIFIC_PASSWORD` | App-specific password for `notarytool`. |
| `APPLE_TEAM_ID` | Apple Developer team identifier. |

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

### Verify the SBOM / provenance attestation

```sh
# CycloneDX SBOM attestation produced by `cosign attest`
cosign verify-attestation --type cyclonedx \
  --certificate-identity-regexp 'https://github.com/<owner>/chancela/.github/workflows/release-signing.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/<owner>/chancela-server@sha256:<digest>

# BuildKit provenance / SBOM attestation attached to the image
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

Each run also uploads machine-readable status documents
(`container-signing-status.json`, `desktop-signing-status-<platform>.json`) as
workflow artifacts. They record the trust state and the evidence anchors behind
any positive claim.

---

## Design notes

- The default `ci.yml` (Docker build + smoke) and `release.yml` (packaging) jobs
  intentionally carry **no** signing commands and always record an honest
  unsigned status; this is enforced by a static guard in
  `scripts/check-release-trust.mjs`. Signing is isolated to this opt-in workflow.
- Action versions are pinned (`sigstore/cosign-installer@v4.1.2`,
  `docker/build-push-action@v7.3.0`, `docker/login-action@v4.4.0`,
  `anchore/syft:v1.9.0`, and the `actions/*@v4` set).
- The recorded trust status is derived from what actually ran, not hardcoded. A
  missing identity yields a skipped step and an unsigned record — never a false
  signed claim.
