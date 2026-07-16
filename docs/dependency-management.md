# Dependency management

Chancela keeps production and build dependencies reproducible while still
receiving scheduled update proposals. Dependabot runs every Monday and the
normal CI gates validate every proposed update.

## Runtime and compiler floor

The workspace, standalone Tauri crate, CI action, and container builders use
Rust 1.97. Their `rust-version` declarations are also 1.97, so a dependency
update cannot compile in CI while claiming an older unsupported floor. The
supply-chain policy gate checks both Rust manifests against the pinned
toolchain. The S3 connector pins `aws-sdk-s3` 1.138.0 and selects its current
HTTP 1.x default HTTPS client; the legacy `rustls` feature is deliberately
absent because it activates the older Hyper 0.14 / rustls 0.21 compatibility
stack.

For an update sweep, run:

```console
cargo outdated --workspace --depth 1
cargo update
cargo check --workspace --all-targets --locked
cargo audit
```

The web workspace currently uses TypeScript 6.0.3 even though 7.0.2 is the
newest published compiler. This is an upstream compatibility hold, not an
overlooked update: the current `typescript-eslint` 8.64.0 release declares a
TypeScript peer range of `>=4.8.4 <6.1.0`. The dependency sweep must revisit
TypeScript 7 as soon as that maintained lint stack publishes support; forcing
the major today would install an unsupported peer graph and invalidate the
lint gate.

The SFTP connector uses `russh` without its optional RSA feature. It accepts
only fingerprint-pinned Ed25519 or ECDSA server host keys; operators of an
RSA-only SSH server must rotate or add a modern host key before enabling the
connector.

## Automated coverage

| Ecosystem | Dependabot directory | Lock or manifest boundary |
| --- | --- | --- |
| npm | `/` | Root lockfile and the `apps/web` workspace |
| npm | `/apps/desktop` | Standalone Tauri desktop frontend lockfile |
| Cargo | `/` | Root Rust workspace and `Cargo.lock` |
| Cargo | `/apps/desktop/src-tauri` | Standalone desktop Rust workspace and lockfile |
| pip | `/` | `requirements-docs.in` and the hash-locked `requirements-docs.txt` |
| GitHub Actions | `/` | Every workflow action reference under `.github/workflows` |
| Docker | `/` and `/docker` | Root and server Dockerfiles and Compose image references |

Minor and patch library updates are grouped by lockfile boundary to keep the
review queue manageable. Major npm, Cargo, and Python updates remain separate
so breaking changes receive focused review. Action and container-image updates
are grouped within their own scopes.

## Immutable CI and image references

Third-party actions are referenced by full commit SHA, with the human-readable
release next to each reference. Dependabot updates the SHA and version comment
together. Container build inputs use an exact release tag plus a multi-platform
digest; this gives reviewers both version intent and immutable bytes.

The normal server image and the hardened image follow the same digest-pinning
policy. Compose also pins security-sensitive helper images. An update is not
complete until CI has rebuilt the image and the Docker smoke gate has passed.

## Documentation lockfile

`requirements-docs.in` contains the direct documentation dependency. Compile
the lock under Python 3.14 on Linux (the same platform and compiler used by
CI); pip-tools can emit different `# via` annotations for conditional Windows
dependencies even when the resolved artifacts and hashes are identical:

```console
python -m pip install --upgrade pip==26.1.2
python -m pip install pip-tools==7.5.3
pip-compile --generate-hashes --strip-extras --resolver=backtracking requirements-docs.in
```

CI regenerates the lockfile, rejects any diff, installs it with
`--require-hashes`, and renders the complete site with `mkdocs build --strict`.

## Time-bounded RustSec exception

The raw Cargo audit currently contains exactly one accepted, upstream-unfixed
finding: `RUSTSEC-2023-0071` for `rsa` 0.9.10. Its remaining affected private
operation is RSA software-certificate signing through the PKCS#12 path. That
signer is exposed through authenticated API routes, so remote timing can be
observable; the RustSec local-only timing workaround is **not** claimed as a
complete mitigation. RSA public encryption used by CMD and public signature
verification do not expose an RSA private-key timing oracle.

Until the upstream implementation is fixed or replaced, prefer ECDSA P-256,
smartcard signing, CMD/CSC/SCAP remote signing, or a network-isolated deployment
for software RSA certificates. The exception has a mandatory review date of
**2026-08-31**.

CI always uploads the unfiltered `cargo-audit-raw.json`. The policy checker
accepts only the exact tuple `RUSTSEC-2023-0071` / `rsa` / `0.9.10`, rejects any
additional advisory, rejects version drift, and fails when the review date
expires. Once upstream changes, the checker intentionally fails until this
exception and its documentation are removed or explicitly re-reviewed.

## Manual update boundaries

Dependabot does not manage every version-looking value in this repository.
In particular, it does not currently update:

- the Rust release in `rust-toolchain.toml`;
- command-line tool versions embedded in workflow shell steps, such as
  `cargo-audit`;
- container references used inside workflow shell commands rather than in a
  Dockerfile or Compose model, such as the Syft and Trivy scan images;
- the Python and Node runtime versions declared directly in workflow matrices.

Review these values during the scheduled dependency sweep. When one changes,
update its associated documentation, immutable digest or action SHA, and run
the same CI/checkpoint gates that protect an automated update.
