# Build iteration

Chancela keeps the broad release and CI gates intact, but day-to-day compilation
does not need to start at the broadest surface.

## Measure before tuning

From the repository root, run:

```console
npm run measure:rust-build
```

The default `server` mode runs the locked `chancela-server` check twice against
an isolated Cargo target directory. The first result starts with an empty
target; the second is an unchanged warm build. It deliberately preserves the
shared Cargo registry, Git dependency cache, and installed toolchain, so the
report calls the first measurement `clean target`, not a brand-new-machine
build. It never runs `cargo clean` against the normal workspace target.

Broader compile surfaces are available when that is the question being
measured:

```console
node scripts/measure-rust-build.mjs --mode workspace
node scripts/measure-rust-build.mjs --mode tests
node scripts/measure-rust-build.mjs --mode server --keep-target
```

Reports are written under ignored `dist/build-iteration/` as JSON and include
the exact command, toolchain, platform, Git revision and worktree state, both
durations, and the warm speedup. Successful temporary targets are removed unless
`--keep-target` is supplied. A failed target is retained for diagnosis.

Compare results only on the same machine, power profile, toolchain, and source
revision. Run the command more than once and use a median before making a build
configuration decision; antivirus scans and concurrent linker work can dominate
a single Windows sample.

## Current compile boundaries

- Development and test profiles keep line tables while omitting duplicated
  variable/type debug records. Set `CARGO_PROFILE_DEV_DEBUG=full` or
  `CARGO_PROFILE_TEST_DEBUG=full` only for a debugging session that needs local
  variables.
- The API integration suites are explicit Cargo test targets instead of dozens
  of auto-discovered binaries. This avoids repeatedly linking the complete
  service graph while preserving the test cases.
- PostgreSQL, Redis, SQLCipher, live network seams, hardware seams, and server
  E2E support remain opt-in features. Normal local checks do not compile those
  provider graphs; dedicated CI jobs still compile or execute every supported
  seam.
- The desktop Tauri crate remains outside the server workspace because it has a
  separate lockfile, target directory, platform matrix, and packaging lifecycle.
- Web application and Vite configuration typechecks retain separate incremental
  build-info files. Vite still transforms the production bundle after typecheck;
  removing either pass would weaken a gate rather than optimize it.

Use `cargo check -p <changed-crate> --locked` while iterating on a leaf crate,
then run the owning focused tests. Before integration, run the full lint, test,
and release build commands documented in the root `package.json`.

## CI topology

Cargo caches stay separated where the operating system, profile, feature set,
instrumentation, or standalone desktop workspace differs. Sharing those target
trees aggressively produces large low-hit caches and can make feature leakage
harder to reason about.

The core and full Chromium jobs are an exception: both execute the same Linux
release `chancela-server` at the same commit. CI builds that binary once,
uploads it as a one-day artifact, and lets both browser suites consume it in
parallel. The web bundle and both Playwright suites are still built and run in
their original jobs; only the duplicate Rust release compilation is removed.

Coverage, SQLCipher, Postgres, live-seam, E2E-feature, and release compilation
remain separate because they prove different compiler inputs or instrumentation.
