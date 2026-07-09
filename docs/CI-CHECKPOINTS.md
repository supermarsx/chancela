# CI Checkpoints

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
