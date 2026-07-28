# Versioning

Chancela uses a **CalVer** scheme: **`YY.N`**, where

- `YY` — the two-digit release year (e.g. `26` for 2026).
- `N` — the release number within that year, starting at `1` and **resetting to `1`
  each new year**.

The release record is the **git tag list**: every release is a `vYY.N` tag. The
manifests below are set to match the tag being cut, so the newest `vYY.N` tag and
the manifests always agree between releases.

## Manifest form vs. display form

Cargo, npm, and Tauri all require a three-part [SemVer](https://semver.org) string,
so `YY.N` on its own is invalid there. Every machine-parsed manifest therefore pins
the canonical **`YY.N.0`** form:

| Surface | Gated by `check:versions` |
| --- | --- |
| root `package.json` | yes |
| `apps/web/package.json` | yes |
| `apps/desktop/package.json` | yes |
| `Cargo.toml` (`[workspace.package] version`) | yes |
| `apps/desktop/src-tauri/Cargo.toml` (`[package] version`) | yes |
| `apps/desktop/src-tauri/tauri.conf.json` | yes |
| root `package-lock.json` (top-level `version` and every local `packages` entry) | no |
| `apps/desktop/package-lock.json` (same) | no |

`npm run check:versions` gates that the first six agree. The two lockfiles are
not covered by that gate, so the release automation rewrites all eight together
and `scripts/release-version.test.mjs` asserts its file list stays a superset of
the six.

User-facing surfaces (the shell footer, the Settings → "Sobre" screen, crash diagnostics,
any version label) show the shorter **`YY.N`** form — the trailing `.0` is stripped for display by
`displayVersion()` in `apps/web/src/api/versionCheck.ts`. The underlying values used for
version-skew checks stay in the full `YY.N.0` form.

## Cutting a release

Releases are cut by `.github/workflows/auto-release.yml`. Bumping is **not** a
manual multi-manifest edit; the only manual part is deciding that a release
happens.

There are two ways to make that decision:

- **Run the `Auto release` workflow** (`workflow_dispatch`). It takes a `dry_run`
  input that computes the release and prints the manifest edits without
  committing, tagging or packaging anything.
- **Push to `main` with a `Release: yes` trailer** on the head commit:

  ```
  feat(archive): add the retention export

  Release: yes
  ```

`main` takes well over a hundred commits on a busy day, so releasing on every
green push would burn `26.1 … 26.160` in a day and make the number meaningless in
a product that prints its version in the About tab and alongside evidentiary
documents. The trailer is what keeps the scheme "automatic" without spending
numbers on commits that are not releases.

Everything after the trigger is automatic: compute the next `YY.N`, rewrite all
eight manifests, verify with `check:versions`, commit, tag `vYY.N`, push, and
hand the tag to `release.yml` for packaging.

To preview a release locally:

```
npm run release:dry-run
```

## How the next version is computed

`scripts/release-version.mjs` derives the release from the **existing git tags**,
never from the manifests — manifests can drift through a bad merge or a hand
edit, whereas a tag is the artefact a release was built from. The rules, all
covered by `npm run test:release-version`:

- `YY` is the two-digit build year.
- `N` is one past the highest `N` **already tagged for that year**, so the first
  release of a new year resets to `1`. If the last release of 2026 is `v26.7`,
  the first release of 2027 is `v27.1`, not `v27.8`.
- Sequences are compared numerically, so `v26.9` is followed by `v26.10`.
- Tags outside the `vYY.N` namespace (`v1.2.3`, `nightly-2027-03-01`) are ignored.
- Tags **inside** the namespace that are not canonical (`v26.1.0`, `v26.01`,
  `v26.0`) are an error, not a skip: any one of them may record a real past
  release, and ignoring it would re-issue a number that has already shipped.
- It refuses to overwrite an existing tag, and refuses to move backwards — both
  when a tag from a later year exists and when the manifests are already ahead of
  the computed release.

A release whose manifests already carry the computed version is valid: the tag is
created and there is simply nothing to commit. That is the shape of the first
release, `v26.1`.

## Why the bump commit cannot re-trigger a release

The release job pushes a bump commit to `main`, and `main` is a release trigger.
Four independent guards stop that from cutting another release, each sufficient
on its own:

1. The bump commit carries **no `Release: yes` trailer**, and a push only
   releases when the head commit has one.
2. Its subject carries **`[skip ci]`**, which the gate rejects (and which GitHub
   itself honours by not starting a run).
3. The pushing actor is **`github-actions[bot]`**, which the gate rejects.
4. Structurally, a push made with `GITHUB_TOKEN` **does not create workflow
   runs** at all.

Guard 4 is also why `auto-release.yml` calls `release.yml` through
`workflow_call` instead of relying on its `push: tags` trigger, passing the new
tag as the `ref` input so the packaged artefacts carry the version just tagged
rather than the caller's pre-bump `main`.

> **Not covered by this scheme:** the HTTP API path version (`/v1/...`) and the paper-import
> OCR `engine_version` are independent contract versions and are **not** tied to the app
> release version.
