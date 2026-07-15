# Versioning

Chancela uses a **CalVer** scheme: **`YY.N`**, where

- `YY` — the two-digit release year (e.g. `26` for 2026).
- `N` — the release number within that year, starting at `1` and **resetting to `1`
  each new year**.

The current release is **`26.1`** (the first 2026 release).

## Manifest form vs. display form

Cargo, npm, and Tauri all require a three-part [SemVer](https://semver.org) string,
so `YY.N` on its own is invalid there. Every machine-parsed manifest therefore pins
the canonical **`YY.N.0`** form:

| Surface | Value |
| --- | --- |
| `Cargo.toml` (`[workspace.package] version`) | `26.1.0` |
| `apps/web/package.json`, root `package.json`, `apps/desktop/package.json` (+ their `package-lock.json`) | `26.1.0` |
| `apps/desktop/src-tauri/tauri.conf.json` and `src-tauri/Cargo.toml` | `26.1.0` |

User-facing surfaces (the Settings → "Sobre" screen, crash diagnostics, any version
label) show the shorter **`YY.N`** form — the trailing `.0` is stripped for display by
`displayVersion()` in `apps/web/src/api/versionCheck.ts`. The underlying values used for
version-skew checks stay in the full `YY.N.0` form.

## Bumping the version

- Another release in the same year: increment `N` (`26.1` → `26.2`, manifest
  `26.2.0`).
- First release of a new year: reset `N` to `1` and roll `YY` (`26.4` → `27.1`,
  manifest `27.1.0`).

Update every manifest in the table above (keep the `.0` patch), plus the lockfile
root `version` fields, together in one change.

> **Not covered by this scheme:** the HTTP API path version (`/v1/...`) and the paper-import
> OCR `engine_version` are independent contract versions and are **not** tied to the app
> release version.
