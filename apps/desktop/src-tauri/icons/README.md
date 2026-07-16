# Desktop icons

`tauri.conf.json` references the standard Tauri icon set:

```
icons/32x32.png
icons/128x128.png
icons/128x128@2x.png
icons/icon.icns
icons/icon.ico
```

These platform-specific files are committed so a clean checkout can build and bundle the app.
They are generated from one canonical, project-authored vector:

- **`icon-source.svg`** — the production Chancela mark, derived from the established web favicon
  and the dark-green, parchment, and gilt tokens in `apps/web/src/theme.css`. Its `C` is a vector
  path rather than a system-font glyph, so generation is deterministic on every platform.

The artwork is original to this project and covered by the repository license; it has no external
logo or font dependency.

## Generate the icon set (run once before building)

From `apps/desktop`:

```bash
npm install                 # brings in @tauri-apps/cli
npx tauri icon src-tauri/icons/icon-source.svg
```

This refreshes every size/format Tauri needs (the five paths above, Windows Store logos, and
Android/iOS assets). Commit all generated derivatives with the source so CI and release builders
consume exactly the reviewed artwork.

Regenerate whenever `icon-source.svg` changes.
