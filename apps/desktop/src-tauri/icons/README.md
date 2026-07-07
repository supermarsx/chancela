# Desktop icons

`tauri.conf.json` references the standard Tauri icon set:

```
icons/32x32.png
icons/128x128.png
icons/128x128@2x.png
icons/icon.icns
icons/icon.ico
```

These platform-specific files are **not committed** — they are generated from a
single source image. This repo ships only the source:

- **`icon-source.png`** — a 1024×1024 placeholder mark (dark-green editorial
  seal, per the spec-10 theme). Replace it with the real brand artwork when
  available.

## Generate the icon set (run once before building)

From `apps/desktop`:

```bash
npm install                 # brings in @tauri-apps/cli
npx tauri icon src-tauri/icons/icon-source.png
```

This produces every size/format Tauri needs (the five paths above plus the
Windows Store logos) into this directory. A full `tauri build` — and, on some
platforms, `tauri dev` — requires these files to exist, which is why generation
is a prerequisite step rather than something committed to git.

Regenerate whenever `icon-source.png` (or the brand artwork replacing it)
changes.
