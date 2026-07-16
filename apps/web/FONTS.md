# Bundled web fonts

The web and desktop UI bundle four Google Fonts families locally through Fontsource. Vite emits
the selected Latin-subset WOFF2 files into the application build; the app makes no runtime font
request and remains typographically complete offline (UX-03).

| Role | Family | Fontsource package | Version | Copyright |
| --- | --- | --- | --- | --- |
| Body / formal UI | Noto Serif | `@fontsource/noto-serif` | 5.2.9 | Copyright 2022 The Noto Project Authors |
| UI sans | Noto Sans | `@fontsource/noto-sans` | 5.2.10 | Copyright 2022 The Noto Project Authors |
| Technical / digest | Noto Sans Mono | `@fontsource/noto-sans-mono` | 5.2.10 | Copyright 2022 The Noto Project Authors |
| Editorial display | Playfair Display | `@fontsource/playfair-display` | 5.2.8 | Copyright 2017 The Playfair Display Project Authors; Reserved Font Name “Playfair Display” |

All four packages declare the SIL Open Font License 1.1. The repository keeps the complete license
text at [`../../crates/chancela-doc/assets/fonts/OFL.txt`](../../crates/chancela-doc/assets/fonts/OFL.txt).
The Noto Serif family is intentionally shared with the existing PDF/A font asset documented at
[`../../crates/chancela-doc/assets/fonts/PROVENANCE.md`](../../crates/chancela-doc/assets/fonts/PROVENANCE.md),
while the web uses Fontsource's browser-optimised WOFF2 build. Package metadata points to the
upstream [Google Fonts repository](https://github.com/google/fonts); the Playfair Display source is
the [Playfair Display project](https://github.com/clauseggers/Playfair-Display).

Only the weights imported in `src/main.tsx` are shipped. Do not replace these imports with CDN
stylesheets: offline parity and privacy are release requirements.
