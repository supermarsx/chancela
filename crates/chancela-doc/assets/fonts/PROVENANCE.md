# Bundled font — provenance (t48-e2a, UX-03)

## NotoSerif-Regular.ttf

- **Family / face:** Noto Serif, Regular (static instance, TrueType `glyf` outlines).
- **License:** SIL Open Font License, Version 1.1 — see `OFL.txt` (verbatim, shipped alongside).
- **Why this face:** libre, OFL-1.1 (permits embedding in documents **and** redistribution with
  software), TrueType/`glyf` outlines (embeds as `/FontFile2` / `CIDFontType2` — the simplest path
  for a hand-rolled PDF writer), full pt-PT Latin coverage (ã õ ç á à â é ê í ó ô ú, «», …).
- **Key metrics** (read from the file): `unitsPerEm = 1000` (font units map 1:1 onto PDF glyph
  space), `FontBBox = [-693 -389 2797 1048]`, ascent `1069`, descent `-293`, capHeight `714`,
  numGlyphs `3691`, italicAngle `0`, weightClass `400`. cmap has a format-4 `(3,1)` Unicode subtable.

### Source
- **URL:** https://github.com/googlefonts/noto-fonts/raw/main/hinted/ttf/NotoSerif/NotoSerif-Regular.ttf
- **Downloaded:** 2026-07-08
- **Size:** 616196 bytes
- **sha256:** `c8f669ceb2c9c60ccf55198b305e08a997ffca79a38cc7eeb551e643cbe66505`

### OFL.txt
- **URL:** https://github.com/googlefonts/noto-fonts/raw/main/LICENSE
- **Size:** 4377 bytes
- **sha256:** `0dab92d0544f7b233403f14b84a663bdbfa746982eda629e7f4f9ffe1b036feb`

## Notes
- The **whole** font program is embedded verbatim as `/FontFile2` (no subsetting in v1); PDF/A
  permits full embedding. Because it is a full, unmodified embed, the `/BaseFont` is the plain name
  `NotoSerif` with **no subset prefix** (a `ABCDEF+` prefix must appear only for an actual subset;
  veraPDF checks this). The bytes are unmodified, so the OFL rule against reusing the Reserved Font
  Name on a modified program does not apply.
- Bold/Italic faces are a fast-follow (UX-04 is single-weight for v1); bold/italic runs are
  synthesized in the content stream (stroke for bold, text-matrix shear for italic).
