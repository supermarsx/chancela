# Bundled ICC profile — provenance (t48-e2 OutputIntent)

## sRGB-v2-micro.icc

- **What:** a compact sRGB display profile used as the PDF/A-2 OutputIntent `DestOutputProfile`.
- **ICC header (verified):** device class `mntr`, data colour space `RGB ` (**N = 3**), PCS `XYZ `,
  ICC version 2.1, `acsp` signature present. A 3-channel RGB profile — matches the `/N 3`
  declared on the ICC stream and permits `DeviceGray`/`DeviceRGB` under the intent.
- **License:** **CC0 1.0 Universal (public domain dedication)** — see `COMPACT-ICC-LICENSE.txt`.
  Freely embeddable and redistributable without restriction.
- **Why not color.org `sRGB2014.icc`:** the cheatsheet's first choice; color.org served an HTML wall
  (not the binary) at build time from every probed path, and the GitHub mirrors 404'd. The
  saucecontrol Compact-ICC-Profiles `sRGB-v2-micro` is a modern, minimal (456 B), CC0, 3-channel
  RGB v2 profile purpose-built for embedding and routinely accepted by veraPDF as a valid PDF/A
  OutputIntent — a clean, license-simpler substitute. (Avoids the legacy HP/Microsoft blob the
  cheatsheet warns against.)

### Source
- **URL:** https://github.com/saucecontrol/Compact-ICC-Profiles/raw/master/profiles/sRGB-v2-micro.icc
- **Downloaded:** 2026-07-08
- **Size:** 456 bytes
- **sha256:** `0a8a33aea66a6f154a5642ebe168ef287e73265d9f7b51c42a45e6eedbacda7a`

### COMPACT-ICC-LICENSE.txt (CC0 1.0)
- **URL:** https://raw.githubusercontent.com/saucecontrol/Compact-ICC-Profiles/master/license
- **Size:** 6552 bytes
