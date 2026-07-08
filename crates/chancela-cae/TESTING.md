# Testing `chancela-cae`

## What runs offline (CI, zero network)

```
cargo test  -p chancela-cae
cargo clippy -p chancela-cae --all-targets -- -D warnings
cargo clippy -p chancela-cae --all-targets --features network-tests -- -D warnings
cargo fmt   -p chancela-cae --check
```

| Test file | Covers |
|---|---|
| `tests/fidelity.rs` | **The fidelity gate.** Per-level structural counts equal the official totals for both revisions (asserted against the shared `EXPECTED_REV{3,4}_COUNTS` the obtainer also uses); every node chains to a secção; ~20 spot-check codes resolve to their exact official designations; the one reconstructed node (Rev.3 group 843) is present; the embedded catalog passes `verify_fidelity`. |
| `tests/catalog.rs` | `lookup` (case-insensitive secções, Rev.4-first / Rev.3-fallback), `hierarchy`, `children`, accent/case-folded `search` (limit + revision filters). |
| `tests/cache.rs` | `CachedCae::is_stale` around the TTL; `load_catalog` returns `Embedded` with no/older/corrupt cache and `Cache` with a valid newer one; `write_cache_atomic` round-trip; `refresh` over `Bytes`/`File` sources writes + prefers the cache and is a no-op on identical data; corrupt update rejected (`Integrity`) / unparseable bytes rejected (`Parse`), embedded retained. |
| `tests/obtain.rs` | **The official-source obtainer** (`obtain/`), fully offline over the committed DR PDFs. `vendored_obtain_reproduces_official_table`: the in-app `lopdf` parser output equals the offline-generated embedded dataset — exact totals (1962/1847) AND byte-equal designations on ~27 spot codes (proves the Rust port = the pymupdf generator). `obtain_and_supersede` end-to-end; supersede swaps + writes the cache; identical data is a no-op; a structurally-valid but **short** parse and a structurally-**invalid** parse are both rejected (`Integrity`) and the known-good catalog is retained. |
| `tests/obtain_json.rs` | **Multi-format JSON obtain** (plan t23 §2.2–2.3). The **Simple JSON** mirror parser: the full official table hosted as a flat array with every `level`/`parent` **omitted** re-derives byte-identically (`simple_json_full_table_derives_and_passes_the_gates`) and clears integrity + fidelity; a **short** array fails fidelity; a **level-mismatch** and an **orphan parent** each fail integrity. **Format auto-detection**: `%PDF`→`Pdf`, `{`→`Envelope`, `[`→`SimpleJson`, garbage→`None`; a real envelope and a real Simple-JSON mirror each parse through `parse_artifact(Auto)`; a `%PDF` on the mirror path and malformed bytes are clear `Parse` errors. |
| `tests/obtain_chain.rs` | **The ordered source chain** (plan t23 §2.7) over in-memory (`Bytes`) mirrors: the **first superseding source wins** (later entries not applied; Mirror provenance stamped); a **failing entry is recorded and the chain falls through** to the next valid one; when **all sources fail** the known-good catalog is retained unchanged (on-disk + returned); an **up-to-date** source is valid but not a winner (not a failure). |
| `tests/obtain_smi.rs` | **The INE SMI version-catalog source** (user directive t33). Parses the checked-in real-capture export → extracts both current CAE versions (`V05497` Rev.4 / `V00554` Rev.3, resolved from the `Sigla`); `SmiSource` targets the reliable `/Versao/Exportacao` endpoint (never the 500-ing `/Categoria` tree); **`default_official_chain()` is INE-first then the digest-pinned DR pair** (`official_chain_for` orders by preference, DR always present; t37); `IneOfficialSource` always fails honestly; a non-SMI payload is a `Parse` error (never a silently-empty catalog). |
| lib unit (`obtain/smi.rs`) | The SMI parser internals: UTF-16LE+BOM fixture decode; a UTF-8 mirror of the same shape; only the two current CAE revisions resolve a `CaeRevision` (older revisions / NACE do not); a quoted designation containing a comma is one CSV field; a missing header and a header-without-rows are each `Parse` errors; `version_export_url` composition. |
| lib unit (`obtain/mod.rs`) | Digest pinning: the vendored PDFs' sha256 equal the pinned official `DR_REV{3,4}_PDF_SHA256` (so the committed files ARE the official artifacts) → obtain accepts; a wrong expected digest is rejected. |
| lib unit (`obtain/format.rs`) | `detect_format` per branch (PDF/object/array/none); `parse_artifact(Auto)` rejects garbage and a `%PDF` on the mirror path with a clear `Parse` error. |
| lib unit (`obtain/simple.rs`) | Simple-JSON parse: derives `level` + `parent` when absent (divisão ← most-recent secção, deeper ← code prefix); uses explicit `level`/`parent` verbatim; partitions both revisions by tag; an undecodable code shape and malformed JSON are `Parse` errors. |
| lib unit (`obtain/verify.rs`) | The **SICONF verifier seam** (plan t23 §2.6): the response **parser** resolves a code→designation from a TreeView node fragment and from the checked-in `fixtures/siconf_node.html` (exact node, not a prefix; absent code → `NotFound`); the **live transport is deferred** and returns a clear `Config` error. |
| `tests/network.rs` | The **live** fetches, double-gated (`#[cfg(feature = "network-tests")]` + `#[ignore]`): the dataset-envelope fetch (`CHANCELA_CAE_URL`); the **live DR diploma-PDF obtain** (`DrPdfSource::official()` → fetch + digest-pin + in-app parse → full official totals); the **live SMI version-catalog probe** (`SmiSource::official().fetch_catalog()` → the real `/Versao/Exportacao` export lists `V05497`/`V00554`); and the **SICONF live verifier skeleton** (marks the missing viewstate-postback capture — deferred). Compile under the feature, run 0 in CI. |

## Structural totals enforced (the gate)

| Revision | Secções | Divisões | Grupos | Classes | Subclasses | Total |
|---|---|---|---|---|---|---|
| CAE-Rev.4 | 22 | 87 | 287 | 651 | 915 | **1962** |
| CAE-Rev.3 | 21 | 88 | 272 | 616 | 850 | **1847** |

**Both revisions ship complete** — no one-revision fallback was needed. The counts are proven, not
asserted: they are computed from the embedded dataset and compared to the official Rev.4 totals and
the primary-source Rev.3 totals (class count 616 corroborated by INE — NACE-Rev.2's 615 + 1). See
`data/source/PROVENANCE.md`.

## Multi-format obtain engine (plan t23 §2)

The obtainer accepts several **pull mechanisms**, each auto-detected, all funnelling through the same
integrity + fidelity gates before anything may supersede the cache — so reliability is a property of
the pipeline, not any one feed:

| Mechanism | Format | How bytes become a dataset |
|---|---|---|
| **Diário da República diplomas** | PDF pair | `DrPdfSource` — both immutable diploma URLs, digest-pinned, parsed in-app (lopdf). The authoritative bulk source. |
| **Envelope JSON** | object | `CaeDataset` envelope at a URL (today's `cae_update_url`). |
| **Simple JSON** | array | the public flat `[{code, designation, revision, level?, parent?}]` mirror anyone can host — spec in `data/source/SIMPLE_JSON_SCHEMA.md`; `level`/`parent` derived when absent. |

**Auto-detection** (`detect_format` / `parse_artifact`) sniffs the leading bytes: `%PDF`→`Pdf`,
`{`→`Envelope`, `[`→`SimpleJson`. A `%PDF` on the mirror path is a deliberate error — the two-diploma
DR pair is obtained through the dedicated official source, never a single mirror URL.

**Ordered source chain** (`CaeSourceChain` / `obtain_from_chain`) tries entries in order — the
built-in official DR pair (`ChainEntry::official()`) and/or mirror URLs — and the **first dataset that
passes the gates and supersedes wins**. Per-entry failures are recorded (never abort the chain), and
the chain never destroys the known-good catalog. This is what the API's `cae_sources` setting drives.

**No-config default = the official chain.** When no update URL is configured, `default_official_chain()`
returns the built-in official chain — the digest-pinned DR diploma pair (`ChainEntry::official()`) —
so a refresh still obtains CAE Rev.3 + Rev.4 from the official gov source instead of erroring. This is
the fallback the API leg runs after any operator-configured mirrors.

**INE SMI version-catalog source** (`SmiSource` / `parse_smi_version_catalog`, plan t23 §1, user
directive t33) is an official **update-availability signal**, not a bulk catalog. Live investigation
of `smi.ine.pt` established the boundary: the CAE **node tree** (`/Categoria`, `/Categoria/Parent`,
`/Categoria/Exportacao`) returns **HTTP 500** for every anonymous access pattern (bare / with the
host's own `ASP.NET_SessionId` cookie / after visiting a version-detail page / with query params /
POST) — it only renders through the site's stateful interactive flow, so the codes cannot be crawled
reliably or politely. What SMI *does* serve cleanly (cold, cookieless, `Transfer-Encoding: chunked` —
so no duplicate-`Content-Length` hazard, which is confined to the 500 pages) is the **version
catalog** at `/Versao/Exportacao?tipo={0,1,2}`: the list of classification versions, including
`V05497` (CAE Rev.4) and `V00554` (CAE Rev.3). `SmiSource` fetches + parses that (UTF-16LE+BOM CSV) to
report which CAE version INE currently publishes — a real update signal to compare against the
embedded dataset. It deliberately does **not** implement `OfficialCaeSource` (it cannot supply the
codes a fidelity-passing dataset needs), so it is not a bulk chain entry.

**SICONF per-code verifier** (`CaeVerifier` / `SiconfVerifier`) is a spot-check enricher, **never a
catalog builder** (SICONF is a postback-only WebForms tree with no bulk export). The **response
parser** is shipped and tested against `fixtures/siconf_node.html`; the **live viewstate transport is
deferred** (documented `todo`, `#[ignore]` skeleton in `tests/network.rs`).

## Environment variables

| Var | Used by | Meaning |
|---|---|---|
| `CHANCELA_CAE_URL` | `HttpCaeSource::from_env`, `spawn_background_refresh` | URL of a dataset (the `CaeDataset` envelope JSON). **No default** — there is no official CAE feed, so this is an ops decision. |
| `CHANCELA_DATA_DIR` | the binaries wiring `load_catalog`/`spawn_background_refresh` | data dir holding `cae-catalog.json` (the cache). A valid cache newer than the embedded build is preferred. |

## Validating the live auto-update (honest boundary)

There is no official machine-readable CAE feed, so the *live remote* is deferred exactly like
`chancela-registry`'s live certidão path: the mechanism (fetch → integrity → cache write →
cache-preferred load) is fully built and exercised against `Bytes`/`File`/local sources; only the
default remote is an ops decision. To validate the network leg end to end, serve the dataset over
HTTP and point the env var at it:

```
# 1. produce a dataset envelope to serve (both embedded arrays + metadata):
cargo run -p chancela-cae --bin gen_cae            # prints the embedded counts + digest
# 2. serve any valid CaeDataset JSON (e.g. a cache-catalog.json or fixtures/cae_update.json):
python -m http.server 8099 --directory fixtures    # exposes /cae_update.json
# 3. run the double-gated live test:
CHANCELA_CAE_URL=http://127.0.0.1:8099/cae_update.json \
  cargo test -p chancela-cae --features network-tests -- --ignored --nocapture
```

The dataset envelope, parser and cache localise any real-feed change to the dataset file — no
API/UI contract churns when a new revision or a corrected table is published.

## Regenerating the embedded dataset

The embedded `data/cae_rev3.json` / `data/cae_rev4.json` are generated from the two vendored
official DR PDFs by the committed, reproducible generator. Coordinate-based PDF table extraction
needs a PDF engine, so the transform is a documented Python step (the raw PDFs are vendored for
offline audit):

```
pip install pymupdf
cd crates/chancela-cae/data/source
python gen_cae.py --rev3-pdf rev3.pdf --rev4-pdf rev4.pdf --out-dir ..
```

`gen_cae.py` self-validates (no duplicate codes, every parent resolves, prefix relationships hold)
and refuses to write on any failure. The pure-cargo `gen_cae` binary re-validates a dataset through
the crate's own integrity path and prints its counts + digest, so it doubles as a regeneration
guard:

```
cargo run -p chancela-cae --bin gen_cae               # verify the embedded dataset
cargo run -p chancela-cae --bin gen_cae -- some.json  # verify a candidate dataset file
```

## The in-app official-source obtainer (`obtain/`)

The `obtain/` module fetches an OFFICIAL artifact, parses it, and — only if it passes structural
integrity **and** the full-count fidelity gate — supersedes the cache exactly like `refresh`, so a
bad parse can never corrupt the active catalog. The one shipped source is `DrPdfSource`: the two
immutable, digest-pinned Diário da República diploma PDFs (CAE-Rev.4 = DL 9/2025, CAE-Rev.3 =
DL 381/2007).

**PDF engine = pure-Rust `lopdf`, no native library** (coordinator ruling; `pdfium-render` is the
documented escalation, not used). `obtain/pdf.rs` is a faithful port of `data/source/gen_cae.py`: it
runs the text-positioning subset of the PDF imaging model (`Tm`/`Td`/`TD`/`T*`/`Tj`/`TJ` + glyph
widths + `ToUnicode` decoding) over the content streams to recover pymupdf-equivalent positioned
"words", then applies the identical level-from-code-shape / structural-parent / group-843
reconstruction logic. The default build stays native-dep-free — the same binary ships the obtainer
on every platform, with no per-platform `pdfium` binary to acquire in CI/Docker/Tauri.

The obtainer is **operator-initiated only** (endpoint/UI), never at startup, so nothing new runs
offline or when the network is down.

### Validating the live DR obtain (honest boundary)

The offline `tests/obtain.rs` parses the **committed real PDFs** (`data/source/rev{3,4}.pdf`) — the
identical artifacts to the pinned official URLs (a test asserts their sha256 equal
`DR_REV{3,4}_PDF_SHA256`), so CI fully exercises the parser. The **live network fetch** is
double-gated exactly like the certidão path:

```
cargo test -p chancela-cae --features network-tests -- --ignored --nocapture
```

`live_dr_pdf_obtain` fetches both diploma PDFs from their immutable URLs, digest-verifies them,
parses in-app, and asserts the full official totals (1962/1847).

## Honest boundaries recorded

- **No official CAE JSON feed** — `CHANCELA_CAE_URL` has no default; the live remote is deferred and
  validated only when a real dataset URL is supplied (above). The DR diploma PDF is the reliable
  *official* obtainer target (`DrPdfSource`), and `default_official_chain()` makes it the no-config
  default so a refresh never errors for want of a URL.
- **INE SMI is an update signal, not a bulk source** (live-probed, user directive t33; see
  `src/obtain/smi.rs`). Its CAE **node tree** (`/Categoria*`) returns HTTP 500 for every anonymous
  access pattern — the only surface carrying actual codes cannot be obtained non-interactively — so
  `SmiSource` parses the reliably-served **version catalog** (`/Versao/Exportacao`) to report the
  current CAE version (`V05497` Rev.4 / `V00554` Rev.3) instead. Live-probeable
  (`live_smi_version_catalog_lists_the_current_cae_revisions`), parser covered offline by
  `fixtures/smi_version_catalog.csv`. gov.pt **SICONF** remains a deferred postback-only per-code
  verifier with no bulk export.
- **No INE bulk artifact exists anywhere — DR stays the default** (t37, 2026-07-08; the user asked for
  INE as the default source). A full re-probe of `ine.pt` proper (not just `/Categoria`) found only
  PDFs: the SMI per-version document tab (`/Versao/Detalhes_TabDocumento/{id}` → `/Versao/Download/{n}`)
  serves four PDFs per revision (EU regulation, CSE deliberação, the DR diploma, the INE *publicação*);
  the `ine.pt/xportal` publication pages serve one consolidated `CAE-Rev.4.pdf`. The INE *publicação*
  PDF is Rev.4-**only**, differently typeset (a new coordinate parser at fidelity risk), on a less
  stable app URL, for **identical** data — strictly worse than the digest-pinned DR pair, so building an
  `IneSource` was rejected, not faked. `/Categoria/Exportacao` re-probed with a cookie jar after seeding
  the session still 500s (no cookie is set); `dados.gov.pt` has no CAE *classification* dataset (only
  statistics organised by CAE). The DR diploma **is** the INE classification — `DL 9/2025` is the legal
  instrument enacting INE's CAE-Rev.4 — so "from INE" and "from the DR" are the same data.
- **`preferred_official_source` (default `Ine`) is honoured honestly** (t37 extension, user directive
  "default is ine"). `official_chain_for(Ine)` = `[IneOfficialSource, DrPdfSource]`; the INE entry
  always fails (it cannot supply a fidelity-passing dataset — above) and is recorded in the chain
  `failures`, and the always-present DR pair fulfils the refresh — the outcome shows "INE indisponível →
  Diário da República", never a silent substitution. `official_chain_for(DiarioRepublica)` = `[DR]`
  alone. `default_official_chain()` uses the default (`Ine`). `IneOfficialSource` is the single seam to
  implement a real INE bulk obtain if INE ever ships one (mirrors the deferred `SiconfVerifier`).
- **Rev.3 group 843** ("Segurança social obrigatória") has no printed header row in DL 381/2007 and
  is reconstructed from its sole child — the only synthesized node (see `PROVENANCE.md`).
- **Designations are verbatim** (trailing period and "n. e." abbreviations preserved); Rev.3 keeps
  pre-Acordo-Ortográfico spelling, Rev.4 the current spelling.
- **One source-font ligature glyph** — Rev.3 code `59`'s designation contains an `fi`-ligature glyph
  that the diploma font encodes with **no `ToUnicode` entry**. Both the offline pymupdf generator
  (embedded `U+FB01`) and this in-app `lopdf` port render it imperfectly; the port reproduces every
  other designation of both revisions byte-for-byte (3808/3809 nodes). No spot-check code is
  affected, and the fidelity gate is about counts, not glyph rendering.
