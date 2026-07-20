# CAE dataset provenance

The embedded catalog (`../cae_rev3.json`, `../cae_rev4.json`) is generated from the two
official *Diário da República* diplomas that establish each CAE revision. Those PDFs are
vendored here verbatim so the whole transform is auditable offline; `gen_cae.py` is the
reproducible generator that turns them into the committed JSON.

## Vendored official sources

| File | Diploma | Official URL | sha256 |
|---|---|---|---|
| `rev4.pdf` | Decreto-Lei n.º 9/2025, de 12 de fevereiro (DR 1.ª série N.º 30) — establishes **CAE-Rev.4** (in force since 2025-01-01, harmonised with NACE-Rev.2.1) | https://files.diariodarepublica.pt/1s/2025/02/03000/0000800049.pdf | `84286f31e98b06347007d78b3bcf3258ad4c81dd84adce728af15c27be29c641` |
| `rev3.pdf` | Decreto-Lei n.º 381/2007, de 14 de novembro (DR 1.ª série N.º 219) — establishes **CAE-Rev.3** (governed 2008-01-01 → 2024-12-31) | https://files.dre.pt/1s/2007/11/21900/0844008464.pdf | `ab037e43d4376870fd9a3559a2176c07032d0ada6eccb104ccef1efcdf11662a` |

Retrieved 2026-07-07. There is **no** official machine-readable (JSON/CSV) CAE feed; INE
publishes the tables through its Metainformation portal (Excel/PDF behind a portal) and the
legal source is the DRE diploma PDF. The PDF is therefore the authoritative source.

## How the JSON is regenerated

```
pip install pymupdf
python gen_cae.py --rev3-pdf rev3.pdf --rev4-pdf rev4.pdf --out-dir ..
```

`gen_cae.py` extracts the classification table by **word bounding boxes** (not layout text):
the DR tables are sparse multi-column grids (Secção/Divisão/Grupo/Classe/Subclasse/Designação)
with designations that wrap across physical lines, which line-oriented extractors scramble.
A node's **level** is derived from its code shape (1 letter → Secção; 2/3/4/5 digits →
Divisão/Grupo/Classe/Subclasse) and its **parent** structurally (code prefix; divisions inherit
the current section walked in reading order). The generator self-validates (no duplicate codes,
every parent resolves, prefix relationships hold) and refuses to write on any failure.

## Verified structural totals (the CI fidelity gate)

| Revision | Secções | Divisões | Grupos | Classes | Subclasses | Total |
|---|---|---|---|---|---|---|
| **CAE-Rev.4** | 22 | 87 | 287 | 651 | 915 | 1962 |
| **CAE-Rev.3** | 21 | 88 | 272 | 616 | 850 | 1847 |

The Rev.4 totals equal the official figures published for DL 9/2025 (22/87/287/651/915). The
Rev.3 totals are derived from the primary legal source (DL 381/2007); the class count of **616**
is independently corroborated by INE's own CAE-Rev.3 presentation, which states the classification
has *"mais uma Classe do que a NACE-Rev.2"* (NACE-Rev.2 = 615 classes → 616). These primary-source
totals supersede looser secondary approximations.

## Known source quirks (faithfully handled, not fabricated)

- **Rev.3 group 843** ("Segurança social obrigatória") has no printed header row in DL 381/2007 —
  its single class 8430 is listed directly. Group 843 exists in NACE-Rev.2/CAE-Rev.3, so it is
  reconstructed from its sole child's designation so the hierarchy chains to a secção. This is the
  **only** synthesized node.
- **Designations preserve the official text verbatim**, including the trailing period the DR table
  prints and abbreviations such as "n. e." (não especificado). A handful of source designations
  omit the trailing period (e.g. Rev.4 `012` "Culturas permanentes"); these are kept as printed.
- Rev.3 uses pre-Acordo-Ortográfico spelling ("Actividades", "Electricidade", "excepto"); Rev.4
  uses the current spelling ("Atividades", "eletricidade", "exceto"). Both are faithful to their
  respective diplomas.
