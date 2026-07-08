# Law corpus provenance

The embedded corpus (`../law_corpus.json`) is the full-text statute shelf behind Legislação. It is
the law analogue of `crates/chancela-cae/data/source/PROVENANCE.md`: authentic text is vendored from
its official source, per article, with a hard authenticity gate.

## Authenticity gate (non-negotiable)

Embedding **wrong** statute text is worse than a reference-only link. So:

- An article is `Verified` **only** when its `source` cites a complete authentic origin
  (`diploma` + `article` + `dr_reference` + `url`). The `LawCatalog` build and
  `tests/authenticity.rs` both reject a `Verified` article without one.
- Any article not yet authentically vendored ships `Pending`, `body = ""`, and renders the loud
  marker `[NÃO VERIFICADO / fonte pendente]` — **never** a fabricated, paraphrased, or recalled body.

## Seeding status — t55-E1a (this commit)

The buildable **skeleton**: the full in-scope diploma list (plan t55 §5), each with the app-cited
articles pre-allocated **Pending**. No statute body is filled yet. **Priority:** CSC art. 255.º
(Remuneração dos gerentes) + art. 399.º (Remuneração dos administradores) are seeded first and carry
their epígrafes, so E1b fills them first (the user's manager-remuneration request).

| Diploma id | Kind | Reference | Seeded (Pending) articles |
|---|---|---|---|
| `csc` | Código | Decreto-Lei n.º 262/86, de 2 de setembro | **255, 399** (priority), 56, 58, 63, 246, 248, 250, 265, 270-A, 270-E, 376, 377, 386, 388 |
| `cc` | Código | Decreto-Lei n.º 47344, de 25-11-1966 | 157, 173, 175, 184, 1414, 1424, 1430, 1432, 1433, 1436, 1438, 1438-A |
| `dl-268-94` | Decreto-Lei | Decreto-Lei n.º 268/94, de 25 de outubro | 1–6 |
| `dl-76-a-2006` | Decreto-Lei | Decreto-Lei n.º 76-A/2006, de 29 de março | 1, 2 |
| `cod-cooperativo` | Lei | Lei n.º 119/2015, de 31 de agosto | 33, 34, 41 |
| `lei-24-2012` | Lei | Lei n.º 24/2012, de 9 de julho | 1, 5 |
| `eidas-910-2014` | Regulamento (UE) | Regulamento (UE) n.º 910/2014 | 25 |
| `gdpr-2016-679` | Regulamento (UE) | Regulamento (UE) 2016/679 | 5, 25, 32, 35 |
| `eidas2-2024-1183` | Regulamento (UE) | Regulamento (UE) 2024/1183 | 1 |

The seeded slots are the app-cited articles (guaranteed-correct keys). The **complete** article set
of each diploma is defined by its authentic source — E1b expands each list when vendoring (see below).

## E1b — the FULL-DIPLOMA vendoring pipeline (per diploma, in parallel)

For each diploma, vendor the authentic Diário da República / EUR-Lex text and fill its articles:

1. **Locate the authentic source** by diploma kind:
   - **Consolidated codes (CSC, Código Civil, Código Cooperativo):** DRE *legislação consolidada*
     HTML at the ELI —
     `https://diariodarepublica.pt/dr/legislacao-consolidada/<tipo>/<id>` or the ELI resolver
     `https://data.dre.pt/eli/<tipo>/<num>/<ano>/p/cons/<yyyymmdd>`. The consolidated HTML enumerates
     **every** article of the code (this is where "full diploma" is realised — the source, not the
     E1a seed, is the authority on the article set).
   - **Standalone diplomas (DL 268/94, DL 76-A/2006, Lei 24/2012):** the immutable original
     publication PDF under `https://files.dre.pt/1s/<ano>/<mes>/<serie>/<pags>.pdf`.
   - **EU regulations (910/2014, 2016/679, 2024/1183):** EUR-Lex by CELEX —
     `https://eur-lex.europa.eu/legal-content/PT/TXT/?uri=CELEX:<celex>` (text) and `.../TXT/PDF/...`.
2. **Vendor the source artifact** into this `data/source/` directory (verbatim, like the CAE PDFs)
   and record its sha256 in the table below — so the transform stays auditable offline.
3. **Extract each article VERBATIM** (epígrafe + full numbered body; preserve `n.º` numbering and
   paragraph breaks). Expand the diploma's article list to the complete set from the source.
4. **Fill the article** by editing `../law_corpus.json` (or extending `gen_law.py`'s manifest and
   re-running): set `body` to the verbatim text, complete `source`
   (`dr_reference`, `dr_date`, `url`, `source_digest`), and flip `verification` to `"Verified"`.
5. **Add a fidelity spot-check test** for the vendored diploma (a known article's heading + first
   words), mirroring `chancela-cae/tests/fidelity.rs`.

## Vendored official sources (filled by E1b)

| File | Diploma | Official URL | sha256 |
|---|---|---|---|
| _(none yet — E1a skeleton)_ | | | |

## Regeneration

```
python gen_law.py            # rewrite ../law_corpus.json from the manifest
python gen_law.py --check    # CI guard: fail if the committed JSON is stale
cargo run -p chancela-law --bin gen_law   # validate the embedded corpus (counts + digest)
```

Any example entity in tests/docs built on this corpus uses the fictional "Encosto Estratégico Lda"
/ "Amélia Marques" — never real names. No "valor probatório" in user-visible copy.
