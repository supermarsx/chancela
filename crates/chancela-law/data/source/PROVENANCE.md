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
| `eurlex/32014R0910.pt.html` | Regulamento (UE) n.º 910/2014 (eIDAS) | https://eur-lex.europa.eu/legal-content/PT/TXT/HTML/?uri=CELEX:32014R0910 | `bf56872ea8cea5da4af290a3418ae65804491d9f86092a6fe4d8fc93b2e5889f` |
| `eurlex/32016R0679.pt.html` | Regulamento (UE) 2016/679 (RGPD) | https://eur-lex.europa.eu/legal-content/PT/TXT/HTML/?uri=CELEX:32016R0679 | `b27b27f500866926adcb775f2ac115eb075fc2ab8f7985101ea0fe5c68937c23` |
| `eurlex/32024R1183.pt.html` | Regulamento (UE) 2024/1183 (eIDAS 2.0) | https://eur-lex.europa.eu/legal-content/PT/TXT/HTML/?uri=CELEX:32024R1183 | `4c5bef3e6149a679888869e856ebe3728ae6cc3aff70b01e81f5d0c5bfc9eabf` |

## E1b-eu — the 3 EU regulations vendored VERBATIM from EUR-Lex — 2026-07-08

**Outcome: all 3 EU-regulation diplomas are now authentic and Verified** — 153 articles vendored
verbatim from the EUR-Lex Portuguese OJ HTML, each with a complete source (OJ citation + URL +
artifact sha256 + retrieved_at). This confirms the pilot's control finding: **EUR-Lex serves the
full verbatim OJ text to `curl`** (unlike the JS-gated DRE SPA).

| Diploma | CELEX | Articles vendored → Verified | OJ reference |
|---|---|---|---|
| `eidas-910-2014` | 32014R0910 | **52** (Artigos 1.º–52.º) | JO L 257 de 28.8.2014, p. 73 |
| `gdpr-2016-679` | 32016R0679 | **99** (Artigos 1.º–99.º) | JO L 119 de 4.5.2016, p. 1 |
| `eidas2-2024-1183` | 32024R1183 | **2** (Artigos 1.º–2.º) | JO L, 2024/1183, de 30.4.2024 |

Total: **153 Verified**, **0 left Pending** among the EU regs. (The full corpus is now 153 Verified
+ 40 Pending = 193 articles; the 40 Pending are the 6 DRE-sourced diplomas, blocked by the SPA — the
pilot's recommendation stands for those.)

**Version decision — original OJ text (not consolidated).** The vendored artifact for each regulation
is the **original OJ publication** (the CELEX named in the task), not the consolidated in-force
version. Rationale: the original OJ HTML is clean (`oj-ti-art` / `oj-sti-art` / `oj-normal`), which
gives reliable, unambiguous verbatim extraction; the consolidated HTML (`02014R0910-20241018`,
`02016R0679-20160504` — both fetch fine via curl) interleaves amendment markers that would pollute an
article body. The exact version is pinned by CELEX + URL + sha256, and the eIDAS→eIDAS2 amendments are
themselves captured authentically as the separate `eidas2-2024-1183` diploma (its Artigo 1.º is the
verbatim amending clause). A reader thus sees each act exactly as the OJ published it.

**Extraction (deterministic, offline, reproducible).** `gen_law.py` parses the committed
`eurlex/*.pt.html` artifacts: each article is the `<div class="eli-subdivision" id="art_N">` block
(sliced by balancing `<div>`/`</div>`, so chapter/section/annex headings are excluded), the label is
`oj-ti-art`, the epígrafe is `oj-sti-art`, and the body is every paragraph after the title div. Only
HTML whitespace artifacts are normalized (the ordinal superscript `o` → `º`, `&nbsp;` → space,
entities unescaped, block tags → newlines) — **every word, accent and punctuation mark is left
exactly as served**. The generator re-verifies each artifact's sha256 before extracting, so a
tampered/stale source is caught before it can be presented as law. `python gen_law.py --check` runs
fully offline against the committed HTML (CI needs no network; the embedded `law_corpus.json` is the
artifact tests run against).

Fidelity gate: `tests/fidelity.rs` asserts the complete article counts (52/99/2), contiguous
numbering, that every EU-reg article is Verified + sourced + pinned to the artifact digest, and
verbatim spot-checks (eIDAS 25 «efeito legal equivalente ao de uma assinatura manuscrita», RGPD 5
«licitude, lealdade e transparência», RGPD 25 «pseudonimização», eIDAS2 1 amending-clause opening).

## E1b pilot findings — 2026-07-08 (CSC, priority arts 255.º + 399.º)

**Outcome: 0 articles vendored to Verified. The whole corpus stays Pending — the correct authentic
outcome (a Pending gap is right; a fabricated body is a critical failure).** The documented
curl-based DRE pipeline does **not** work for the consolidated Portuguese codes. Probes performed:

- `diariodarepublica.pt/dr/legislacao-consolidada/...` (the in-force consolidated CSC) is a
  **JS-gated OutSystems React SPA**. Every `curl` returns a constant **2346-byte HTML shell**
  (`<div id="reactContainer">` + `<noscript>JavaScript is required</noscript>`). The article text
  is loaded at runtime by JS from CSRF-token-gated OutSystems `screenservices` POST endpoints that
  are bootstrapped inside the SPA session and are not reachable with `curl`. The loader scripts
  (`dr.index.js` 1.3 KB, `dr.appDefinition.js` 664 B) are themselves stubs that pull modules
  dynamically, so the endpoint names/version tokens can't be recovered statically either.
- `data.dre.pt/eli/dec-lei/262/1986/p/cons/...` (the ELI resolver) **301-redirects into that same
  SPA** (`.../redirect/LinkELI.aspx?...` → `diariodarepublica.pt`). No JSON body.
- `files.dre.pt/1s/1986/09/...` (the immutable **original** 1986 publication PDF) — constructed
  URLs **301 back into the SPA**; the exact page-encoded filename is not discoverable via search.
  Even if fetched, the 1986 *original* wording of arts 255.º/399.º has since been amended, so it is
  **not** the current in-force text and must not be presented as such for a remuneration feature.
- No Chrome browser is connected (`list_connected_browsers` → `[]`), so legitimate SPA rendering
  (the one reliable way to extract verbatim text from dre.pt) was unavailable in this run.
- `WebFetch` only yields processed/summarised markdown of the SPA shell — explicitly **not** good
  enough for `Verified` per the authenticity rule.

**What DID work:** **EUR-Lex serves verbatim HTML directly to `curl`** — e.g.
`eur-lex.europa.eu/legal-content/PT/TXT/?uri=CELEX:32014R0910` returns **619 KB** of real content
containing "Artigo 25.º" and "assinatura eletrónica". So the EU-regulation diplomas
(`eidas-910-2014`, `gdpr-2016-679`, `eidas2-2024-1183`) ARE autonomously vendorable by CELEX; the
6 DRE-sourced diplomas (CSC, Código Civil, DL 268/94, DL 76-A/2006, Código Cooperativo, Lei 24/2012)
are **not**, via curl.

**Fan-out recommendation:** do NOT fan out curl-based per-diploma DRE vendoring — it will fail
identically for every consolidated code. Unblock the 6 DRE diplomas by one of: (a) run the vendoring
step with a connected/headless browser that renders the SPA and extract the DOM text verbatim; or
(b) obtain user-supplied authoritative text (official PDF export from the DRE "descarregar" button)
to vendor from. The 3 EU regs can be fanned out with the existing curl+CELEX pipeline immediately.

## Regeneration

```
python gen_law.py            # rewrite ../law_corpus.json from the manifest
python gen_law.py --check    # CI guard: fail if the committed JSON is stale
cargo run -p chancela-law --bin gen_law   # validate the embedded corpus (counts + digest)
```

Any example entity in tests/docs built on this corpus uses the fictional "Encosto Estratégico Lda"
/ "Amélia Marques" — never real names. No "valor probatório" in user-visible copy.
