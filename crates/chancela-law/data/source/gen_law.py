#!/usr/bin/env python3
"""gen_law.py — the reproducible generator for the embedded full-text law corpus.

This is the law analogue of `crates/chancela-cae/data/source/gen_cae.py`. It emits the
committed `../law_corpus.json` — a JSON array of diplomas, each with its article skeleton —
from the compact in-file DIPLOMA_MANIFEST below.

## What E1a produces (this script, as committed)
Every article is seeded **Pending**: `verification = "Pending"`, `body = ""`, and a `source`
whose *structural* fields (`diploma`, `article`) are pre-filled but whose *authenticity* fields
(`dr_reference`, `dr_date`, `url`) are `null`. Because the authenticity gate refuses to mark an
article `Verified` without a COMPLETE source, a Pending article can never masquerade as law:
its rendered body is the loud marker `[NÃO VERIFICADO / fonte pendente]`.

## What E1b does (per diploma, in parallel — the FULL-DIPLOMA vendoring pipeline)
For each diploma, E1b vendors the authentic Diário da República text and, per article:

  1. **Locate the authentic source.** For the consolidated codes (CSC, Código Civil) the DRE
     serves the *legislação consolidada* HTML at the diploma's ELI:
         https://diariodarepublica.pt/dr/legislacao-consolidada/<tipo>/<id>
         https://data.dre.pt/eli/<tipo>/<num>/<ano>/p/cons/<yyyymmdd>   (ELI resolver)
     For the standalone diplomas (DL 268/94, DL 76-A/2006, Lei 24/2012, Código Cooperativo)
     the immutable original publication PDF lives under
         https://files.dre.pt/1s/<ano>/<mes>/<serie>/<pags>.pdf
     For the EU regulations, EUR-Lex serves the OJ text/PDF by CELEX
         https://eur-lex.europa.eu/legal-content/PT/TXT/?uri=CELEX:<celex>
     The exact per-diploma URL is recorded in `PROVENANCE.md` beside its sha256.

  2. **Vendor the source artifact** into `data/source/` (verbatim, like the CAE PDFs) and record
     its sha256 in `PROVENANCE.md` — so the whole transform stays auditable offline.

  3. **Extract the article VERBATIM** (heading/epígrafe + full numbered body). The DRE consolidated
     HTML enumerates *every* article of the code, so E1b expands each diploma's article list to the
     COMPLETE set (not just the E1a cited skeleton) — this is where "full diploma" is realised: the
     authentic source, not this script's seed, is the authority on the article set.

  4. **Fill the article** by editing `../law_corpus.json` directly (or extending the manifest and
     re-running): set `body` to the verbatim text, complete `source` (`dr_reference`, `dr_date`,
     `url`, `source_digest`), and flip `verification` to `"Verified"`.

  5. **Add a fidelity spot-check test** for the vendored diploma (a known article's heading/first
     words), mirroring `chancela-cae/tests/fidelity.rs`.

## Priority
CSC art. 255.º (Remuneração dos gerentes) + art. 399.º (Remuneração dos administradores) are
seeded first and carry their epígrafes so E1b fills them first (the user's manager-remuneration ask).

## Usage
    python gen_law.py                 # rewrite ../law_corpus.json from the manifest
    python gen_law.py --check         # exit non-zero if ../law_corpus.json is stale

Example entities in any doc/test built on this corpus use the fictional "Encosto Estratégico Lda"
/ "Amélia Marques" — never real names.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# The loud placeholder a Pending article renders instead of a (never-fabricated) body. Kept in
# sync with `UNVERIFIED_MARKER` in `src/model.rs`.
UNVERIFIED_MARKER = "[NÃO VERIFICADO / fonte pendente]"

# The full in-scope diploma list (plan t55 §5, FULL-DIPLOMAS decision). Each diploma lists the
# article numbers the app already cites (guaranteed-correct slots, seeded Pending). E1b expands
# each to the diploma's COMPLETE article set from the authentic DRE source. `articles` items are
# (number, heading, cross_refs); heading is "" unless a well-established epígrafe is known.
DIPLOMA_MANIFEST = [
    {
        "id": "csc",
        "kind": "Codigo",
        "number": "262/86",
        "title": "Código das Sociedades Comerciais",
        "reference": "Decreto-Lei n.º 262/86, de 2 de setembro",
        "official_url": "https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1986-34443975",
        "eli": "https://data.dre.pt/eli/dec-lei/262/1986/p/cons/20260101",
        "articles": [
            # Priority — the user's explicit manager-remuneration request. E1b fills these first.
            ("255", "Remuneração dos gerentes", ["csc:399"]),
            ("399", "Remuneração dos administradores", ["csc:255"]),
            # The rest of the app-cited CSC skeleton (headings left for E1b to vendor from source).
            ("56", "", []),
            ("58", "", []),
            ("63", "", []),
            ("246", "", []),
            ("248", "", []),
            ("250", "", []),
            ("265", "", []),
            ("270-A", "", []),
            ("270-E", "", []),
            ("376", "", []),
            ("377", "", []),
            ("386", "", []),
            ("388", "", []),
        ],
    },
    {
        "id": "cc",
        "kind": "Codigo",
        "number": "47344/66",
        "title": "Código Civil",
        "reference": "Decreto-Lei n.º 47344, de 25 de novembro de 1966",
        "official_url": "https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1966-34509075",
        "eli": "https://data.dre.pt/eli/dec-lei/47344/1966/p/cons/20260101",
        "articles": [
            # Associações (157–184) and propriedade horizontal (1414–1438-A) — cited anchors.
            ("157", "", []),
            ("173", "", []),
            ("175", "", []),
            ("184", "", []),
            ("1414", "", []),
            ("1424", "", []),
            ("1430", "", []),
            ("1432", "", []),
            ("1433", "", []),
            ("1436", "", []),
            ("1438", "", []),
            ("1438-A", "", []),
        ],
    },
    {
        "id": "dl-268-94",
        "kind": "DecretoLei",
        "number": "268/94",
        "title": "Normas regulamentares do regime da propriedade horizontal (condomínios)",
        "reference": "Decreto-Lei n.º 268/94, de 25 de outubro",
        "official_url": "https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1994-144575382",
        "eli": "https://data.dre.pt/eli/dec-lei/268/1994/p/cons/20260101",
        "articles": [
            ("1", "", []),
            ("2", "", []),
            ("3", "", []),
            ("4", "", []),
            ("5", "", []),
            ("6", "", []),
        ],
    },
    {
        "id": "dl-76-a-2006",
        "kind": "DecretoLei",
        "number": "76-A/2006",
        "title": "Simplificação e eliminação de atos registais e notariais (societários)",
        "reference": "Decreto-Lei n.º 76-A/2006, de 29 de março",
        "official_url": "https://diariodarepublica.pt/dr/detalhe/decreto-lei/76-a-2006-620286",
        "eli": "https://data.dre.pt/eli/dec-lei/76-a/2006/p/cons/20260101",
        "articles": [
            ("1", "", []),
            ("2", "", []),
        ],
    },
    {
        "id": "cod-cooperativo",
        "kind": "Lei",
        "number": "119/2015",
        "title": "Código Cooperativo",
        "reference": "Lei n.º 119/2015, de 31 de agosto",
        "official_url": "https://diariodarepublica.pt/dr/legislacao-consolidada/lei/2015-70139602",
        "eli": "https://data.dre.pt/eli/lei/119/2015/p/cons/20260101",
        "articles": [
            ("33", "", []),
            ("34", "", []),
            ("41", "", []),
        ],
    },
    {
        "id": "lei-24-2012",
        "kind": "Lei",
        "number": "24/2012",
        "title": "Lei-Quadro das Fundações",
        "reference": "Lei n.º 24/2012, de 9 de julho",
        "official_url": "https://diariodarepublica.pt/dr/legislacao-consolidada/lei/2012-61239015",
        "eli": "https://data.dre.pt/eli/lei/24/2012/p/cons/20260101",
        "articles": [
            ("1", "", []),
            ("5", "", []),
        ],
    },
    {
        "id": "eidas-910-2014",
        "kind": "RegulamentoUe",
        "number": "910/2014",
        "title": "Regulamento eIDAS — identificação eletrónica e serviços de confiança",
        "reference": "Regulamento (UE) n.º 910/2014, de 23 de julho",
        "official_url": "https://eur-lex.europa.eu/legal-content/PT/TXT/?uri=CELEX:32014R0910",
        "eli": "https://eur-lex.europa.eu/eli/reg/2014/910/oj",
        "articles": [
            ("25", "Efeitos legais das assinaturas eletrónicas", []),
        ],
    },
    {
        "id": "gdpr-2016-679",
        "kind": "RegulamentoUe",
        "number": "2016/679",
        "title": "Regulamento Geral sobre a Proteção de Dados (RGPD)",
        "reference": "Regulamento (UE) 2016/679, de 27 de abril",
        "official_url": "https://eur-lex.europa.eu/legal-content/PT/TXT/?uri=CELEX:32016R0679",
        "eli": "https://eur-lex.europa.eu/eli/reg/2016/679/oj",
        "articles": [
            ("5", "", []),
            ("25", "", []),
            ("32", "", []),
            ("35", "", []),
        ],
    },
    {
        "id": "eidas2-2024-1183",
        "kind": "RegulamentoUe",
        "number": "2024/1183",
        "title": "Quadro Europeu de Identidade Digital (eIDAS 2.0)",
        "reference": "Regulamento (UE) 2024/1183, que altera o Regulamento (UE) n.º 910/2014",
        "official_url": "https://eur-lex.europa.eu/legal-content/PT/TXT/?uri=CELEX:32024R1183",
        "eli": "https://eur-lex.europa.eu/eli/reg/2024/1183/oj",
        "articles": [
            ("1", "", []),
        ],
    },
]


def article_label(number: str) -> str:
    """Canonical printed label from a canonical number: "255" -> "Artigo 255.º",
    "270-A" -> "Artigo 270.º-A", "1438-A" -> "Artigo 1438.º-A"."""
    if "-" in number:
        base, suffix = number.split("-", 1)
        return f"Artigo {base}.º-{suffix}"
    return f"Artigo {number}.º"


def build_article(diploma_id: str, diploma_ref: str, number: str, heading: str, cross_refs):
    return {
        "diploma_id": diploma_id,
        "number": number,
        "label": article_label(number),
        "heading": heading,
        # Never a fabricated body. The marker is what a Pending article renders (see model.rs).
        "body": "",
        "source": {
            # Structural provenance is known already; authenticity fields await E1b's vendoring.
            "diploma": diploma_ref,
            "article": article_label(number),
            "dr_reference": None,
            "dr_date": None,
            "url": None,
        },
        "verification": "Pending",
        "cross_refs": list(cross_refs),
    }


def build_corpus():
    diplomas = []
    for d in DIPLOMA_MANIFEST:
        articles = [
            build_article(d["id"], d["reference"], num, heading, cross_refs)
            for (num, heading, cross_refs) in d["articles"]
        ]
        diplomas.append(
            {
                "id": d["id"],
                "kind": d["kind"],
                "number": d["number"],
                "title": d["title"],
                "reference": d["reference"],
                "official_url": d["official_url"],
                "eli": d["eli"],
                "articles": articles,
            }
        )
    return diplomas


def render(diplomas) -> str:
    return json.dumps(diplomas, ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the embedded law corpus JSON.")
    parser.add_argument(
        "--out",
        default=os.path.join(os.path.dirname(__file__), "..", "law_corpus.json"),
        help="output path (default: ../law_corpus.json)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed file matches the manifest; exit non-zero if stale",
    )
    args = parser.parse_args()

    out = render(build_corpus())
    out_path = os.path.abspath(args.out)

    if args.check:
        try:
            with open(out_path, "r", encoding="utf-8") as fh:
                current = fh.read()
        except OSError as e:
            print(f"gen_law: cannot read {out_path}: {e}", file=sys.stderr)
            return 1
        if current != out:
            print(f"gen_law: {out_path} is stale — rerun `python gen_law.py`", file=sys.stderr)
            return 1
        print(f"gen_law: {out_path} is up to date")
        return 0

    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(out)
    n_dip = len(DIPLOMA_MANIFEST)
    n_art = sum(len(d["articles"]) for d in DIPLOMA_MANIFEST)
    print(f"gen_law: wrote {out_path} — {n_dip} diplomas, {n_art} Pending article slots")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
