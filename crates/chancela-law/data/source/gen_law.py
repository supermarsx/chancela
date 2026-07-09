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
import hashlib
import html
import json
import os
import re
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
DRE_CAPTURE_MANIFEST = os.path.join(HERE, "dre-captures.manifest.json")
LEGAL_APPROVAL_MARKER = "LEGAL_APPROVED_FOR_VERIFIED"

# The loud placeholder a Pending article renders instead of a (never-fabricated) body. Kept in
# sync with `UNVERIFIED_MARKER` in `src/model.rs`.
UNVERIFIED_MARKER = "[NÃO VERIFICADO / fonte pendente]"

# ---------------------------------------------------------------------------
# EU-regulation vendoring (t55-E1b-eu) — the 3 EU-reg diplomas are vendored
# VERBATIM from the EUR-Lex original OJ (Portuguese) HTML, committed under
# `eurlex/`. EUR-Lex serves the full verbatim OJ text to curl (unlike the
# JS-gated DRE SPA — see the pilot findings in PROVENANCE.md), so these three
# are fully autonomous. The extraction below is deterministic and OFFLINE: it
# parses the committed artifact, so `--check` never needs the network.
#
# Version decision: the ORIGINAL OJ publication text is vendored (the CELEX the
# task named), not the consolidated version. Rationale: the original OJ HTML is
# clean (`oj-ti-art`/`oj-sti-art`/`oj-normal`), giving reliable verbatim
# extraction, whereas the consolidated HTML interleaves amendment markers that
# would pollute the body. The exact version is pinned by CELEX + URL + sha256.
# ---------------------------------------------------------------------------
EU_REG_SOURCES = {
    "eidas-910-2014": {
        "html": "eurlex/32014R0910.pt.html",
        "celex": "32014R0910",
        "url": "https://eur-lex.europa.eu/legal-content/PT/TXT/HTML/?uri=CELEX:32014R0910",
        "dr_reference": "JO L 257 de 28.8.2014, p. 73",
        "dr_date": "2014-08-28",
        "sha256": "bf56872ea8cea5da4af290a3418ae65804491d9f86092a6fe4d8fc93b2e5889f",
        "retrieved_at": "2026-07-08T00:00:00Z",
    },
    "gdpr-2016-679": {
        "html": "eurlex/32016R0679.pt.html",
        "celex": "32016R0679",
        "url": "https://eur-lex.europa.eu/legal-content/PT/TXT/HTML/?uri=CELEX:32016R0679",
        "dr_reference": "JO L 119 de 4.5.2016, p. 1",
        "dr_date": "2016-05-04",
        "sha256": "b27b27f500866926adcb775f2ac115eb075fc2ab8f7985101ea0fe5c68937c23",
        "retrieved_at": "2026-07-08T00:00:00Z",
    },
    "eidas2-2024-1183": {
        "html": "eurlex/32024R1183.pt.html",
        "celex": "32024R1183",
        "url": "https://eur-lex.europa.eu/legal-content/PT/TXT/HTML/?uri=CELEX:32024R1183",
        "dr_reference": "JO L, 2024/1183, de 30.4.2024",
        "dr_date": "2024-04-30",
        "sha256": "4c5bef3e6149a679888869e856ebe3728ae6cc3aff70b01e81f5d0c5bfc9eabf",
        "retrieved_at": "2026-07-08T00:00:00Z",
    },
}


def _strip_to_text(frag: str) -> str:
    """Reduce an HTML fragment to its verbatim text: the ordinal superscript
    `o` becomes `º`, block boundaries become newlines, entities are unescaped
    and non-breaking spaces normalized. Only HTML whitespace artifacts are
    normalized — every word/accent/punctuation mark is left exactly as served."""
    frag = re.sub(r'<span class="oj-super">o</span>', "º", frag)
    frag = re.sub(r"</p>", "\n", frag)
    frag = re.sub(r"<br\s*/?>", "\n", frag)
    frag = re.sub(r"<[^>]+>", "", frag)
    frag = html.unescape(frag)
    frag = frag.replace("\xa0", " ")
    lines = [re.sub(r"[ \t]+", " ", ln).strip() for ln in frag.split("\n")]
    return "\n".join(ln for ln in lines if ln)


def _article_blocks(doc: str):
    """Yield (number, block_html) for each `<div class="eli-subdivision"
    id="art_N">` article, sliced by balancing <div>/</div> so the block is
    exactly that article (chapter/section/annex headings, which use other ids,
    are excluded)."""
    for m in re.finditer(r'<div class="eli-subdivision" id="art_([^"]+)">', doc):
        depth = 0
        pos = m.start()
        end = len(doc)
        while True:
            nxt = re.search(r"<div\b|</div>", doc[pos:])
            if not nxt:
                break
            tok = nxt.group(0)
            abspos = pos + nxt.start()
            if tok == "</div>":
                depth -= 1
                if depth == 0:
                    end = abspos + len("</div>")
                    break
            else:
                depth += 1
            pos = abspos + len(tok)
        yield m.group(1), doc[m.start() : end]


def extract_eu_articles(html_path: str, expected_sha256: str):
    """Parse the vendored EUR-Lex OJ HTML into a verbatim article list:
    [(number, label, heading, body), ...]. Verifies the artifact sha256 so a
    tampered/stale source is caught before it can be presented as law."""
    with open(html_path, "rb") as fh:
        raw = fh.read()
    got = hashlib.sha256(raw).hexdigest()
    if got != expected_sha256:
        raise SystemExit(
            f"gen_law: {html_path} sha256 mismatch\n  expected {expected_sha256}\n  got      {got}"
        )
    doc = raw.decode("utf-8")
    out = []
    for number, block in _article_blocks(doc):
        m = re.search(r'<p[^>]*class="oj-ti-art"[^>]*>(.*?)</p>', block, re.S)
        label = _strip_to_text(m.group(1)).strip() if m else ""
        m = re.search(r'<p[^>]*class="oj-sti-art"[^>]*>(.*?)</p>', block, re.S)
        heading = _strip_to_text(m.group(1)).strip() if m else ""
        ti = re.search(r'<div class="eli-title"[^>]*>.*?</div>', block, re.S)
        if ti:
            body_frag = block[ti.end() :]
        else:
            lm = re.search(r'<p[^>]*class="oj-ti-art"[^>]*>.*?</p>', block, re.S)
            body_frag = block[lm.end() :] if lm else block
        body = _strip_to_text(body_frag)
        if not body:
            raise SystemExit(f"gen_law: empty body extracted for {html_path} art {number}")
        out.append((number, label, heading, body))
    return out

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


def build_verified_article(diploma_id, diploma_ref, src, number, heading, body, cross_refs):
    """A VERIFIED article: verbatim `body` + a COMPLETE authentic source (the
    EUR-Lex OJ citation + URL + artifact sha256). This is what flips an EU-reg
    article past the authenticity gate."""
    return {
        "diploma_id": diploma_id,
        "number": number,
        "label": article_label(number),
        "heading": heading,
        "body": body,
        "source": {
            "diploma": diploma_ref,
            "article": article_label(number),
            "dr_reference": src["dr_reference"],
            "dr_date": src["dr_date"],
            "url": src["url"],
            "source_digest": src["sha256"],
            "retrieved_at": src["retrieved_at"],
        },
        "verification": "Verified",
        "cross_refs": list(cross_refs),
    }

def _is_non_empty_string(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_rfc3339_utc(value: str) -> bool:
    if not _is_non_empty_string(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return value.endswith("Z") or value.endswith("+00:00")


def _load_dre_capture_manifest(path=DRE_CAPTURE_MANIFEST):
    with open(path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    if manifest.get("schema_version") != 1:
        raise SystemExit("gen_law: DRE capture manifest schema_version must be 1")
    if manifest.get("approval_marker_required") != LEGAL_APPROVAL_MARKER:
        raise SystemExit(
            f"gen_law: DRE capture manifest approval_marker_required must be {LEGAL_APPROVAL_MARKER!r}"
        )
    captures = manifest.get("captures")
    if not isinstance(captures, list):
        raise SystemExit("gen_law: DRE capture manifest captures must be an array")

    by_article = {}
    for i, capture in enumerate(captures):
        prefix = f"gen_law: DRE capture manifest captures[{i}]"
        for field in ["diploma_id", "official_page_url", "eli", "reviewer_status", "legal_approval_status"]:
            if not _is_non_empty_string(capture.get(field)):
                raise SystemExit(f"{prefix}.{field} must be a non-empty string")
        if not str(capture["official_page_url"]).startswith("https://diariodarepublica.pt/"):
            raise SystemExit(f"{prefix}.official_page_url must point at diariodarepublica.pt")
        if not str(capture["eli"]).startswith("https://data.dre.pt/eli/"):
            raise SystemExit(f"{prefix}.eli must be a data.dre.pt ELI")
        article_ids = capture.get("article_ids")
        if not isinstance(article_ids, list) or not article_ids or not all(_is_non_empty_string(a) for a in article_ids):
            raise SystemExit(f"{prefix}.article_ids must be a non-empty string array")
        for article_id in article_ids:
            key = (capture["diploma_id"], article_id)
            if key in by_article:
                raise SystemExit(f"gen_law: duplicate DRE capture row for {key[0]}:{key[1]}")
            by_article[key] = capture
    return manifest, by_article


def _verify_approved_capture(diploma_id: str, article_id: str, capture: dict):
    label = f"{diploma_id}:{article_id}"
    if capture.get("reviewer_status") != "Approved":
        raise SystemExit(f"gen_law: refusing to mark {label} Verified without reviewer approval")
    if capture.get("legal_approval_status") != "Approved":
        raise SystemExit(f"gen_law: refusing to mark {label} Verified without legal approval")
    if capture.get("approval_marker") != LEGAL_APPROVAL_MARKER:
        raise SystemExit(f"gen_law: refusing to mark {label} Verified without {LEGAL_APPROVAL_MARKER}")
    if not _is_rfc3339_utc(capture.get("capture_timestamp")):
        raise SystemExit(f"gen_law: refusing to mark {label} Verified without RFC3339 capture_timestamp")
    artifact_path = capture.get("captured_artifact_path")
    if not _is_non_empty_string(artifact_path):
        raise SystemExit(f"gen_law: refusing to mark {label} Verified without captured_artifact_path")
    artifact_parts = artifact_path.replace("\\", "/").split("/")
    if os.path.isabs(artifact_path) or ".." in artifact_parts:
        raise SystemExit(f"gen_law: refusing to mark {label} Verified with unsafe artifact path")
    full_path = os.path.join(HERE, artifact_path)
    if not os.path.isfile(full_path):
        raise SystemExit(f"gen_law: refusing to mark {label} Verified; missing artifact {artifact_path}")
    expected_sha = capture.get("sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", str(expected_sha or "")):
        raise SystemExit(f"gen_law: refusing to mark {label} Verified without lowercase sha256")
    with open(full_path, "rb") as fh:
        got = hashlib.sha256(fh.read()).hexdigest()
    if got != expected_sha:
        raise SystemExit(
            f"gen_law: refusing to mark {label} Verified; artifact sha256 mismatch\n"
            f"  expected {expected_sha}\n  got      {got}"
        )


def guard_dre_verified_articles(diplomas):
    """DRE-specific Pending→Verified guard. A generated DRE article may only be
    Verified after an operator capture row names the official page URL, ELI,
    artifact path, capture timestamp, sha256, article ids, reviewer approval,
    legal approval, and the explicit approval marker."""
    _manifest, by_article = _load_dre_capture_manifest()
    for diploma in diplomas:
        if diploma["id"] in EU_REG_SOURCES:
            continue
        for article in diploma["articles"]:
            if article["verification"] != "Verified":
                continue
            key = (diploma["id"], article["number"])
            capture = by_article.get(key)
            if capture is None:
                raise SystemExit(
                    f"gen_law: refusing to mark {key[0]}:{key[1]} Verified without a DRE capture row"
                )
            _verify_approved_capture(key[0], key[1], capture)


def build_corpus():
    diplomas = []
    for d in DIPLOMA_MANIFEST:
        src = EU_REG_SOURCES.get(d["id"])
        if src is not None:
            # EU regulation: vendor the COMPLETE verbatim article set from the
            # committed EUR-Lex OJ HTML (the manifest seed is superseded by the
            # authentic source, which is the authority on the article set).
            seed_cross = {num: cr for (num, _h, cr) in d["articles"]}
            extracted = extract_eu_articles(os.path.join(HERE, src["html"]), src["sha256"])
            articles = [
                build_verified_article(
                    d["id"], d["reference"], src, num, heading, body, seed_cross.get(num, [])
                )
                for (num, _label, heading, body) in extracted
            ]
        else:
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
    guard_dre_verified_articles(diplomas)
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
    corpus = build_corpus()
    n_dip = len(corpus)
    n_art = sum(len(d["articles"]) for d in corpus)
    n_ver = sum(
        1 for d in corpus for a in d["articles"] if a["verification"] == "Verified"
    )
    print(
        f"gen_law: wrote {out_path} — {n_dip} diplomas, {n_art} articles "
        f"({n_ver} Verified, {n_art - n_ver} Pending)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
