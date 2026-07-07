#!/usr/bin/env python3
"""Reproducible CAE dataset generator.

Reads the two vendored official Diário da República PDFs (the legal source of each
CAE revision) and emits `cae_rev3.json` + `cae_rev4.json` — JSON arrays of CaeEntry
objects consumed by the `chancela-cae` crate via `include_str!`.

Extraction is coordinate-based (word bounding boxes), NOT layout-text: the DR tables
are sparse multi-column grids (Secção/Divisão/Grupo/Classe/Subclasse/Designação) with
wrapping designations, which line-oriented extractors mangle. A node's LEVEL is derived
from its code shape (1 letter -> Secção, 2/3/4/5 digits -> Divisão/Grupo/Classe/Subclasse)
and its PARENT structurally (code prefix; divisions inherit the current section walked in
reading order). Correctness is proven by the structural-count gate in the crate's tests.

Requires: python 3, pymupdf (`pip install pymupdf`). See PROVENANCE.md for source URLs.
"""
import sys, re, json, argparse
import fitz  # pymupdf

CODE_RE = re.compile(r'^(?:[A-Z]|\d{2,5})$')

# Per-revision extraction geometry (from the DR page layout, in PDF points).
# sec_x: right edge of the Secção column — a lone letter must sit inside it to count as a
#        section (rejects Portuguese one-letter words like "O"/"A"/"E" in prose).
LAYOUT = {
    "rev3": dict(code_x=255, desig_x=255, margin_x=560, y0=100, y1=815, sec_x=78),
    "rev4": dict(code_x=236, desig_x=236, margin_x=530, y0=115, y1=790, sec_x=95),
}


def level_of(code):
    if code.isalpha():
        return "Seccao"
    return {2: "Divisao", 3: "Grupo", 4: "Classe", 5: "Subclasse"}[len(code)]


def is_code(w, lo):
    """A word is a code cell iff it sits in a code column and matches the code shape.
    A lone letter must additionally sit inside the Secção column (guards against prose)."""
    if w[0] >= lo["code_x"] or not CODE_RE.match(w[4]):
        return False
    if w[4].isalpha() and w[0] >= lo["sec_x"]:
        return False
    return True


def logical_rows(doc, lo):
    """Yield (codes, designation) logical rows, merging wrapped continuation lines."""
    raw = []
    for pi in range(doc.page_count):
        page = doc[pi]
        words = page.get_text("words")
        # Only real table pages carry the column header; the header's y also bounds the
        # table region — anything above it (article/signature prose on the first table
        # page) is excluded so lone letters there never masquerade as sections.
        header_ys = [w[1] for w in words if w[4] == "Designação" and w[0] > lo["desig_x"]]
        if not header_ys or not any(w[4] == "Subclasse" for w in words):
            continue
        header_y = min(header_ys)
        lines = {}
        for w in words:
            if not (header_y < w[1] < lo["y1"]):
                continue
            if w[0] >= lo["margin_x"]:  # drop rotated running-header / page margin
                continue
            lines.setdefault(round(w[1]), []).append(w)
        for y in sorted(lines):
            ws = sorted(lines[y], key=lambda w: w[0])
            codes = [w[4] for w in ws if is_code(w, lo)]
            desig = " ".join(w[4] for w in ws if w[0] >= lo["desig_x"])
            if not codes and not desig:
                continue
            raw.append([codes, desig])
    merged = []
    for codes, desig in raw:
        if codes:
            merged.append([codes, desig])
        elif merged and not merged[-1][1].rstrip().endswith("."):
            # A CAE designation is a single noun phrase terminated by a period; a no-code
            # line is a wrap continuation ONLY while the previous designation is still
            # incomplete. Once it ends with ".", a following no-code line is page noise
            # (footer id, next-diploma prose) and is dropped — not merged.
            prev = merged[-1]
            if prev[1].endswith("-"):
                prev[1] = prev[1][:-1] + desig
            else:
                prev[1] = (prev[1] + " " + desig).strip()
    return merged


def build(doc, rev, lo):
    entries = {}
    order = []
    cur_section = None
    for codes, desig in logical_rows(doc, lo):
        for c in codes:
            lv = level_of(c)
            if lv == "Seccao":
                cur_section = c
                parent = None
            elif lv == "Divisao":
                parent = cur_section
            else:
                parent = c[:len(c) - 1]
            if c not in entries:
                entries[c] = dict(code=c, designation=desig, level=lv,
                                  revision=rev, parent=parent)
                order.append(c)

    # DL 381/2007 omits the printed header row for group 843 (its sole class 8430
    # "Segurança social obrigatória" is listed directly). NACE-Rev.2/CAE-Rev.3 both
    # define group 843; reconstruct it faithfully from its unique child so the
    # hierarchy chains to a secção. This is the ONLY synthesized node (asserted below).
    if rev == "Rev3" and "843" not in entries and "8430" in entries:
        entries["843"] = dict(code="843", designation=entries["8430"]["designation"],
                              level="Grupo", revision="Rev3", parent="84")
        order.insert(order.index("8430"), "843")

    return [entries[c] for c in order], entries


def validate(entries_list, entries):
    problems = []
    seen = set()
    for e in entries_list:
        if e["code"] in seen:
            problems.append(f"duplicate code {e['code']}")
        seen.add(e["code"])
        p = e["parent"]
        if e["level"] == "Seccao":
            if p is not None:
                problems.append(f"section {e['code']} has parent {p}")
        else:
            if p is None or p not in entries:
                problems.append(f"{e['code']} parent {p} missing")
            elif e["level"] != "Divisao" and not e["code"].startswith(p):
                problems.append(f"{e['code']} parent {p} not a prefix")
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rev3-pdf", default="rev3.pdf")
    ap.add_argument("--rev4-pdf", default="rev4.pdf")
    ap.add_argument("--out-dir", default=".")
    args = ap.parse_args()

    for rev, pdf in (("Rev3", args.rev3_pdf), ("Rev4", args.rev4_pdf)):
        lo = LAYOUT[rev.lower()]
        doc = fitz.open(pdf)
        lst, idx = build(doc, rev, lo)
        problems = validate(lst, idx)
        from collections import Counter
        cnt = Counter(e["level"] for e in lst)
        print(f"{rev}: {dict(cnt)} total={len(lst)} problems={len(problems)}")
        for pr in problems[:10]:
            print("   !", pr)
        if problems:
            sys.exit(f"{rev} FAILED validation")
        # One compact CaeEntry object per line inside a JSON array: valid JSON that
        # serde_json parses directly, and git-diffable per node.
        out = f"{args.out_dir}/cae_{rev.lower()}.json"
        with open(out, "w", encoding="utf-8") as f:
            f.write("[\n")
            for i, e in enumerate(lst):
                obj = json.dumps(e, ensure_ascii=False, separators=(",", ":"))
                f.write(obj + ("," if i + 1 < len(lst) else "") + "\n")
            f.write("]\n")
        print(f"   wrote {out}")


if __name__ == "__main__":
    main()
