# Simple JSON — the public CAE mirror schema

`chancela-cae`'s obtainer engine (plan t23) can update its catalog from several formats. The **Simple
JSON** format is the one anyone can host: a plain, flat JSON array of classification nodes, designed
so a third party can publish a CAE mirror without knowing anything about this crate's internals.

This document is the spec third-party mirrors follow. It is enforced by the parser in
`src/obtain/simple.rs` and cross-checked against the real official table by
`tests/obtain_json.rs::simple_json_full_table_derives_and_passes_the_gates`.

## Shape

A single top-level JSON **array**. Each element is one classification node:

```json
[
  {"code": "A",     "designation": "Agricultura, produção animal, caça, floresta e pesca.", "revision": "Rev4", "level": "Seccao",    "parent": null},
  {"code": "68",    "designation": "Atividades imobiliárias.",                                "revision": "Rev4"},
  {"code": "681",   "designation": "Compra, venda e arrendamento de bens imobiliários.",     "revision": "Rev4"},
  {"code": "6811",  "designation": "Compra e venda de bens imobiliários.",                    "revision": "Rev4"},
  {"code": "68110", "designation": "Compra e venda de bens imobiliários.",                    "revision": "Rev4"}
]
```

### Fields

| Field | Required | Type | Meaning |
|---|---|---|---|
| `code` | **yes** | string | The canonical printed code: a secção letter (`"A"`..`"V"`) or the digit code (`"68"`, `"681"`, `"6811"`, `"68110"`). |
| `designation` | **yes** | string | The official Portuguese designation, verbatim (accents included). |
| `revision` | **yes** | string | `"Rev3"` or `"Rev4"` — the CAE revision this node belongs to. Each node self-tags, so **both revisions may share one array**. |
| `level` | no (derived) | string | `"Seccao"` / `"Divisao"` / `"Grupo"` / `"Classe"` / `"Subclasse"`. When omitted, derived from the code shape. |
| `parent` | no (derived) | string / null | The parent code in the **same** revision (`null` for a secção). When omitted, derived (see below). |

Unknown extra fields are ignored (forward-compatible).

## Both revisions in one array

A mirror is **one flat array carrying both revisions**; the parser partitions the nodes by each
node's `revision` tag. There is no separate per-revision file format — to host per-revision data,
concatenate the two arrays into one.

Because a superseding update must be a **complete both-revision** catalog (it has to pass the
full-count fidelity gate for *both* Rev.3 and Rev.4), a single-revision array simply leaves the other
revision empty and is rejected by fidelity. Host both revisions.

## Deriving `level` and `parent`

When `level` / `parent` are omitted, they are derived exactly as the offline generator
(`gen_cae.py`) does — so the embedded `data/cae_rev{3,4}.json` arrays are themselves valid Simple
JSON:

- **`level`** — from the code shape: a single letter is a `Seccao`; otherwise the digit count picks
  the level (2 → `Divisao`, 3 → `Grupo`, 4 → `Classe`, 5 → `Subclasse`). A code of no valid shape is
  a parse error.
- **`parent`**:
  - a **secção** has `parent = null`;
  - a **divisão** inherits the **most recent secção in array order** — so a derived-parent mirror
    **must be ordered** with each secção before its divisões (the generator's document order);
  - a **grupo / classe / subclasse** drops its code's last digit (`"6811"` → `"681"`).

An explicit `level` / `parent` is used **verbatim** (never overridden by derivation).

## Safety — nothing is trusted blindly

Whether values are given or derived, the parsed dataset must clear the **same two gates** every
format goes through before it may replace the active catalog:

1. **Structural integrity** — every declared level matches its code shape, codes are unique, and
   every parent resolves to a node one level up in the same revision (a wrong derivation, a bad
   `level`, or an orphan `parent` is rejected here).
2. **Full-count fidelity** — the per-level totals must equal the exact official figures
   (Rev.4 `22 / 87 / 287 / 651 / 915`; Rev.3 `21 / 88 / 272 / 616 / 850`). A truncated or scrambled
   mirror is rejected here.

A mirror that fails either gate is refused and the known-good embedded/cache catalog is retained. A
mirror is therefore a convenience, never a trust boundary — the digest-pinned Diário da República
diploma pair remains the authoritative bulk source.

## Producing a mirror

The simplest valid mirror is the concatenation of the two embedded arrays:

```
cat crates/chancela-cae/data/cae_rev4.json crates/chancela-cae/data/cae_rev3.json
# → merge the two arrays into one top-level array and serve it (Content-Type application/json)
```

Those arrays already carry `level` + `parent`, so they are used verbatim; dropping those two keys
per node yields a smaller mirror that the engine re-derives on fetch.
