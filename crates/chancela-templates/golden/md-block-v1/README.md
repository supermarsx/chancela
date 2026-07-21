# `md-block/v1` golden corpus

Each case is a pair: `<name>.md` (input) and `<name>.blocks.json` (the exact `Vec<Block>` that
`chancela_templates::markdown::compile_markdown` must produce for it, serialized with serde).
`golden_corpus_matches_exactly` in `src/markdown.rs` asserts the pair, and the case list there uses
`include_str!`, so deleting or renaming a file is a compile error rather than a skipped test.

## Why this exists

The compiled blocks are bound into the seal preimage. A `pulldown-cmark` bump — even a patch — that
perturbs output would change what a sealed document says. This corpus makes that a loud CI failure
instead of a silent drift.

## If `golden_corpus_matches_exactly` fails

**Do not re-bless these files.** A failure means one of two things:

- an accidental change (a parser bump, an edit to the compiler) — revert it; or
- a deliberate change to the mapping — then it is not a `v1` edit. Ship it as `md-block/v2` with a
  new `golden/md-block-v2/` corpus, keep `v1` and these files intact, and keep compiling acts sealed
  under `v1` with `v1`.

Editing a `v1` expectation in place retroactively changes what an already-sealed act compiles to.

## Adding a case

Add the `.md`, add the name to the `GOLDEN` list in `src/markdown.rs`, and write the `.blocks.json`
by hand or by copying the `got:` block the assertion prints. Read it before committing — the point
of the corpus is that a human agreed the output is right.
