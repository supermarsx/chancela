# Chancela template bundle — portable JSON+MD envelope

A Chancela template is a two-part unit:

- a **JSON spec** — the template's properties and block layout (its render identity), and
- a **markdown seed body** — the human-editable narrative a fresh instrument (an ata, a termo) is
  drafted with before an operator fills it in.

The **template bundle** carries both in one versioned envelope so a template is:

- **fully portable** Chancela-instance → Chancela-instance (import reconstructs spec and seed), and
- **partially portable to other tools** — the seed is standard CommonMark a human or another program
  can lift out directly, and the spec is governed by the published JSON Schema
  [`template-bundle.v1.json`](./template-bundle.v1.json) (JSON Schema draft 2020-12).

## Envelope shape

```jsonc
{
  "format": "chancela.template-bundle",
  "format_version": 1,
  "spec": { /* the template JSON, with its seed (default_body) removed */ },
  "body_markdown": "## Abertura\n\nO presente livro destina-se ao registo…"
}
```

- `format` / `format_version` — the discriminator and **major** version. An importer reads a version
  it implements and **rejects** anything else. It never best-effort transforms a newer bundle.
- `spec` — the template spec JSON **with its seed removed**. There is exactly one seed representation
  in the bundle (`body_markdown`), so the two can never drift out of sync.
- `body_markdown` — the seed body as `md-block/v1` markdown. Each seed clause is one section: an
  optional `## <heading>` line, then the clause text, with a blank line between sections. It is
  **plain text**: a seed is rendered as a *value*, never compiled, so it must contain no minijinja
  (`{{ … }}` / `{% … %}`) syntax. It is restricted to the `md-block/v1` subset (headings, paragraphs,
  bold, italic, thematic rules); lists, tables, links, images and code are **rejected** on import,
  never silently kept as literal text.

## Endpoints

- `GET /v1/templates/{id}/export` → the bundle, as an `attachment` download named
  `<sanitized-id>.json`. The body's `format`/`format_version` keys make it self-describing.
- `POST /v1/templates/import` → accepts the bundle **and** a legacy bare spec (a pre-t43 export with
  no `format` key). `?dry_run=true` returns a `{ok, error?}` verdict without persisting.

## Fixity

The seed is **not** part of a template's digested canonical spec (it is `#[serde(skip)]`), so editing
a seed never moves a `template_spec_digest` and never trips the shipped-template freeze. Only the
`spec` half carries render identity. Editing the digested `spec` of a shipped template is a re-version
(`/v2`), exactly as before; editing a seed is a normal, non-evidentiary edit.

## Versioning

A deliberate change to the envelope shape or the seed encoding ships as `format_version: 2` with a new
`schema/template-bundle.v2.json`; `v1` is retained so an older bundle still imports. The version is the
**major**: an importer that only knows `v1` rejects a `v2` bundle rather than guessing.
