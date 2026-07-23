/**
 * Where a template's own page lives.
 *
 * A template id contains a slash (`csc-ata-ag/v1`), so the id segment is percent-encoded:
 * without it the `/v1` would read as a second path segment and the route would not match.
 * React Router decodes the param again for `useParams`, so the page still sees the real id.
 */
export function templateDetailPath(id: string): string {
  return `/templates/${encodeURIComponent(id)}`;
}

/** The explicit read-only authored preview for a template. */
export function templatePreviewPath(id: string): string {
  return `${templateDetailPath(id)}/preview`;
}

/**
 * A user template's full-width editing view (t109).
 *
 * `edit` is a **section** of the template route — one more member of the same closed set as
 * `identification`/`source`/`blocks`/`fields` — not a segment reserved beside `:sec?`. A path
 * names *where you are*; the editor is the same record in a different pane. It therefore goes
 * through the same validated-section parse and unknown-segment fallback as every other section,
 * and cannot be shadowed by (or shadow) a future one.
 *
 * Kept here next to the detail path so the spelling lives in one file rather than in the router
 * and at every link site.
 */
export function templateEditPath(id: string): string {
  return `/templates/${encodeURIComponent(id)}/edit`;
}

/**
 * The full-page CREATE surface (t56). A static top-level route (`/templates/new`) rather than a
 * `:sec?` section: it is not a view of an existing template, so it lives beside the catalog, not
 * under a template id. React Router ranks the static `new` segment above the dynamic `:id`, so it is
 * never shadowed by `/templates/:id/:sec?`.
 */
export function templateNewPath(): string {
  return '/templates/new';
}

/**
 * FORK is a create SEEDED from a source (t56): the same page as create, carrying the source id as a
 * `?fork=<id>` query so the page can copy that template's spec + body into a fresh `user-…` draft.
 * A query rather than a path segment because the target is still `/templates/new` — a new template,
 * not a view of the source.
 */
export function templateForkPath(sourceId: string): string {
  return `/templates/new?fork=${encodeURIComponent(sourceId)}`;
}
