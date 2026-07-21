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
