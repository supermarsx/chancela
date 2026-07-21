/**
 * Where a template's own page lives.
 *
 * A template id contains a slash (`csc-ata-ag/v1`), so the id segment is percent-encoded:
 * without it the `/v1` would read as a second path segment and the route would not match.
 * React Router decodes the param again for `useParams`, so the page still sees the real id.
 */
export function templateDetailPath(id: string): string {
  return `/minutas/${encodeURIComponent(id)}`;
}
