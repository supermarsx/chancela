/**
 * Client mirror of the closed page-furniture placeholder vocabulary
 * (`chancela-core::document_layout`, `parse_furniture_template`).
 *
 * The server is authoritative: it rejects an unauthorable template with `422` whether or not this
 * module agrees. This exists so the operator finds out while typing rather than on save, and so
 * the pane can show what a template will actually print. That matters more here than in an
 * ordinary form: furniture text is drawn on every page of an instrument that will be signed, and
 * the vocabulary is closed precisely because a general engine would render `{{ pagina }}` as the
 * empty string and nobody would notice until it was too late.
 *
 * Keep the vocabulary, the limits, and the failure cases in step with the Rust. `MAX` counts
 * Unicode scalar values, matching Rust's `chars().count()` — `String.length` would count UTF-16
 * code units and let a 200-character template with an emoji through here and fail on the server.
 */

/** Every token an author may write between `{{` and `}}`, in the core crate's document order. */
export const FURNITURE_PLACEHOLDERS = [
  'page',
  'page_count',
  'page_capacity',
  'entity_name',
  'entity_nipc',
  'title',
  'subject',
  'date',
] as const;

export type FurniturePlaceholder = (typeof FURNITURE_PLACEHOLDERS)[number];

/** Longest furniture template the server accepts, in characters. */
export const MAX_FURNITURE_TEXT_CHARS = 200;

export type FurnitureSegment =
  { kind: 'literal'; text: string } | { kind: 'placeholder'; placeholder: FurniturePlaceholder };

/**
 * Why a template is not authorable. A discriminated code rather than a message: the copy is the
 * caller's to translate, and a test that asserts on a rendered sentence would be asserting on
 * whichever locale happened to be mounted.
 */
export type FurnitureTemplateError =
  | { code: 'too_long'; maximum: number; actual: number }
  | { code: 'line_break' }
  | { code: 'unclosed_placeholder' }
  | { code: 'unknown_placeholder'; name: string };

export type FurnitureTemplateResult =
  { ok: true; segments: FurnitureSegment[] } | { ok: false; error: FurnitureTemplateError };

const KNOWN = new Set<string>(FURNITURE_PLACEHOLDERS);

function isPlaceholder(token: string): token is FurniturePlaceholder {
  return KNOWN.has(token);
}

/** Parse a furniture template into literal/placeholder segments, or say why it cannot be one. */
export function parseFurnitureTemplate(source: string): FurnitureTemplateResult {
  const actual = [...source].length;
  if (actual > MAX_FURNITURE_TEXT_CHARS) {
    return { ok: false, error: { code: 'too_long', maximum: MAX_FURNITURE_TEXT_CHARS, actual } };
  }
  if (source.includes('\n') || source.includes('\r')) {
    return { ok: false, error: { code: 'line_break' } };
  }

  const segments: FurnitureSegment[] = [];
  let literal = '';
  let rest = source;
  for (let open = rest.indexOf('{{'); open !== -1; open = rest.indexOf('{{')) {
    literal += rest.slice(0, open);
    const after = rest.slice(open + 2);
    const close = after.indexOf('}}');
    if (close === -1) return { ok: false, error: { code: 'unclosed_placeholder' } };
    const name = after.slice(0, close).trim();
    if (!isPlaceholder(name)) {
      return { ok: false, error: { code: 'unknown_placeholder', name } };
    }
    if (literal !== '') {
      segments.push({ kind: 'literal', text: literal });
      literal = '';
    }
    segments.push({ kind: 'placeholder', placeholder: name });
    rest = after.slice(close + 2);
  }
  literal += rest;
  if (literal !== '') segments.push({ kind: 'literal', text: literal });
  return { ok: true, segments };
}

/** The per-page facts a template resolves against. A missing key means the document lacks the fact. */
export type FurnitureFacts = Partial<Record<FurniturePlaceholder, string>>;

/**
 * Resolve parsed segments, or `null` when the document does not carry a fact the template asks
 * for. The renderer withholds the whole line in that case rather than printing `"Página 3 de "`,
 * which on a signed instrument would state something false.
 */
export function resolveFurnitureSegments(
  segments: readonly FurnitureSegment[],
  facts: FurnitureFacts,
): string | null {
  let out = '';
  for (const segment of segments) {
    if (segment.kind === 'literal') {
      out += segment.text;
      continue;
    }
    const value = facts[segment.placeholder];
    if (value === undefined) return null;
    out += value;
  }
  return out;
}

/**
 * The illustrative document the pane resolves against, so an operator can read back what a
 * template prints without generating anything.
 *
 * Deliberately not catalog copy: every value is a proper noun, an identifier, a number or an
 * ISO date, so translating them would be wrong, and fourteen byte-identical catalog entries
 * would have to be registered as reviewed for no gain. The entity is fictional.
 */
export const FURNITURE_SAMPLE_FACTS: Required<FurnitureFacts> = {
  page: '3',
  page_count: '12',
  page_capacity: '100',
  entity_name: 'Encosto Estratégico Lda',
  entity_nipc: '500123456',
  title: 'Ata n.º 4/2026',
  subject: 'Assembleia Geral Ordinária',
  date: '2026-03-14',
};

/** Resolve `source` against the sample document, or `null` when it is not authorable. */
export function previewFurnitureTemplate(source: string): string | null {
  const parsed = parseFurnitureTemplate(source);
  if (!parsed.ok) return null;
  return resolveFurnitureSegments(parsed.segments, FURNITURE_SAMPLE_FACTS);
}
