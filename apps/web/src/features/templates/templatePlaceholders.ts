/**
 * The record fields an authored template expects — derived from the spec, not declared by it.
 *
 * A `TemplateSpec`'s blocks carry minijinja source (`{{ entity.nipc }}`,
 * `{% for item in agenda_items %}`), and neither the asset nor `TemplateSummary` publishes a
 * field list. The detail page needs one to answer the only question an operator actually has
 * about a template — *what does this document need from the ata record?* — so it is read out
 * of the expressions.
 *
 * This is a reader, not a validator: it reports what the template REFERS to. A name here does
 * not promise the server can supply it, and a name missing here does not make the template
 * invalid. Loop variables (`item` in the example above) are excluded — they are internal to
 * the block, not inputs — as are filter names, literals and minijinja keywords.
 */
import type { TemplateBlockSpec, TemplateSpec } from '../../api/types';

/** minijinja keywords, constants and loop internals — never a record field. */
const RESERVED = new Set([
  'if',
  'else',
  'elif',
  'endif',
  'for',
  'endfor',
  'in',
  'is',
  'and',
  'or',
  'not',
  'set',
  'with',
  'endwith',
  'macro',
  'endmacro',
  'raw',
  'endraw',
  'filter',
  'endfilter',
  'true',
  'false',
  'none',
  'True',
  'False',
  'None',
  'loop',
]);

const IDENTIFIER_PATH = /[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*/g;

/** Every string in a block that may hold minijinja source. */
function blockExpressions(block: TemplateBlockSpec): string[] {
  switch (block.kind) {
    case 'Heading':
      return [block.template];
    case 'Paragraph':
      return [block.template, ...(block.items ? [`{{ ${block.items} }}`] : [])];
    case 'KeyValue':
      return [
        ...(block.items ? [`{{ ${block.items} }}`] : []),
        ...block.rows.flatMap((row) => [row.key, row.value]),
      ];
    case 'VoteTable':
      return [
        `{{ ${block.items} }}`,
        block.label,
        ...(block.vote_field ? [`{{ ${block.vote_field} }}`] : []),
        ...(block.unanimous_total ? [`{{ ${block.unanimous_total} }}`] : []),
      ];
    case 'SignatureBlock':
      return [`{{ ${block.source} }}`, block.role, block.name];
    default:
      return [];
  }
}

/** Strip quoted literals so a string's contents never read as identifiers. */
function withoutLiterals(expression: string): string {
  return expression.replace(/'[^']*'/g, ' ').replace(/"[^"]*"/g, ' ');
}

/**
 * Drop each `|filter` name while keeping its arguments: `x | default("y")` refers to `x`,
 * and `default` is a filter, not a field.
 */
function withoutFilterNames(expression: string): string {
  return expression.replace(/\|\s*[A-Za-z_][A-Za-z0-9_]*/g, ' ');
}

/** The bodies of every `{{ … }}` and `{% … %}` tag in a string. */
function tagBodies(source: string): string[] {
  const bodies: string[] = [];
  const tags = /\{\{-?([\s\S]*?)-?\}\}|\{%-?([\s\S]*?)-?%\}/g;
  let match: RegExpExecArray | null;
  while ((match = tags.exec(source)) !== null) {
    bodies.push(match[1] ?? match[2] ?? '');
  }
  return bodies;
}

/**
 * The dotted field paths a spec's blocks read, sorted and de-duplicated.
 *
 * Paths are kept whole (`entity.nipc`, not `entity`) because that is the shape an operator
 * fills in; a bare root that is also used with members appears only if the template really
 * uses it bare.
 */
export function templatePlaceholders(spec: Pick<TemplateSpec, 'blocks'>): string[] {
  const locals = new Set<string>();
  const paths = new Set<string>();

  for (const block of spec.blocks ?? []) {
    for (const source of blockExpressions(block)) {
      if (typeof source !== 'string') continue;
      for (const body of tagBodies(source)) {
        const loop = /^\s*for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s/.exec(body);
        if (loop) locals.add(loop[1]);
        const cleaned = withoutFilterNames(withoutLiterals(body));
        for (const path of cleaned.match(IDENTIFIER_PATH) ?? []) {
          if (!RESERVED.has(path)) paths.add(path);
        }
      }
    }
  }

  return [...paths]
    .filter((path) => {
      const root = path.split('.')[0];
      return !locals.has(root) && !RESERVED.has(root);
    })
    .sort((left, right) => left.localeCompare(right));
}
