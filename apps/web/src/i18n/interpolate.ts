/**
 * Minimal `{name}` interpolation for catalog messages.
 *
 * A message template carries named placeholders in single braces — `"Insc. {event}"`,
 * `"Cadeia verificada ({count} eventos)"`. `interpolate` substitutes each `{name}`
 * with the matching param, coercing numbers to strings. An unknown placeholder is left
 * verbatim (a missing param is a bug we want to see, not silently blank), and a message
 * with no params is returned untouched (the common case, so no allocation).
 */
export type TParams = Record<string, string | number>;

const PLACEHOLDER = /\{(\w+)\}/g;

export function interpolate(template: string, params?: TParams): string {
  if (!params) return template;
  return template.replace(PLACEHOLDER, (match, name: string) =>
    name in params ? String(params[name]) : match,
  );
}
