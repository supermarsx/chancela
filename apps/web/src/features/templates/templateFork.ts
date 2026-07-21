/**
 * Forking a template into the `user-…` namespace.
 *
 * Built-in templates are frozen ON PURPOSE and this module is the consequence, not a
 * workaround. A sealed document records the digest of the spec it was generated from, so
 * editing a shipped template in place would retroactively change what a past seal meant.
 * "Editar" on a built-in therefore copies it; only the copy is editable.
 *
 * The id the copy gets must satisfy the server's own rule (`^user-[a-z0-9-]+/v[0-9]+$`,
 * `crates/chancela-templates/src/authoring.rs`), so it is derived here rather than typed:
 * an id the operator has to invent is an id the operator gets wrong.
 */
import type { TemplateSpec } from '../../api/types';

/** The id without its `/vN` suffix, e.g. `assoc-ata-direcao/v1` → `assoc-ata-direcao`. */
export function templateIdBase(id: string): string {
  const slash = id.lastIndexOf('/');
  return slash === -1 ? id : id.slice(0, slash);
}

/** The `/vN` suffix, or an empty string when the id carries none. */
export function templateIdVersion(id: string): string {
  const slash = id.lastIndexOf('/');
  return slash === -1 ? '' : id.slice(slash + 1);
}

/** Reduce any base to the `[a-z0-9-]+` the server accepts, accents folded rather than dropped. */
function slugify(value: string): string {
  const folded = value
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return folded || 'modelo';
}

/**
 * A free `user-…/v1` id derived from `sourceId`, avoiding every id in `taken`.
 *
 * A built-in `assoc-ata-direcao/v1` yields `user-assoc-ata-direcao/v1`; forking that copy
 * again yields `user-assoc-ata-direcao-2/v1`, and so on. Version is always `v1` — the copy is
 * a new template with its own history, not a new version of the original.
 */
export function forkedTemplateId(sourceId: string, taken: Iterable<string> = []): string {
  const existing = new Set(taken);
  const base = slugify(templateIdBase(sourceId)).replace(/^user-/, '');
  const stem = `user-${base}`;
  if (!existing.has(`${stem}/v1`)) return `${stem}/v1`;
  for (let suffix = 2; ; suffix += 1) {
    const candidate = `${stem}-${suffix}/v1`;
    if (!existing.has(candidate)) return candidate;
  }
}

/**
 * The forked spec: the source's body verbatim under a new id.
 *
 * Nothing else is rewritten — family, stage, channels, signature policy, rule pack and locale
 * are what make the copy a usable starting point, and silently changing any of them would
 * make the fork behave unlike the template it was copied from.
 */
export function forkTemplateSpec(spec: TemplateSpec, id: string): TemplateSpec {
  return { ...spec, id };
}
