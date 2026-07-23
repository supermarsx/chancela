/**
 * "Nova ata" DRAFT copy (t59) — the optional ata-template picker on the new-ata form
 * (`DraftAtaForm`). Choosing a template threads its id into `POST /v1/acts` so the server can seed
 * the new act's editable narrative from that template's default body; leaving it on the default
 * omits the id and the server resolves the family default.
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts`) are edited additively by several in-flight tasks under a shared lock, so t59's
 * two new strings own their keys end to end and expose their own locale-aware resolver
 * ({@link useDraftAtaT}). It follows the shape of `actBodyFallback.ts` (a pt-PT source object plus
 * an English fallback that `satisfies` the key set); folding these into the catalogs later is a
 * mechanical spread.
 *
 * Copy rule: **no legal / evidentiary claim** (memory `tagline-no-valor-probatorio`). pt-PT is the
 * source; no anglicisms.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const draftAtaPtPT = {
  'acts.template.label': 'Modelo da ata (opcional)',
  'acts.template.hint':
    'Escolha o modelo a aplicar. Se não escolher, é usado o modelo predefinido para este tipo de entidade.',
  'acts.template.default': 'Modelo predefinido',
} as const;

/** The key set the new-ata draft copy resolves. */
export type DraftAtaCopyKey = keyof typeof draftAtaPtPT;

export const draftAtaEnglish = {
  'acts.template.label': 'Minutes template (optional)',
  'acts.template.hint':
    'Choose the template to apply. If you do not choose one, the default template for this entity type is used.',
  'acts.template.default': 'Default template',
} as const satisfies Record<DraftAtaCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split the sibling fallback modules use while off the shared catalog chain.
 */
export function useDraftAtaCopy(): Record<DraftAtaCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? draftAtaPtPT : draftAtaEnglish;
}

/**
 * The form's draft-copy translate hook, shaped like {@link useT}:
 * `const dt = useDraftAtaT(); dt('acts.template.label')`.
 */
export function useDraftAtaT(): (key: DraftAtaCopyKey, params?: TParams) => string {
  const copy = useDraftAtaCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
