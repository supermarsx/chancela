/**
 * Ata NARRATIVE-BODY copy (t35) — the WYSIWYG narrative surface mounted in `AtaEditorPage`: its
 * card title and guidance, the demotion note on the legacy plain `deliberations` field, the
 * one-time "seed the narrative from the notes" affordance, and the friendly nouns the body
 * editor's rejection diagnostic shows in place of the server's machine `code`.
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts` + `reviewedIdenticalValues.ts`) are edited additively by several in-flight tasks
 * under a shared lock, so t35's web copy owns its keys end to end and exposes its own locale-aware
 * resolver ({@link useActBodyT}). `AtaEditorPage` reads this copy through that resolver exactly as
 * it would through `useT`, so nothing in the shared catalog moves and the catalog-leak / literal-
 * copy gates never see these strings. It follows the shape of `actLifecycleFallback.ts` and
 * `notificationsRetentionFallback.ts` (a pt-PT source object plus an English fallback that
 * `satisfies` the key set); folding these into the catalogs later is a mechanical spread.
 *
 * The editor component's OWN copy (`acts.body.editor.*`, `acts.body.rejected.*`, `acts.body.paste.*`,
 * `acts.body.construct.*`) already lives in all 14 catalogs (t74) and is NOT duplicated here — this
 * module only adds the page-level chrome that mounts it.
 *
 * Copy rule: **no legal / evidentiary claim.** The narrative body is where the operator writes the
 * ata's prose; the copy says what the field is and how it relates to the plain notes, never anything
 * about "valor probatório" (memory `tagline-no-valor-probatorio`). pt-PT is the source; no anglicisms.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const actBodyPtPT = {
  // — The narrative body card: the primary prose surface (D1a) —————————————————————
  'acts.body.card.title': 'Narrativa da ata',
  'acts.body.card.hint':
    'Escreva aqui o corpo da ata com formatação. É este o texto que passa a constar do documento gerado.',

  // — The demoted plain-text «Deliberações» field (kept, secondary) ————————————————
  'acts.body.deliberations.note':
    'Este campo de texto simples mantém-se para notas sem formatação. A narrativa formatada acima é a que consta do documento.',
  'acts.body.seed.button': 'Copiar estas notas para a narrativa',
  'acts.body.seed.hint':
    'Copia o texto simples abaixo para a narrativa formatada, para continuar a editá-lo com formatação. As notas ficam intactas.',

  // — Friendly nouns for the body editor's rejection diagnostic (server `code`) ————————
  'acts.body.diagnostic.unsupported_markdown': 'Formatação não suportada',
  'acts.body.diagnostic.invalid_placeholder': 'Campo inválido',
  'acts.body.diagnostic.body_too_large': 'Texto demasiado longo',
  'acts.body.diagnostic.body_block_too_large': 'Parágrafo demasiado longo',
} as const;

/** The key set the ata narrative-body copy resolves. */
export type ActBodyCopyKey = keyof typeof actBodyPtPT;

export const actBodyEnglish = {
  'acts.body.card.title': 'Minutes narrative',
  'acts.body.card.hint':
    'Write the body of the minutes here, with formatting. This is the text that appears in the generated document.',

  'acts.body.deliberations.note':
    'This plain-text field remains for unformatted notes. The formatted narrative above is what appears in the document.',
  'acts.body.seed.button': 'Copy these notes into the narrative',
  'acts.body.seed.hint':
    'Copies the plain text below into the formatted narrative so you can keep editing it with formatting. The notes are left intact.',

  'acts.body.diagnostic.unsupported_markdown': 'Unsupported formatting',
  'acts.body.diagnostic.invalid_placeholder': 'Invalid field',
  'acts.body.diagnostic.body_too_large': 'Text too long',
  'acts.body.diagnostic.body_block_too_large': 'Paragraph too long',
} as const satisfies Record<ActBodyCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split the sibling fallback modules use while off the shared catalog chain.
 */
export function useActBodyCopy(): Record<ActBodyCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? actBodyPtPT : actBodyEnglish;
}

/**
 * The page's narrative-body translate hook, shaped like {@link useT}:
 * `const bt = useActBodyT(); bt('acts.body.card.title')`.
 */
export function useActBodyT(): (key: ActBodyCopyKey, params?: TParams) => string {
  const copy = useActBodyCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}

/**
 * Map a rejected-body `ApiError.code` to the copy key for the friendly noun the diagnostic chip
 * shows. Unknown codes fall back to the generic "unsupported formatting" label so a future server
 * code never renders a raw machine token to the operator.
 */
export function bodyDiagnosticKey(code: string | undefined): ActBodyCopyKey {
  switch (code) {
    case 'invalid_placeholder':
      return 'acts.body.diagnostic.invalid_placeholder';
    case 'body_too_large':
      return 'acts.body.diagnostic.body_too_large';
    case 'body_block_too_large':
      return 'acts.body.diagnostic.body_block_too_large';
    case 'unsupported_markdown':
    default:
      return 'acts.body.diagnostic.unsupported_markdown';
  }
}
