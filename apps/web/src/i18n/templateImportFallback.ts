/**
 * Template import copy (t43) — the honest rejection messages for the bundle envelope's new
 * `422` codes, plus the "paste JSON" alternative to the file picker in the import dialog.
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts` + `reviewedIdenticalValues.ts`) sit under a single-writer serial lock during the
 * batch, so t43 may not add the usual "one import + one spread line per locale" wiring. This module
 * owns its keys end to end and exposes its own locale-aware resolver ({@link useTemplateImportT});
 * the dialog reads copy through it exactly as through `useT`, so nothing in the shared catalog moves
 * and the catalog-leak gate never sees these strings. It follows `tableColumnsFallback.ts`'s shape
 * (a pt-PT source object plus an English fallback that `satisfies` its key set); folding these into
 * the catalog later is a mechanical spread.
 *
 * The five bundle codes are surfaced verbatim to the operator — reject, never transform: an
 * unrepresentable bundle is refused with the reason, never silently dropped or altered. The existing
 * codes (`too_large`/`malformed`/`conflict`/…) keep their catalog messages via `mappedTemplateError`;
 * only the genuinely new strings live here.
 *
 * pt-PT is the source; no anglicisms are invented, and nothing here makes an evidentiary claim (an
 * import is a disposable editing action, memory `tagline-no-valor-probatorio`).
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

/**
 * The bundle envelope's own `422` rejection codes (t43-e3). A code in this set is answered by this
 * module's `templates.import.error.<code>` message; every other code falls back to the catalog's
 * `templates.error.<code>` via `mappedTemplateError`, so nothing is ever swallowed.
 */
export const TEMPLATE_IMPORT_BUNDLE_ERROR_CODES: ReadonlySet<string> = new Set([
  'unsupported_bundle_version',
  'unsupported_bundle_format',
  'unsupported_markdown',
  'body_too_large',
  'invalid_seed',
]);

export const templateImportPtPT = {
  // — Origem: ficheiro ou colar ————————————————————————————————————————————
  'templates.import.source.file': 'Carregar ficheiro',
  'templates.import.source.paste': 'Colar JSON',
  'templates.import.paste.label': 'JSON do modelo',
  'templates.import.paste.placeholder': 'Cole aqui o conteúdo do ficheiro exportado…',
  'templates.import.paste.validate': 'Validar',
  'templates.import.hint':
    'Aceita um pacote exportado (envelope «chancela.template-bundle») ou o JSON simples de um modelo. O conteúdo é enviado tal como está — nada é reescrito.',

  // — Rejeições do envelope (código a código, honestas) —————————————————————
  'templates.import.error.unsupported_bundle_version':
    'A versão do pacote não é suportada por esta instalação. Exporte novamente a partir de uma versão compatível.',
  'templates.import.error.unsupported_bundle_format':
    'O ficheiro não é um pacote de modelo reconhecido. O campo «format» tem de ser «chancela.template-bundle».',
  'templates.import.error.unsupported_markdown':
    'O corpo do modelo (body_markdown) usa formatação não suportada. Só é aceite o subconjunto Markdown dos modelos (parágrafos e títulos); listas, tabelas e outros elementos são recusados.',
  'templates.import.error.body_too_large':
    'O corpo do modelo (body_markdown) excede o limite permitido.',
  'templates.import.error.invalid_seed':
    'O texto inicial do modelo é inválido: não pode estar vazio nem conter expressões de modelo (minijinja), e cada título tem de ter texto.',
} as const;

/** The key set the template-import copy resolves. */
export type TemplateImportCopyKey = keyof typeof templateImportPtPT;

export const templateImportEnglish = {
  'templates.import.source.file': 'Upload file',
  'templates.import.source.paste': 'Paste JSON',
  'templates.import.paste.label': 'Template JSON',
  'templates.import.paste.placeholder': 'Paste the contents of the exported file here…',
  'templates.import.paste.validate': 'Validate',
  'templates.import.hint':
    'Accepts an exported bundle (the “chancela.template-bundle” envelope) or a plain template JSON. The content is sent exactly as given — nothing is rewritten.',

  'templates.import.error.unsupported_bundle_version':
    'This bundle version is not supported by this installation. Re-export from a compatible version.',
  'templates.import.error.unsupported_bundle_format':
    'This file is not a recognised template bundle. Its “format” field must be “chancela.template-bundle”.',
  'templates.import.error.unsupported_markdown':
    'The template body (body_markdown) uses unsupported formatting. Only the templates’ Markdown subset (paragraphs and headings) is accepted; lists, tables and other elements are rejected.',
  'templates.import.error.body_too_large':
    'The template body (body_markdown) exceeds the allowed size.',
  'templates.import.error.invalid_seed':
    'The template’s starting text is invalid: it cannot be empty or contain template expressions (minijinja), and every heading must have text.',
} as const satisfies Record<TemplateImportCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split the sibling fallback modules use while the catalogs are locked.
 */
export function useTemplateImportCopy(): Record<TemplateImportCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? templateImportPtPT : templateImportEnglish;
}

/**
 * The dialog's extra translate hook, shaped like {@link useT}:
 * `const it = useTemplateImportT(); it('templates.import.source.file')`.
 */
export function useTemplateImportT(): (key: TemplateImportCopyKey, params?: TParams) => string {
  const copy = useTemplateImportCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
