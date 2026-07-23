/**
 * The template write-path error map — shared by every surface that POSTs/PUTs/imports a template
 * (the full-page create/edit surfaces and the import dialog).
 *
 * Extracted here (t56) when the create/fork modal `TemplateEditorForm` was retired in favour of
 * full pages: the mapping outlived the modal it used to live in, so it moved to its own module
 * rather than being anchored to a component that no longer exists.
 */
import type { MessageKey } from '../../i18n';

/**
 * The server's `422`/`409` error codes that carry a localized `templates.error.<code>` message.
 * A code outside this set (or an unexpected transport error) falls back to the server message so
 * nothing is ever swallowed.
 */
export const TEMPLATE_ERROR_CODES: ReadonlySet<string> = new Set([
  'too_large',
  'malformed',
  'invalid_id',
  'no_blocks',
  'bad_template',
  'unknown_threshold',
  'unsupported_locale',
  'conflict',
  'id_mismatch',
]);
// NB: the bundle / narrative-body write codes (`invalid_placeholder`, `unsupported_markdown`,
// `body_too_large`, `unsupported_bundle_format`, …) are deliberately NOT in this set — they carry no
// `templates.error.<code>` catalog message, so they fall through to the server's own sentence rather
// than to a missing-key marker. The body editor shows a friendly per-code noun of its own inline
// (see `bodyDiagnosticKey` in `actBodyFallback`); this map is only for form-level submit errors.

/** Map a server error code to its localized message, falling back to the raw server text. */
export function mappedTemplateError(
  t: (key: MessageKey) => string,
  code: string | undefined,
  fallback: string,
): string {
  return code && TEMPLATE_ERROR_CODES.has(code)
    ? t(`templates.error.${code}` as MessageKey)
    : fallback;
}
