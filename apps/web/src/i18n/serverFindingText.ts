/**
 * The shared shape for rendering a **server-authored coded finding** in the operator's language.
 *
 * Extracted after the second vocabulary, because the first two disagree about one thing and
 * everything else is identical. Both `AsicInspectionFinding` and `PdfSignatureValidationFinding`
 * are `{severity, code, message}` where `message` is English written in `chancela-api`; both are
 * rendered by a panel that no client-side i18n gate can see into. What differs is **where the
 * untranslatable part lives**:
 *
 * - **ASiC** — `message` *is* the validator's own reason text in its entirety
 *   (`technical_failure_summary()`), so the whole thing is verbatim and the catalog supplies a
 *   frame around it.
 * - **PDF** — `message` is `"<our summary>: <PadesError>"`. The first half is ours and translatable;
 *   only the tail is verbatim, and the server now hands it over separately in `params.error`.
 *
 * So "the verbatim payload" is a *function of the finding*, not a fixed field. That is the single
 * generalisation this module makes: {@link resolveServerFinding} takes a `verbatimOf` callback and
 * is otherwise identical for every vocabulary.
 *
 * # What every caller gets, and must not skip
 *
 * An unknown code yields `kind: 'untranslated'` — the server's English, which the panel MUST mark
 * with `lang="en"` and an "Em inglês" badge. A silent fallback would pass English off as localized
 * copy and make the next backend-added code invisible instead of loud.
 *
 * A framed finding yields `before`/`verbatim`/`after` so the panel can mark **only** the foreign
 * substring. Returning one joined string cannot express that, and the first version of the ASiC
 * resolver did exactly that: a Portuguese frame around unmarked English, which presents as fully
 * translated and is worse than raw English. See `asicInspectionDiagnostics.ts` for the full note.
 */
import type { MessageKey, TParams } from './types';

/** What to render for one finding. */
export type ResolvedServerFinding =
  /** Fully translated; nothing foreign inside. */
  | { kind: 'translated'; text: string }
  /** A translated frame around verbatim foreign text; `verbatim` must be marked `lang="en"`. */
  | { kind: 'framed'; before: string; verbatim: string; after: string }
  /** The server's raw English, for a code this build does not know. Mark it AND badge it. */
  | { kind: 'untranslated'; text: string };

/**
 * Sentinel used to locate the placeholder inside the *translated* string.
 *
 * Splitting the rendered frame is what lets `before`/`after` be correct in a locale that does not
 * put the placeholder last. Assuming it is sentence-final would break the first locale that fronts
 * it, and it would break invisibly. U+0000 cannot occur in catalog copy.
 */
const PLACEHOLDER_SENTINEL = '\u0000';

export interface ServerFindingInput {
  code: string;
  /** The server's English sentence. Always present; the fallback of last resort. */
  message: string;
}

export interface ResolveOptions<T extends ServerFindingInput> {
  /** Code → catalog key. A code absent here takes the marked-English path. */
  keys: Record<string, MessageKey>;
  /**
   * The untranslatable payload for this finding, or `undefined` when it is fully translatable.
   *
   * Returning a blank string is treated as "nothing to frame" and degrades to marked English —
   * a frame ending in "…pelo validador:" with silence after it reads as a broken UI and would
   * hide that the server sent us nothing.
   */
  verbatimOf?: (finding: T) => string | undefined;
  /** The placeholder name the catalog frame uses for the verbatim payload. Defaults to `reasons`. */
  placeholder?: string;
}

/** Resolve one server-authored finding into the operator's language. */
export function resolveServerFinding<T extends ServerFindingInput>(
  finding: T,
  t: (key: MessageKey, params?: TParams) => string,
  { keys, verbatimOf, placeholder = 'reasons' }: ResolveOptions<T>,
): ResolvedServerFinding {
  const key = finding.code ? keys[finding.code] : undefined;
  if (!key) return { kind: 'untranslated', text: finding.message };

  const verbatim = verbatimOf?.(finding)?.trim();
  if (verbatim === undefined) return { kind: 'translated', text: t(key) };
  if (!verbatim) return { kind: 'untranslated', text: finding.message };

  const framed = t(key, { [placeholder]: PLACEHOLDER_SENTINEL });
  const at = framed.indexOf(PLACEHOLDER_SENTINEL);
  // A catalog entry that lost its placeholder is a translation bug the guard tests catch at CI
  // time. At runtime, degrade to marked English rather than dropping the payload or throwing —
  // and do NOT claim it is framed, because there would be nowhere to mark the foreign text.
  if (at < 0) return { kind: 'untranslated', text: finding.message };

  return {
    kind: 'framed',
    before: framed.slice(0, at),
    verbatim,
    after: framed.slice(at + PLACEHOLDER_SENTINEL.length),
  };
}
