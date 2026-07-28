/**
 * PAPER-BOOK PACKAGE PRESERVATION STATUS (t98) — what the import report's preservation state means
 * to the operator reading it.
 *
 * `PaperBookCandidateClassification.preservation_status` was rendered verbatim in the middle of a
 * Portuguese sentence on the book detail page: «Estado: preserved_non_canonical_package. Validade
 * legal declarada: não.» An internal identifier standing in for copy, and folded into prose rather
 * than presented as an identifier. This module supplies the human label and the sentence; the
 * identifier itself is kept, in `mono`, as the stable thing to quote in a support thread — the same
 * split as `externalValidatorStatusFallback.ts` and `platformServiceFallback.ts`.
 *
 * ─── THIS IS AN OPERATIONAL STATUS; ITS SIBLINGS ARE NOT ───────────────────────────────────────
 *
 * `PaperBookCandidateClassification` in `crates/chancela-api/src/paper_import.rs` carries a
 * no-claims population, and it is a DIFFERENT set of fields: `canonical_minutes_claimed`,
 * `legal_validity_claimed`, `signature_validity_claimed` and `qualified_signature_claimed` are all
 * hard-coded `false` at both construction sites, and the sibling `BookDetailPage.tsx::flag` list
 * (`destructive_disposal_completed`, `disposal_approved`, `legal_compliance_claimed`) is the
 * documented untranslated family. None of those are touched here.
 *
 * `preservation_status` is not of that family. It is one of two literals hard-coded at the two
 * struct constructions — one on the validation path, one on the preservation path — and it reports a
 * plain fact about stored bytes: did this installation keep the package, or only read it? Saying so
 * asserts nothing about validity, conformity or legal effect.
 *
 * What the copy must NOT do is drop the `non_canonical` qualifier the token carries. Preservation
 * here is explicitly preservation as historical evidence, and both entries say so, because the
 * denial is the substance of the state rather than a caveat attached to it.
 *
 * ─── WHY A SELF-CONTAINED MODULE ───────────────────────────────────────────────────────────────
 *
 * `Catalog` is `Record<MessageKey, string>`, total over 14 locales, so every new key is 14 edits
 * across files several live lanes are serialised on. This follows the established escape valve —
 * `apiErrorFallback.ts`, `externalValidatorStatusFallback.ts` and ~20 siblings: a pt-PT source
 * object plus an English tier that `satisfies` the same key set, resolved through its own
 * locale-aware hook. Fold it into the catalogs once all 14 are in one hand.
 *
 * ─── THE DIVERGENCE GUARANTEE ──────────────────────────────────────────────────────────────────
 *
 * `paperBookPreservationFallback.test.ts` parses the emitting struct constructions in
 * `paper_import.rs` and asserts set equality in BOTH directions: a token the emitter gains with no
 * entry here is red, and an entry here for a token the emitter can no longer produce is red.
 *
 * ─── AUTHORING RULES ───────────────────────────────────────────────────────────────────────────
 *
 * Written from what the emitting code decides, never from the token's spelling; no entry restates
 * its own identifier. Each `meaning` is a COMPLETE standalone sentence group with no placeholder: a
 * noun interpolated into Portuguese breaks article, adjective and participle agreement, so copy that
 * varies by token varies by entry (memory: `i18n-interpolated-nouns-break-agreement`). pt-PT, never
 * pt-BR, no invented anglicisms (memory: `pt-pt-no-invented-anglicisms`). The tokens stay English —
 * they are identifiers.
 */
import { useMemo } from 'react';
import type { Locale } from '../api/types';
import { useActiveLocale } from './useT';

/** Narrower than the `Badge` component's tone union; every value here is assignable to it. */
export type PaperBookPreservationTone = 'ok' | 'neutral' | 'warn';

export interface PaperBookPreservationEntry {
  /** Short human label for the badge. Never the identifier. */
  label: string;
  /** One complete standalone sentence group saying what the status means for the operator. */
  meaning: string;
  tone: PaperBookPreservationTone;
}

type PreservationTable = Readonly<Record<string, PaperBookPreservationEntry>>;

/** pt-PT is the authoring source. */
export const paperBookPreservationPtPT = {
  /** The validation path: the report was produced, nothing was written. */
  not_preserved_by_validation: {
    label: 'Ainda não preservado',
    meaning:
      'A validação leu o pacote em papel e produziu este relatório, mas não guardou nenhum ficheiro nesta instalação. Nada foi acrescentado ao livro. Execute a ação de preservação para que o pacote fique retido como prova histórica.',
    tone: 'neutral',
  },
  /** The preservation path: the package is stored, explicitly as non-canonical evidence. */
  preserved_non_canonical_package: {
    label: 'Preservado como prova histórica',
    meaning:
      'O pacote em papel ficou guardado nesta instalação como prova histórica. Não constitui um ato do livro nem substitui as atas canónicas, e a continuação digital continua a exigir uma ação separada do operador.',
    tone: 'ok',
  },
} as const satisfies PreservationTable;

export const paperBookPreservationEnglish = {
  not_preserved_by_validation: {
    label: 'Not preserved yet',
    meaning:
      'Validation read the paper package and produced this report, but stored no file on this installation. Nothing was added to the book. Run the preservation action so the package is retained as historical evidence.',
    tone: 'neutral',
  },
  preserved_non_canonical_package: {
    label: 'Preserved as historical evidence',
    meaning:
      'The paper package is stored on this installation as historical evidence. It is not a book act and does not replace the canonical minutes, and digital continuation still requires a separate operator action.',
    tone: 'ok',
  },
} as const satisfies PreservationTable;

/** Shown when the server serves a token this build has no entry for. Never blank. */
const UNRECOGNISED_PT_PT: PaperBookPreservationEntry = {
  label: 'Estado não reconhecido',
  meaning:
    'Esta versão da aplicação não reconhece este estado de preservação. O identificador apresentado é o valor exato devolvido pelo servidor; cite-o tal como está ao pedir apoio.',
  tone: 'neutral',
};
const UNRECOGNISED_ENGLISH: PaperBookPreservationEntry = {
  label: 'Unrecognised status',
  meaning:
    'This version of the application does not recognise this preservation status. The identifier shown is the exact value the server returned; quote it verbatim when asking for support.',
  tone: 'neutral',
};

interface PreservationTier {
  table: PreservationTable;
  unrecognised: PaperBookPreservationEntry;
}

const PT_PT_TIER: PreservationTier = {
  table: paperBookPreservationPtPT,
  unrecognised: UNRECOGNISED_PT_PT,
};
const ENGLISH_TIER: PreservationTier = {
  table: paperBookPreservationEnglish,
  unrecognised: UNRECOGNISED_ENGLISH,
};

/** pt-PT is the source; every other locale receives the English tier until it is reviewed. */
const TIERS_BY_LOCALE: Partial<Record<Locale, PreservationTier>> = {
  'pt-PT': PT_PT_TIER,
  'en-US': ENGLISH_TIER,
  'en-GB': ENGLISH_TIER,
};

/** A resolved status. `label` and `meaning` are never empty, so the UI renders them unconditionally. */
export interface PaperBookPreservationDescription extends PaperBookPreservationEntry {
  /** False when this build has no entry for the token the server served. */
  known: boolean;
}

/** Resolve one token. Exported shape used by both the hook and the test. */
export function describePaperBookPreservation(
  token: string,
  tier: PreservationTier = PT_PT_TIER,
): PaperBookPreservationDescription {
  const entry = tier.table[token];
  return entry === undefined ? { ...tier.unrecognised, known: false } : { ...entry, known: true };
}

/**
 * The book detail page's resolver, locale-aware:
 * `const describe = usePaperBookPreservationResolver(); describe(report.…preservation_status)`.
 */
export function usePaperBookPreservationResolver(): (
  token: string,
) => PaperBookPreservationDescription {
  const locale = useActiveLocale();
  const tier = TIERS_BY_LOCALE[locale] ?? ENGLISH_TIER;
  return useMemo(() => (token: string) => describePaperBookPreservation(token, tier), [tier]);
}
