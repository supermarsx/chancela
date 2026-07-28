/**
 * RETENTION NEXT-STEP PROSE (t93) — the operator-facing "what to do about it" sentence on the
 * Privacidade/Retenção panel, as distinct from the *status* sentence `retentionExecutionStatusFallback.ts`
 * (t98) already covers for the same tokens.
 *
 * `crates/chancela-api/src/privacy.rs` puts raw English prose on the wire in `next_step` and
 * `evidence_next_step` fields across several retention structs, and `PrivacyComplianceSection.tsx`
 * rendered every one of them verbatim: `candidate.next_step`, `candidate.evidence_next_step`,
 * `priorExecution.next_step`, `priorExecution.evidence_next_step`, `latestResolution.next_step`,
 * `queuedReview.evidence_next_step`, `record.workflow.next_step` and `record.evidence_next_step` —
 * eight render sites, one more (`latestResolution.next_step`) than the seven originally reported,
 * since the same struct field reaches the screen from a second component. The same three fields also
 * feed `retentionExecutionSearchText()`, but that is a normalised, lower-cased search-matching corpus
 * an operator's own query is matched against, never rendered — left untranslated on purpose, not an
 * oversight.
 *
 * ─── WHY THE EXISTING GATES DID NOT CATCH THIS ─────────────────────────────────────────────────
 *
 * Same structural hole as `platformServiceFallback.ts` (t92): `noLiteralUiCopy.test.ts` walks the
 * TSX AST for string *literals*; `<span>{candidate.next_step}</span>` is a JSX expression holding a
 * runtime value, not a literal, so there is nothing in the tree to flag. `catalogLeakGate.test.ts`
 * only inspects the 13 shipped locale catalogs, and this prose was never in one. A client-side
 * literal gate cannot see server-authored prose.
 *
 * ─── WHY TEXT MATCH, NOT A STRUCTURED KEY ──────────────────────────────────────────────────────
 *
 * Most of these strings ARE reachable from a wire enum — `RetentionExecutionOutcome` drives most of
 * `retention_operator_workflow()`'s `next_step` match and `retention_execution_evidence_next_step()`,
 * and `RetentionCandidateDisposition` drives `retention_candidate_resolution_next_step()` — but two
 * literals break a clean per-field enum key:
 *
 *  - the due-candidate builder's `unsupported_retention_period` special case writes its own
 *    `next_step` sentence directly, before any `RetentionExecutionOutcome` match runs;
 *  - `legacy_retention_operator_workflow()`/`legacy_retention_execution_result()` — the
 *    `#[serde(default = …)]` fallback for `RetentionExecutionRecord`s persisted before the
 *    `workflow`/`execution_result` fields existed — write a fixed sentence with no outcome behind it
 *    at all.
 *
 * Rather than juggle two different keying schemes across eight render sites for a population that is,
 * structurally, one flat set of fixed sentences, every one of the twenty distinct literals Rust can
 * emit is resolved the same way `platformServiceFallback.ts` resolves `limitations[]`: by matching the
 * server's English text against the {@link retentionNextStepEnglish} tier, which is pinned to the Rust
 * literal verbatim. None of the twenty ever interpolates a value — no `format!()` anywhere in this
 * surface's next-step prose — so text match is sound here (memory: `i18n-interpolated-nouns-break-agreement`
 * is about a different failure mode, splicing a noun into a template; nothing here does that either).
 *
 * `retentionNextStepFallback.test.ts` parses the five sites in `privacy.rs` that can produce one of
 * these sentences — the three `RETENTION_PRIOR_BOUNDED_*_NEXT_STEP` consts,
 * `retention_due_candidate_for_book_policy`, `retention_operator_workflow`,
 * `retention_execution_evidence_next_step`, `retention_candidate_resolution_next_step`, and
 * `legacy_retention_operator_workflow` — by brace matching, and asserts set equality in both
 * directions against {@link retentionNextStepEnglish}. A sentence gained in Rust with no entry here
 * is red; an entry for a sentence Rust can no longer produce is red; a one-word reword of any Rust
 * literal is red, because the guard compares against the pinned copy, not a paraphrase of it.
 *
 * ─── THIS IS OPERATIONAL GUIDANCE, NOT A DPIA NO-CLAIMS FLAG ───────────────────────────────────
 *
 * `PrivacyComplianceSection.tsx` also holds the 28 DPIA `no_claims` flag identifiers, deliberately
 * left untranslated because translating one would assert a legal claim the product does not make
 * (memory: `no-claims-flags-untranslated`). None of the twenty sentences here is one of those flags:
 * every one names a concrete next action or states what did NOT happen operationally — "review the
 * retained evidence", "no disposal has been executed", "no source document deletion or GDPR erasure
 * was performed" — the same denial-carrying genre `retentionExecutionStatusFallback.ts` already
 * translates for the outcome/evidence-state tokens on this exact surface. None asserts that a legal
 * obligation was met, only what this application did or did not do.
 *
 * ─── DEGRADATION ────────────────────────────────────────────────────────────────────────────────
 *
 * `resolveRetentionNextStep` returns the server's own text, unchanged, when nothing matches (`known:
 * false`) — never blank, never a key (memory: `reject-never-silently-transform`). In DEV this also
 * warns, because an unmatched sentence means this module and `privacy.rs` have diverged.
 *
 * ─── WHY A SELF-CONTAINED MODULE ───────────────────────────────────────────────────────────────
 *
 * `Catalog` is `Record<MessageKey, string>`, total over 14 locales; this is twenty keys, so folding
 * it in today is 280 edits across files several live lanes are serialised on. Same escape valve as
 * `platformServiceFallback.ts`, `retentionExecutionStatusFallback.ts` and ~20 siblings: a pt-PT source
 * object plus an English tier that `satisfies` the same key set, behind a locale-aware hook. A copy
 * change here moves 2 places in 1 file.
 *
 * pt-PT, never pt-BR, no invented anglicisms (memory: `pt-pt-no-invented-anglicisms`). Vocabulary
 * matches `retentionExecutionStatusFallback.ts` and the existing `settings.privacy.*` catalog keys on
 * this same page — «descarte», «retenção legal», «evidência delimitada», «aprovação de governação»,
 * «RGPD» — so the next-step sentence and the status badge beside it read as one voice. Every entry is
 * a complete standalone sentence; none interpolates a noun.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';

/**
 * Stable client-side codes for the twenty sentences `privacy.rs` can put in a `next_step` or
 * `evidence_next_step` field. None reaches the wire; see the module header for why a structured key
 * per field was not used instead.
 */
export type RetentionNextStepCode =
  | 'unsupportedRetentionPeriod'
  | 'blockedLegalHold'
  | 'blockedPolicySelection'
  | 'blockedDestructiveAction'
  | 'blockedApprovalMismatch'
  | 'blockedMissingTarget'
  | 'manualReviewRequired'
  | 'boundedArchiveWorkflow'
  | 'boundedNoActionWorkflow'
  | 'alreadyExecutedWorkflow'
  | 'boundedArchiveEvidence'
  | 'boundedNoActionEvidence'
  | 'alreadyExecutedEvidence'
  | 'priorBoundedArchive'
  | 'priorBoundedNoAction'
  | 'priorBoundedGeneric'
  | 'resolutionEvidenceAcknowledged'
  | 'resolutionFollowUpRequired'
  | 'resolutionBlockedFollowUp'
  | 'legacyReviewOnly';

export type RetentionNextStepCopy = Record<RetentionNextStepCode, string>;

/** pt-PT source copy — the reviewed sentences. */
export const retentionNextStepPtPT: RetentionNextStepCopy = {
  unsupportedRetentionPeriod:
    'Reveja a sintaxe do período da política de retenção; não foi executado qualquer descarte.',
  blockedLegalHold:
    'Resolva a aprovação da retenção legal antes de continuar; não foi executado qualquer descarte.',
  blockedPolicySelection:
    'Selecione ou atualize uma política de retenção ativa correspondente; não foi executado qualquer descarte.',
  blockedDestructiveAction:
    'Registe uma aprovação de governação separada antes de qualquer processo destrutivo externo; esta API não o executa.',
  blockedApprovalMismatch:
    'Corrija os metadados de aprovação para corresponderem à política/ação pedida; não foi executado qualquer descarte.',
  blockedMissingTarget:
    'Indique um record_id concreto antes da execução delimitada; não foi executado qualquer descarte.',
  manualReviewRequired:
    'Reveja a evidência retida para aprovação manual; não foi executado qualquer descarte.',
  boundedArchiveWorkflow:
    'Foi registada evidência delimitada de arquivo para este alvo; nenhum documento de origem foi apagado e nenhum apagamento ao abrigo do RGPD foi executado.',
  boundedNoActionWorkflow:
    'Foi registada evidência delimitada de ausência de ação para este alvo; nenhum documento de origem foi apagado e nenhum apagamento ao abrigo do RGPD foi executado.',
  alreadyExecutedWorkflow:
    'Uma execução delimitada anterior já registou esta ação de alvo/política; não foi registada qualquer ação duplicada.',
  boundedArchiveEvidence:
    'Evidência delimitada de arquivo registada; não foi realizada qualquer operação destrutiva.',
  boundedNoActionEvidence:
    'Evidência delimitada de ausência de ação registada; não foi realizada qualquer operação destrutiva.',
  alreadyExecutedEvidence:
    'Já existe evidência delimitada anterior disponível para este alvo/política; não foi registada qualquer ação duplicada.',
  priorBoundedArchive:
    'Está disponível para revisão evidência delimitada de arquivo anterior; esta análise de candidatos pendentes é apenas de leitura e exige aprovação de governação separada antes de qualquer ação operacional.',
  priorBoundedNoAction:
    'Está disponível para revisão evidência delimitada de ausência de ação anterior; esta análise de candidatos pendentes é apenas de leitura e exige aprovação de governação separada antes de qualquer ação operacional.',
  priorBoundedGeneric:
    'Está disponível para revisão evidência delimitada de retenção anterior; esta análise de candidatos pendentes é apenas de leitura e exige aprovação de governação separada antes de qualquer ação operacional.',
  resolutionEvidenceAcknowledged:
    'Foi registada uma disposição apenas de evidência; o candidato pendente continua disponível para revisão de governação separada.',
  resolutionFollowUpRequired:
    'Foi registada evidência de seguimento; o candidato pendente continua disponível para revisão de governação separada.',
  resolutionBlockedFollowUp:
    'Foi registada evidência de seguimento com impedimentos; os impedimentos mantêm-se ativos para revisão de governação separada.',
  legacyReviewOnly: 'Reveja a evidência de execução retida; não foi executado qualquer descarte.',
};

/**
 * English tier, served to the other 13 locales — and the Rust literal, character for character.
 * `retentionNextStepFallback.test.ts` parses `privacy.rs` and asserts exact equality against this
 * object in both directions. Do not reword an entry here to read better; change the Rust and mirror
 * it, or the guard is comparing against a fiction.
 */
export const retentionNextStepEnglish: RetentionNextStepCopy = {
  unsupportedRetentionPeriod:
    'Review the retention policy period syntax; no disposal has been executed.',
  blockedLegalHold:
    'Resolve the legal hold approval before continuing; no disposal has been executed.',
  blockedPolicySelection:
    'Select or update an active matching retention policy; no disposal has been executed.',
  blockedDestructiveAction:
    'Record separate governance approval before any external destructive process; this API will not execute it.',
  blockedApprovalMismatch:
    'Correct the approval metadata so it matches the requested policy/action; no disposal has been executed.',
  blockedMissingTarget:
    'Provide a concrete record_id before bounded execution; no disposal has been executed.',
  manualReviewRequired:
    'Review the retained evidence for manual approval; no disposal has been executed.',
  boundedArchiveWorkflow:
    'Bounded archive evidence was recorded for this target; no source document deletion or GDPR erasure was performed.',
  boundedNoActionWorkflow:
    'Bounded no-action evidence was recorded for this target; no source document deletion or GDPR erasure was performed.',
  alreadyExecutedWorkflow:
    'A prior bounded execution already recorded this target/policy action; no duplicate action was recorded.',
  boundedArchiveEvidence:
    'Bounded archive evidence recorded; no destructive operation was performed.',
  boundedNoActionEvidence:
    'Bounded no-action evidence recorded; no destructive operation was performed.',
  alreadyExecutedEvidence:
    'Prior bounded evidence is already available for this target/policy; no duplicate action was recorded.',
  priorBoundedArchive:
    'Prior bounded archive evidence is available for review; this due-candidate scan is read-only and requires separate governance approval before any operational action.',
  priorBoundedNoAction:
    'Prior bounded no-action evidence is available for review; this due-candidate scan is read-only and requires separate governance approval before any operational action.',
  priorBoundedGeneric:
    'Prior bounded retention evidence is available for review; this due-candidate scan is read-only and requires separate governance approval before any operational action.',
  resolutionEvidenceAcknowledged:
    'Evidence-only disposition recorded; the due candidate remains available for separate governance review.',
  resolutionFollowUpRequired:
    'Follow-up evidence recorded; the due candidate remains available for separate governance review.',
  resolutionBlockedFollowUp:
    'Blocked follow-up evidence recorded; blockers remain active for separate governance review.',
  legacyReviewOnly: 'Review the retained execution evidence; no disposal has been executed.',
};

/** English prose → code, built from the pinned English tier. */
const CODE_BY_ENGLISH: ReadonlyMap<string, RetentionNextStepCode> = new Map(
  (Object.entries(retentionNextStepEnglish) as [RetentionNextStepCode, string][]).map(
    ([code, english]) => [english, code] as const,
  ),
);

function warnDrift(serverText: string): void {
  if (import.meta.env.DEV) {
    console.warn(
      `[retentionNextStepFallback] no copy for a next-step sentence (${serverText}); the ` +
        "server's English was rendered verbatim. privacy.rs and this module have diverged.",
    );
  }
}

/** How a server sentence resolved. `text` is never empty. */
export interface RetentionNextStepResolution {
  /** The sentence to render. */
  text: string;
  /**
   * `false` when no entry matched and `text` is the server's own English, rendered verbatim rather
   * than dropped.
   */
  known: boolean;
}

/**
 * Resolve one `next_step`/`evidence_next_step` value by matching the server's English against the
 * pinned tier. See the module header for why text match, not a structured key, is sound here.
 */
export function resolveRetentionNextStep(
  copy: RetentionNextStepCopy,
  serverText: string,
): RetentionNextStepResolution {
  const code = CODE_BY_ENGLISH.get(serverText.trim());
  if (code === undefined) {
    warnDrift(serverText);
    return { text: serverText, known: false };
  }
  return { text: copy[code], known: true };
}

/**
 * The active copy tier: pt-PT gets the reviewed sentences, every other locale gets the pinned
 * English — the same split the sibling fallback modules use while off the shared catalog chain.
 */
export function useRetentionNextStepCopy(): RetentionNextStepCopy {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? retentionNextStepPtPT : retentionNextStepEnglish;
}

/** `resolveRetentionNextStep` bound to the active locale. */
export function useRetentionNextStep(): (serverText: string) => RetentionNextStepResolution {
  const copy = useRetentionNextStepCopy();
  return useMemo(() => (serverText: string) => resolveRetentionNextStep(copy, serverText), [copy]);
}
