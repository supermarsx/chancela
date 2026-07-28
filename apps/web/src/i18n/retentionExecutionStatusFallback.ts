/**
 * RETENTION EXECUTION STATUSES (t98) — the sentences that say what the Privacidade/Retenção panel's
 * server-emitted tokens mean to the operator reading them.
 *
 * Ten render sites on `PrivacyComplianceSection.tsx` showed their raw wire token as the whole
 * visible value — `record.outcome`, `record.evidence_state`, the three `priorExecution.*` fields,
 * the two `queuedReview.*` fields, `candidate.candidate_evidence_state`,
 * `latestResolution.disposition` and `report.mode`. Ten sites, but only FIVE token populations: the
 * same `RetentionExecutionOutcome` is behind two of them and the same `RetentionEvidenceState`
 * behind four. This module owns four of the five; see below for the fifth.
 *
 * The identifier is NOT replaced. It stays, in `mono`, as the stable thing an operator quotes in a
 * support thread; the copy is added around it. Same split as `externalValidatorStatusFallback.ts`.
 *
 * ─── THE FIFTH POPULATION IS DELIBERATELY NOT HERE ─────────────────────────────────────────────
 *
 * `RetentionExecutionStatus` (`awaiting_review` / `blocked` / `executed`) ALREADY has operator copy:
 * `RETENTION_EXECUTION_STATUS_LABEL_KEYS` in `PrivacyComplianceSection.tsx` maps it to
 * `settings.privacy.execution.status.*`, which is in the shipped `Catalog` and already translated
 * across all 14 locales. Adding a competing table here would give the same three tokens two sources
 * of truth. Those two sites reuse the existing label and tone helpers and gain only the `mono`
 * identifier beside them. The divergence test still covers that population — it checks the exported
 * `RETENTION_EXECUTION_STATUSES` union against the Rust enum — so the catalog cannot drift from the
 * emitter either.
 *
 * ─── THESE ARE OPERATIONAL STATUSES; THE 28 DPIA FLAGS IN THE SAME FILE ARE NOT ────────────────
 *
 * `PrivacyComplianceSection.tsx` holds both families, which is exactly why the classification had to
 * be made per expression rather than per file. `PrivacyComplianceSection.tsx::key` is the 28
 * `no_claims` DPIA flag identifiers — names of legal claims the product does NOT make, left
 * untranslated forever in `mono` because translating one would assert it (`dpiaTemplateLabels.ts`).
 * Nothing here touches them.
 *
 * Every token below is computed from a plain boolean or a short state machine in
 * `crates/chancela-api/src/privacy.rs` and reports a fact about progress:
 *
 *  - `outcome` is the arm the execution evaluator reached, each carrying its own `reason_code`;
 *  - `evidence_state` is `retention_execution_evidence_state(outcome)`, a total match on outcome;
 *  - `disposition` is which of three evidence records an operator chose to file;
 *  - `mode` is `execution_record.is_some()` — one boolean, nothing else.
 *
 * `disposition` and `mode` deserved the hardest look, and both survive it. "Disposition" in a
 * records-management context normally names a destruction or transfer action; here it does not.
 * `RetentionCandidateResolutionSummary` hard-codes `evidence_only: true` alongside
 * `destructive_disposal_completed: false`, `disposal_completed: false`, `full_erasure_completed:
 * false`, `erasure_completed: false`, `legal_hold_mutated: false` and `legal_hold_resolved: false`,
 * and the Rust next_step reads "Evidence-only disposition recorded; the due candidate remains
 * available for separate governance review." It records that an operator acknowledged evidence. It
 * effects nothing.
 *
 * ─── THE DENIAL IS PART OF THE COPY, NOT A CAVEAT ON IT ────────────────────────────────────────
 *
 * Every arm of the Rust workflow says what did NOT happen — "no disposal has been executed", "no
 * source document deletion or GDPR erasure was performed", "no duplicate action was recorded". On a
 * retention surface that denial is the operator's most important fact, so every `outcome` and every
 * `disposition` entry here carries one, and `retentionExecutionStatusFallback.test.ts` asserts its
 * presence. Copy that dropped it would read as though something had been destroyed.
 *
 * ─── WHY A SELF-CONTAINED MODULE ───────────────────────────────────────────────────────────────
 *
 * `Catalog` is `Record<MessageKey, string>`, total over 14 locales, so every new key is 14 edits
 * across files several live lanes are serialised on — and this is 21 keys. This follows the
 * established escape valve: a pt-PT source object plus an English tier that `satisfies` the same key
 * set, resolved through its own locale-aware hook. Fold it into the catalogs once all 14 are in one
 * hand.
 *
 * ─── AUTHORING RULES ───────────────────────────────────────────────────────────────────────────
 *
 * Written from what the emitting code decides, never from the token's spelling; no entry restates
 * its own identifier. Each `meaning` is a COMPLETE standalone sentence group with no placeholder: a
 * noun interpolated into Portuguese breaks article, adjective and participle agreement, so copy that
 * varies by token varies by entry (memory: `i18n-interpolated-nouns-break-agreement`). pt-PT, never
 * pt-BR, no invented anglicisms (memory: `pt-pt-no-invented-anglicisms`) — "RGPD", not a coined
 * rendering of "GDPR". The tokens stay English; they are identifiers.
 */
import { useMemo } from 'react';
import type { Locale } from '../api/types';
import { useActiveLocale } from './useT';

/** Narrower than the `Badge` component's tone union; every value here is assignable to it. */
export type RetentionStatusTone = 'ok' | 'neutral' | 'warn' | 'error';

export interface RetentionStatusEntry {
  /** Short human label for the badge. Never the identifier. */
  label: string;
  /** One complete standalone sentence group saying what the status means for the operator. */
  meaning: string;
  tone: RetentionStatusTone;
}

/**
 * The four populations this module owns. `RetentionExecutionStatus` is deliberately absent — it is
 * already in the shipped catalog; see the header.
 */
export type RetentionStatusGroup = 'outcome' | 'evidenceState' | 'disposition' | 'dryRunMode';

type StatusGroupTable = Readonly<Record<string, RetentionStatusEntry>>;
type StatusGroups = Readonly<Record<RetentionStatusGroup, StatusGroupTable>>;

/** pt-PT is the authoring source. */
export const retentionStatusPtPT = {
  /** `RetentionExecutionOutcome`, the arm the execution evaluator reached. */
  outcome: {
    blocked_missing_policy: {
      label: 'Bloqueado: falta a política',
      meaning:
        'O pedido não indicou uma política de retenção que exista nesta instalação, pelo que a execução não avançou. Indique uma política ativa e repita o pedido. Nada foi eliminado.',
      tone: 'error',
    },
    blocked_stale_policy: {
      label: 'Bloqueado: política não ativa',
      meaning:
        'A política indicada existe mas não está em vigor, pelo que a execução não avançou. Ative a política, ou escolha outra que esteja em vigor, antes de repetir. Nada foi eliminado.',
      tone: 'error',
    },
    blocked_policy_mismatch: {
      label: 'Bloqueado: política não corresponde',
      meaning:
        'O âmbito ou a categoria da política indicada não coincide com o candidato em causa, pelo que a execução não avançou. Confirme que está a aplicar a política certa a este registo. Nada foi eliminado.',
      tone: 'error',
    },
    blocked_legal_hold: {
      label: 'Bloqueado: retenção legal ativa',
      meaning:
        'Há uma retenção legal ativa sobre este registo, e a retenção legal prevalece sobre o prazo da política. Levante a retenção legal, com a aprovação devida, antes de voltar a pedir a execução. Nada foi eliminado.',
      tone: 'error',
    },
    blocked_destructive_action: {
      label: 'Bloqueado: ação destrutiva',
      meaning:
        'A política pedida implica uma ação destrutiva, que esta aplicação não executa em circunstância alguma. Registe a aprovação de governação e conduza esse processo fora desta aplicação. Nada foi eliminado.',
      tone: 'error',
    },
    blocked_approval_mismatch: {
      label: 'Bloqueado: aprovação não corresponde',
      meaning:
        'Os dados da aprovação apresentada não coincidem com a política e a ação pedidas, pelo que a execução não avançou. Corrija a referência da aprovação e repita o pedido. Nada foi eliminado.',
      tone: 'error',
    },
    blocked_missing_target: {
      label: 'Bloqueado: falta o registo alvo',
      meaning:
        'O pedido não identificou um registo concreto sobre o qual atuar, pelo que a execução não avançou. Indique o identificador do registo antes de repetir. Nada foi eliminado.',
      tone: 'error',
    },
    manual_review_required: {
      label: 'Requer revisão manual',
      meaning:
        'A execução parou à espera de apreciação humana da prova reunida. Um responsável tem de a apreciar e decidir se o caso segue. Nada foi eliminado.',
      tone: 'warn',
    },
    bounded_archive_recorded: {
      label: 'Prova de arquivo registada',
      meaning:
        'Ficou registada prova de arquivo para este alvo, dentro dos limites em que esta aplicação atua. Nenhum documento de origem foi apagado e nenhum apagamento ao abrigo do RGPD foi executado.',
      tone: 'ok',
    },
    bounded_no_action_recorded: {
      label: 'Prova de não-ação registada',
      meaning:
        'Ficou registado que, para este alvo, não havia ação a tomar ao abrigo da política. Nenhum documento de origem foi apagado e nenhum apagamento ao abrigo do RGPD foi executado.',
      tone: 'ok',
    },
    already_executed: {
      label: 'Já registado antes',
      meaning:
        'Uma execução anterior já tinha registado esta combinação de alvo e política, pelo que não voltou a ser registada. Nada de novo foi eliminado.',
      tone: 'neutral',
    },
  },

  /** `RetentionEvidenceState`, a total match on the outcome. */
  evidenceState: {
    review_queued: {
      label: 'Em fila para revisão',
      meaning:
        'O caso está à espera de apreciação humana e a prova reunida fica retida até essa decisão. Nada foi eliminado.',
      tone: 'warn',
    },
    blocked: {
      label: 'Sem prova, por impedimento',
      meaning:
        'Há impedimentos por resolver, pelo que não chegou a ser reunida prova de execução para este candidato. Os impedimentos estão listados neste registo. Nada foi eliminado.',
      tone: 'error',
    },
    bounded_archive_recorded: {
      label: 'Prova de arquivo reunida',
      meaning:
        'A prova associada a este candidato é o registo de arquivo produzido por uma execução limitada. Não inclui qualquer eliminação de documentos.',
      tone: 'ok',
    },
    bounded_no_action_recorded: {
      label: 'Prova de não-ação reunida',
      meaning:
        'A prova associada a este candidato regista que não havia ação a tomar. Não inclui qualquer eliminação de documentos.',
      tone: 'ok',
    },
    prior_bounded_evidence_available: {
      label: 'Prova anterior disponível',
      meaning:
        'Já existe prova de uma execução limitada anterior para este candidato, e é essa que fica associada. Esta análise é apenas de leitura e qualquer ação operacional exige aprovação de governação separada.',
      tone: 'neutral',
    },
  },

  /** `RetentionCandidateDisposition` — which evidence record an operator filed. Effects nothing. */
  disposition: {
    evidence_acknowledged: {
      label: 'Prova reconhecida',
      meaning:
        'Um operador registou que tomou conhecimento da prova reunida para este candidato. O candidato continua disponível para revisão de governação separada. Nada foi eliminado nem anonimizado.',
      tone: 'ok',
    },
    follow_up_required: {
      label: 'Exige seguimento',
      meaning:
        'Um operador registou que este candidato precisa de seguimento antes de qualquer decisão. O candidato continua disponível para revisão de governação separada. Nada foi eliminado nem anonimizado.',
      tone: 'warn',
    },
    blocked_follow_up: {
      label: 'Seguimento com impedimentos',
      meaning:
        'Um operador registou seguimento para um candidato que tem impedimentos ativos, e esses impedimentos mantêm-se para revisão de governação separada. Nada foi eliminado nem anonimizado.',
      tone: 'error',
    },
  },

  /** `mode` on the dry-run report: `execution_record.is_some()`, one boolean. */
  dryRunMode: {
    dry_run: {
      label: 'Simulação',
      meaning:
        'Este relatório é uma simulação: mostra que registos a política abrangeria, sem que nenhum pedido de execução tenha sido feito. Nada foi alterado.',
      tone: 'neutral',
    },
    execution_request: {
      label: 'Pedido de execução',
      meaning:
        'Este relatório acompanha um pedido de execução registado, cujo desfecho aparece a seguir. Ter sido pedido não quer dizer que algo tenha acontecido: é o desfecho que o diz.',
      tone: 'warn',
    },
  },
} as const satisfies StatusGroups;

export const retentionStatusEnglish = {
  outcome: {
    blocked_missing_policy: {
      label: 'Blocked: policy missing',
      meaning:
        'The request named no retention policy that exists on this installation, so the execution did not proceed. Name an active policy and repeat the request. Nothing was deleted.',
      tone: 'error',
    },
    blocked_stale_policy: {
      label: 'Blocked: policy not active',
      meaning:
        'The named policy exists but is not in force, so the execution did not proceed. Activate it, or choose one that is in force, before repeating. Nothing was deleted.',
      tone: 'error',
    },
    blocked_policy_mismatch: {
      label: 'Blocked: policy does not match',
      meaning:
        'The scope or category of the named policy does not match the candidate in question, so the execution did not proceed. Check that you are applying the right policy to this record. Nothing was deleted.',
      tone: 'error',
    },
    blocked_legal_hold: {
      label: 'Blocked: legal hold active',
      meaning:
        'A legal hold is active on this record, and a legal hold prevails over the policy’s period. Release the hold, with the proper approval, before requesting execution again. Nothing was deleted.',
      tone: 'error',
    },
    blocked_destructive_action: {
      // Not "Blocked: destructive action" — that is the identifier with its underscores removed,
      // which the divergence gate rejects and which tells the operator nothing new.
      label: 'Blocked: destruction never carried out here',
      meaning:
        'The requested policy implies a destructive action, which this application never carries out. Record the governance approval and conduct that process outside this application. Nothing was deleted.',
      tone: 'error',
    },
    blocked_approval_mismatch: {
      label: 'Blocked: approval does not match',
      meaning:
        'The approval metadata supplied does not match the requested policy and action, so the execution did not proceed. Correct the approval reference and repeat the request. Nothing was deleted.',
      tone: 'error',
    },
    blocked_missing_target: {
      label: 'Blocked: target record missing',
      meaning:
        'The request identified no concrete record to act on, so the execution did not proceed. Supply the record identifier before repeating. Nothing was deleted.',
      tone: 'error',
    },
    manual_review_required: {
      label: 'Awaiting a human decision',
      meaning:
        'The execution stopped to await human consideration of the evidence gathered. A responsible person must review it and decide whether the case proceeds. Nothing was deleted.',
      tone: 'warn',
    },
    bounded_archive_recorded: {
      label: 'Archive evidence recorded',
      meaning:
        'Archive evidence was recorded for this target, within the bounds this application acts in. No source document was deleted and no GDPR erasure was performed.',
      tone: 'ok',
    },
    bounded_no_action_recorded: {
      label: 'No-action evidence recorded',
      meaning:
        'It was recorded that, for this target, there was no action to take under the policy. No source document was deleted and no GDPR erasure was performed.',
      tone: 'ok',
    },
    already_executed: {
      label: 'Already recorded earlier',
      meaning:
        'An earlier execution had already recorded this target and policy pair, so it was not recorded a second time. Nothing new was deleted.',
      tone: 'neutral',
    },
  },
  evidenceState: {
    review_queued: {
      label: 'Queued for review',
      meaning:
        'The case is awaiting human consideration and the evidence gathered is retained until that decision. Nothing was deleted.',
      tone: 'warn',
    },
    blocked: {
      label: 'No evidence, blocked',
      meaning:
        'There are unresolved blockers, so no execution evidence was gathered for this candidate. The blockers are listed on this record. Nothing was deleted.',
      tone: 'error',
    },
    bounded_archive_recorded: {
      label: 'Archive evidence gathered',
      meaning:
        'The evidence attached to this candidate is the archive record produced by a bounded execution. It includes no deletion of documents.',
      tone: 'ok',
    },
    bounded_no_action_recorded: {
      label: 'No-action evidence gathered',
      meaning:
        'The evidence attached to this candidate records that there was no action to take. It includes no deletion of documents.',
      tone: 'ok',
    },
    prior_bounded_evidence_available: {
      label: 'Earlier evidence available',
      meaning:
        'Evidence from an earlier bounded execution already exists for this candidate, and that is what is attached. This scan is read-only and any operational action requires separate governance approval.',
      tone: 'neutral',
    },
  },
  disposition: {
    evidence_acknowledged: {
      label: 'Operator has seen the evidence',
      meaning:
        'An operator recorded that they have seen the evidence gathered for this candidate. The candidate remains available for separate governance review. Nothing was deleted or anonymised.',
      tone: 'ok',
    },
    follow_up_required: {
      label: 'Operator flagged it for follow-up',
      meaning:
        'An operator recorded that this candidate needs follow-up before any decision. The candidate remains available for separate governance review. Nothing was deleted or anonymised.',
      tone: 'warn',
    },
    blocked_follow_up: {
      label: 'Follow-up with blockers',
      meaning:
        'An operator recorded follow-up for a candidate that has active blockers, and those blockers remain in place for separate governance review. Nothing was deleted or anonymised.',
      tone: 'error',
    },
  },
  dryRunMode: {
    dry_run: {
      label: 'Simulation',
      meaning:
        'This report is a simulation: it shows which records the policy would cover, with no execution request having been made. Nothing was changed.',
      tone: 'neutral',
    },
    execution_request: {
      label: 'Attached to a requested execution',
      meaning:
        'This report accompanies a recorded execution request, whose outcome appears below. Having been requested does not mean anything happened: the outcome is what says so.',
      tone: 'warn',
    },
  },
} as const satisfies StatusGroups;

/** Shown when the server serves a token this build has no entry for. Never blank. */
const UNRECOGNISED_PT_PT: RetentionStatusEntry = {
  label: 'Estado não reconhecido',
  meaning:
    'Esta versão da aplicação não reconhece este estado. O identificador apresentado é o valor exato devolvido pelo servidor; cite-o tal como está ao pedir apoio.',
  tone: 'neutral',
};
const UNRECOGNISED_ENGLISH: RetentionStatusEntry = {
  label: 'Unrecognised status',
  meaning:
    'This version of the application does not recognise this status. The identifier shown is the exact value the server returned; quote it verbatim when asking for support.',
  tone: 'neutral',
};

interface StatusTier {
  groups: StatusGroups;
  unrecognised: RetentionStatusEntry;
}

const PT_PT_TIER: StatusTier = { groups: retentionStatusPtPT, unrecognised: UNRECOGNISED_PT_PT };
const ENGLISH_TIER: StatusTier = {
  groups: retentionStatusEnglish,
  unrecognised: UNRECOGNISED_ENGLISH,
};

/** pt-PT is the source; every other locale receives the English tier until it is reviewed. */
const TIERS_BY_LOCALE: Partial<Record<Locale, StatusTier>> = {
  'pt-PT': PT_PT_TIER,
  'en-US': ENGLISH_TIER,
  'en-GB': ENGLISH_TIER,
};

/** A resolved status. `label` and `meaning` are never empty, so the UI renders them unconditionally. */
export interface RetentionStatusDescription extends RetentionStatusEntry {
  /** False when this build has no entry for the token the server served. */
  known: boolean;
}

/** Resolve one token within its group. Exported shape used by both the hook and the test. */
export function describeRetentionStatus(
  group: RetentionStatusGroup,
  token: string,
  tier: StatusTier = PT_PT_TIER,
): RetentionStatusDescription {
  const entry = tier.groups[group][token];
  return entry === undefined ? { ...tier.unrecognised, known: false } : { ...entry, known: true };
}

/**
 * The panel's status resolver, locale-aware:
 * `const describe = useRetentionStatusResolver(); describe('outcome', record.outcome)`.
 */
export function useRetentionStatusResolver(): (
  group: RetentionStatusGroup,
  token: string,
) => RetentionStatusDescription {
  const locale = useActiveLocale();
  const tier = TIERS_BY_LOCALE[locale] ?? ENGLISH_TIER;
  return useMemo(
    () => (group: RetentionStatusGroup, token: string) => describeRetentionStatus(group, token, tier),
    [tier],
  );
}
