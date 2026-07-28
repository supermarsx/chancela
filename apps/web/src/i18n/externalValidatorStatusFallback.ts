/**
 * EXTERNAL-VALIDATOR TECHNICAL REPORT STATUSES (t87) — the sentence that says what a status means
 * to the operator reading the card.
 *
 * The technical-reports panel used to render the server's raw tokens verbatim: a card labelled
 * «Estado» whose whole value was `no_external_validator_report_metadata_attached`. That is an
 * internal identifier, not copy, and at 45 characters with no break opportunity it also blew out
 * its own card. This module supplies the human label and the explanatory sentence rendered beside
 * it.
 *
 * The identifier is NOT replaced. It stays, in `mono`, as the stable thing an operator quotes in a
 * support thread; the copy is added around it. Same split as `permissionDescriptionsFallback.ts`.
 *
 * ─── THESE ARE OPERATIONAL STATUSES, NOT NO-CLAIMS IDENTIFIERS ─────────────────────────────────
 *
 * This surface has a no-claims population and it is a DIFFERENT one. On the wire the no-claims
 * facts are `legal_validity_claimed` (rejected unless `false`), `legal_validity_assessment`
 * (rejected unless `"not_assessed"`) and `scope.claim` — all validated in
 * `crates/chancela-api/src/external_validator_evidence.rs`; in the UI they are the standalone
 * `externalValidatorReports.notice.noClaims` banner. None of those are touched here, and none of
 * them are translated, exactly as `dpiaTemplateLabels.ts` leaves the 28 DPIA flags alone.
 *
 * The six identifiers below are not of that family. Each is a plain fact about what this
 * installation currently holds, computed from a boolean and nothing else:
 * `reports.is_empty()`, `bytes.is_some()`, `metadata_dir.is_some()`. Saying «não há nenhum
 * relatório guardado» asserts nothing about validity, conformity or legal effect — it reports an
 * absence of stored bytes. `chancela-mcp`'s `DOCUMENT_ARCHIVE_STATUS_LABELS` classifies all four
 * status tokens alongside `ok`, `passed` and `invalid`, which is the same reading.
 *
 * ─── WHY A SELF-CONTAINED MODULE ───────────────────────────────────────────────────────────────
 *
 * `Catalog` is `Record<MessageKey, string>`, a total type over 14 locales, so every new key is 14
 * edits across files that several live lanes are serialised on. This follows the established
 * escape valve — `apiErrorFallback.ts`, `privacyLegalHoldFallback.ts`, `envelopeSlotStatusFallback.ts`
 * and ~20 siblings: a pt-PT source object plus an English tier that `satisfies` the same key set,
 * resolved through its own locale-aware hook. Fold it into the catalogs once all 14 are in one hand.
 *
 * ─── THE DIVERGENCE GUARANTEE ──────────────────────────────────────────────────────────────────
 *
 * `externalValidatorStatusFallback.test.ts` parses `external_validator_evidence.rs` and asserts set
 * equality in BOTH directions, per group: a token the emitter gained with no entry here is red, and
 * an entry here for a token the emitter can no longer produce is red. At runtime an unrecognised
 * token still must not render as blank space — {@link describeExternalValidatorStatus} returns an
 * explicit "not recognised" description with `known: false`, never an empty string.
 *
 * ─── AUTHORING RULES ───────────────────────────────────────────────────────────────────────────
 *
 * Written from what the emitting code actually decides, never from the token's spelling; no entry
 * restates its own identifier. Each `meaning` is a COMPLETE standalone sentence with no
 * placeholder: a noun interpolated into Portuguese breaks article, adjective and participle
 * agreement, so copy that varies by token varies by entry (memory:
 * `i18n-interpolated-nouns-break-agreement`). pt-PT, never pt-BR, no invented anglicisms (memory:
 * `pt-pt-no-invented-anglicisms`). The tokens themselves stay English — they are identifiers.
 */
import { useMemo } from 'react';
import type { Locale } from '../api/types';
import { useActiveLocale } from './useT';

/** Narrower than the `Badge` component's tone union; every value here is assignable to it. */
export type ExternalValidatorStatusTone = 'ok' | 'neutral' | 'warn';

export interface ExternalValidatorStatusEntry {
  /** Short human label for the badge. Never the identifier. */
  label: string;
  /** One complete standalone sentence group saying what the status means for the operator. */
  meaning: string;
  tone: ExternalValidatorStatusTone;
}

/**
 * The three independently-emitted token populations rendered by the technical-reports panel. Each
 * is derived from its own site in `crates/chancela-api/src/external_validator_evidence.rs`, and the
 * divergence test checks each against its own site.
 */
export type ExternalValidatorStatusGroup = 'metadataStatus' | 'preservationStatus' | 'storageMode';

type StatusGroupTable = Readonly<Record<string, ExternalValidatorStatusEntry>>;
type StatusGroups = Readonly<Record<ExternalValidatorStatusGroup, StatusGroupTable>>;

/** pt-PT is the authoring source. */
export const externalValidatorStatusPtPT = {
  /**
   * `ExternalValidatorReportMetadataList.status`, from `metadata_list_response`, plus the identical
   * token on `ExternalValidatorReportMetadataCreateResponse`.
   */
  metadataStatus: {
    external_validator_report_metadata_attached: {
      label: 'Metadados anexados',
      meaning:
        'Esta instalação tem guardados os metadados técnicos de pelo menos um relatório de validador externo. A tabela abaixo lista cada relatório aceite.',
      tone: 'ok',
    },
    no_external_validator_report_metadata_attached: {
      label: 'Sem metadados anexados',
      meaning:
        'Esta instalação não tem nenhum relatório de validador externo aceite. Os relatórios malformados e aqueles cujo caminho de arquivo se repete são excluídos da lista, pelo que este estado também pode surgir depois de um carregamento. Confirme os contadores de malformados e de caminhos duplicados ao lado.',
      tone: 'neutral',
    },
  },

  /** `ExternalValidatorRawReportAttachment::preservation_status()`. */
  preservationStatus: {
    raw_report_attached: {
      label: 'Relatório bruto guardado',
      meaning:
        'Os bytes do relatório bruto do validador estão guardados no servidor, a par dos metadados. Este painel mostra apenas o resumo redigido e não descarrega esses bytes.',
      tone: 'ok',
    },
    raw_report_manifest_only: {
      label: 'Apenas manifesto, sem bytes',
      meaning:
        'Foram guardados o tipo de conteúdo, o tamanho e o SHA-256 declarados para o relatório bruto, mas não os seus bytes. A fixidez indicada não pode ser recalculada a partir desta instalação.',
      tone: 'neutral',
    },
  },

  /** `storage_mode(durable)`, where durability is whether a metadata directory is configured. */
  storageMode: {
    data_dir: {
      label: 'Pasta de dados',
      meaning:
        'Os metadados carregados são gravados na pasta de dados do servidor e sobrevivem a um reinício.',
      tone: 'ok',
    },
    in_memory: {
      label: 'Apenas em memória',
      meaning:
        'Os metadados carregados existem apenas na memória do servidor e perdem-se quando o processo reinicia. Configure uma pasta de dados para os preservar.',
      tone: 'warn',
    },
  },
} as const satisfies StatusGroups;

export const externalValidatorStatusEnglish = {
  metadataStatus: {
    external_validator_report_metadata_attached: {
      label: 'Metadata attached',
      meaning:
        'This installation holds the technical metadata of at least one external-validator report. The table below lists every accepted report.',
      tone: 'ok',
    },
    no_external_validator_report_metadata_attached: {
      label: 'No metadata attached',
      meaning:
        'This installation holds no accepted external-validator report. Malformed reports, and those whose archive path repeats, are excluded from the list, so this status can also appear after an upload. Check the malformed and duplicate-path counters beside it.',
      tone: 'neutral',
    },
  },
  preservationStatus: {
    raw_report_attached: {
      label: 'Raw report stored',
      meaning:
        'The bytes of the validator’s raw report are stored on the server alongside the metadata. This panel shows only the redacted summary and does not download those bytes.',
      tone: 'ok',
    },
    raw_report_manifest_only: {
      label: 'Manifest only, no bytes',
      meaning:
        'The declared content type, size and SHA-256 of the raw report were stored, but not its bytes. The stated fixity cannot be recomputed from this installation.',
      tone: 'neutral',
    },
  },
  storageMode: {
    data_dir: {
      label: 'Data directory',
      meaning:
        'Uploaded metadata is written to the server’s data directory and survives a restart.',
      tone: 'ok',
    },
    in_memory: {
      label: 'In memory only',
      meaning:
        'Uploaded metadata exists only in the server’s memory and is lost when the process restarts. Configure a data directory to preserve it.',
      tone: 'warn',
    },
  },
} as const satisfies StatusGroups;

/** Shown when the server serves a token this build has no entry for. Never blank. */
const UNRECOGNISED_PT_PT: ExternalValidatorStatusEntry = {
  label: 'Estado não reconhecido',
  meaning:
    'Esta versão da aplicação não reconhece este estado. O identificador apresentado é o valor exato devolvido pelo servidor; cite-o tal como está ao pedir apoio.',
  tone: 'neutral',
};
const UNRECOGNISED_ENGLISH: ExternalValidatorStatusEntry = {
  label: 'Unrecognised status',
  meaning:
    'This version of the application does not recognise this status. The identifier shown is the exact value the server returned; quote it verbatim when asking for support.',
  tone: 'neutral',
};

interface StatusTier {
  groups: StatusGroups;
  unrecognised: ExternalValidatorStatusEntry;
}

const PT_PT_TIER: StatusTier = {
  groups: externalValidatorStatusPtPT,
  unrecognised: UNRECOGNISED_PT_PT,
};
const ENGLISH_TIER: StatusTier = {
  groups: externalValidatorStatusEnglish,
  unrecognised: UNRECOGNISED_ENGLISH,
};

/** pt-PT is the source; every other locale receives the English tier until it is reviewed. */
const TIERS_BY_LOCALE: Partial<Record<Locale, StatusTier>> = {
  'pt-PT': PT_PT_TIER,
  'en-US': ENGLISH_TIER,
  'en-GB': ENGLISH_TIER,
};

/** A resolved status. `label` and `meaning` are never empty, so the UI renders them unconditionally. */
export interface ExternalValidatorStatusDescription extends ExternalValidatorStatusEntry {
  /** False when this build has no entry for the token the server served. */
  known: boolean;
}

/** Resolve one token within its group. Exported shape used by both the hook and the test. */
export function describeExternalValidatorStatus(
  group: ExternalValidatorStatusGroup,
  token: string,
  tier: StatusTier = PT_PT_TIER,
): ExternalValidatorStatusDescription {
  const entry = tier.groups[group][token];
  return entry === undefined ? { ...tier.unrecognised, known: false } : { ...entry, known: true };
}

/**
 * The panel's status resolver, locale-aware:
 * `const describe = useExternalValidatorStatusResolver(); describe('metadataStatus', data.status)`.
 */
export function useExternalValidatorStatusResolver(): (
  group: ExternalValidatorStatusGroup,
  token: string,
) => ExternalValidatorStatusDescription {
  const locale = useActiveLocale();
  const tier = TIERS_BY_LOCALE[locale] ?? ENGLISH_TIER;
  return useMemo(
    () => (group: ExternalValidatorStatusGroup, token: string) =>
      describeExternalValidatorStatus(group, token, tier),
    [tier],
  );
}
