/**
 * DATA-RECOVERY AND PERSISTENCE STATUSES (t98) — the sentences that say what the Gestão de dados
 * panel's server-emitted tokens mean to the operator reading them.
 *
 * Four token fields on this surface rendered their raw wire identifier as the whole visible value:
 * `persistence.sidecar_storage_mode` and `persistence.active_backend_family` in the same card, the
 * sync-handoff `readiness.status`, and the recovery drill's isolated-restore `verification.status`.
 * This module supplies the human label and the explanatory sentence; the identifier is NOT replaced,
 * it stays in `mono` as the stable thing an operator quotes in a support thread. Same split as
 * `externalValidatorStatusFallback.ts`.
 *
 * ─── WHY `active_backend_family` IS HERE AND NOT IN A LATER PASS ───────────────────────────────
 *
 * `rawIdentifierRenderGuards.test.ts` cannot see it. Its type is `'sqlite' | 'postgres'` — single
 * lowercase words with no underscore — and the guard deliberately matches only multi-word
 * snake_case, because widening it to any lowercase literal would flag every `'ok'`/`'warn'` tone
 * union in the app. That guard records the limit rather than papering over it. The field renders raw
 * in the SAME CARD as `sidecar_storage_mode`, so fixing only the visible half would have left half a
 * card in identifiers. It is fixed here, with its cardmate, and the guard is left alone.
 *
 * ─── THESE ARE OPERATIONAL STATUSES ────────────────────────────────────────────────────────────
 *
 * Every token below is computed from a plain boolean or a short state machine and reports a fact
 * about storage or progress:
 *
 *  - `sidecar_storage_mode` and `active_backend_family` are `state.sidecars_db_backed` and
 *    `data_dir.is_some()` in `data_status.rs::get_data_status`, nothing more;
 *  - `readiness.status` is `blockers.is_empty()` then `missing_evidence.is_empty()` in
 *    `sync_handoff.rs`;
 *  - `verification.status` is a conjunction of five local booleans
 *    (`BackupRecoveryDrillIsolatedRestoreVerification::is_verified`).
 *
 * None asserts validity, conformity or legal effect, so none belongs to the no-claims family.
 *
 * Two entries nevertheless carry a scoping clause that is load-bearing rather than decorative, and
 * removing it would let the copy claim more than the emitter does:
 *
 *  - `local_review_ready` sits beside a `no_claims` block whose fields are hard-coded `false`
 *    (`production_sync_ready`, `external_connector_ready`, `active_sync_performed`,
 *    `production_sync_readiness_claimed`, `deployment_readiness_claimed`). "Ready" here means the
 *    LOCAL review may proceed; it does not mean this installation is ready to synchronise, and the
 *    entry says so outright.
 *  - `verified` is the drill's own self-check, and the Rust next_step it travels with is "record as
 *    preflight-only isolated snapshot evidence; authorize any recovery execution separately". The
 *    entry keeps that scope: the drill passed, which is not the same as the backup being certified.
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
 * `dataRecoveryStatusFallback.test.ts` parses all four emitters — two Rust enums with their serde
 * rename, one if-chain, one set of consts — and asserts set equality in BOTH directions per group.
 *
 * ─── AUTHORING RULES ───────────────────────────────────────────────────────────────────────────
 *
 * Written from what the emitting code decides, never from the token's spelling; no entry restates
 * its own identifier. Each `meaning` is a COMPLETE standalone sentence group with no placeholder: a
 * noun interpolated into Portuguese breaks article, adjective and participle agreement, so copy that
 * varies by token varies by entry (memory: `i18n-interpolated-nouns-break-agreement`). pt-PT, never
 * pt-BR, no invented anglicisms (memory: `pt-pt-no-invented-anglicisms`). The tokens stay English —
 * they are identifiers, and so are the two product names.
 */
import { useMemo } from 'react';
import type { Locale } from '../api/types';
import { useActiveLocale } from './useT';

/** Narrower than the `Badge` component's tone union; every value here is assignable to it. */
export type DataRecoveryStatusTone = 'ok' | 'neutral' | 'warn' | 'error';

export interface DataRecoveryStatusEntry {
  /** Short human label for the badge. Never the identifier. */
  label: string;
  /** One complete standalone sentence group saying what the status means for the operator. */
  meaning: string;
  tone: DataRecoveryStatusTone;
}

/**
 * The four independently-emitted token populations on this surface. Each is derived from its own
 * site in Rust, and the divergence test checks each against its own site.
 */
export type DataRecoveryStatusGroup =
  | 'sidecarStorageMode'
  | 'backendFamily'
  | 'readinessStatus'
  | 'isolatedRestoreStatus';

type StatusGroupTable = Readonly<Record<string, DataRecoveryStatusEntry>>;
type StatusGroups = Readonly<Record<DataRecoveryStatusGroup, StatusGroupTable>>;

/** pt-PT is the authoring source. */
export const dataRecoveryStatusPtPT = {
  /** `SidecarStorageMode`, chosen in `data_status.rs::get_data_status`. */
  sidecarStorageMode: {
    file: {
      label: 'Ficheiros na pasta de dados',
      meaning:
        'Os anexos são gravados como ficheiros na pasta de dados do servidor, fora da base de dados. Sobrevivem a um reinício, mas uma cópia de segurança que leve apenas a base de dados deixa-os para trás.',
      tone: 'ok',
    },
    database: {
      label: 'Dentro da base de dados',
      meaning:
        'Os anexos são guardados dentro da própria base de dados. Uma cópia de segurança da base de dados leva-os consigo, sem passo separado para a pasta de anexos.',
      tone: 'ok',
    },
    in_memory: {
      label: 'Apenas em memória',
      meaning:
        'Não há pasta de dados configurada, pelo que os anexos existem apenas na memória do servidor e perdem-se quando o processo reinicia. Configure uma pasta de dados antes de usar esta instalação para trabalho real.',
      tone: 'warn',
    },
  },

  /** `DurableBackendFamily`, present only while a durable store is open. */
  backendFamily: {
    sqlite: {
      label: 'SQLite (ficheiro local)',
      meaning:
        'O arquivo durável desta instalação está aberto sobre SQLite, num ficheiro do próprio servidor. É o modo predefinido e não depende de nenhum serviço de base de dados externo.',
      tone: 'ok',
    },
    postgres: {
      label: 'PostgreSQL (servidor externo)',
      meaning:
        'O arquivo durável desta instalação está aberto sobre PostgreSQL, num servidor de base de dados separado. As cópias de segurança e o plano de recuperação passam a ter de cobrir também esse servidor.',
      tone: 'ok',
    },
  },

  /** `readiness_status` in `sync_handoff.rs`, from the blockers and missing-evidence lists. */
  readinessStatus: {
    blocked: {
      label: 'Revisão bloqueada',
      meaning:
        'A pré-verificação encontrou impedimentos locais que têm de ser resolvidos antes de a revisão de entrega poder avançar. Os impedimentos estão listados neste relatório.',
      tone: 'error',
    },
    missing_local_evidence: {
      label: 'Falta prova local',
      meaning:
        'Não há impedimentos, mas falta prova local que a revisão de entrega precisa de consultar. O relatório indica o que ainda não existe nesta instalação.',
      tone: 'warn',
    },
    local_review_ready: {
      label: 'Revisão local pode avançar',
      meaning:
        'A prova local necessária está reunida e a revisão de entrega pode ser feita nesta instalação. Isto diz respeito apenas à revisão local: esta pré-verificação não sincroniza nada, não contacta serviços externos e não afirma que a instalação está pronta para produção.',
      tone: 'ok',
    },
  },

  /** The `ISOLATED_RESTORE_STATUS_*` consts in `backup_recovery.rs`. */
  isolatedRestoreStatus: {
    verified: {
      label: 'Ensaio de restauro passou',
      meaning:
        'O ensaio restaurou o instantâneo num ambiente isolado e todas as verificações locais passaram. É prova do ensaio, não uma certificação da cópia de segurança: qualquer recuperação real continua a exigir autorização separada.',
      tone: 'ok',
    },
    failed: {
      label: 'Ensaio de restauro falhou',
      meaning:
        'O ensaio tentou restaurar o instantâneo num ambiente isolado e pelo menos uma verificação não passou. Consulte os achados e os erros registados antes de contar com esta cópia de segurança.',
      tone: 'error',
    },
    not_recorded: {
      label: 'Sem verificação registada',
      meaning:
        'Este recibo não traz verificação de restauro isolado. É o que acontece com recibos gravados por versões anteriores da aplicação; repita o ensaio para obter esta prova.',
      tone: 'neutral',
    },
  },
} as const satisfies StatusGroups;

export const dataRecoveryStatusEnglish = {
  sidecarStorageMode: {
    file: {
      label: 'Files in the data directory',
      meaning:
        'Sidecars are written as files in the server’s data directory, outside the database. They survive a restart, but a backup that takes only the database leaves them behind.',
      tone: 'ok',
    },
    database: {
      label: 'Inside the database',
      meaning:
        'Sidecars are stored inside the database itself. A database backup carries them with it, with no separate step for the attachment directory.',
      tone: 'ok',
    },
    in_memory: {
      label: 'In memory only',
      meaning:
        'No data directory is configured, so sidecars exist only in the server’s memory and are lost when the process restarts. Configure a data directory before using this installation for real work.',
      tone: 'warn',
    },
  },
  backendFamily: {
    sqlite: {
      label: 'SQLite (local file)',
      meaning:
        'This installation’s durable store is open on SQLite, in a file on the server itself. It is the default mode and depends on no external database service.',
      tone: 'ok',
    },
    postgres: {
      label: 'PostgreSQL (external server)',
      meaning:
        'This installation’s durable store is open on PostgreSQL, on a separate database server. Backups and the recovery plan must now cover that server too.',
      tone: 'ok',
    },
  },
  readinessStatus: {
    blocked: {
      label: 'Review blocked',
      meaning:
        'The preflight found local blockers that must be resolved before the handoff review can proceed. The blockers are listed in this report.',
      tone: 'error',
    },
    missing_local_evidence: {
      label: 'Local evidence missing',
      meaning:
        'There are no blockers, but local evidence the handoff review needs to consult is missing. The report states what does not yet exist on this installation.',
      tone: 'warn',
    },
    local_review_ready: {
      label: 'Local review can proceed',
      meaning:
        'The required local evidence is present and the handoff review can be carried out on this installation. This concerns the local review only: the preflight synchronises nothing, contacts no external service, and makes no claim that the installation is production-ready.',
      tone: 'ok',
    },
  },
  isolatedRestoreStatus: {
    verified: {
      label: 'Restore drill passed',
      meaning:
        'The drill restored the snapshot in an isolated environment and every local check passed. This is evidence of the drill, not certification of the backup: any real recovery still requires separate authorisation.',
      tone: 'ok',
    },
    failed: {
      label: 'Restore drill failed',
      meaning:
        'The drill attempted to restore the snapshot in an isolated environment and at least one check did not pass. Review the recorded findings and errors before relying on this backup.',
      tone: 'error',
    },
    not_recorded: {
      label: 'No verification recorded',
      meaning:
        'This receipt carries no isolated-restore verification. That is what receipts written by earlier versions of the application look like; run the drill again to obtain this evidence.',
      tone: 'neutral',
    },
  },
} as const satisfies StatusGroups;

/** Shown when the server serves a token this build has no entry for. Never blank. */
const UNRECOGNISED_PT_PT: DataRecoveryStatusEntry = {
  label: 'Estado não reconhecido',
  meaning:
    'Esta versão da aplicação não reconhece este estado. O identificador apresentado é o valor exato devolvido pelo servidor; cite-o tal como está ao pedir apoio.',
  tone: 'neutral',
};
const UNRECOGNISED_ENGLISH: DataRecoveryStatusEntry = {
  label: 'Unrecognised status',
  meaning:
    'This version of the application does not recognise this status. The identifier shown is the exact value the server returned; quote it verbatim when asking for support.',
  tone: 'neutral',
};

/**
 * `active_backend_family` is `Option<DurableBackendFamily>` on the wire and arrives `null` whenever
 * no durable store is open. That absence is a real state of the installation, not a missing label,
 * so it gets its own sentence instead of the em dash the card used to render.
 */
const ABSENT_BACKEND_PT_PT: DataRecoveryStatusEntry = {
  label: 'Sem arquivo durável aberto',
  meaning:
    'Nenhum arquivo durável está aberto neste momento, pelo que não há família de base de dados ativa. O servidor está a funcionar sem persistência, ou não conseguiu abrir o arquivo configurado.',
  tone: 'warn',
};
const ABSENT_BACKEND_ENGLISH: DataRecoveryStatusEntry = {
  label: 'No durable store open',
  meaning:
    'No durable store is open at the moment, so there is no active database family. The server is either running without persistence, or failed to open the configured store.',
  tone: 'warn',
};

interface StatusTier {
  groups: StatusGroups;
  unrecognised: DataRecoveryStatusEntry;
  absentBackend: DataRecoveryStatusEntry;
}

const PT_PT_TIER: StatusTier = {
  groups: dataRecoveryStatusPtPT,
  unrecognised: UNRECOGNISED_PT_PT,
  absentBackend: ABSENT_BACKEND_PT_PT,
};
const ENGLISH_TIER: StatusTier = {
  groups: dataRecoveryStatusEnglish,
  unrecognised: UNRECOGNISED_ENGLISH,
  absentBackend: ABSENT_BACKEND_ENGLISH,
};

/** pt-PT is the source; every other locale receives the English tier until it is reviewed. */
const TIERS_BY_LOCALE: Partial<Record<Locale, StatusTier>> = {
  'pt-PT': PT_PT_TIER,
  'en-US': ENGLISH_TIER,
  'en-GB': ENGLISH_TIER,
};

/** A resolved status. `label` and `meaning` are never empty, so the UI renders them unconditionally. */
export interface DataRecoveryStatusDescription extends DataRecoveryStatusEntry {
  /** False when this build has no entry for the token the server served. */
  known: boolean;
}

/**
 * Resolve one token within its group. A `null` token is only meaningful for `backendFamily`, where
 * it is the `Option::None` case; anywhere else it falls through to the unrecognised entry.
 */
export function describeDataRecoveryStatus(
  group: DataRecoveryStatusGroup,
  token: string | null,
  tier: StatusTier = PT_PT_TIER,
): DataRecoveryStatusDescription {
  if (token === null) {
    return group === 'backendFamily'
      ? { ...tier.absentBackend, known: true }
      : { ...tier.unrecognised, known: false };
  }
  const entry = tier.groups[group][token];
  return entry === undefined ? { ...tier.unrecognised, known: false } : { ...entry, known: true };
}

/**
 * The panel's status resolver, locale-aware:
 * `const describe = useDataRecoveryStatusResolver(); describe('readinessStatus', report.readiness.status)`.
 */
export function useDataRecoveryStatusResolver(): (
  group: DataRecoveryStatusGroup,
  token: string | null,
) => DataRecoveryStatusDescription {
  const locale = useActiveLocale();
  const tier = TIERS_BY_LOCALE[locale] ?? ENGLISH_TIER;
  return useMemo(
    () => (group: DataRecoveryStatusGroup, token: string | null) =>
      describeDataRecoveryStatus(group, token, tier),
    [tier],
  );
}
