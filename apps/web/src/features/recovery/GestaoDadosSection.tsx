/**
 * "Gestão de Dados" — the Configurações sub-tab for the destructive data-management
 * taxonomy (t54-E4, deliverable #2, §2.11).
 *
 * One backup action plus FIVE clearly-distinguished reset operations so the destructive ones
 * are never mistaken for the continue-operating ones:
 *  0. **Backup operacional** — hot durable-store backup; shows only manifest metadata.
 *  1. **Repor interface** — CLIENT-ONLY (clear localStorage + React Query cache + reload);
 *     single confirm, NO server call. The low-risk sibling.
 *  2. **Recomeçar instância** — whole-instance archive-then-fresh; the app keeps running
 *     with empty domain data, users/settings preserved, the old history archived. Phrase
 *     `RECOMEÇAR` + step-up re-auth.
 *  3. **Limpar dados** — backend domain wipe; the append-only ledger is PRESERVED and the
 *     wipe is chained (`data.wiped`). Phrase `LIMPAR DADOS` + re-auth + mandatory export-first.
 *  4. **Reposição de fábrica** — factory reset; clears everything (ledger + users + settings)
 *     to a blank first-run instance. Phrase `REPOR FÁBRICA` + re-auth + export-first (guarded
 *     skip only).
 *  5. **Reposição total** — factory reset PLUS a client-side clear + reboot in one action.
 *
 * Every destructive server op routes the shared {@link ConfirmActionModal} (type-phrase + step-up
 * re-auth + export-first); the server enforces the same gates. Nothing is silently destructive.
 */
import { type FormEvent, type ReactNode, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
  useCleanDataStorage,
  useBackupRecoveryDrills,
  useCreateBackupRecoveryDrill,
  useCreateBackup,
  useDataKeyRotationExecution,
  useDataKeyRotationPreflight,
  useDataStatus,
  useResetData,
  useSettings,
  useStartOverInstance,
  useSyncHandoffPreflight,
} from '../../api/hooks';
import {
  DEFAULT_SETTINGS,
  RESET_PHRASE,
  type BackupRecoveryFreshnessReview,
  type BackupRecoveryDrillBody,
  type BackupRecoveryDrillReceipt,
  type BackupManifest,
  type DataCleanupBody,
  type DataCleanupResult,
  type DataCleanupTarget,
  type DataDatabaseEncryptionStatus,
  type DataKeyRotationExecuteBody,
  type DataKeyRotationExecution,
  type DataKeyRotationPreflight,
  type DataKeyRotationPreflightBody,
  type DataKeyRotationReceipt,
  type DataKeyRotationReceiptStatus,
  type DataPayloadStats,
  type DataPermissionCheck,
  type DataPermissionStatus,
  type DataPersistenceMode,
  type DataUsageBasis,
  type DataUsageConcern,
  type ResetOutcomeView,
  type SyncHandoffPreflightReport,
} from '../../api/types';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import { formatTimestamp } from '../../format';
import { t as translateNow, useLocale, useT, type MessageKey, type TFunction } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  ConfirmActionModal,
  ErrorNote,
  Field,
  FieldHelp,
  Icon,
  InlineWarning,
  Input,
  SkeletonRegion,
  SkeletonTable,
  SubNav,
  Table,
  TextArea,
  TooltipText,
  useToast,
} from '../../ui';
import { GateButton } from '../session/permissions';
import { resetFrontend } from './frontendReset';

type Dialog = 'none' | 'frontend' | 'startover' | 'domain' | 'factory' | 'full';

/** The Gestão de dados surface splits into three logically-grouped sub-sub-tabs reached
 *  through the shared `<SubNav>` (the same segmented idiom the Operations surface uses):
 *  "Armazenamento" holds storage usage, folder permissions and local file cleanup;
 *  "Cópias e recuperação" holds backup, recovery drills and the restore/handoff preflights;
 *  "Chaves e reposição" holds data-key rotation plus the reset/recomeço operations, keeping
 *  the destructive resets separated from the everyday storage view. */
type GestaoTab = 'armazenamento' | 'copias' | 'chaves';

const DEFAULT_EXPORT_CLEANUP_POLICY = DEFAULT_SETTINGS.data_management.retained_export_cleanup;
const SYNC_HANDOFF_PREFLIGHT_EXPORT_FILENAME = 'chancela-sync-handoff-preflight.json';
const SYNC_HANDOFF_PREFLIGHT_EXPORT_CONTENT_TYPE = 'application/json;charset=utf-8';

function exportCleanupBody(
  policy: typeof DEFAULT_EXPORT_CLEANUP_POLICY,
  dryRun: boolean,
): DataCleanupBody {
  return {
    target: 'exports' as const,
    dry_run: dryRun,
    minimum_age_days: policy.minimum_age_days,
    keep_latest: policy.keep_latest,
  };
}

function exportCleanupPreviewDescription(policy: typeof DEFAULT_EXPORT_CLEANUP_POLICY): string {
  return (
    `Pré-visualiza ficheiros de exportação locais retidos com pelo menos ${policy.minimum_age_days} dias, ` +
    `preservando os ${policy.keep_latest} mais recentes. Nenhum ficheiro é removido nesta ação. ` +
    'Esta política é apenas a pré-visualização de limpeza de exportações retidas.'
  );
}

const EXPORT_CLEANUP_CONFIRM_DESCRIPTION =
  'Limpa apenas ficheiros de exportação locais retidos que a pré-visualização marcou como elegíveis pela política configurada. Não é apagamento legal, conclusão RGPD, eliminação de arquivo ou certificação de descarte.';
const EXPORT_CLEANUP_PREVIEW_BUTTON = 'Pré-visualizar limpeza';
const EXPORT_CLEANUP_PREVIEW_PENDING = 'A pré-visualizar…';
const EXPORT_CLEANUP_PREVIEW_DONE = 'Pré-visualização pronta.';
const EXPORT_CLEANUP_PREVIEW_TITLE = 'Pré-visualização da limpeza de exportações retidas';
const EXPORT_CLEANUP_EXECUTION_BUTTON = 'Executar limpeza de ficheiros';
const EXPORT_CLEANUP_EXECUTION_TOOLTIP =
  'Executa a limpeza apenas dos ficheiros locais retidos aprovados na pré-visualização.';
const EXPORT_CLEANUP_EXECUTION_PENDING = 'A executar limpeza de ficheiros…';
const EXPORT_CLEANUP_EXECUTION_TITLE = 'Limpeza de exportações retidas concluída';
const EXPORT_CLEANUP_EXECUTION_DONE = 'Limpeza de ficheiros retidos concluída.';

type CleanupConfig = {
  target: DataCleanupTarget;
  title: MessageKey;
  body: MessageKey;
  button: MessageKey;
  confirm: MessageKey;
  help: MessageKey;
};

const CLEANUP_TARGETS: CleanupConfig[] = [
  {
    target: 'crash',
    title: 'data.status.cleanup.crash.title',
    body: 'data.status.cleanup.crash.body',
    button: 'data.status.cleanup.crash.button',
    confirm: 'data.status.cleanup.crash.confirm',
    help: 'data.status.help.crashCleanup',
  },
  {
    target: 'platform_logs',
    title: 'data.status.cleanup.platformLogs.title',
    body: 'data.status.cleanup.platformLogs.body',
    button: 'data.status.cleanup.platformLogs.button',
    confirm: 'data.status.cleanup.platformLogs.confirm',
    help: 'data.status.help.platformLogsCleanup',
  },
  {
    target: 'exports',
    title: 'data.status.cleanup.exports.title',
    body: 'data.status.cleanup.exports.body',
    button: 'data.status.cleanup.exports.button',
    confirm: 'data.status.cleanup.exports.confirm',
    help: 'data.status.help.exportCleanup',
  },
];

const MODE_LABEL: Record<DataPersistenceMode, MessageKey> = {
  durable: 'data.status.mode.durable',
  in_memory: 'data.status.mode.in_memory',
  fallback_in_memory: 'data.status.mode.fallback_in_memory',
};

/** Total over `DataUsageBasis`: a basis added to the API is a compile error here, never a raw
 *  `sidecar_logical_payload` token rendered at an operator. */
const BASIS_LABEL: Record<DataUsageBasis, MessageKey> = {
  filesystem: 'data.status.basis.filesystem',
  logical_payload: 'data.status.basis.logical_payload',
  sidecar_logical_payload: 'data.status.basis.sidecar_logical_payload',
  sqlite_file: 'data.status.basis.sqlite_file',
  sqlite_logical_payload: 'data.status.basis.sqlite_logical_payload',
};

const SQLITE_LOGICAL_TABLE_KIND = 'sqlite_logical_table';
const SQLITE_TABLE_ID_PREFIX = 'sqlite_table_';

/**
 * The folder/store probes, each with the copy for its own outcome.
 *
 * The probe `message` on the wire is untranslated English prose assembled by the API
 * (`data_status.rs::probe_permissions`) — "durable store is open", "probe file cannot be
 * created: {os error}". Rendering it verbatim leaked English into a pt-PT UI, so the sentence
 * is re-derived here from the probe's own outcome and only the OS error detail, which no
 * catalog could translate, is carried through (redacted, see {@link probeMessage}).
 */
const PERMISSION_ROWS: {
  key: keyof DataPermissionStatus;
  label: MessageKey;
  okMessage: MessageKey;
  failedMessage: MessageKey;
  /** Some probes report a distinct failure when there is no data folder configured at all. */
  noDataDirMessage?: MessageKey;
}[] = [
  {
    key: 'read_dir',
    label: 'data.status.permission.read_dir',
    okMessage: 'data.status.probe.read_dir.ok',
    failedMessage: 'data.status.probe.read_dir.failed',
  },
  {
    key: 'create_file',
    label: 'data.status.permission.create_file',
    okMessage: 'data.status.probe.create_file.ok',
    failedMessage: 'data.status.probe.create_file.failed',
  },
  {
    key: 'write_file',
    label: 'data.status.permission.write_file',
    okMessage: 'data.status.probe.write_file.ok',
    failedMessage: 'data.status.probe.write_file.failed',
  },
  {
    key: 'delete_probe_file',
    label: 'data.status.permission.delete_probe_file',
    okMessage: 'data.status.probe.delete_probe_file.ok',
    failedMessage: 'data.status.probe.delete_probe_file.failed',
  },
  {
    key: 'durable_store_open',
    label: 'data.status.permission.durable_store_open',
    okMessage: 'data.status.probe.durable_store_open.ok',
    failedMessage: 'data.status.probe.durable_store_open.failed',
    noDataDirMessage: 'data.status.probe.durable_store_open.noDataDir',
  },
];

function formatBytes(value: number, locale: string): string {
  if (!Number.isFinite(value) || value < 0) return '—';
  if (value < 1024) return `${new Intl.NumberFormat(locale).format(value)} B`;
  const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
  let amount = value;
  let unit = 'B';
  for (const candidate of units) {
    amount /= 1024;
    unit = candidate;
    if (amount < 1024) break;
  }
  return `${new Intl.NumberFormat(locale, {
    maximumFractionDigits: amount >= 10 ? 0 : 1,
  }).format(amount)} ${unit}`;
}

function formatOptionalNumber(value: number | null | undefined, locale: string): string {
  return value === null || value === undefined ? '—' : new Intl.NumberFormat(locale).format(value);
}

function yesNo(value: boolean | null, t: TFunction): string {
  if (value === null) return '—';
  return value ? t('common.yes') : t('common.no');
}

const SHA256_LIKE_RE = /\b[A-Fa-f0-9]{64}\b/g;
const WINDOWS_PATH_RE = /\b[A-Za-z]:\\[^\s<>"']+/g;
const POSIX_ARCHIVE_PATH_RE =
  /\/[A-Za-z0-9._~!$&()*+,;=:@%/-]+\.(?:zip|cbackup|sqlite|sqlite3|db)\b/g;
const SECRETISH_ASSIGNMENT_RE = /\b(?:passphrase|secret|token)\s*[:=]\s*[^\s,;]+/gi;
const SECRETISH_TOKEN_RE = /\b[^\s,;:]*?(?:passphrase|secret)[^\s,;:]*/gi;
const MEMBER_FILENAME_RE = /\b[\w.-]+\.(?:zip|cbackup|sqlite|sqlite3|db|json)\b/g;

function safeArchiveLabel(archive: string): string {
  const trimmed = archive.trim();
  if (!trimmed) return '—';
  const parts = trimmed.split(/[\\/]+/).filter(Boolean);
  const label = parts.length > 0 ? parts[parts.length - 1] : trimmed;
  return label
    .replace(SHA256_LIKE_RE, '[hash redigido]')
    .replace(SECRETISH_ASSIGNMENT_RE, '[segredo redigido]')
    .replace(SECRETISH_TOKEN_RE, '[segredo redigido]');
}

function redactReceiptEvidenceText(value: string): string {
  return value
    .replace(SHA256_LIKE_RE, '[hash redigido]')
    .replace(WINDOWS_PATH_RE, '[caminho redigido]')
    .replace(POSIX_ARCHIVE_PATH_RE, '[caminho redigido]')
    .replace(SECRETISH_ASSIGNMENT_RE, '[segredo redigido]')
    .replace(SECRETISH_TOKEN_RE, '[segredo redigido]')
    .replace(MEMBER_FILENAME_RE, '[membro redigido]');
}

/**
 * A probe the response carries no entry for is reported as unchecked, not as a crash:
 * a server that predates a probe key omits it, which for the operator is the same
 * situation as a probe that did not run. Never claim `ok` for a probe we have no result for.
 */
function permissionTone(check: DataPermissionCheck | undefined): 'ok' | 'warn' | 'neutral' {
  if (!check?.checked) return 'neutral';
  return check.ok ? 'ok' : 'warn';
}

function permissionLabel(check: DataPermissionCheck | undefined, t: TFunction): string {
  if (!check?.checked) return t('data.status.permission.unchecked');
  return check.ok ? t('data.status.permission.ok') : t('data.status.permission.warn');
}

/**
 * The translated sentence for one probe outcome, plus the untranslatable OS detail the API
 * appends after a colon on a failure ("probe file cannot be written: {os error}"). The detail
 * goes through the same redaction as receipt evidence, so a path or hash in an OS error never
 * reaches the panel verbatim.
 */
function probeMessage(
  row: (typeof PERMISSION_ROWS)[number],
  check: DataPermissionCheck | undefined,
  dataDirConfigured: boolean,
  t: TFunction,
): { text: string; detail: string | null } {
  if (!check?.checked) {
    return {
      text: t(
        dataDirConfigured
          ? 'data.status.probe.unchecked.probeSkipped'
          : 'data.status.probe.unchecked.noDataDir',
      ),
      detail: null,
    };
  }
  if (check.ok) return { text: t(row.okMessage), detail: null };
  const failed =
    !dataDirConfigured && row.noDataDirMessage ? row.noDataDirMessage : row.failedMessage;
  const separator = check.message.indexOf(': ');
  const detail =
    separator >= 0 ? redactReceiptEvidenceText(check.message.slice(separator + 2)) : '';
  return { text: t(failed), detail: detail.trim() || null };
}

function basisLabel(basis: DataUsageBasis, t: TFunction): string {
  return t(BASIS_LABEL[basis]);
}

function permissionSummary(
  permissions: DataPermissionStatus,
  t: TFunction,
): { label: string; tone: 'ok' | 'warn' | 'neutral' } {
  const checks: (DataPermissionCheck | undefined)[] = PERMISSION_ROWS.map(
    (row) => permissions[row.key],
  );
  if (checks.some((check) => check?.checked && !check.ok)) {
    return { label: t('data.status.permission.warn'), tone: 'warn' };
  }
  if (checks.some((check) => !check?.checked)) {
    return { label: t('data.status.permission.unchecked'), tone: 'neutral' };
  }
  return { label: t('data.status.permission.ok'), tone: 'ok' };
}

function concernMetaItems(concern: DataUsageConcern, t: TFunction, locale: string): string[] {
  const parts = [
    basisLabel(concern.basis, t),
    t(concern.exact ? 'data.status.exact' : 'data.status.estimated'),
    t('data.status.files', {
      count: new Intl.NumberFormat(locale).format(concern.file_count),
    }),
    t('data.status.directories', {
      count: new Intl.NumberFormat(locale).format(concern.directory_count),
    }),
  ];
  if (concern.row_count !== undefined) {
    parts.push(
      t('data.status.rows', {
        count: new Intl.NumberFormat(locale).format(concern.row_count),
      }),
    );
  }
  if (concern.relative_roots.length > 0) {
    parts.push(t('data.status.roots', { roots: concern.relative_roots.join(', ') }));
  }
  return parts;
}

function isSqliteTableConcern(concern: DataUsageConcern): boolean {
  return (
    concern.kind === SQLITE_LOGICAL_TABLE_KIND || concern.id.startsWith(SQLITE_TABLE_ID_PREFIX)
  );
}

function stripSqliteTablePrefix(value: string): string {
  const trimmed = value.trim();
  const withoutIdPrefix = trimmed.startsWith(SQLITE_TABLE_ID_PREFIX)
    ? trimmed.slice(SQLITE_TABLE_ID_PREFIX.length)
    : trimmed;
  const withoutLabelPrefix = withoutIdPrefix
    .replace(/^sqlite(?:\s+logical)?\s+table\s*[:-]?\s*/i, '')
    .trim();
  return withoutLabelPrefix || trimmed;
}

function sqliteTableLabel(concern: DataUsageConcern): string {
  const root = concern.relative_roots.find((candidate) => candidate.trim().length > 0);
  const label = stripSqliteTablePrefix(root ?? concern.label);
  return label || stripSqliteTablePrefix(concern.id);
}

function sqlitePayloadStats(concern: DataUsageConcern): DataPayloadStats {
  const rowCount = concern.payload_stats?.row_count ?? concern.row_count ?? 0;
  const bytes = concern.payload_stats?.estimated_payload_bytes ?? concern.bytes;
  return {
    table_name: concern.payload_stats?.table_name ?? sqliteTableLabel(concern),
    estimated_payload_bytes: bytes,
    row_count: rowCount,
    average_bytes_per_row:
      concern.payload_stats?.average_bytes_per_row ??
      (rowCount > 0 ? Math.floor(bytes / rowCount) : null),
    estimate_method: concern.payload_stats?.estimate_method ?? 'local_loaded_payload_estimate',
    estimate_basis: concern.payload_stats?.estimate_basis ?? concern.basis,
  };
}

function usageForTarget(
  concerns: DataUsageConcern[] | undefined,
  target: DataCleanupTarget,
): DataUsageConcern | undefined {
  return concerns?.find((concern) => concern.id === target);
}

function cleanupSummary(result: DataCleanupResult, t: TFunction, locale: string): string {
  if (result.dry_run) {
    const files = new Intl.NumberFormat(locale).format(result.would_delete_files ?? 0);
    const directories = new Intl.NumberFormat(locale).format(result.would_delete_directories ?? 0);
    const bytes = formatBytes(result.would_delete_bytes ?? 0, locale);
    return `Pré-visualização: ${files} ficheiros e ${directories} pastas seriam removidos numa limpeza confirmada, totalizando ${bytes}. Nenhum ficheiro foi removido.`;
  }

  if (result.target === 'exports') {
    const files = new Intl.NumberFormat(locale).format(result.deleted_files);
    const directories = new Intl.NumberFormat(locale).format(result.deleted_directories);
    const bytes = formatBytes(result.deleted_bytes, locale);
    return `Limpeza executada: ${files} ficheiros e ${directories} pastas de exportações locais retidas foram removidos, libertando ${bytes}.`;
  }

  return t('data.status.cleanup.result', {
    files: new Intl.NumberFormat(locale).format(result.deleted_files),
    directories: new Intl.NumberFormat(locale).format(result.deleted_directories),
    bytes: formatBytes(result.deleted_bytes, locale),
  });
}

function backupFileSummary(manifest: BackupManifest, locale: string): string {
  const files = new Intl.NumberFormat(locale).format(manifest.files.length);
  const bytes = formatBytes(
    manifest.files.reduce((total, file) => total + file.bytes, 0),
    locale,
  );
  return `${files} / ${bytes}`;
}

function buildKeyRotationPreflightBody(
  currentKey: string,
  replacementKey: string,
): DataKeyRotationPreflightBody {
  const body: DataKeyRotationPreflightBody = { new_key: replacementKey };
  if (currentKey.length > 0) body.current_key = currentKey;
  return body;
}

function buildKeyRotationExecutionBody(replacementKey: string): DataKeyRotationExecuteBody {
  return { new_key: replacementKey };
}

function buildRecoveryDrillBody(
  archive: string,
  passphrase: string,
  notes: string,
  custodyLocation: string,
): BackupRecoveryDrillBody {
  const body: BackupRecoveryDrillBody = { archive: archive.trim() };
  const note = notes.trim();
  const custody = custodyLocation.trim();
  if (passphrase.trim().length > 0) body.passphrase = passphrase;
  if (note.length > 0) body.operator_notes = note;
  if (custody.length > 0) body.custody_location = custody;
  return body;
}

function StatusBadge({
  value,
  positive = true,
  t,
}: {
  value: boolean | null;
  positive?: boolean;
  t: TFunction;
}) {
  if (value === null) return <Badge>{'—'}</Badge>;
  const ok = positive ? value : !value;
  return <Badge tone={ok ? 'ok' : 'warn'}>{value ? t('common.yes') : t('common.no')}</Badge>;
}

function syncHandoffPreflightReportJson(report: SyncHandoffPreflightReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

type FactRow = {
  key: string;
  label: ReactNode;
  value: ReactNode;
  /** Identifiers, digests, paths and backend names: monospace, never truncated. */
  mono?: boolean;
};

/**
 * One read-only name/value block, as a real table.
 *
 * t69 converted this surface's *forms* to the shared `.settings-rows` grid and deliberately left
 * the ~25 fact readouts as `dl.deflist.data-status-summary`, reasoning that read-only facts should
 * not be dressed as editable settings. That reasoning was about not looking like a *form*; a table
 * is the opposite of a form, and it is what t83 already did for the Sobre panel. So the facts
 * become tables here: hidden `<caption>` naming the block, `<th scope="row">` per fact, and no
 * control of any kind inside. Nothing on this surface became editable.
 */
function FactTable({
  caption,
  columns,
  rows,
}: {
  caption: string;
  /** Column headers. Defaults to the generic Informação / Valor pair. */
  columns?: [string, string];
  rows: FactRow[];
}) {
  const t = useT();
  const [factColumn, valueColumn] = columns ?? [
    t('data.status.col.fact'),
    t('data.status.col.value'),
  ];
  return (
    <Table
      className="data-status-table"
      caption={caption}
      head={
        <tr>
          <th scope="col">{factColumn}</th>
          <th scope="col">{valueColumn}</th>
        </tr>
      }
    >
      {rows.map((row) => (
        <tr key={row.key}>
          <th scope="row">{row.label}</th>
          <td className={row.mono ? 'mono' : undefined}>{row.value}</td>
        </tr>
      ))}
    </Table>
  );
}

function DataDatabaseEncryptionReadiness({
  encryption,
  t,
}: {
  encryption: DataDatabaseEncryptionStatus;
  t: TFunction;
}) {
  const migration = encryption.key_ops?.migration_plan;
  const gaps: string[] = [];

  if (!encryption.sqlcipher_available) gaps.push('Build sem SQLCipher');
  if (encryption.key_source === 'none') gaps.push('Fonte de chave ausente');
  if (encryption.plaintext_migration_pending) gaps.push('Migração de plaintext pendente');
  if (encryption.plaintext_migration_blocked) gaps.push('Migração direta plaintext bloqueada');
  if (!encryption.hardware_derived_fallback.available) {
    gaps.push('Fallback derivado de hardware indisponível');
  }
  if (encryption.hardware_derived_fallback.fail_closed_if_requested) {
    gaps.push('Fallback derivado de hardware falha fechado quando solicitado');
  }
  if (encryption.key_ops_plan === 'sqlcipher_build_required') {
    gaps.push('Plano requer build SQLCipher antes de operar a chave');
  }
  if (encryption.key_ops?.key_config === 'empty') {
    gaps.push('Fonte de chave configurada está vazia');
  }
  if (encryption.key_ops_plan === 'key_required_for_non_plaintext_store') {
    gaps.push('Base não-plaintext requer chave configurada');
  }

  return (
    <InlineWarning
      tone={gaps.length > 0 || encryption.key_ops_error ? 'warn' : 'info'}
      title={translateNow('uiLiteral.gestaoDadosSection.prontidaoSqlcipherECustodiaDaChave')}
    >
      <div className="stack--tight">
        <p>
          {' '}
          {translateNow(
            'uiLiteral.gestaoDadosSection.sinaisLocaisDoBackendComSegredosRedigidosNao',
          )}{' '}
        </p>
        <FactTable
          caption={translateNow('uiLiteral.gestaoDadosSection.prontidaoSqlcipherECustodiaDaChave')}
          rows={[
            {
              key: 'sqlcipher_available',
              label: translateNow('uiLiteral.gestaoDadosSection.sqlcipherNoBuild'),
              value: <StatusBadge value={encryption.sqlcipher_available} t={t} />,
            },
            {
              key: 'configured',
              label: translateNow('uiLiteral.gestaoDadosSection.lojaAbertaComChaveConfigurada'),
              value: <StatusBadge value={encryption.configured} t={t} />,
            },
            {
              key: 'sqlcipher_backed',
              label: translateNow('uiLiteral.gestaoDadosSection.backendSqlcipherLocal'),
              value: <StatusBadge value={encryption.sqlcipher_backed} t={t} />,
            },
            {
              key: 'key_source',
              label: translateNow('uiLiteral.gestaoDadosSection.fonteDeChave'),
              value: encryption.key_source,
              mono: true,
            },
            {
              key: 'database_format',
              label: translateNow('uiLiteral.gestaoDadosSection.formatoDoCabecalho'),
              value: encryption.database_format ?? '—',
              mono: true,
            },
            {
              key: 'key_ops_plan',
              label: translateNow('uiLiteral.gestaoDadosSection.planoKeyOps'),
              value: encryption.key_ops_plan ?? '—',
              mono: true,
            },
            {
              key: 'key_config',
              label: translateNow('uiLiteral.gestaoDadosSection.configuracaoDaChave'),
              value: encryption.key_ops?.key_config ?? '—',
              mono: true,
            },
            {
              key: 'plaintext_migration_pending',
              label: translateNow('uiLiteral.gestaoDadosSection.migracaoPlaintextPendente'),
              value: (
                <StatusBadge
                  value={encryption.plaintext_migration_pending}
                  positive={false}
                  t={t}
                />
              ),
            },
            {
              key: 'plaintext_migration_blocked',
              label: translateNow('uiLiteral.gestaoDadosSection.migracaoPlaintextBloqueada'),
              value: (
                <StatusBadge
                  value={encryption.plaintext_migration_blocked}
                  positive={false}
                  t={t}
                />
              ),
            },
            {
              key: 'hardware_derived_fallback',
              label: translateNow('uiLiteral.gestaoDadosSection.fallbackHardware'),
              value: encryption.hardware_derived_fallback.status,
              mono: true,
            },
            {
              key: 'fail_closed_if_requested',
              label: translateNow('uiLiteral.gestaoDadosSection.fallbackFalhaFechado'),
              value: (
                <StatusBadge
                  value={encryption.hardware_derived_fallback.fail_closed_if_requested}
                  t={t}
                />
              ),
            },
            ...(migration
              ? [
                  {
                    key: 'migration_plan',
                    label: translateNow('uiLiteral.gestaoDadosSection.planoDeMigracao'),
                    value: (
                      <>
                        <span className="mono">{migration.status}</span>
                        {' · '}
                        {migration.summary}
                      </>
                    ),
                  },
                ]
              : []),
            ...(encryption.key_ops_error
              ? [
                  {
                    key: 'key_ops_error',
                    label: translateNow('uiLiteral.gestaoDadosSection.erroKeyOps'),
                    value: encryption.key_ops_error,
                  },
                ]
              : []),
          ]}
        />
        <div>
          <h5>{translateNow('uiLiteral.gestaoDadosSection.lacunasDeProntidao')}</h5>
          {gaps.length > 0 ? (
            <ul className="plain-list">
              {gaps.map((gap) => (
                <li key={gap}>{gap}</li>
              ))}
            </ul>
          ) : (
            <p className="field__hint">
              {translateNow('uiLiteral.gestaoDadosSection.semLacunasLocaisReportadasNesteEstado')}
            </p>
          )}
        </div>
        {migration && migration.steps.length > 0 ? (
          <div>
            <h5>{translateNow('uiLiteral.gestaoDadosSection.passosDeclarados')}</h5>
            {/* `title: detail` pairs repeated down the block — two columns, not list items. */}
            <FactTable
              caption={translateNow('uiLiteral.gestaoDadosSection.passosDeclarados')}
              columns={[t('data.status.col.step'), t('data.status.col.detail')]}
              rows={migration.steps.map((step) => ({
                key: String(step.order),
                label: <span className="mono">{step.title}</span>,
                value: step.detail,
              }))}
            />
          </div>
        ) : null}
      </div>
    </InlineWarning>
  );
}

function IsolatedRestoreVerificationReport({
  receipt,
  t,
  locale,
}: {
  receipt: BackupRecoveryDrillReceipt;
  t: TFunction;
  locale: string;
}) {
  const verification = receipt.isolated_restore_verification;
  const verified = receipt.isolated_restore_verified && verification.status === 'verified';
  const statusTone =
    verification.status === 'verified'
      ? 'ok'
      : verification.status === 'not_recorded'
        ? 'neutral'
        : 'warn';
  const booleanRows = [
    { label: 'Snapshot materializado', value: verification.db_snapshot_materialized },
    { label: 'Snapshot aberto', value: verification.db_snapshot_opened },
    { label: 'Estado carregado', value: verification.state_loaded },
    { label: 'Ledger verificado', value: verification.ledger_verified },
    { label: 'Limpeza verificada', value: verification.cleanup_verified },
  ];
  const countRows = [
    { label: 'Entidades', value: verification.entity_count },
    { label: 'Livros', value: verification.book_count },
    { label: 'Atos', value: verification.act_count },
    { label: 'Raízes sidecar', value: verification.sidecar_root_count },
    {
      label: 'Ficheiros sidecar materializados',
      value: verification.sidecar_materialized_file_count,
    },
    {
      label: 'Bytes sidecar materializados',
      value: formatBytes(verification.sidecar_materialized_bytes, locale),
    },
  ];
  const findings = verification.findings.map(redactReceiptEvidenceText).filter(Boolean);
  const errors = verification.errors.map(redactReceiptEvidenceText).filter(Boolean);

  return (
    <div>
      <h5>{translateNow('uiLiteral.gestaoDadosSection.verificacaoIsolada')}</h5>
      <FactTable
        caption={translateNow('uiLiteral.gestaoDadosSection.verificacaoIsolada')}
        rows={[
          {
            key: 'status',
            label: translateNow('uiLiteral.gestaoDadosSection.estado'),
            value: <Badge tone={statusTone}>{verification.status}</Badge>,
          },
          {
            key: 'isolated_restore_verified',
            label: translateNow('uiLiteral.gestaoDadosSection.snapshotIsoladoVerificado'),
            value: (
              <Badge tone={verified ? 'ok' : 'warn'}>
                {verified ? t('common.yes') : t('common.no')}
              </Badge>
            ),
          },
          ...booleanRows.map((row) => ({
            key: row.label,
            label: row.label,
            value: (
              <Badge tone={row.value ? 'ok' : 'warn'}>
                {row.value ? t('common.yes') : t('common.no')}
              </Badge>
            ),
          })),
          {
            key: 'sqlcipher_encryption_verified',
            label: translateNow('uiLiteral.gestaoDadosSection.sqlcipherVerificado'),
            value: <StatusBadge value={verification.sqlcipher_encryption_verified} t={t} />,
          },
          ...countRows.map((row) => ({
            key: row.label,
            label: row.label,
            value:
              typeof row.value === 'number'
                ? new Intl.NumberFormat(locale).format(row.value)
                : row.value,
            mono: true,
          })),
          {
            key: 'next_step',
            label: translateNow('uiLiteral.gestaoDadosSection.proximoPasso'),
            value: redactReceiptEvidenceText(verification.next_step),
          },
        ]}
      />

      <div>
        <h5>{translateNow('uiLiteral.gestaoDadosSection.constatacoes')}</h5>
        {findings.length === 0 ? (
          <p className="field__hint">
            {translateNow('uiLiteral.gestaoDadosSection.semConstatacoesRegistadas')}
          </p>
        ) : (
          <ul className="plain-list">
            {findings.map((finding, index) => (
              <li key={`${finding}-${index}`}>{finding}</li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <h5>{translateNow('uiLiteral.gestaoDadosSection.erros')}</h5>
        {errors.length === 0 ? (
          <p className="field__hint">
            {translateNow('uiLiteral.gestaoDadosSection.semErrosRegistados')}
          </p>
        ) : (
          <ul className="plain-list">
            {errors.map((error, index) => (
              <li key={`${error}-${index}`}>{error}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function RecoveryDrillReceiptReport({
  receipt,
  t,
  locale,
}: {
  receipt: BackupRecoveryDrillReceipt;
  t: TFunction;
  locale: string;
}) {
  const manifest = receipt.manifest;
  const limitRows: { label: string; confirmed: boolean }[] = [
    { label: 'Sem restauro ao vivo', confirmed: !receipt.restore_executed },
    { label: 'Sem troca ao vivo da base de dados', confirmed: !receipt.live_db_swapped },
    { label: 'Sem preparação ao vivo de sidecars', confirmed: !receipt.sidecars_staged },
    { label: 'Sem evento ledger.restored', confirmed: !receipt.ledger_restored_appended },
    { label: 'Sem apagamento de dados', confirmed: !receipt.data_deleted },
    { label: 'Sem certificação de custódia off-site', confirmed: !receipt.offsite_custody_proven },
    { label: 'Sem certificação legal ou de arquivo', confirmed: !receipt.legal_archive_certified },
  ];
  const isolatedVerified =
    receipt.isolated_restore_verified &&
    receipt.isolated_restore_verification.status === 'verified';
  const drillVerified = receipt.preflight_ok && receipt.preflight_ready && isolatedVerified;
  const evidenceRows: FactRow[] = [
    {
      key: 'archive',
      label: translateNow('uiLiteral.gestaoDadosSection.arquivoVerificado'),
      value: safeArchiveLabel(receipt.archive),
      mono: true,
    },
    {
      key: 'created_at',
      label: translateNow('uiLiteral.gestaoDadosSection.registadoEm'),
      value: formatTimestamp(receipt.created_at),
    },
    {
      key: 'preflight_ok',
      label: translateNow('uiLiteral.gestaoDadosSection.preValidacaoOk'),
      value: (
        <Badge tone={receipt.preflight_ok ? 'ok' : 'warn'}>
          {receipt.preflight_ok ? t('common.yes') : t('common.no')}
        </Badge>
      ),
    },
    {
      key: 'preflight_ready',
      label: translateNow('uiLiteral.gestaoDadosSection.prontoParaRestauro'),
      value: (
        <Badge tone={receipt.preflight_ready ? 'ok' : 'warn'}>
          {receipt.preflight_ready ? t('common.yes') : t('common.no')}
        </Badge>
      ),
    },
    {
      key: 'encrypted',
      label: translateNow('uiLiteral.gestaoDadosSection.cifrado'),
      value: yesNo(receipt.encrypted, t),
    },
    {
      key: 'ledger_verified',
      label: t('data.status.ledgerVerified'),
      value: receipt.ledger_verified ? t('common.yes') : t('common.no'),
    },
    ...(manifest
      ? [
          {
            key: 'schema',
            label: t('data.status.schemaVersion'),
            value: manifest.schema,
            mono: true,
          },
          {
            key: 'store_schema_version',
            label: translateNow('uiLiteral.gestaoDadosSection.esquemaDaBaseDeDados'),
            value: manifest.store_schema_version,
            mono: true,
          },
          {
            key: 'ledger_length',
            label: t('data.status.ledgerLength'),
            value: manifest.ledger_length,
            mono: true,
          },
          {
            key: 'member_count',
            label: translateNow('uiLiteral.gestaoDadosSection.membrosNoArquivo'),
            value: manifest.member_count,
            mono: true,
          },
          {
            key: 'sidecar_member_count',
            label: translateNow('uiLiteral.gestaoDadosSection.membrosSidecar'),
            value: manifest.sidecar_member_count,
            mono: true,
          },
          {
            key: 'db_member_present',
            label: translateNow('uiLiteral.gestaoDadosSection.membroDaBaseDeDadosPresente'),
            value: manifest.db_member_present ? t('common.yes') : t('common.no'),
          },
          {
            key: 'total_member_bytes',
            label: translateNow('uiLiteral.gestaoDadosSection.totalDeBytesDosMembros'),
            value: formatBytes(manifest.total_member_bytes, locale),
            mono: true,
          },
        ]
      : []),
    ...(receipt.custody_location
      ? [
          {
            key: 'custody_location',
            label: translateNow('uiLiteral.gestaoDadosSection.localDeCustodiaIndicado'),
            value: redactReceiptEvidenceText(receipt.custody_location),
          },
        ]
      : []),
    ...(receipt.operator_notes
      ? [
          {
            key: 'operator_notes',
            label: translateNow('uiLiteral.gestaoDadosSection.notasDoOperador'),
            value: redactReceiptEvidenceText(receipt.operator_notes),
          },
        ]
      : []),
  ];
  return (
    <InlineWarning
      tone={drillVerified ? 'info' : 'warn'}
      title={t(
        drillVerified
          ? 'data.status.recoveryDrill.verdictTitleOk'
          : 'data.status.recoveryDrill.verdictTitleFailed',
      )}
    >
      <div className="stack--tight">
        <div className="recovery-verdict">
          <p className="recovery-verdict__eyebrow">
            {t('data.status.recoveryDrill.receiptEyebrow')}
          </p>
          <p className="recovery-verdict__why">
            <Badge tone={drillVerified ? 'ok' : 'warn'}>{drillVerified ? '✓' : '✗'}</Badge>{' '}
            {t(
              drillVerified
                ? 'data.status.recoveryDrill.verdictWhyOk'
                : 'data.status.recoveryDrill.verdictWhyFailed',
            )}
          </p>
        </div>
        <details className="recovery-evidence">
          <summary>{t('data.status.recoveryDrill.evidenceToggle')}</summary>
          <div className="stack--tight">
            <FactTable
              caption={t('data.status.recoveryDrill.evidenceToggle')}
              rows={evidenceRows}
            />

            <IsolatedRestoreVerificationReport receipt={receipt} t={t} locale={locale} />

            <div>
              <h5>{translateNow('uiLiteral.gestaoDadosSection.limitesDoRecibo')}</h5>
              <FactTable
                caption={translateNow('uiLiteral.gestaoDadosSection.limitesDoRecibo')}
                columns={[t('data.status.col.boundary'), t('data.status.col.state')]}
                rows={limitRows.map((row) => ({
                  key: row.label,
                  label: row.label,
                  value: (
                    <Badge tone={row.confirmed ? 'ok' : 'warn'}>
                      {row.confirmed ? 'Confirmado' : 'Não confirmado'}
                    </Badge>
                  ),
                }))}
              />
            </div>
          </div>
        </details>
      </div>
    </InlineWarning>
  );
}

function recoveryFreshnessLabel(status: BackupRecoveryFreshnessReview['status']): string {
  switch (status) {
    case 'fresh':
      return 'Ensaio dentro da política';
    case 'stale':
      return 'Ensaio desatualizado';
    case 'failed':
      return 'Último ensaio sem verificação';
    case 'no_receipt':
    default:
      return 'Sem recibo local';
  }
}

function RecoveryFreshnessReviewReport({
  freshness,
}: {
  freshness: BackupRecoveryFreshnessReview;
}) {
  const warning = freshness.status !== 'fresh';
  return (
    <InlineWarning
      tone={warning ? 'warn' : 'info'}
      title={translateNow('uiLiteral.gestaoDadosSection.politicaLocalDeRecuperacao')}
    >
      <div className="stack--tight">
        <FactTable
          caption={translateNow('uiLiteral.gestaoDadosSection.politicaLocalDeRecuperacao')}
          rows={[
            {
              key: 'status',
              label: translateNow('uiLiteral.gestaoDadosSection.estadoDoEnsaio'),
              value: (
                <Badge tone={warning ? 'warn' : 'ok'}>
                  {recoveryFreshnessLabel(freshness.status)}
                </Badge>
              ),
            },
            {
              key: 'max_drill_age_days',
              label: translateNow('uiLiteral.gestaoDadosSection.idadeMaximaConfigurada'),
              value: `${freshness.policy.max_drill_age_days} ${translateNow('uiLiteral.gestaoDadosSection.dias')}`,
            },
            {
              key: 'target_rpo_minutes',
              label: translateNow('uiLiteral.gestaoDadosSection.rpoAlvoDeclarado'),
              value: `${freshness.policy.target_rpo_minutes} ${translateNow('uiLiteral.gestaoDadosSection.min')}`,
            },
            {
              key: 'target_rto_minutes',
              label: translateNow('uiLiteral.gestaoDadosSection.rtoAlvoDeclarado'),
              value: `${freshness.policy.target_rto_minutes} ${translateNow('uiLiteral.gestaoDadosSection.min')}`,
            },
            {
              key: 'latest_receipt_at',
              label: translateNow('uiLiteral.gestaoDadosSection.ultimoRecibo'),
              value: freshness.latest_receipt_at
                ? formatTimestamp(freshness.latest_receipt_at)
                : 'Sem recibo local',
            },
            {
              key: 'latest_receipt_age_days',
              label: translateNow('uiLiteral.gestaoDadosSection.idadeDoUltimoRecibo'),
              value:
                freshness.latest_receipt_age_days === null
                  ? '—'
                  : `${freshness.latest_receipt_age_days} dias`,
            },
            {
              key: 'latest_receipt_preflight_ready',
              label: translateNow('uiLiteral.gestaoDadosSection.preValidacaoDoUltimoRecibo'),
              value: freshness.latest_receipt_preflight_ready === true ? 'Sim' : 'Não',
            },
            {
              key: 'latest_receipt_isolated_restore_verified',
              label: translateNow('uiLiteral.gestaoDadosSection.snapshotIsoladoVerificado'),
              value: freshness.latest_receipt_isolated_restore_verified === true ? 'Sim' : 'Não',
            },
          ]}
        />
        <p className="field__hint">
          {' '}
          {translateNow(
            'uiLiteral.gestaoDadosSection.resumoLocalDerivadoDeRecibosDeEnsaioSem',
          )}{' '}
        </p>
      </div>
    </InlineWarning>
  );
}

function SyncHandoffPreflightReportCard({
  report,
  locale,
  t,
  savingJson,
  onSaveJson,
}: {
  report: SyncHandoffPreflightReport;
  locale: string;
  t: TFunction;
  savingJson: boolean;
  onSaveJson: () => void;
}) {
  const ready = report.readiness.local_handoff_review_ready;
  const blocked = report.blockers.length > 0;
  // Verdict-first: lead with a plain-language result; a warn/error frame flags "not ready".
  const tone = ready ? 'info' : blocked ? 'error' : 'warn';
  const badgeTone = ready ? 'ok' : 'warn';
  const verdictSymbol = ready ? '✓' : blocked ? '✗' : '?';
  const verdictTitle = ready
    ? 'data.status.syncHandoff.verdictTitleReady'
    : blocked
      ? 'data.status.syncHandoff.verdictTitleBlocked'
      : 'data.status.syncHandoff.verdictTitleMissing';
  const verdictWhy = ready
    ? 'data.status.syncHandoff.verdictWhyReady'
    : blocked
      ? 'data.status.syncHandoff.verdictWhyBlocked'
      : 'data.status.syncHandoff.verdictWhyMissing';
  const readinessTone = ready ? 'ok' : blocked ? 'warn' : 'neutral';
  const hasActionable =
    report.blockers.length > 0 ||
    report.missing_evidence.length > 0 ||
    report.operator_actions.length > 0;
  const latestCandidate = report.backup.backup_directory.latest_candidate_file;
  const latestDrill = report.backup.latest_recovery_drill;
  const boundaryRows = [
    ['Sem sincronização ativa', !report.no_claims.active_sync_implemented],
    ['Protocolo de conector externo implementado', report.no_claims.connector_protocol_implemented],
    ['Sem importação executada', !report.no_claims.import_performed],
    ['Sem registos alterados', !report.no_claims.records_mutated],
    [
      'Sem certificação DGLAB/archive',
      !report.no_claims.dglab_certification_claimed &&
        !report.no_claims.archive_certification_claimed,
    ],
    ['Sem prontidão de produção', !report.no_claims.production_sync_readiness_claimed],
  ] as const;

  return (
    <InlineWarning tone={tone} title={t(verdictTitle)}>
      <div className="stack--tight">
        <div className="recovery-verdict">
          <p className="recovery-verdict__eyebrow">{t('data.status.syncHandoff.eyebrow')}</p>
          <p className="recovery-verdict__why">
            <Badge tone={badgeTone}>{verdictSymbol}</Badge> {t(verdictWhy)}
          </p>
          <p className="field__hint">{t('data.status.syncHandoff.nonMutating')}</p>
        </div>

        <div className="form__actions">
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.Save />}
            disabled={savingJson}
            onClick={onSaveJson}
          >
            {savingJson ? t('common.saving') : t('pdfValidator.report.saveJson')}
          </Button>
        </div>

        {hasActionable ? (
          <div className="stack--tight">
            {report.blockers.length > 0 ? (
              <div>
                <h5>{t('data.status.syncHandoff.blockers')}</h5>
                <ul className="plain-list">
                  {report.blockers.map((blocker) => (
                    <li key={blocker}>{blocker}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {report.missing_evidence.length > 0 ? (
              <div>
                <h5>{t('data.status.syncHandoff.missingEvidence')}</h5>
                <ul className="plain-list">
                  {report.missing_evidence.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {report.operator_actions.length > 0 ? (
              <div>
                <h5>{t('data.status.syncHandoff.operatorActions')}</h5>
                <ul className="plain-list">
                  {report.operator_actions.map((action) => (
                    <li key={action}>{action}</li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        ) : null}

        <details className="recovery-evidence">
          <summary>{t('data.status.syncHandoff.evidenceToggle')}</summary>
          <div className="stack--tight">
            <FactTable
              caption={t('data.status.syncHandoff.evidenceToggle')}
              rows={[
                {
                  key: 'readiness',
                  label: translateNow('uiLiteral.gestaoDadosSection.estado'),
                  value: <Badge tone={readinessTone}>{report.readiness.status}</Badge>,
                },
                {
                  key: 'generated_at',
                  label: translateNow('uiLiteral.gestaoDadosSection.geradoEm'),
                  value: formatTimestamp(report.generated_at),
                },
                {
                  key: 'untrusted_candidates',
                  label: translateNow('uiLiteral.gestaoDadosSection.candidatosNaoValidados'),
                  value: (
                    <>
                      {new Intl.NumberFormat(locale).format(
                        report.backup.backup_directory.untrusted_candidate_file_count,
                      )}{' '}
                      /{' '}
                      <span className="mono">
                        {formatBytes(report.backup.backup_directory.total_candidate_bytes, locale)}
                      </span>
                    </>
                  ),
                },
                {
                  key: 'latest_candidate',
                  label: translateNow(
                    'uiLiteral.gestaoDadosSection.candidatoNaoValidadoMaisRecente',
                  ),
                  value: latestCandidate
                    ? `${latestCandidate.file_name} (${formatBytes(latestCandidate.bytes, locale)})`
                    : '—',
                  mono: true,
                },
                {
                  key: 'verified_evidence',
                  label: translateNow('uiLiteral.gestaoDadosSection.evidenciaVerificada'),
                  value: (
                    <Badge tone={report.backup.verified_recovery_drill_evidence ? 'ok' : 'warn'}>
                      {report.backup.verified_recovery_drill_evidence ? 'verified' : 'missing'}
                    </Badge>
                  ),
                },
                {
                  key: 'drill_count',
                  label: translateNow('uiLiteral.gestaoDadosSection.ensaiosDeRecuperacao'),
                  value: new Intl.NumberFormat(locale).format(
                    report.backup.recovery_drill_receipt_count,
                  ),
                },
                {
                  key: 'latest_drill',
                  label: translateNow('uiLiteral.gestaoDadosSection.ultimoEnsaio'),
                  value: latestDrill ? (
                    <Badge
                      tone={latestDrill.verified_manifest_and_isolated_snapshot ? 'ok' : 'warn'}
                    >
                      {latestDrill.verified_manifest_and_isolated_snapshot ? 'verified' : 'missing'}
                    </Badge>
                  ) : (
                    '—'
                  ),
                },
                {
                  key: 'books',
                  label: translateNow('uiLiteral.gestaoDadosSection.livros'),
                  value: `${new Intl.NumberFormat(locale).format(report.book_bundles.book_count)} ${translateNow('uiLiteral.gestaoDadosSection.total')} ${new Intl.NumberFormat(locale).format(report.book_bundles.closed_book_count)} ${translateNow('uiLiteral.gestaoDadosSection.fechados')}`,
                },
                {
                  key: 'preservable_acts',
                  label: translateNow('uiLiteral.gestaoDadosSection.atosPreservaveis'),
                  value: new Intl.NumberFormat(locale).format(
                    report.archive_dglab.sealed_or_archived_act_count,
                  ),
                },
                {
                  key: 'preserved_documents',
                  label: translateNow('uiLiteral.gestaoDadosSection.documentosPreservados'),
                  value: new Intl.NumberFormat(locale).format(
                    report.archive_dglab.preserved_document_count,
                  ),
                },
                {
                  key: 'import_preflight',
                  label: translateNow('uiLiteral.gestaoDadosSection.preValidacaoDeImportacao'),
                  value: (
                    <Badge tone={report.book_bundles.import_preflight_read_only ? 'ok' : 'warn'}>
                      {report.book_bundles.import_preflight_read_only ? 'read-only' : 'mutating'}
                    </Badge>
                  ),
                },
              ]}
            />

            {/* The declared boundaries were `<li>`s inside a `<dd>` — six label/verdict pairs read
                down a column, which is a table. They get their own, with real column headers,
                instead of hiding as one row of the evidence list. */}
            <div>
              <h5>{translateNow('uiLiteral.gestaoDadosSection.semAlegacoes')}</h5>
              <FactTable
                caption={translateNow('uiLiteral.gestaoDadosSection.semAlegacoes')}
                columns={[t('data.status.col.boundary'), t('data.status.col.state')]}
                rows={boundaryRows.map(([label, satisfied]) => ({
                  key: label,
                  label,
                  value: (
                    <Badge tone={satisfied ? 'ok' : 'warn'}>
                      {satisfied ? t('common.yes') : t('common.no')}
                    </Badge>
                  ),
                }))}
              />
            </div>
          </div>
        </details>
      </div>
    </InlineWarning>
  );
}

function DataKeyRotationPreflightReport({
  report,
  t,
}: {
  report: DataKeyRotationPreflight;
  t: TFunction;
}) {
  const blockerItems = report.ready ? [] : [report.status];
  return (
    <InlineWarning
      tone={report.ready ? 'info' : 'warn'}
      title={t('data.status.keyRotation.resultTitle')}
    >
      <div className="stack--tight">
        <FactTable
          caption={t('data.status.keyRotation.resultTitle')}
          rows={[
            {
              key: 'status',
              label: t('data.status.keyRotation.status'),
              value: <Badge tone={report.ready ? 'ok' : 'warn'}>{report.status}</Badge>,
            },
            {
              key: 'ready',
              label: t('data.status.keyRotation.ready'),
              value: (
                <Badge tone={report.ready ? 'ok' : 'warn'}>
                  {report.ready
                    ? t('data.status.keyRotation.ready.yes')
                    : t('data.status.keyRotation.ready.no')}
                </Badge>
              ),
            },
            {
              key: 'next_action',
              label: t('data.status.keyRotation.nextAction'),
              value: report.next_action,
            },
          ]}
        />

        <div>
          <h5>{t('data.status.keyRotation.blockers')}</h5>
          {blockerItems.length === 0 ? (
            <p className="field__hint">{t('data.status.keyRotation.blockers.none')}</p>
          ) : (
            <ul className="plain-list">
              {blockerItems.map((item) => (
                <li key={item}>
                  <code className="mono">{item}</code>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div>
          <h5>{t('data.status.keyRotation.evidence')}</h5>
          <FactTable
            caption={t('data.status.keyRotation.evidence')}
            rows={[
              {
                key: 'database_format',
                label: t('data.status.keyRotation.evidence.databaseFormat'),
                value: report.evidence.database_format,
                mono: true,
              },
              {
                key: 'current_key_config',
                label: t('data.status.keyRotation.evidence.currentKey'),
                value: report.evidence.current_key_config,
                mono: true,
              },
              {
                key: 'requested_key_config',
                label: t('data.status.keyRotation.evidence.replacementKey'),
                value: report.evidence.requested_key_config,
                mono: true,
              },
              {
                key: 'sqlcipher_available',
                label: t('data.status.keyRotation.evidence.sqlcipher'),
                value: report.evidence.sqlcipher_available ? t('common.yes') : t('common.no'),
              },
              {
                key: 'database_file',
                label: t('data.status.keyRotation.evidence.databaseFile'),
                value: report.evidence.database_file,
                mono: true,
              },
            ]}
          />
        </div>

        <div>
          <h5>{t('data.status.keyRotation.metadata')}</h5>
          <FactTable
            caption={t('data.status.keyRotation.metadata')}
            rows={[
              {
                key: 'provider',
                label: t('data.status.keyRotation.metadata.provider'),
                value: translateNow('uiLiteral.gestaoDadosSection.sqlcipher'),
              },
              {
                key: 'read_only',
                label: t('data.status.keyRotation.metadata.readOnly'),
                value: <Badge tone="ok">{t('common.yes')}</Badge>,
              },
              {
                key: 'execution',
                label: t('data.status.keyRotation.metadata.execution'),
                value: t('data.status.keyRotation.metadata.execution.none'),
              },
            ]}
          />
        </div>
      </div>
    </InlineWarning>
  );
}

function BackupManifestReport({
  manifest,
  t,
  locale,
}: {
  manifest: BackupManifest;
  t: TFunction;
  locale: string;
}) {
  return (
    <InlineWarning
      tone={manifest.ledger_verified ? 'info' : 'warn'}
      title={t('data.status.backup.doneTitle')}
    >
      <FactTable
        caption={t('data.status.backup.doneTitle')}
        rows={[
          // The archive path is an identifier: full value, monospace, wrapped rather than clipped.
          { key: 'path', label: t('data.status.backup.path'), value: manifest.path, mono: true },
          {
            key: 'created_at',
            label: t('data.status.backup.createdAt'),
            value: formatTimestamp(manifest.created_at),
          },
          {
            key: 'bytes',
            label: t('data.status.backup.size'),
            value: formatBytes(manifest.bytes, locale),
            mono: true,
          },
          {
            key: 'files',
            label: t('data.status.backup.files'),
            value: backupFileSummary(manifest, locale),
            mono: true,
          },
          {
            key: 'store_schema_version',
            label: t('data.status.schemaVersion'),
            value: formatOptionalNumber(manifest.store_schema_version, locale),
          },
          {
            key: 'ledger_length',
            label: t('data.status.ledgerLength'),
            value: formatOptionalNumber(manifest.ledger_length, locale),
          },
          {
            key: 'ledger_verified',
            label: t('data.status.ledgerVerified'),
            value: (
              <Badge tone={manifest.ledger_verified ? 'ok' : 'warn'}>
                {manifest.ledger_verified ? t('common.yes') : t('common.no')}
              </Badge>
            ),
          },
        ]}
      />
    </InlineWarning>
  );
}

function DataKeyRotationExecutionReport({
  execution,
  t,
  locale,
}: {
  execution: DataKeyRotationExecution;
  t: TFunction;
  locale: string;
}) {
  return (
    <InlineWarning
      tone={execution.ledger_integrity_verified ? 'info' : 'warn'}
      title={translateNow('uiLiteral.gestaoDadosSection.resultadoDaExecucaoSqlcipher')}
    >
      <div className="stack--tight">
        <FactTable
          caption={translateNow('uiLiteral.gestaoDadosSection.resultadoDaExecucaoSqlcipher')}
          rows={[
            {
              key: 'status',
              label: t('data.status.keyRotation.status'),
              value: (
                <Badge tone={execution.rekey_executed ? 'ok' : 'warn'}>{execution.status}</Badge>
              ),
            },
            {
              key: 'rekey_executed',
              label: translateNow('uiLiteral.gestaoDadosSection.rekeyExecutado'),
              value: (
                <Badge tone={execution.rekey_executed ? 'ok' : 'warn'}>
                  {execution.rekey_executed ? t('common.yes') : t('common.no')}
                </Badge>
              ),
            },
            {
              key: 'ledger_integrity_verified',
              label: t('data.status.ledgerVerified'),
              value: (
                <Badge tone={execution.ledger_integrity_verified ? 'ok' : 'warn'}>
                  {execution.ledger_integrity_verified ? t('common.yes') : t('common.no')}
                </Badge>
              ),
            },
            {
              key: 'ledger_length',
              label: t('data.status.ledgerLength'),
              value: new Intl.NumberFormat(locale).format(execution.ledger_length),
            },
          ]}
        />

        <div>
          <h5>{t('data.status.keyRotation.evidence')}</h5>
          <FactTable
            caption={t('data.status.keyRotation.evidence')}
            rows={[
              {
                key: 'operation',
                label: translateNow('uiLiteral.gestaoDadosSection.operacao'),
                value: execution.evidence.operation,
                mono: true,
              },
              {
                key: 'requested_key_config',
                label: t('data.status.keyRotation.evidence.replacementKey'),
                value: execution.evidence.requested_key_config,
                mono: true,
              },
              {
                key: 'sqlcipher_available',
                label: t('data.status.keyRotation.evidence.sqlcipher'),
                value: execution.evidence.sqlcipher_available ? t('common.yes') : t('common.no'),
              },
              {
                key: 'checkpointed_before_rekey',
                label: translateNow('uiLiteral.gestaoDadosSection.checkpointAntes'),
                value: execution.evidence.checkpointed_before_rekey
                  ? t('common.yes')
                  : t('common.no'),
              },
              {
                key: 'checkpointed_after_rekey',
                label: translateNow('uiLiteral.gestaoDadosSection.checkpointDepois'),
                value: execution.evidence.checkpointed_after_rekey
                  ? t('common.yes')
                  : t('common.no'),
              },
              {
                key: 'post_rekey_integrity_checked',
                label: translateNow('uiLiteral.gestaoDadosSection.integridadePosRekey'),
                value: execution.evidence.post_rekey_integrity_checked
                  ? t('common.yes')
                  : t('common.no'),
              },
            ]}
          />
        </div>
      </div>
    </InlineWarning>
  );
}

function DataKeyRotationReceiptSummary({
  summary,
  locale,
  t,
}: {
  summary: DataKeyRotationReceiptStatus;
  locale: string;
  t: TFunction;
}) {
  const latest = summary.latest_receipt;
  const history = summary.history.slice(0, Math.min(summary.history.length, summary.history_limit));

  return (
    <InlineWarning
      tone={summary.read_error ? 'warn' : 'info'}
      title={translateNow('uiLiteral.gestaoDadosSection.recibosLocaisDeRotacao')}
    >
      <div className="stack--tight">
        <p>
          {' '}
          {translateNow(
            'uiLiteral.gestaoDadosSection.evidenciaOperacionalLocalGeradaAposRekeySqlcipherAceite',
          )}{' '}
        </p>
        {summary.read_error ? <p className="field__hint">{summary.read_error}</p> : null}
        {latest ? (
          <>
            <FactTable
              caption={translateNow('uiLiteral.gestaoDadosSection.recibosLocaisDeRotacao')}
              rows={[
                {
                  key: 'rotated_at',
                  label: translateNow('uiLiteral.gestaoDadosSection.ultimaRotacao'),
                  value: formatTimestamp(latest.rotated_at),
                },
                {
                  key: 'status',
                  label: t('data.status.keyRotation.status'),
                  value: (
                    <Badge tone={latest.rekey_executed ? 'ok' : 'warn'}>{latest.status}</Badge>
                  ),
                },
                {
                  key: 'mode',
                  label: translateNow('uiLiteral.gestaoDadosSection.modo'),
                  value: latest.mode,
                  mono: true,
                },
                {
                  key: 'backend_family',
                  label: translateNow('uiLiteral.gestaoDadosSection.backend'),
                  value: latest.backend_family ?? '—',
                  mono: true,
                },
                {
                  key: 'actor_user_id',
                  label: translateNow('uiLiteral.gestaoDadosSection.utilizador'),
                  value: latest.actor_user_id ?? '—',
                  mono: true,
                },
                {
                  key: 'ledger_length',
                  label: t('data.status.ledgerLength'),
                  value: new Intl.NumberFormat(locale).format(latest.ledger_length),
                },
                {
                  key: 'ledger_integrity_verified',
                  label: t('data.status.ledgerVerified'),
                  value: <StatusBadge value={latest.ledger_integrity_verified} t={t} />,
                },
                {
                  key: 'history',
                  label: translateNow('uiLiteral.gestaoDadosSection.historicoGuardado'),
                  value: `${new Intl.NumberFormat(locale).format(summary.history_count)} / ${new Intl.NumberFormat(locale).format(summary.history_limit)}`,
                },
              ]}
            />
            <FactTable
              caption={t('data.status.keyRotation.evidence')}
              rows={[
                {
                  key: 'operation',
                  label: translateNow('uiLiteral.gestaoDadosSection.operacao'),
                  value: latest.evidence.operation,
                  mono: true,
                },
                {
                  key: 'requested_key_config',
                  label: t('data.status.keyRotation.evidence.replacementKey'),
                  value: latest.evidence.requested_key_config,
                  mono: true,
                },
                {
                  key: 'sqlcipher_available',
                  label: t('data.status.keyRotation.evidence.sqlcipher'),
                  value: latest.evidence.sqlcipher_available ? t('common.yes') : t('common.no'),
                },
                {
                  key: 'no_key_persisted',
                  label: translateNow('uiLiteral.gestaoDadosSection.semChaveGuardada'),
                  value:
                    !latest.no_claims.current_key_persisted &&
                    !latest.no_claims.replacement_key_persisted &&
                    !latest.no_claims.key_fingerprint_persisted
                      ? t('common.yes')
                      : t('common.no'),
                },
                {
                  key: 'no_database_path',
                  label: translateNow('uiLiteral.gestaoDadosSection.semCaminhoDaBd'),
                  value: latest.no_claims.database_path_persisted
                    ? t('common.no')
                    : t('common.yes'),
                },
              ]}
            />
          </>
        ) : (
          <p className="muted">
            {translateNow('uiLiteral.gestaoDadosSection.aindaNaoHaRecibosDeRotacaoSqlcipherBem')}
          </p>
        )}
        {history.length > 1 ? (
          <div>
            <h5>{translateNow('uiLiteral.gestaoDadosSection.historicoRecente')}</h5>
            {/* Repeated homogeneous receipts — date, verdict, backend — read down three columns. */}
            <Table
              className="data-status-table"
              caption={translateNow('uiLiteral.gestaoDadosSection.historicoRecente')}
              head={
                <tr>
                  <th scope="col">{t('data.status.col.when')}</th>
                  <th scope="col">{t('data.status.col.state')}</th>
                  <th scope="col">{translateNow('uiLiteral.gestaoDadosSection.backend')}</th>
                </tr>
              }
            >
              {history.map((receipt: DataKeyRotationReceipt) => (
                <tr key={receipt.receipt_id}>
                  <th scope="row">{formatTimestamp(receipt.rotated_at)}</th>
                  <td>
                    <Badge tone={receipt.rekey_executed ? 'ok' : 'warn'}>{receipt.status}</Badge>
                  </td>
                  <td className="mono">{receipt.backend_family ?? '—'}</td>
                </tr>
              ))}
            </Table>
          </div>
        ) : null}
      </div>
    </InlineWarning>
  );
}

/**
 * One usage breakdown as a table. Every row is the same shape — a storage set, its size and the
 * measurement detail behind that size — so the sizes are compared down a real column instead of
 * being read out of stacked list items.
 */
function UsageList({
  concerns,
  label,
  locale,
  t,
}: {
  concerns: DataUsageConcern[];
  /** The group's own heading, reused as the table's visually hidden caption. */
  label: string;
  locale: string;
  t: TFunction;
}) {
  if (concerns.length === 0) {
    return <p className="muted">{t('data.status.usage.empty')}</p>;
  }
  return (
    <Table
      className="data-status-table"
      caption={label}
      head={
        <tr>
          <th scope="col">{t('data.status.col.item')}</th>
          <th scope="col">{t('data.status.col.size')}</th>
          <th scope="col">{t('data.status.col.detail')}</th>
        </tr>
      }
    >
      {concerns.map((concern) => {
        const meta = concernMetaItems(concern, t, locale);
        return (
          <tr key={`${concern.id}:${concern.basis}`}>
            <th scope="row">{concern.label}</th>
            <td className="mono">{formatBytes(concern.bytes, locale)}</td>
            {/* Each measurement stays its own element rather than one joined sentence: the
                basis, exactness and counts are separate facts an operator reads individually. */}
            <td className="data-status-table__meta data-status-table__tags">
              {meta.map((item) => (
                <span key={item}>{item}</span>
              ))}
            </td>
          </tr>
        );
      })}
    </Table>
  );
}

function SqliteTablePayloadList({
  concerns,
  ariaLabel,
  locale,
  t,
}: {
  concerns: DataUsageConcern[];
  ariaLabel: string;
  locale: string;
  t: TFunction;
}) {
  // Five values per row, already laid out in five pseudo-columns by CSS: a real table with real
  // column headers is what this list has been imitating.
  return (
    <Table
      className="data-status-table data-status-sqlite-table"
      caption={ariaLabel}
      head={
        <tr>
          <th scope="col">{t('data.status.col.table')}</th>
          <th scope="col">{t('data.status.col.rows')}</th>
          <th scope="col">{t('data.status.col.size')}</th>
          <th scope="col">{t('data.status.col.average')}</th>
          <th scope="col">{t('data.status.col.method')}</th>
        </tr>
      }
    >
      {concerns.map((concern) => {
        const stats = sqlitePayloadStats(concern);
        const label = stats.table_name || sqliteTableLabel(concern);
        const rowCount =
          stats.row_count === undefined
            ? '—'
            : t('data.status.rows', {
                count: new Intl.NumberFormat(locale).format(stats.row_count),
              });
        const average =
          stats.average_bytes_per_row === null
            ? t('data.status.usage.sqliteAverageUnavailable')
            : t('data.status.usage.sqliteAverage', {
                bytes: formatBytes(stats.average_bytes_per_row, locale),
              });
        const meta = [
          label,
          formatBytes(stats.estimated_payload_bytes, locale),
          ...concernMetaItems(concern, t, locale),
          average,
        ];
        return (
          <tr key={`${concern.id}:${concern.basis}`} aria-label={meta.join(' · ')}>
            <th scope="row">
              <TooltipText className="data-status-sqlite-table-row__label" label={concern.label}>
                {label}
              </TooltipText>
            </th>
            <td>{rowCount}</td>
            <td className="mono">{formatBytes(stats.estimated_payload_bytes, locale)}</td>
            <td>{average}</td>
            <td className="data-status-table__meta">
              {t('data.status.usage.sqliteEstimateMethod.localLoadedPayload')}
            </td>
          </tr>
        );
      })}
    </Table>
  );
}

function SqliteLogicalUsageList({
  concerns,
  largestPayloadTable,
  label,
  locale,
  t,
}: {
  concerns: DataUsageConcern[];
  largestPayloadTable?: DataPayloadStats;
  label: string;
  locale: string;
  t: TFunction;
}) {
  if (concerns.length === 0) {
    return <p className="muted">{t('data.status.usage.empty')}</p>;
  }

  const tableConcerns = concerns.filter(isSqliteTableConcern);
  const summaryConcerns = concerns.filter((concern) => !isSqliteTableConcern(concern));
  const largest =
    largestPayloadTable ??
    tableConcerns
      .map(sqlitePayloadStats)
      .sort((left, right) => right.estimated_payload_bytes - left.estimated_payload_bytes)[0];

  return (
    <div className="data-status-sqlite-usage">
      <p className="data-status-section__hint">{t('data.status.usage.sqliteLogicalHint')}</p>
      {largest ? (
        <p className="data-status-sqlite-table-summary">
          {t('data.status.usage.sqliteLargestTable', {
            table: largest.table_name,
            bytes: formatBytes(largest.estimated_payload_bytes, locale),
            rows: new Intl.NumberFormat(locale).format(largest.row_count),
          })}
        </p>
      ) : null}
      {summaryConcerns.length > 0 ? (
        <UsageList concerns={summaryConcerns} label={label} locale={locale} t={t} />
      ) : null}
      {tableConcerns.length > 0 ? (
        <SqliteTablePayloadList concerns={tableConcerns} ariaLabel={label} locale={locale} t={t} />
      ) : null}
    </div>
  );
}

function DataStatusPanel({ tab, resetControls }: { tab: GestaoTab; resetControls: ReactNode }) {
  const t = useT();
  const locale = useLocale();
  const toast = useToast();
  const status = useDataStatus();
  const settings = useSettings();
  const backup = useCreateBackup();
  const recoveryDrill = useCreateBackupRecoveryDrill();
  const recoveryDrills = useBackupRecoveryDrills();
  const syncHandoffPreflight = useSyncHandoffPreflight();
  const cleanup = useCleanDataStorage();
  const keyRotationPreflight = useDataKeyRotationPreflight();
  const keyRotationExecution = useDataKeyRotationExecution();
  const data = status.data;
  const dataPath = data?.data_dir.path ?? null;
  const [cleanupTarget, setCleanupTarget] = useState<DataCleanupTarget | null>(null);
  const [lastCleanup, setLastCleanup] = useState<DataCleanupResult | null>(null);
  const [exportCleanupPreview, setExportCleanupPreview] = useState<DataCleanupResult | null>(null);
  const [exportCleanupPreviewPolicy, setExportCleanupPreviewPolicy] = useState<
    typeof DEFAULT_EXPORT_CLEANUP_POLICY | null
  >(null);
  const [previewingExports, setPreviewingExports] = useState(false);
  const [currentKey, setCurrentKey] = useState('');
  const [replacementKey, setReplacementKey] = useState('');
  const [executionKey, setExecutionKey] = useState('');
  const [drillArchive, setDrillArchive] = useState('');
  const [drillPassphrase, setDrillPassphrase] = useState('');
  const [drillNotes, setDrillNotes] = useState('');
  const [drillCustodyLocation, setDrillCustodyLocation] = useState('');
  const [savingSyncHandoffPreflight, setSavingSyncHandoffPreflight] = useState(false);
  const [lastBackup, setLastBackup] = useState<BackupManifest | null>(null);
  const [lastDrillReceipt, setLastDrillReceipt] = useState<BackupRecoveryDrillReceipt | null>(null);
  const [lastPreflight, setLastPreflight] = useState<DataKeyRotationPreflight | null>(null);
  const [lastExecution, setLastExecution] = useState<DataKeyRotationExecution | null>(null);
  const exportCleanupPolicy =
    settings.data?.data_management?.retained_export_cleanup ?? DEFAULT_EXPORT_CLEANUP_POLICY;
  const exportCleanupExecutionBody = exportCleanupBody(
    exportCleanupPreviewPolicy ?? exportCleanupPolicy,
    false,
  );
  const exportCleanupDescription = exportCleanupPreviewDescription(exportCleanupPolicy);
  const activeCleanup = CLEANUP_TARGETS.find((target) => target.target === cleanupTarget) ?? null;
  const exportCleanupPreviewToken =
    exportCleanupPreview?.target === 'exports' && exportCleanupPreview.dry_run
      ? (exportCleanupPreview.preview_token?.trim() ?? '')
      : '';
  const hasExportCleanupPreview = exportCleanupPreviewToken.length > 0;
  const permissions = data ? permissionSummary(data.permissions, t) : null;
  const logicalUsage =
    data && data.usage.logical_payload.length > 0
      ? data.usage.logical_payload
      : (data?.usage.sqlite_logical ?? []);
  const largestPayloadTable =
    data?.usage.largest_payload_table ?? data?.usage.sqlite_largest_payload_table;
  const logicalUsageLabel = 'Payload lógico durável';
  const showSidecars =
    Boolean(data) &&
    (data!.persistence.sidecar_storage_mode === 'database' || data!.usage.sidecars.length > 0);
  const canClean = Boolean(
    dataPath &&
    data?.data_dir.exists &&
    data?.data_dir.is_directory &&
    data?.permissions.delete_probe_file.ok,
  );

  async function previewExportsCleanup() {
    setPreviewingExports(true);
    setExportCleanupPreview(null);
    setExportCleanupPreviewPolicy(null);
    try {
      const previewPolicy = exportCleanupPolicy;
      const previewBody = exportCleanupBody(previewPolicy, true);
      const result = await cleanup.mutateAsync(previewBody);
      setLastCleanup(result);
      setExportCleanupPreview(result.preview_token ? result : null);
      setExportCleanupPreviewPolicy(result.preview_token ? previewPolicy : null);
      toast.success(EXPORT_CLEANUP_PREVIEW_DONE);
    } catch (err) {
      toast.error(err);
    } finally {
      setPreviewingExports(false);
    }
  }

  async function copyPath() {
    if (!dataPath) return;
    if (!navigator.clipboard) {
      toast.error(t('data.status.copyUnsupported'));
      return;
    }
    try {
      await navigator.clipboard.writeText(dataPath);
      toast.success(t('data.status.copyDone'));
    } catch (err) {
      toast.error(err);
    }
  }

  function showSaveResult(result: SaveBlobResult) {
    if (result.kind === 'cancelled') {
      toast.info(saveBlobResultMessage(result));
      return;
    }
    toast.success(saveBlobResultMessage(result));
  }

  async function saveSyncHandoffPreflightReport(report: SyncHandoffPreflightReport) {
    setSavingSyncHandoffPreflight(true);
    try {
      const blob = new Blob([syncHandoffPreflightReportJson(report)], {
        type: SYNC_HANDOFF_PREFLIGHT_EXPORT_CONTENT_TYPE,
      });
      showSaveResult(
        await saveBlobAs({
          blob,
          filename: SYNC_HANDOFF_PREFLIGHT_EXPORT_FILENAME,
          contentType: SYNC_HANDOFF_PREFLIGHT_EXPORT_CONTENT_TYPE,
          filters: [{ name: 'JSON', extensions: ['json'] }],
          preferBrowserSavePicker: true,
        }),
      );
    } catch (err) {
      toast.error(err);
    } finally {
      setSavingSyncHandoffPreflight(false);
    }
  }

  async function submitKeyRotationPreflight(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const body = buildKeyRotationPreflightBody(currentKey, replacementKey);
    keyRotationPreflight.reset();
    setLastPreflight(null);
    setLastExecution(null);
    try {
      const result = await keyRotationPreflight.mutateAsync(body);
      setLastPreflight(result);
      toast.success(t('data.status.keyRotation.done'));
    } catch (err) {
      toast.error(err);
    } finally {
      setCurrentKey('');
      setReplacementKey('');
    }
  }

  async function submitKeyRotationExecution(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const body = buildKeyRotationExecutionBody(executionKey);
    keyRotationExecution.reset();
    setLastExecution(null);
    try {
      const result = await keyRotationExecution.mutateAsync(body);
      setLastExecution(result);
      toast.success('Rekey SQLCipher executado.');
    } catch (err) {
      toast.error(err);
    } finally {
      setExecutionKey('');
    }
  }

  async function createBackup() {
    backup.reset();
    setLastBackup(null);
    try {
      const manifest = await backup.mutateAsync();
      setLastBackup(manifest);
      toast.success(t('data.status.backup.done'));
    } catch (err) {
      toast.error(err);
    }
  }

  async function submitRecoveryDrill(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const body = buildRecoveryDrillBody(
      drillArchive,
      drillPassphrase,
      drillNotes,
      drillCustodyLocation,
    );
    if (!body.archive) return;
    recoveryDrill.reset();
    setLastDrillReceipt(null);
    try {
      const receipt = await recoveryDrill.mutateAsync(body);
      setLastDrillReceipt(receipt);
      toast.success('Recibo de ensaio registado.');
    } catch (err) {
      toast.error(err);
    } finally {
      setDrillPassphrase('');
    }
  }

  return (
    <>
      <div className="route-transition stack" key={tab}>
        {tab === 'armazenamento' ? (
          <Card
            title={t('data.status.title')}
            actions={
              <Button
                type="button"
                variant="secondary"
                icon={<Icon.Refresh />}
                disabled={status.isFetching}
                onClick={() => void status.refetch()}
              >
                {status.isFetching ? t('data.status.refreshing') : t('data.status.refresh')}
              </Button>
            }
          >
            {/* What arrives is `.data-status` — a two-column fact table over sectioned blocks
                — so the placeholder reserves that instead of a line of text. */}
            {status.isLoading ? (
              <SkeletonRegion className="data-status" label={t('data.status.loading')}>
                <SkeletonTable rows={5} cols={2} />
              </SkeletonRegion>
            ) : null}
            {status.isError ? <ErrorNote error={status.error} /> : null}
            {data ? (
              <div className="data-status">
                <FactTable
                  caption={t('data.status.title')}
                  rows={[
                    {
                      key: 'mode',
                      label: t('data.status.mode'),
                      value: (
                        <Badge tone={data.persistence.durable_store_open ? 'ok' : 'warn'}>
                          {t(MODE_LABEL[data.persistence.mode])}
                        </Badge>
                      ),
                    },
                    {
                      key: 'generated_at',
                      label: t('data.status.generatedAt'),
                      value: formatTimestamp(data.generated_at),
                    },
                    {
                      key: 'total_bytes',
                      label: t('data.status.usage.title'),
                      value: formatBytes(data.usage.total_bytes, locale),
                      mono: true,
                    },
                    {
                      key: 'permissions',
                      label: t('data.status.permissions.title'),
                      value: permissions ? (
                        <Badge tone={permissions.tone}>{permissions.label}</Badge>
                      ) : (
                        '—'
                      ),
                    },
                    {
                      key: 'durable',
                      label: t('data.status.durable'),
                      value: (
                        <Badge tone={data.persistence.durable_store_open ? 'ok' : 'warn'}>
                          {data.persistence.durable_store_open
                            ? t('data.status.durable.open')
                            : t('data.status.durable.closed')}
                        </Badge>
                      ),
                    },
                    {
                      key: 'backend',
                      label: t('uiLiteral.gestaoDadosSection.backendDuravel'),
                      value: (
                        <Badge tone={data.persistence.active_backend_family ? 'ok' : 'neutral'}>
                          {data.persistence.active_backend_family ?? '—'}
                        </Badge>
                      ),
                    },
                    {
                      key: 'sidecars',
                      label: t('uiLiteral.gestaoDadosSection.sidecars'),
                      value: (
                        <Badge
                          tone={
                            data.persistence.sidecar_storage_mode === 'database' ? 'ok' : 'neutral'
                          }
                        >
                          {data.persistence.sidecar_storage_mode}
                        </Badge>
                      ),
                    },
                    {
                      key: 'encryption',
                      label: t('data.status.encryption'),
                      value: (
                        <StatusBadge
                          value={data.persistence.database_encryption_configured}
                          t={t}
                        />
                      ),
                    },
                    {
                      key: 'schema_version',
                      label: t('data.status.schemaVersion'),
                      value: formatOptionalNumber(data.persistence.store_schema_version, locale),
                    },
                    {
                      key: 'ledger_length',
                      label: t('data.status.ledgerLength'),
                      value: formatOptionalNumber(data.persistence.ledger_length, locale),
                    },
                    {
                      key: 'ledger_verified',
                      label: t('data.status.ledgerVerified'),
                      value: <StatusBadge value={data.persistence.ledger_verified} t={t} />,
                    },
                    {
                      key: 'degraded',
                      label: t('data.status.degraded'),
                      value: (
                        <StatusBadge value={data.persistence.degraded} positive={false} t={t} />
                      ),
                    },
                  ]}
                />

                <section className="data-status-section" aria-labelledby="data-status-folder">
                  <div className="data-status-section__head">
                    <h4 id="data-status-folder">{t('data.status.dataDir')}</h4>
                    <div className="row-wrap">
                      <Button
                        type="button"
                        variant="secondary"
                        icon={<Icon.Copy />}
                        disabled={!dataPath}
                        onClick={() => void copyPath()}
                      >
                        {t('data.status.copyPath')}
                      </Button>
                      <Button
                        type="button"
                        variant="secondary"
                        icon={<Icon.ExternalLink />}
                        disabled
                        title={t('data.status.openUnavailable')}
                      >
                        {t('data.status.openFolder')}
                      </Button>
                    </div>
                  </div>
                  {/* `data.status.folderState` crammed three name/value pairs into one sentence
                      separated by `·`. Those are facts about the folder, so they are rows; the
                      path keeps its own boxed, selectable, never-truncated cell. */}
                  <FactTable
                    caption={t('data.status.dataDir')}
                    rows={[
                      {
                        key: 'path',
                        label: t('data.status.folder.path'),
                        value: (
                          <span className="data-status-path mono">
                            {dataPath ?? t('data.status.path.unconfigured')}
                          </span>
                        ),
                      },
                      {
                        key: 'configured',
                        label: t('data.status.folder.configured'),
                        value: yesNo(data.persistence.data_dir_configured, t),
                      },
                      {
                        key: 'exists',
                        label: t('data.status.folder.exists'),
                        value: yesNo(data.data_dir.exists, t),
                      },
                      {
                        key: 'is_directory',
                        label: t('data.status.folder.isDirectory'),
                        value: yesNo(data.data_dir.is_directory, t),
                      },
                    ]}
                  />
                  <p className="field__hint">{t('data.status.openUnavailable')}</p>
                </section>

                <section className="data-status-section" aria-labelledby="data-status-permissions">
                  <div className="data-status-section__head">
                    <h4 id="data-status-permissions">{t('data.status.permissions.title')}</h4>
                  </div>
                  {/* Five probes, identical in shape — probe, verdict, what the verdict means.
                      Compared down columns rather than read out of stacked list items. */}
                  <Table
                    className="data-status-table"
                    caption={t('data.status.permissions.title')}
                    head={
                      <tr>
                        <th scope="col">{t('data.status.col.check')}</th>
                        <th scope="col">{t('data.status.col.state')}</th>
                        <th scope="col">{t('data.status.col.result')}</th>
                      </tr>
                    }
                  >
                    {PERMISSION_ROWS.map((row) => {
                      // Typed as possibly absent on purpose: a response missing this probe
                      // renders as "unchecked" instead of taking the page down.
                      const check: DataPermissionCheck | undefined = data.permissions[row.key];
                      const message = probeMessage(
                        row,
                        check,
                        data.persistence.data_dir_configured,
                        t,
                      );
                      return (
                        <tr key={row.key} className={`data-status-probe--${permissionTone(check)}`}>
                          <th scope="row">{t(row.label)}</th>
                          <td>
                            <Badge tone={permissionTone(check)}>{permissionLabel(check, t)}</Badge>
                          </td>
                          <td className="data-status-table__meta">
                            {message.text}
                            {message.detail ? (
                              <span className="data-status-probe__message mono">
                                {t('data.status.probe.detail', { detail: message.detail })}
                              </span>
                            ) : null}
                          </td>
                        </tr>
                      );
                    })}
                  </Table>
                </section>

                <section className="data-status-section" aria-labelledby="data-status-usage">
                  <div className="data-status-section__head">
                    <h4 id="data-status-usage">{t('data.status.usage.title')}</h4>
                    <p className="data-status-total">
                      {t('data.status.usage.total')}:{' '}
                      <span className="mono">{formatBytes(data.usage.total_bytes, locale)}</span>
                    </p>
                  </div>

                  <div className="data-status-usage-groups data-status-usage-groups--breakdown">
                    <div className="data-status-usage-group">
                      <h5>{t('data.status.usage.filesystem')}</h5>
                      <UsageList
                        concerns={data.usage.filesystem}
                        label={t('data.status.usage.filesystem')}
                        locale={locale}
                        t={t}
                      />
                    </div>
                    <div className="data-status-usage-group">
                      <h5>{logicalUsageLabel}</h5>
                      <SqliteLogicalUsageList
                        concerns={logicalUsage}
                        largestPayloadTable={largestPayloadTable}
                        label={logicalUsageLabel}
                        locale={locale}
                        t={t}
                      />
                    </div>
                    {showSidecars ? (
                      <div className="data-status-usage-group">
                        <h5>{t('uiLiteral.gestaoDadosSection.sidecarsDuraveis')}</h5>
                        <UsageList
                          concerns={data.usage.sidecars}
                          label={t('uiLiteral.gestaoDadosSection.sidecarsDuraveis')}
                          locale={locale}
                          t={t}
                        />
                      </div>
                    ) : null}
                  </div>

                  {data.usage.scan_errors.length > 0 ? (
                    <InlineWarning tone="warn" title={t('data.status.scanErrors.title')}>
                      <ul className="plain-list">
                        {data.usage.scan_errors.map((error) => (
                          <li key={error}>{error}</li>
                        ))}
                      </ul>
                    </InlineWarning>
                  ) : null}
                </section>

                <section className="data-status-section" aria-labelledby="data-status-maintenance">
                  <div className="data-status-section__head">
                    <div>
                      <h4 id="data-status-maintenance">{t('data.status.cleanup.title')}</h4>
                      <p className="data-status-section__hint">{t('data.status.cleanup.body')}</p>
                    </div>
                  </div>
                  {/* Three maintenance targets, identical in shape: what it clears, how much it
                      currently occupies, and the action. The action column carries the existing
                      gated buttons — a control that *acts*, never a field that edits a fact. */}
                  <Table
                    className="data-status-table data-status-cleanup-table"
                    caption={t('data.status.cleanup.title')}
                    head={
                      <tr>
                        <th scope="col">{t('data.status.col.cleanup')}</th>
                        <th scope="col">{t('data.status.col.usage')}</th>
                        <th scope="col">{t('data.status.col.action')}</th>
                      </tr>
                    }
                  >
                    {CLEANUP_TARGETS.map((target) => {
                      const usage = usageForTarget(data.usage.filesystem, target.target);
                      const isExportsPreview = target.target === 'exports';
                      const isTargetPending =
                        cleanup.isPending &&
                        (isExportsPreview ? previewingExports : cleanupTarget === target.target);
                      return (
                        <tr key={target.target} className="data-status-cleanup-row">
                          <th scope="row">
                            <div className="data-status-cleanup__main">
                              <h5>
                                {t(target.title)} <FieldHelp text={t(target.help)} />
                              </h5>
                              <span className="data-status-cleanup__description">
                                {isExportsPreview ? exportCleanupDescription : t(target.body)}
                              </span>
                              {isExportsPreview && hasExportCleanupPreview ? (
                                <span className="data-status-cleanup__description">
                                  {EXPORT_CLEANUP_CONFIRM_DESCRIPTION}
                                </span>
                              ) : null}
                            </div>
                          </th>
                          <td>
                            <p className="data-status-cleanup__metric">
                              <span className="mono">{formatBytes(usage?.bytes ?? 0, locale)}</span>
                              <span>
                                {t('data.status.cleanup.items', {
                                  files: new Intl.NumberFormat(locale).format(
                                    usage?.file_count ?? 0,
                                  ),
                                  directories: new Intl.NumberFormat(locale).format(
                                    usage?.directory_count ?? 0,
                                  ),
                                })}
                              </span>
                            </p>
                          </td>
                          <td>
                            <div className="data-status-cleanup__actions">
                              <GateButton
                                perm="settings.manage"
                                type="button"
                                variant="secondary"
                                icon={isExportsPreview ? <Icon.Search /> : <Icon.Wrench />}
                                disabled={!canClean || cleanup.isPending}
                                onClick={() => {
                                  if (isExportsPreview) {
                                    void previewExportsCleanup();
                                    return;
                                  }
                                  setCleanupTarget(target.target);
                                }}
                              >
                                {isTargetPending
                                  ? isExportsPreview
                                    ? EXPORT_CLEANUP_PREVIEW_PENDING
                                    : t('data.status.cleanup.pending')
                                  : isExportsPreview
                                    ? EXPORT_CLEANUP_PREVIEW_BUTTON
                                    : t(target.button)}
                              </GateButton>
                              {isExportsPreview ? (
                                <GateButton
                                  perm="settings.manage"
                                  type="button"
                                  variant="secondary"
                                  icon={<Icon.Wrench />}
                                  title={EXPORT_CLEANUP_EXECUTION_TOOLTIP}
                                  disabled={
                                    !canClean || cleanup.isPending || !hasExportCleanupPreview
                                  }
                                  onClick={() => setCleanupTarget('exports')}
                                >
                                  {cleanup.isPending && cleanupTarget === 'exports'
                                    ? EXPORT_CLEANUP_EXECUTION_PENDING
                                    : EXPORT_CLEANUP_EXECUTION_BUTTON}
                                </GateButton>
                              ) : null}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </Table>
                  {lastCleanup ? (
                    <InlineWarning
                      tone="info"
                      title={
                        lastCleanup.dry_run
                          ? EXPORT_CLEANUP_PREVIEW_TITLE
                          : lastCleanup.target === 'exports'
                            ? EXPORT_CLEANUP_EXECUTION_TITLE
                            : t('data.status.cleanup.doneTitle')
                      }
                    >
                      <p>{cleanupSummary(lastCleanup, t, locale)}</p>
                      {lastCleanup.skipped.length > 0 ? (
                        <ul className="plain-list">
                          {lastCleanup.skipped.map((item) => (
                            <li key={item} className="mono">
                              {item}
                            </li>
                          ))}
                        </ul>
                      ) : null}
                    </InlineWarning>
                  ) : null}
                </section>
              </div>
            ) : null}
          </Card>
        ) : null}

        {tab === 'copias' ? (
          <Card title={t('data.status.tab.backup')}>
            {/* What arrives is `.data-status` — a two-column fact table over sectioned blocks
                — so the placeholder reserves that instead of a line of text. */}
            {status.isLoading ? (
              <SkeletonRegion className="data-status" label={t('data.status.loading')}>
                <SkeletonTable rows={5} cols={2} />
              </SkeletonRegion>
            ) : null}
            {status.isError ? <ErrorNote error={status.error} /> : null}
            {data ? (
              <div className="data-status">
                <section className="data-status-section" aria-labelledby="data-status-backup">
                  <div className="data-status-section__head">
                    <div>
                      <h4 id="data-status-backup">{t('data.status.backup.title')}</h4>
                      <p className="data-status-section__hint">{t('data.status.backup.body')}</p>
                    </div>
                    <GateButton
                      perm="data.backup"
                      type="button"
                      variant="secondary"
                      icon={<Icon.Archive />}
                      disabled={!data.persistence.durable_store_open || backup.isPending}
                      onClick={() => void createBackup()}
                    >
                      {backup.isPending
                        ? t('data.status.backup.pending')
                        : t('data.status.backup.button')}
                    </GateButton>
                  </div>
                  {!data.persistence.durable_store_open ? (
                    <p className="field__hint">{t('data.status.backup.unavailable')}</p>
                  ) : null}
                  {backup.error ? <ErrorNote error={backup.error} /> : null}
                  {lastBackup ? (
                    <BackupManifestReport manifest={lastBackup} t={t} locale={locale} />
                  ) : null}
                </section>

                <section
                  className="data-status-section"
                  aria-labelledby="data-status-recovery-drill"
                >
                  <div className="data-status-section__head">
                    <div>
                      <h4 id="data-status-recovery-drill">
                        {t('uiLiteral.gestaoDadosSection.ensaioDeRecuperacaoSemRestauro')}
                      </h4>
                      <p className="data-status-section__hint">
                        {' '}
                        {t(
                          'uiLiteral.gestaoDadosSection.executaAPreValidacaoExistenteDoBackupE',
                        )}{' '}
                        <FieldHelp text={t('data.status.help.recoveryDrill')} />
                      </p>
                    </div>
                  </div>
                  {recoveryDrills.isLoading ? (
                    <SkeletonRegion
                      label={t('uiLiteral.gestaoDadosSection.aCarregarPoliticaDeRecuperacao')}
                    >
                      <SkeletonTable rows={4} cols={2} />
                    </SkeletonRegion>
                  ) : null}
                  {recoveryDrills.error ? <ErrorNote error={recoveryDrills.error} /> : null}
                  {recoveryDrills.data ? (
                    <RecoveryFreshnessReviewReport freshness={recoveryDrills.data.freshness} />
                  ) : null}
                  <form
                    className="form settings-rows"
                    onSubmit={(event) => void submitRecoveryDrill(event)}
                  >
                    <div className="data-status-usage-groups">
                      <Field
                        label={t('uiLiteral.gestaoDadosSection.arquivoDoBackupParaEnsaio')}
                        htmlFor="backup-recovery-drill-archive"
                        hint={t(
                          'uiLiteral.gestaoDadosSection.nomeSimplesEmBackupsOuCaminhoAbsolutoDo',
                        )}
                      >
                        <Input
                          id="backup-recovery-drill-archive"
                          name="backup-recovery-drill-archive"
                          value={drillArchive}
                          placeholder={t('uiLiteral.gestaoDadosSection.chancelaBackupZip')}
                          onChange={(event) => setDrillArchive(event.target.value)}
                        />
                      </Field>
                      <Field
                        label={t('uiLiteral.gestaoDadosSection.chaveDoBackupOpcional')}
                        htmlFor="backup-recovery-drill-passphrase"
                        hint={t(
                          'uiLiteral.gestaoDadosSection.usadaSoNestaPreValidacaoNaoEGuardada',
                        )}
                      >
                        <Input
                          id="backup-recovery-drill-passphrase"
                          name="backup-recovery-drill-passphrase"
                          type="password"
                          value={drillPassphrase}
                          autoComplete="off"
                          autoCorrect="off"
                          autoCapitalize="off"
                          spellCheck={false}
                          onChange={(event) => setDrillPassphrase(event.target.value)}
                        />
                      </Field>
                    </div>
                    <Field
                      label={t('uiLiteral.gestaoDadosSection.localDeCustodia')}
                      htmlFor="backup-recovery-drill-custody"
                      hint={t(
                        'uiLiteral.gestaoDadosSection.localIndicadoPeloOperadorIstoNaoComprovaCustodia',
                      )}
                    >
                      <Input
                        id="backup-recovery-drill-custody"
                        name="backup-recovery-drill-custody"
                        value={drillCustodyLocation}
                        onChange={(event) => setDrillCustodyLocation(event.target.value)}
                      />
                    </Field>
                    <Field
                      label={t('uiLiteral.gestaoDadosSection.notasDoOperador')}
                      htmlFor="backup-recovery-drill-notes"
                    >
                      <TextArea
                        id="backup-recovery-drill-notes"
                        name="backup-recovery-drill-notes"
                        value={drillNotes}
                        onChange={(event) => setDrillNotes(event.target.value)}
                      />
                    </Field>
                    {!data.persistence.durable_store_open ? (
                      <p className="field__hint">
                        {t('uiLiteral.gestaoDadosSection.requerArmazenamentoDuravelEmDisco')}
                      </p>
                    ) : null}
                    <p className="field__hint">
                      {' '}
                      {t(
                        'uiLiteral.gestaoDadosSection.ensaioExplicitoEIniciadoPeloOperadorSemRestauro',
                      )}{' '}
                    </p>
                    {recoveryDrill.error ? <ErrorNote error={recoveryDrill.error} /> : null}
                    <div className="form__actions">
                      <GateButton
                        perm="ledger.recover"
                        type="submit"
                        variant="secondary"
                        icon={<Icon.Search />}
                        disabled={
                          !data.persistence.durable_store_open ||
                          recoveryDrill.isPending ||
                          drillArchive.trim().length === 0
                        }
                      >
                        {recoveryDrill.isPending
                          ? 'A registar ensaio…'
                          : 'Registar ensaio sem restauro'}
                      </GateButton>
                    </div>
                  </form>
                  {lastDrillReceipt ? (
                    <RecoveryDrillReceiptReport receipt={lastDrillReceipt} t={t} locale={locale} />
                  ) : null}
                </section>

                <section className="data-status-section" aria-labelledby="data-status-sync-handoff">
                  <div className="data-status-section__head">
                    <div>
                      <h4 id="data-status-sync-handoff">
                        {t('uiLiteral.gestaoDadosSection.preValidacaoLocalDeHandoff')}
                      </h4>
                      <p className="data-status-section__hint">
                        {' '}
                        {t(
                          'uiLiteral.gestaoDadosSection.compoeApenasEvidenciaLocalCandidatosDeBackupEnsaios',
                        )}{' '}
                      </p>
                    </div>
                  </div>
                  {syncHandoffPreflight.isLoading ? (
                    <SkeletonRegion
                      label={t('uiLiteral.gestaoDadosSection.aCarregarPreValidacaoLocalDeHandoff')}
                    >
                      <SkeletonTable rows={5} cols={2} />
                    </SkeletonRegion>
                  ) : null}
                  {syncHandoffPreflight.error ? (
                    <ErrorNote error={syncHandoffPreflight.error} />
                  ) : null}
                  {syncHandoffPreflight.data ? (
                    <SyncHandoffPreflightReportCard
                      report={syncHandoffPreflight.data}
                      locale={locale}
                      t={t}
                      savingJson={savingSyncHandoffPreflight}
                      onSaveJson={() =>
                        void saveSyncHandoffPreflightReport(syncHandoffPreflight.data)
                      }
                    />
                  ) : null}
                </section>
              </div>
            ) : null}
          </Card>
        ) : null}

        {tab === 'chaves' ? (
          <>
            <Card title={t('data.status.tab.keys')}>
              {/* What arrives is `.data-status` — a two-column fact table over sectioned blocks
                — so the placeholder reserves that instead of a line of text. */}
              {status.isLoading ? (
                <SkeletonRegion className="data-status" label={t('data.status.loading')}>
                  <SkeletonTable rows={5} cols={2} />
                </SkeletonRegion>
              ) : null}
              {status.isError ? <ErrorNote error={status.error} /> : null}
              {data ? (
                <div className="data-status">
                  <section
                    className="data-status-section"
                    aria-labelledby="data-status-database-encryption-readiness"
                  >
                    <div className="data-status-section__head">
                      <div>
                        <h4 id="data-status-database-encryption-readiness">
                          {' '}
                          {t(
                            'uiLiteral.gestaoDadosSection.prontidaoSqlcipherECustodiaDaChave',
                          )}{' '}
                        </h4>
                        <p className="data-status-section__hint">
                          {' '}
                          {t(
                            'uiLiteral.gestaoDadosSection.leituraDoEstadoLocalDePersistenciaNaoExecuta',
                          )}{' '}
                        </p>
                      </div>
                    </div>
                    <DataDatabaseEncryptionReadiness
                      encryption={data.persistence.database_encryption}
                      t={t}
                    />
                  </section>
                  <section
                    className="data-status-section"
                    aria-labelledby="data-status-key-rotation"
                  >
                    <div className="data-status-section__head">
                      <div>
                        <h4 id="data-status-key-rotation">{t('data.status.keyRotation.title')}</h4>
                        <p className="data-status-section__hint">
                          {t('data.status.keyRotation.body')}{' '}
                          <FieldHelp text={t('data.status.help.keyRotation')} />
                        </p>
                      </div>
                    </div>
                    <DataKeyRotationReceiptSummary
                      summary={data.key_rotation}
                      locale={locale}
                      t={t}
                    />
                    <form
                      className="form settings-rows"
                      onSubmit={(event) => void submitKeyRotationPreflight(event)}
                    >
                      <div className="data-status-usage-groups">
                        <Field
                          label={t('data.status.keyRotation.currentKey.label')}
                          htmlFor="data-key-rotation-current"
                          hint={t('data.status.keyRotation.currentKey.hint')}
                        >
                          <Input
                            id="data-key-rotation-current"
                            name="data-key-rotation-current"
                            type="password"
                            value={currentKey}
                            autoComplete="off"
                            autoCorrect="off"
                            autoCapitalize="off"
                            spellCheck={false}
                            onChange={(event) => setCurrentKey(event.target.value)}
                          />
                        </Field>
                        <Field
                          label={t('data.status.keyRotation.replacementKey.label')}
                          htmlFor="data-key-rotation-replacement"
                          hint={t('data.status.keyRotation.replacementKey.hint')}
                        >
                          <Input
                            id="data-key-rotation-replacement"
                            name="data-key-rotation-replacement"
                            type="password"
                            value={replacementKey}
                            autoComplete="off"
                            autoCorrect="off"
                            autoCapitalize="off"
                            spellCheck={false}
                            onChange={(event) => setReplacementKey(event.target.value)}
                          />
                        </Field>
                      </div>
                      <p className="field__hint">{t('data.status.keyRotation.secretHint')}</p>
                      {!dataPath ? (
                        <p className="field__hint">{t('data.status.keyRotation.unavailable')}</p>
                      ) : null}
                      {keyRotationPreflight.error ? (
                        <ErrorNote error={keyRotationPreflight.error} />
                      ) : null}
                      <div className="form__actions">
                        <GateButton
                          perm="settings.manage"
                          type="submit"
                          variant="secondary"
                          icon={<Icon.Search />}
                          disabled={!dataPath || keyRotationPreflight.isPending}
                        >
                          {keyRotationPreflight.isPending
                            ? t('data.status.keyRotation.pending')
                            : t('data.status.keyRotation.submit')}
                        </GateButton>
                      </div>
                    </form>
                    {lastPreflight ? (
                      <DataKeyRotationPreflightReport report={lastPreflight} t={t} />
                    ) : null}
                    {lastPreflight?.ready ? (
                      <form
                        className="form settings-rows"
                        aria-label={t('uiLiteral.gestaoDadosSection.execucaoDaRotacaoSqlcipher')}
                        onSubmit={(event) => void submitKeyRotationExecution(event)}
                      >
                        <Field
                          label={t('uiLiteral.gestaoDadosSection.novaChaveSqlcipher')}
                          htmlFor="data-key-rotation-execution"
                          hint={t(
                            'uiLiteral.gestaoDadosSection.enviadaApenasParaExecutarPragmaRekeyAResposta',
                          )}
                        >
                          <Input
                            id="data-key-rotation-execution"
                            name="data-key-rotation-execution"
                            type="password"
                            value={executionKey}
                            autoComplete="off"
                            autoCorrect="off"
                            autoCapitalize="off"
                            spellCheck={false}
                            onChange={(event) => setExecutionKey(event.target.value)}
                          />
                        </Field>
                        <p className="field__hint">
                          {' '}
                          {t(
                            'uiLiteral.gestaoDadosSection.executaApenasORekeySqlcipherNaBaseDe',
                          )}{' '}
                        </p>
                        {keyRotationExecution.error ? (
                          <ErrorNote error={keyRotationExecution.error} />
                        ) : null}
                        <div className="form__actions">
                          <GateButton
                            perm="settings.manage"
                            type="submit"
                            variant="primary"
                            icon={<Icon.Check />}
                            disabled={!dataPath || keyRotationExecution.isPending}
                          >
                            {keyRotationExecution.isPending
                              ? 'A executar rekey…'
                              : 'Executar rekey SQLCipher'}
                          </GateButton>
                        </div>
                      </form>
                    ) : null}
                    {lastExecution ? (
                      <DataKeyRotationExecutionReport
                        execution={lastExecution}
                        t={t}
                        locale={locale}
                      />
                    ) : null}
                  </section>
                </div>
              ) : null}
            </Card>
            {resetControls}
          </>
        ) : null}
      </div>

      <ConfirmActionModal
        open={activeCleanup !== null}
        onClose={() => {
          if (cleanupTarget === 'exports') {
            setExportCleanupPreview(null);
            setExportCleanupPreviewPolicy(null);
          }
          setCleanupTarget(null);
        }}
        title={activeCleanup ? t(activeCleanup.title) : ''}
        danger
        intro={
          activeCleanup?.target === 'exports'
            ? EXPORT_CLEANUP_CONFIRM_DESCRIPTION
            : activeCleanup
              ? t(activeCleanup.confirm)
              : ''
        }
        confirmLabel={
          activeCleanup?.target === 'exports'
            ? EXPORT_CLEANUP_EXECUTION_BUTTON
            : activeCleanup
              ? t(activeCleanup.button)
              : ''
        }
        pendingLabel={
          activeCleanup?.target === 'exports'
            ? EXPORT_CLEANUP_EXECUTION_PENDING
            : t('data.status.cleanup.pending')
        }
        pending={cleanup.isPending}
        canConfirm={activeCleanup?.target !== 'exports' || hasExportCleanupPreview}
        onConfirm={async () => {
          if (!activeCleanup) return;
          if (activeCleanup.target === 'exports') {
            try {
              const result = await cleanup.mutateAsync({
                ...exportCleanupExecutionBody,
                preview_token: exportCleanupPreviewToken,
              });
              setLastCleanup(result);
              setExportCleanupPreview(null);
              setExportCleanupPreviewPolicy(null);
              toast.success(EXPORT_CLEANUP_EXECUTION_DONE);
            } catch (err) {
              setExportCleanupPreview(null);
              setExportCleanupPreviewPolicy(null);
              throw err;
            }
            return;
          }
          const result = await cleanup.mutateAsync({ target: activeCleanup.target });
          setLastCleanup(result);
          toast.success(t('data.status.cleanup.done'));
        }}
      />
    </>
  );
}

/**
 * @param tab When set (t28), the caller — the Operações route — decides which pane shows and the
 *   internal `<SubNav>` is not rendered; each pane is its own route subtab. When omitted the
 *   component is self-contained, driving its own strip (its unit test renders it this way).
 */
export function GestaoDadosSection({ tab: tabProp }: { tab?: GestaoTab } = {}) {
  const t = useT();
  const toast = useToast();
  const qc = useQueryClient();
  const resetData = useResetData();
  const startOverInstance = useStartOverInstance();

  const [dialog, setDialog] = useState<Dialog>('none');
  const [reason, setReason] = useState('');
  const [lastOutcome, setLastOutcome] = useState<ResetOutcomeView | null>(null);
  const [internalTab, setInternalTab] = useState<GestaoTab>('armazenamento');
  const tab = tabProp ?? internalTab;
  const close = () => setDialog('none');

  const tabDescription =
    tab === 'armazenamento'
      ? t('data.status.tab.storage.desc')
      : tab === 'copias'
        ? t('data.status.tab.backup.desc')
        : t('data.status.tab.keys.desc');

  // The "Chaves e reposição" sub-sub-tab hosts the data-key rotation surface (rendered by
  // DataStatusPanel) followed by these reset/recomeço controls, so the destructive resets
  // stay clearly separated from the everyday storage view while keeping every confirm +
  // step-up gate intact.
  const resetControls = (
    <>
      {/* 1 · Repor interface (client-only) -------------------------------------- */}
      <Card title={t('data.frontend.title')}>
        <div className="stack--tight">
          <p className="field__hint">{t('data.frontend.body')}</p>
          <div className="row-wrap">
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.Refresh />}
              onClick={() => setDialog('frontend')}
            >
              {t('data.frontend.button')}
            </Button>
          </div>
        </div>
      </Card>

      {/* 2 · Recomeçar instância (non-destructive, keeps running) --------------- */}
      <Card title={t('data.startOver.title')}>
        <div className="stack--tight">
          <p className="field__hint">
            {t('data.startOver.body')} <FieldHelp text={t('data.status.help.startOver')} />
          </p>
          <div className="row-wrap">
            <GateButton
              perm="data.start_over"
              type="button"
              variant="secondary"
              icon={<Icon.BookPlus />}
              onClick={() => {
                setReason('');
                setDialog('startover');
              }}
            >
              {t('data.startOver.button')}
            </GateButton>
          </div>
        </div>
      </Card>

      {/* 3–5 · Destructive server ops ------------------------------------------ */}
      <Card title={t('data.destructive.title')}>
        <div className="stack--tight">
          <InlineWarning tone="error" title={t('data.destructive.warnTitle')}>
            {t('data.destructive.warnBody')} <FieldHelp text={t('data.status.help.reset')} />
          </InlineWarning>
          <div className="row-wrap">
            <GateButton
              perm="data.wipe"
              type="button"
              variant="secondary"
              className="btn--danger"
              icon={<Icon.Trash />}
              onClick={() => setDialog('domain')}
            >
              {t('data.wipe.button')}
            </GateButton>
            <GateButton
              perm="data.wipe"
              type="button"
              variant="secondary"
              className="btn--danger"
              icon={<Icon.Power />}
              onClick={() => setDialog('factory')}
            >
              {t('data.factory.button')}
            </GateButton>
            <GateButton
              perm="data.wipe"
              type="button"
              variant="secondary"
              className="btn--danger"
              icon={<Icon.Power />}
              onClick={() => setDialog('full')}
            >
              {t('data.full.button')}
            </GateButton>
          </div>
          {lastOutcome ? (
            <InlineWarning tone="info" title={t('data.wipe.doneTitle')}>
              <ul className="plain-list">
                {lastOutcome.cleared.map((c) => (
                  <li key={c} className="mono">
                    {c}
                  </li>
                ))}
              </ul>
              {lastOutcome.export_archive ? (
                <p className="chainrow__meta">
                  {t('data.wipe.archive')}:{' '}
                  <code className="mono">{lastOutcome.export_archive}</code>
                </p>
              ) : null}
            </InlineWarning>
          ) : null}
        </div>
      </Card>
    </>
  );

  return (
    <div className="stack">
      {/* Only when self-contained (t28): under Operações the route strip drives the pane, so a
          second strip here would be a duplicate landmark. */}
      {tabProp === undefined ? (
        <SubNav
          items={[
            {
              id: 'armazenamento',
              label: t('data.status.tab.storage'),
              icon: <Icon.Layers />,
            },
            {
              id: 'copias',
              label: t('data.status.tab.backup'),
              icon: <Icon.Archive />,
            },
            {
              id: 'chaves',
              label: t('data.status.tab.keys'),
              icon: <Icon.Shuffle />,
            },
          ]}
          active={tab}
          onSelect={setInternalTab}
          ariaLabel={t('data.status.subnav.aria')}
        />
      ) : null}
      <p className="field__hint">{tabDescription}</p>

      <DataStatusPanel tab={tab} resetControls={resetControls} />

      {/* 1 · Repor interface modal (client-only — NO server call) --------------- */}
      <ConfirmActionModal
        open={dialog === 'frontend'}
        onClose={close}
        title={t('data.frontend.title')}
        intro={t('data.frontend.confirmBody')}
        confirmLabel={t('data.frontend.button')}
        pendingLabel={t('data.frontend.button')}
        onConfirm={async () => {
          // Client-only: clears local storage + the query cache and reloads. No fetch.
          resetFrontend(qc);
        }}
      />

      {/* 2 · Recomeçar instância modal ----------------------------------------- */}
      <ConfirmActionModal
        open={dialog === 'startover'}
        onClose={close}
        title={t('data.startOver.title')}
        intro={t('data.startOver.confirmBody')}
        confirmLabel={t('data.startOver.button')}
        pendingLabel={t('data.startOver.pending')}
        phrase={RESET_PHRASE.instance}
        requireReauth
        pending={startOverInstance.isPending}
        canConfirm={reason.trim().length > 0}
        onConfirm={async ({ reauth }) => {
          await startOverInstance.mutateAsync({
            reason: reason.trim(),
            confirm_phrase: RESET_PHRASE.instance,
            reauth,
          });
          toast.success(t('data.startOver.done'));
        }}
      >
        <Field label={t('data.startOver.reasonLabel')} htmlFor="inst-reason">
          <TextArea id="inst-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
      </ConfirmActionModal>

      {/* 3 · Limpar dados (backend_domain — ledger preserved) ------------------ */}
      <ConfirmActionModal
        open={dialog === 'domain'}
        onClose={close}
        title={t('data.wipe.title')}
        danger
        intro={t('data.wipe.body')}
        confirmLabel={t('data.wipe.button')}
        pendingLabel={t('data.wipe.pending')}
        phrase={RESET_PHRASE.backend_domain}
        requireReauth
        exportFirst="enforced"
        pending={resetData.isPending}
        onConfirm={async ({ reauth }) => {
          const outcome = await resetData.mutateAsync({
            scope: 'backend_domain',
            confirm_phrase: RESET_PHRASE.backend_domain,
            export_first: true,
            reauth,
          });
          setLastOutcome(outcome);
          toast.success(t('data.wipe.done'));
        }}
      />

      {/* 4 · Reposição de fábrica (backend_factory — guarded export-first skip) - */}
      <ConfirmActionModal
        open={dialog === 'factory'}
        onClose={close}
        title={t('data.factory.title')}
        danger
        intro={t('data.factory.body')}
        confirmLabel={t('data.factory.button')}
        pendingLabel={t('data.factory.pending')}
        phrase={RESET_PHRASE.backend_factory}
        requireReauth
        exportFirst="skippable"
        pending={resetData.isPending}
        onConfirm={async ({ reauth, exportFirst, skipExportConfirm }) => {
          await resetData.mutateAsync({
            scope: 'backend_factory',
            confirm_phrase: RESET_PHRASE.backend_factory,
            export_first: exportFirst,
            skip_export_confirm: skipExportConfirm,
            reauth,
          });
          // A factory reset blanks users/settings → this session is gone. Reboot into the
          // fresh first-run instance (server data is cleared; nothing local to preserve).
          resetFrontend(qc);
        }}
      />

      {/* 5 · Reposição total (factory + explicit client clear) ----------------- */}
      <ConfirmActionModal
        open={dialog === 'full'}
        onClose={close}
        title={t('data.full.title')}
        danger
        intro={t('data.full.body')}
        confirmLabel={t('data.full.button')}
        pendingLabel={t('data.full.pending')}
        phrase={RESET_PHRASE.backend_factory}
        requireReauth
        exportFirst="skippable"
        pending={resetData.isPending}
        onConfirm={async ({ reauth, exportFirst, skipExportConfirm }) => {
          await resetData.mutateAsync({
            scope: 'backend_factory',
            confirm_phrase: RESET_PHRASE.backend_factory,
            export_first: exportFirst,
            skip_export_confirm: skipExportConfirm,
            reauth,
          });
          // Full reset = server factory reset THEN a client-side clear + reboot.
          resetFrontend(qc);
        }}
      />
    </div>
  );
}
