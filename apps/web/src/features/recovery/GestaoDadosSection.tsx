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
  type DataKeyRotationExecuteBody,
  type DataKeyRotationExecution,
  type DataKeyRotationPreflight,
  type DataKeyRotationPreflightBody,
  type DataPayloadStats,
  type DataPermissionCheck,
  type DataPermissionStatus,
  type DataPersistenceMode,
  type DataUsageBasis,
  type DataUsageConcern,
  type ResetOutcomeView,
  type SyncHandoffPreflightReport,
} from '../../api/types';
import { useLocale, useT, type MessageKey, type TFunction } from '../../i18n';
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
  Loading,
  SubNav,
  TextArea,
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
};

const CLEANUP_TARGETS: CleanupConfig[] = [
  {
    target: 'crash',
    title: 'data.status.cleanup.crash.title',
    body: 'data.status.cleanup.crash.body',
    button: 'data.status.cleanup.crash.button',
    confirm: 'data.status.cleanup.crash.confirm',
  },
  {
    target: 'exports',
    title: 'data.status.cleanup.exports.title',
    body: 'data.status.cleanup.exports.body',
    button: 'data.status.cleanup.exports.button',
    confirm: 'data.status.cleanup.exports.confirm',
  },
];

const MODE_LABEL: Record<DataPersistenceMode, MessageKey> = {
  durable: 'data.status.mode.durable',
  in_memory: 'data.status.mode.in_memory',
  fallback_in_memory: 'data.status.mode.fallback_in_memory',
};

const BASIS_LABEL: Record<DataUsageBasis, MessageKey> = {
  filesystem: 'data.status.basis.filesystem',
  sqlite_file: 'data.status.basis.sqlite_file',
  sqlite_logical_payload: 'data.status.basis.sqlite_logical_payload',
};

const SQLITE_LOGICAL_TABLE_KIND = 'sqlite_logical_table';
const SQLITE_TABLE_ID_PREFIX = 'sqlite_table_';

const PERMISSION_ROWS: {
  key: keyof DataPermissionStatus;
  label: MessageKey;
}[] = [
  { key: 'read_dir', label: 'data.status.permission.read_dir' },
  { key: 'create_file', label: 'data.status.permission.create_file' },
  { key: 'write_file', label: 'data.status.permission.write_file' },
  { key: 'delete_probe_file', label: 'data.status.permission.delete_probe_file' },
  { key: 'sqlite_store_open', label: 'data.status.permission.sqlite_store_open' },
];

function formatTimestamp(value: string, locale: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString(locale);
}

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

function permissionTone(check: DataPermissionCheck): 'ok' | 'warn' | 'neutral' {
  if (!check.checked) return 'neutral';
  return check.ok ? 'ok' : 'warn';
}

function permissionLabel(check: DataPermissionCheck, t: TFunction): string {
  if (!check.checked) return t('data.status.permission.unchecked');
  return check.ok ? t('data.status.permission.ok') : t('data.status.permission.warn');
}

function permissionSummary(
  permissions: DataPermissionStatus,
  t: TFunction,
): { label: string; tone: 'ok' | 'warn' | 'neutral' } {
  const checks = PERMISSION_ROWS.map((row) => permissions[row.key]);
  if (checks.some((check) => check.checked && !check.ok)) {
    return { label: t('data.status.permission.warn'), tone: 'warn' };
  }
  if (checks.some((check) => !check.checked)) {
    return { label: t('data.status.permission.unchecked'), tone: 'neutral' };
  }
  return { label: t('data.status.permission.ok'), tone: 'ok' };
}

function concernMetaItems(concern: DataUsageConcern, t: TFunction, locale: string): string[] {
  const parts = [
    t(BASIS_LABEL[concern.basis]),
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
      <h5>Verificação isolada</h5>
      <dl className="deflist data-status-summary">
        <div>
          <dt>Estado</dt>
          <dd>
            <Badge tone={statusTone}>{verification.status}</Badge>
          </dd>
        </div>
        <div>
          <dt>Snapshot isolado verificado</dt>
          <dd>
            <Badge tone={verified ? 'ok' : 'warn'}>
              {verified ? t('common.yes') : t('common.no')}
            </Badge>
          </dd>
        </div>
        {booleanRows.map((row) => (
          <div key={row.label}>
            <dt>{row.label}</dt>
            <dd>
              <Badge tone={row.value ? 'ok' : 'warn'}>
                {row.value ? t('common.yes') : t('common.no')}
              </Badge>
            </dd>
          </div>
        ))}
        <div>
          <dt>SQLCipher verificado</dt>
          <dd>
            <StatusBadge value={verification.sqlcipher_encryption_verified} t={t} />
          </dd>
        </div>
        {countRows.map((row) => (
          <div key={row.label}>
            <dt>{row.label}</dt>
            <dd className="mono">
              {typeof row.value === 'number'
                ? new Intl.NumberFormat(locale).format(row.value)
                : row.value}
            </dd>
          </div>
        ))}
        <div className="deflist__wide">
          <dt>Próximo passo</dt>
          <dd>{redactReceiptEvidenceText(verification.next_step)}</dd>
        </div>
      </dl>

      <div>
        <h5>Constatações</h5>
        {findings.length === 0 ? (
          <p className="field__hint">Sem constatações registadas.</p>
        ) : (
          <ul className="plain-list">
            {findings.map((finding, index) => (
              <li key={`${finding}-${index}`}>{finding}</li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <h5>Erros</h5>
        {errors.length === 0 ? (
          <p className="field__hint">Sem erros registados.</p>
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
        <dl className="deflist data-status-summary">
          <div className="deflist__wide">
            <dt>Arquivo verificado</dt>
            <dd className="mono">{safeArchiveLabel(receipt.archive)}</dd>
          </div>
          <div>
            <dt>Registado em</dt>
            <dd>{formatTimestamp(receipt.created_at, locale)}</dd>
          </div>
          <div>
            <dt>Pré-validação OK</dt>
            <dd>
              <Badge tone={receipt.preflight_ok ? 'ok' : 'warn'}>
                {receipt.preflight_ok ? t('common.yes') : t('common.no')}
              </Badge>
            </dd>
          </div>
          <div>
            <dt>Pronto para restauro</dt>
            <dd>
              <Badge tone={receipt.preflight_ready ? 'ok' : 'warn'}>
                {receipt.preflight_ready ? t('common.yes') : t('common.no')}
              </Badge>
            </dd>
          </div>
          <div>
            <dt>Cifrado</dt>
            <dd>{yesNo(receipt.encrypted, t)}</dd>
          </div>
          <div>
            <dt>{t('data.status.ledgerVerified')}</dt>
            <dd>{receipt.ledger_verified ? t('common.yes') : t('common.no')}</dd>
          </div>
          {manifest ? (
            <>
              <div>
                <dt>{t('data.status.schemaVersion')}</dt>
                <dd className="mono">{manifest.schema}</dd>
              </div>
              <div>
                <dt>Esquema da base de dados</dt>
                <dd className="mono">{manifest.store_schema_version}</dd>
              </div>
              <div>
                <dt>{t('data.status.ledgerLength')}</dt>
                <dd className="mono">{manifest.ledger_length}</dd>
              </div>
              <div>
                <dt>Membros no arquivo</dt>
                <dd className="mono">{manifest.member_count}</dd>
              </div>
              <div>
                <dt>Membros sidecar</dt>
                <dd className="mono">{manifest.sidecar_member_count}</dd>
              </div>
              <div>
                <dt>Membro da base de dados presente</dt>
                <dd>{manifest.db_member_present ? t('common.yes') : t('common.no')}</dd>
              </div>
              <div>
                <dt>Total de bytes dos membros</dt>
                <dd className="mono">{formatBytes(manifest.total_member_bytes, locale)}</dd>
              </div>
            </>
          ) : null}
          {receipt.custody_location ? (
            <div className="deflist__wide">
              <dt>Local de custódia indicado</dt>
              <dd>{redactReceiptEvidenceText(receipt.custody_location)}</dd>
            </div>
          ) : null}
          {receipt.operator_notes ? (
            <div className="deflist__wide">
              <dt>Notas do operador</dt>
              <dd>{redactReceiptEvidenceText(receipt.operator_notes)}</dd>
            </div>
          ) : null}
        </dl>

        <IsolatedRestoreVerificationReport receipt={receipt} t={t} locale={locale} />

        <div>
          <h5>Limites do recibo</h5>
          <dl className="deflist data-status-summary">
            {limitRows.map((row) => (
              <div key={row.label}>
                <dt>{row.label}</dt>
                <dd>
                  <Badge tone={row.confirmed ? 'ok' : 'warn'}>
                    {row.confirmed ? 'Confirmado' : 'Não confirmado'}
                  </Badge>
                </dd>
              </div>
            ))}
          </dl>
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
  locale,
}: {
  freshness: BackupRecoveryFreshnessReview;
  locale: string;
}) {
  const warning = freshness.status !== 'fresh';
  return (
    <InlineWarning tone={warning ? 'warn' : 'info'} title="Política local de recuperação">
      <div className="stack--tight">
        <dl className="deflist data-status-summary">
          <div>
            <dt>Estado do ensaio</dt>
            <dd>
              <Badge tone={warning ? 'warn' : 'ok'}>
                {recoveryFreshnessLabel(freshness.status)}
              </Badge>
            </dd>
          </div>
          <div>
            <dt>Idade máxima configurada</dt>
            <dd>{freshness.policy.max_drill_age_days} dias</dd>
          </div>
          <div>
            <dt>RPO alvo declarado</dt>
            <dd>{freshness.policy.target_rpo_minutes} min</dd>
          </div>
          <div>
            <dt>RTO alvo declarado</dt>
            <dd>{freshness.policy.target_rto_minutes} min</dd>
          </div>
          <div>
            <dt>Último recibo</dt>
            <dd>
              {freshness.latest_receipt_at
                ? formatTimestamp(freshness.latest_receipt_at, locale)
                : 'Sem recibo local'}
            </dd>
          </div>
          <div>
            <dt>Idade do último recibo</dt>
            <dd>
              {freshness.latest_receipt_age_days === null
                ? '—'
                : `${freshness.latest_receipt_age_days} dias`}
            </dd>
          </div>
          <div>
            <dt>Pré-validação do último recibo</dt>
            <dd>{freshness.latest_receipt_preflight_ready === true ? 'Sim' : 'Não'}</dd>
          </div>
          <div>
            <dt>Snapshot isolado verificado</dt>
            <dd>{freshness.latest_receipt_isolated_restore_verified === true ? 'Sim' : 'Não'}</dd>
          </div>
        </dl>
        <p className="field__hint">
          Resumo local derivado de recibos de ensaio: sem restauro executado, sem troca da base de
          dados, sem prova de custódia off-site, sem certificação de RPO/RTO e sem certificação de
          política de backup de produção.
        </p>
      </div>
    </InlineWarning>
  );
}

function SyncHandoffPreflightReportCard({
  report,
  locale,
  t,
}: {
  report: SyncHandoffPreflightReport;
  locale: string;
  t: TFunction;
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
  const noClaimRows = [
    ['Sem sincronização ativa', report.no_claims.active_sync_implemented],
    ['Sem conector externo', report.no_claims.connector_protocol_implemented],
    ['Sem importação executada', report.no_claims.import_performed],
    ['Sem registos alterados', report.no_claims.records_mutated],
    [
      'Sem certificação DGLAB/arquivo',
      report.no_claims.dglab_certification_claimed ||
        report.no_claims.archive_certification_claimed,
    ],
    ['Sem prontidão de produção', report.no_claims.production_sync_readiness_claimed],
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
          <dl className="deflist data-status-summary">
            <div>
              <dt>Estado</dt>
              <dd>
                <Badge tone={readinessTone}>{report.readiness.status}</Badge>
              </dd>
            </div>
            <div>
              <dt>Gerado em</dt>
              <dd>{formatTimestamp(report.generated_at, locale)}</dd>
            </div>
            <div>
              <dt>Candidatos não validados</dt>
              <dd>
                {new Intl.NumberFormat(locale).format(
                  report.backup.backup_directory.untrusted_candidate_file_count,
                )}{' '}
                /{' '}
                <span className="mono">
                  {formatBytes(report.backup.backup_directory.total_candidate_bytes, locale)}
                </span>
              </dd>
            </div>
            <div>
              <dt>Candidato não validado mais recente</dt>
              <dd className="mono">
                {latestCandidate
                  ? `${latestCandidate.file_name} (${formatBytes(latestCandidate.bytes, locale)})`
                  : '—'}
              </dd>
            </div>
            <div>
              <dt>Evidência verificada</dt>
              <dd>
                <Badge tone={report.backup.verified_recovery_drill_evidence ? 'ok' : 'warn'}>
                  {report.backup.verified_recovery_drill_evidence ? 'verified' : 'missing'}
                </Badge>
              </dd>
            </div>
            <div>
              <dt>Ensaios de recuperação</dt>
              <dd>
                {new Intl.NumberFormat(locale).format(report.backup.recovery_drill_receipt_count)}
              </dd>
            </div>
            <div>
              <dt>Último ensaio</dt>
              <dd>
                {latestDrill ? (
                  <Badge tone={latestDrill.verified_manifest_and_isolated_snapshot ? 'ok' : 'warn'}>
                    {latestDrill.verified_manifest_and_isolated_snapshot ? 'verified' : 'missing'}
                  </Badge>
                ) : (
                  '—'
                )}
              </dd>
            </div>
            <div>
              <dt>Livros</dt>
              <dd>
                {new Intl.NumberFormat(locale).format(report.book_bundles.book_count)} total /{' '}
                {new Intl.NumberFormat(locale).format(report.book_bundles.closed_book_count)}{' '}
                fechados
              </dd>
            </div>
            <div>
              <dt>Atos preserváveis</dt>
              <dd>
                {new Intl.NumberFormat(locale).format(
                  report.archive_dglab.sealed_or_archived_act_count,
                )}
              </dd>
            </div>
            <div>
              <dt>Documentos preservados</dt>
              <dd>
                {new Intl.NumberFormat(locale).format(
                  report.archive_dglab.preserved_document_count,
                )}
              </dd>
            </div>
            <div>
              <dt>Pré-validação de importação</dt>
              <dd>
                <Badge tone={report.book_bundles.import_preflight_read_only ? 'ok' : 'warn'}>
                  {report.book_bundles.import_preflight_read_only ? 'read-only' : 'mutating'}
                </Badge>
              </dd>
            </div>
            <div className="deflist__wide">
              <dt>Sem alegações</dt>
              <dd>
                <ul className="plain-list">
                  {noClaimRows.map(([label, claimed]) => (
                    <li key={label}>
                      {label}:{' '}
                      <Badge tone={!claimed ? 'ok' : 'warn'}>
                        {!claimed ? t('common.yes') : t('common.no')}
                      </Badge>
                    </li>
                  ))}
                </ul>
              </dd>
            </div>
          </dl>
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
        <dl className="deflist data-status-summary">
          <div>
            <dt>{t('data.status.keyRotation.status')}</dt>
            <dd>
              <Badge tone={report.ready ? 'ok' : 'warn'}>{report.status}</Badge>
            </dd>
          </div>
          <div>
            <dt>{t('data.status.keyRotation.ready')}</dt>
            <dd>
              <Badge tone={report.ready ? 'ok' : 'warn'}>
                {report.ready
                  ? t('data.status.keyRotation.ready.yes')
                  : t('data.status.keyRotation.ready.no')}
              </Badge>
            </dd>
          </div>
          <div className="deflist__wide">
            <dt>{t('data.status.keyRotation.nextAction')}</dt>
            <dd>{report.next_action}</dd>
          </div>
        </dl>

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
          <dl className="deflist data-status-summary">
            <div>
              <dt>{t('data.status.keyRotation.evidence.databaseFormat')}</dt>
              <dd className="mono">{report.evidence.database_format}</dd>
            </div>
            <div>
              <dt>{t('data.status.keyRotation.evidence.currentKey')}</dt>
              <dd className="mono">{report.evidence.current_key_config}</dd>
            </div>
            <div>
              <dt>{t('data.status.keyRotation.evidence.replacementKey')}</dt>
              <dd className="mono">{report.evidence.requested_key_config}</dd>
            </div>
            <div>
              <dt>{t('data.status.keyRotation.evidence.sqlcipher')}</dt>
              <dd>{report.evidence.sqlcipher_available ? t('common.yes') : t('common.no')}</dd>
            </div>
            <div className="deflist__wide">
              <dt>{t('data.status.keyRotation.evidence.databaseFile')}</dt>
              <dd className="mono">{report.evidence.database_file}</dd>
            </div>
          </dl>
        </div>

        <div>
          <h5>{t('data.status.keyRotation.metadata')}</h5>
          <dl className="deflist data-status-summary">
            <div>
              <dt>{t('data.status.keyRotation.metadata.provider')}</dt>
              <dd>SQLCipher</dd>
            </div>
            <div>
              <dt>{t('data.status.keyRotation.metadata.readOnly')}</dt>
              <dd>
                <Badge tone="ok">{t('common.yes')}</Badge>
              </dd>
            </div>
            <div className="deflist__wide">
              <dt>{t('data.status.keyRotation.metadata.execution')}</dt>
              <dd>{t('data.status.keyRotation.metadata.execution.none')}</dd>
            </div>
          </dl>
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
      <dl className="deflist data-status-summary">
        <div className="deflist__wide">
          <dt>{t('data.status.backup.path')}</dt>
          <dd className="mono">{manifest.path}</dd>
        </div>
        <div>
          <dt>{t('data.status.backup.createdAt')}</dt>
          <dd>{formatTimestamp(manifest.created_at, locale)}</dd>
        </div>
        <div>
          <dt>{t('data.status.backup.size')}</dt>
          <dd className="mono">{formatBytes(manifest.bytes, locale)}</dd>
        </div>
        <div>
          <dt>{t('data.status.backup.files')}</dt>
          <dd className="mono">{backupFileSummary(manifest, locale)}</dd>
        </div>
        <div>
          <dt>{t('data.status.schemaVersion')}</dt>
          <dd>{formatOptionalNumber(manifest.store_schema_version, locale)}</dd>
        </div>
        <div>
          <dt>{t('data.status.ledgerLength')}</dt>
          <dd>{formatOptionalNumber(manifest.ledger_length, locale)}</dd>
        </div>
        <div>
          <dt>{t('data.status.ledgerVerified')}</dt>
          <dd>
            <Badge tone={manifest.ledger_verified ? 'ok' : 'warn'}>
              {manifest.ledger_verified ? t('common.yes') : t('common.no')}
            </Badge>
          </dd>
        </div>
      </dl>
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
      title="Resultado da execução SQLCipher"
    >
      <div className="stack--tight">
        <dl className="deflist data-status-summary">
          <div>
            <dt>{t('data.status.keyRotation.status')}</dt>
            <dd>
              <Badge tone={execution.rekey_executed ? 'ok' : 'warn'}>{execution.status}</Badge>
            </dd>
          </div>
          <div>
            <dt>Rekey executado</dt>
            <dd>
              <Badge tone={execution.rekey_executed ? 'ok' : 'warn'}>
                {execution.rekey_executed ? t('common.yes') : t('common.no')}
              </Badge>
            </dd>
          </div>
          <div>
            <dt>{t('data.status.ledgerVerified')}</dt>
            <dd>
              <Badge tone={execution.ledger_integrity_verified ? 'ok' : 'warn'}>
                {execution.ledger_integrity_verified ? t('common.yes') : t('common.no')}
              </Badge>
            </dd>
          </div>
          <div>
            <dt>{t('data.status.ledgerLength')}</dt>
            <dd>{new Intl.NumberFormat(locale).format(execution.ledger_length)}</dd>
          </div>
        </dl>

        <div>
          <h5>{t('data.status.keyRotation.evidence')}</h5>
          <dl className="deflist data-status-summary">
            <div>
              <dt>Operação</dt>
              <dd className="mono">{execution.evidence.operation}</dd>
            </div>
            <div>
              <dt>{t('data.status.keyRotation.evidence.replacementKey')}</dt>
              <dd className="mono">{execution.evidence.requested_key_config}</dd>
            </div>
            <div>
              <dt>{t('data.status.keyRotation.evidence.sqlcipher')}</dt>
              <dd>{execution.evidence.sqlcipher_available ? t('common.yes') : t('common.no')}</dd>
            </div>
            <div>
              <dt>Checkpoint antes</dt>
              <dd>
                {execution.evidence.checkpointed_before_rekey ? t('common.yes') : t('common.no')}
              </dd>
            </div>
            <div>
              <dt>Checkpoint depois</dt>
              <dd>
                {execution.evidence.checkpointed_after_rekey ? t('common.yes') : t('common.no')}
              </dd>
            </div>
            <div>
              <dt>Integridade pós-rekey</dt>
              <dd>
                {execution.evidence.post_rekey_integrity_checked ? t('common.yes') : t('common.no')}
              </dd>
            </div>
          </dl>
        </div>
      </div>
    </InlineWarning>
  );
}

function UsageList({
  concerns,
  locale,
  t,
}: {
  concerns: DataUsageConcern[];
  locale: string;
  t: TFunction;
}) {
  if (concerns.length === 0) {
    return <p className="muted">{t('data.status.usage.empty')}</p>;
  }
  return (
    <ul className="data-status-usage-list">
      {concerns.map((concern) => {
        const meta = concernMetaItems(concern, t, locale);
        return (
          <li key={`${concern.id}:${concern.basis}`} className="data-status-usage-row">
            <div className="data-status-usage-row__head">
              <span className="data-status-usage-row__label">{concern.label}</span>
              <span className="mono">{formatBytes(concern.bytes, locale)}</span>
            </div>
            <div className="data-status-usage-row__meta" aria-label={meta.join(' · ')}>
              {meta.map((item) => (
                <span key={item}>{item}</span>
              ))}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function SqliteTablePayloadList({
  concerns,
  locale,
  t,
}: {
  concerns: DataUsageConcern[];
  locale: string;
  t: TFunction;
}) {
  return (
    <ul className="data-status-sqlite-table-list" aria-label={t('data.status.usage.sqliteLogical')}>
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
          <li
            key={`${concern.id}:${concern.basis}`}
            className="data-status-sqlite-table-row"
            aria-label={meta.join(' · ')}
          >
            <span className="data-status-sqlite-table-row__label" title={concern.label}>
              {label}
            </span>
            <span className="data-status-sqlite-table-row__rows">{rowCount}</span>
            <span className="data-status-sqlite-table-row__bytes mono">
              {formatBytes(stats.estimated_payload_bytes, locale)}
            </span>
            <span className="data-status-sqlite-table-row__average">{average}</span>
            <span className="data-status-sqlite-table-row__method">
              {t('data.status.usage.sqliteEstimateMethod.localLoadedPayload')}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

function SqliteLogicalUsageList({
  concerns,
  largestPayloadTable,
  locale,
  t,
}: {
  concerns: DataUsageConcern[];
  largestPayloadTable?: DataPayloadStats;
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
        <UsageList concerns={summaryConcerns} locale={locale} t={t} />
      ) : null}
      {tableConcerns.length > 0 ? (
        <SqliteTablePayloadList concerns={tableConcerns} locale={locale} t={t} />
      ) : null}
    </div>
  );
}

function DataStatusPanel({
  tab,
  resetControls,
}: {
  tab: GestaoTab;
  resetControls: ReactNode;
}) {
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
            {status.isLoading ? <Loading label={t('data.status.loading')} /> : null}
            {status.isError ? <ErrorNote error={status.error} /> : null}
            {data ? (
              <div className="data-status">
          <dl className="deflist data-status-summary">
            <div>
              <dt>{t('data.status.mode')}</dt>
              <dd>
                <Badge tone={data.persistence.durable_store_open ? 'ok' : 'warn'}>
                  {t(MODE_LABEL[data.persistence.mode])}
                </Badge>
              </dd>
            </div>
            <div>
              <dt>{t('data.status.generatedAt')}</dt>
              <dd>{formatTimestamp(data.generated_at, locale)}</dd>
            </div>
            <div>
              <dt>{t('data.status.usage.title')}</dt>
              <dd className="mono">{formatBytes(data.usage.total_bytes, locale)}</dd>
            </div>
            <div>
              <dt>{t('data.status.permissions.title')}</dt>
              <dd>
                {permissions ? <Badge tone={permissions.tone}>{permissions.label}</Badge> : '—'}
              </dd>
            </div>
            <div>
              <dt>{t('data.status.durable')}</dt>
              <dd>
                <Badge tone={data.persistence.durable_store_open ? 'ok' : 'warn'}>
                  {data.persistence.durable_store_open
                    ? t('data.status.durable.open')
                    : t('data.status.durable.closed')}
                </Badge>
              </dd>
            </div>
            <div>
              <dt>{t('data.status.encryption')}</dt>
              <dd>
                <StatusBadge value={data.persistence.database_encryption_configured} t={t} />
              </dd>
            </div>
            <div>
              <dt>{t('data.status.schemaVersion')}</dt>
              <dd>{formatOptionalNumber(data.persistence.store_schema_version, locale)}</dd>
            </div>
            <div>
              <dt>{t('data.status.ledgerLength')}</dt>
              <dd>{formatOptionalNumber(data.persistence.ledger_length, locale)}</dd>
            </div>
            <div>
              <dt>{t('data.status.ledgerVerified')}</dt>
              <dd>
                <StatusBadge value={data.persistence.ledger_verified} t={t} />
              </dd>
            </div>
            <div>
              <dt>{t('data.status.degraded')}</dt>
              <dd>
                <StatusBadge value={data.persistence.degraded} positive={false} t={t} />
              </dd>
            </div>
          </dl>

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
            <p className="data-status-path mono">
              {dataPath ?? t('data.status.path.unconfigured')}
            </p>
            <p className="field__hint">
              {t('data.status.folderState', {
                configured: yesNo(data.persistence.data_dir_configured, t),
                exists: yesNo(data.data_dir.exists, t),
                directory: yesNo(data.data_dir.is_directory, t),
              })}
            </p>
            <p className="field__hint">{t('data.status.openUnavailable')}</p>
          </section>

          <section className="data-status-section" aria-labelledby="data-status-permissions">
            <div className="data-status-section__head">
              <h4 id="data-status-permissions">{t('data.status.permissions.title')}</h4>
            </div>
            <ul className="data-status-permissions">
              {PERMISSION_ROWS.map((row) => {
                const check = data.permissions[row.key];
                return (
                  <li
                    key={row.key}
                    className={`data-status-probe data-status-probe--${permissionTone(check)}`}
                  >
                    <span className="data-status-probe__label">{t(row.label)}</span>
                    <Badge tone={permissionTone(check)}>{permissionLabel(check, t)}</Badge>
                    {check.message ? (
                      <span className="data-status-probe__message">{check.message}</span>
                    ) : null}
                  </li>
                );
              })}
            </ul>
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
                <UsageList concerns={data.usage.filesystem} locale={locale} t={t} />
              </div>
              <div className="data-status-usage-group">
                <h5>{t('data.status.usage.sqliteLogical')}</h5>
                <SqliteLogicalUsageList
                  concerns={data.usage.sqlite_logical}
                  largestPayloadTable={data.usage.sqlite_largest_payload_table}
                  locale={locale}
                  t={t}
                />
              </div>
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
            <ul className="data-status-cleanups">
              {CLEANUP_TARGETS.map((target) => {
                const usage = usageForTarget(data.usage.filesystem, target.target);
                const isExportsPreview = target.target === 'exports';
                const isTargetPending =
                  cleanup.isPending &&
                  (isExportsPreview ? previewingExports : cleanupTarget === target.target);
                return (
                  <li key={target.target} className="data-status-cleanup">
                    <div className="data-status-cleanup__main">
                      <h5>
                        {t(target.title)}{' '}
                        <FieldHelp
                          text={t(
                            isExportsPreview
                              ? 'data.status.help.exportCleanup'
                              : 'data.status.help.crashCleanup',
                          )}
                        />
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
                    <p className="data-status-cleanup__metric">
                      <span className="mono">{formatBytes(usage?.bytes ?? 0, locale)}</span>
                      <span>
                        {t('data.status.cleanup.items', {
                          files: new Intl.NumberFormat(locale).format(usage?.file_count ?? 0),
                          directories: new Intl.NumberFormat(locale).format(
                            usage?.directory_count ?? 0,
                          ),
                        })}
                      </span>
                    </p>
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
                          disabled={!canClean || cleanup.isPending || !hasExportCleanupPreview}
                          onClick={() => setCleanupTarget('exports')}
                        >
                          {cleanup.isPending && cleanupTarget === 'exports'
                            ? EXPORT_CLEANUP_EXECUTION_PENDING
                            : EXPORT_CLEANUP_EXECUTION_BUTTON}
                        </GateButton>
                      ) : null}
                    </div>
                  </li>
                );
              })}
            </ul>
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
            {status.isLoading ? <Loading label={t('data.status.loading')} /> : null}
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

          <section className="data-status-section" aria-labelledby="data-status-recovery-drill">
            <div className="data-status-section__head">
              <div>
                <h4 id="data-status-recovery-drill">Ensaio de recuperação sem restauro</h4>
                <p className="data-status-section__hint">
                  Executa a pré-validação existente do backup e grava um recibo de custódia. Não
                  restaura, não troca a base de dados e não prepara sidecars.{' '}
                  <FieldHelp text={t('data.status.help.recoveryDrill')} />
                </p>
              </div>
            </div>
            {recoveryDrills.isLoading ? (
              <Loading label="A carregar política de recuperação" />
            ) : null}
            {recoveryDrills.error ? <ErrorNote error={recoveryDrills.error} /> : null}
            {recoveryDrills.data ? (
              <RecoveryFreshnessReviewReport
                freshness={recoveryDrills.data.freshness}
                locale={locale}
              />
            ) : null}
            <form className="form" onSubmit={(event) => void submitRecoveryDrill(event)}>
              <div className="data-status-usage-groups">
                <Field
                  label="Arquivo do backup para ensaio"
                  htmlFor="backup-recovery-drill-archive"
                  hint="Nome simples em backups/ ou caminho absoluto do arquivo a verificar."
                >
                  <Input
                    id="backup-recovery-drill-archive"
                    name="backup-recovery-drill-archive"
                    value={drillArchive}
                    placeholder="chancela-backup-….zip"
                    onChange={(event) => setDrillArchive(event.target.value)}
                  />
                </Field>
                <Field
                  label="Chave do backup (opcional)"
                  htmlFor="backup-recovery-drill-passphrase"
                  hint="Usada só nesta pré-validação; não é guardada no recibo."
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
                label="Local de custódia"
                htmlFor="backup-recovery-drill-custody"
                hint="Local indicado pelo operador; isto não comprova custódia off-site."
              >
                <Input
                  id="backup-recovery-drill-custody"
                  name="backup-recovery-drill-custody"
                  value={drillCustodyLocation}
                  onChange={(event) => setDrillCustodyLocation(event.target.value)}
                />
              </Field>
              <Field label="Notas do operador" htmlFor="backup-recovery-drill-notes">
                <TextArea
                  id="backup-recovery-drill-notes"
                  name="backup-recovery-drill-notes"
                  value={drillNotes}
                  onChange={(event) => setDrillNotes(event.target.value)}
                />
              </Field>
              {!data.persistence.durable_store_open ? (
                <p className="field__hint">Requer armazenamento durável em disco.</p>
              ) : null}
              <p className="field__hint">
                Ensaio explícito e iniciado pelo operador: sem restauro ao vivo, sem certificação
                legal de arquivo, sem prova automática de RPO/RTO ou custódia off-site.
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
                  {recoveryDrill.isPending ? 'A registar ensaio…' : 'Registar ensaio sem restauro'}
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
                <h4 id="data-status-sync-handoff">Pré-validação local de handoff</h4>
                <p className="data-status-section__hint">
                  Compõe apenas evidência local: candidatos de backup, ensaios verificados, pacotes
                  de livros, arquivo e estado do ledger.
                </p>
              </div>
            </div>
            {syncHandoffPreflight.isLoading ? (
              <Loading label="A carregar pré-validação local de handoff" />
            ) : null}
            {syncHandoffPreflight.error ? <ErrorNote error={syncHandoffPreflight.error} /> : null}
            {syncHandoffPreflight.data ? (
              <SyncHandoffPreflightReportCard
                report={syncHandoffPreflight.data}
                locale={locale}
                t={t}
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
              {status.isLoading ? <Loading label={t('data.status.loading')} /> : null}
              {status.isError ? <ErrorNote error={status.error} /> : null}
              {data ? (
                <div className="data-status">
          <section className="data-status-section" aria-labelledby="data-status-key-rotation">
            <div className="data-status-section__head">
              <div>
                <h4 id="data-status-key-rotation">{t('data.status.keyRotation.title')}</h4>
                <p className="data-status-section__hint">
                  {t('data.status.keyRotation.body')}{' '}
                  <FieldHelp text={t('data.status.help.keyRotation')} />
                </p>
              </div>
            </div>
            <form className="form" onSubmit={(event) => void submitKeyRotationPreflight(event)}>
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
              {keyRotationPreflight.error ? <ErrorNote error={keyRotationPreflight.error} /> : null}
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
            {lastPreflight ? <DataKeyRotationPreflightReport report={lastPreflight} t={t} /> : null}
            {lastPreflight?.ready ? (
              <form
                className="form"
                aria-label="Execução da rotação SQLCipher"
                onSubmit={(event) => void submitKeyRotationExecution(event)}
              >
                <Field
                  label="Nova chave SQLCipher"
                  htmlFor="data-key-rotation-execution"
                  hint="Enviada apenas para executar PRAGMA rekey; a resposta devolve só evidência sem segredo."
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
                  Executa apenas o rekey SQLCipher na base de dados durável já aberta; não converte
                  lojas SQLite em plaintext.
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
              <DataKeyRotationExecutionReport execution={lastExecution} t={t} locale={locale} />
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

export function GestaoDadosSection() {
  const t = useT();
  const toast = useToast();
  const qc = useQueryClient();
  const resetData = useResetData();
  const startOverInstance = useStartOverInstance();

  const [dialog, setDialog] = useState<Dialog>('none');
  const [reason, setReason] = useState('');
  const [lastOutcome, setLastOutcome] = useState<ResetOutcomeView | null>(null);
  const [tab, setTab] = useState<GestaoTab>('armazenamento');
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
            {t('data.destructive.warnBody')}{' '}
            <FieldHelp text={t('data.status.help.reset')} />
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
        onSelect={setTab}
        ariaLabel={t('data.status.subnav.aria')}
      />
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
