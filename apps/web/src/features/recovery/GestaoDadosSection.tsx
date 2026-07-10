/**
 * "Gestão de Dados" — the Configurações sub-tab for the destructive data-management
 * taxonomy (t54-E4, deliverable #2, §2.11).
 *
 * FIVE clearly-distinguished operations so the destructive ones are never mistaken for the
 * continue-operating ones:
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
 * Every server op routes the shared {@link ConfirmActionModal} (type-phrase + step-up
 * re-auth + export-first); the server enforces the same gates. Nothing is silently destructive.
 */
import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
  useCleanDataStorage,
  useDataStatus,
  useResetData,
  useStartOverInstance,
} from '../../api/hooks';
import {
  RESET_PHRASE,
  type DataCleanupResult,
  type DataCleanupTarget,
  type DataPermissionCheck,
  type DataPermissionStatus,
  type DataPersistenceMode,
  type DataUsageBasis,
  type DataUsageConcern,
  type ResetOutcomeView,
} from '../../api/types';
import { useLocale, useT, type MessageKey, type TFunction } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  ConfirmActionModal,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Loading,
  TextArea,
  useToast,
} from '../../ui';
import { GateButton } from '../session/permissions';
import { resetFrontend } from './frontendReset';

type Dialog = 'none' | 'frontend' | 'startover' | 'domain' | 'factory' | 'full';

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

function permissionTone(check: DataPermissionCheck): 'ok' | 'warn' | 'neutral' {
  if (!check.checked) return 'neutral';
  return check.ok ? 'ok' : 'warn';
}

function permissionLabel(check: DataPermissionCheck, t: TFunction): string {
  if (!check.checked) return t('data.status.permission.unchecked');
  return check.ok ? t('data.status.permission.ok') : t('data.status.permission.warn');
}

function concernMeta(concern: DataUsageConcern, t: TFunction, locale: string): string {
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
  return parts.join(' · ');
}

function usageForTarget(
  concerns: DataUsageConcern[] | undefined,
  target: DataCleanupTarget,
): DataUsageConcern | undefined {
  return concerns?.find((concern) => concern.id === target);
}

function cleanupSummary(result: DataCleanupResult, t: TFunction, locale: string): string {
  return t('data.status.cleanup.result', {
    files: new Intl.NumberFormat(locale).format(result.deleted_files),
    directories: new Intl.NumberFormat(locale).format(result.deleted_directories),
    bytes: formatBytes(result.deleted_bytes, locale),
  });
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
      {concerns.map((concern) => (
        <li key={`${concern.id}:${concern.basis}`} className="data-status-usage-row">
          <div className="data-status-usage-row__head">
            <span className="data-status-usage-row__label">{concern.label}</span>
            <span className="mono">{formatBytes(concern.bytes, locale)}</span>
          </div>
          <p className="data-status-usage-row__meta">{concernMeta(concern, t, locale)}</p>
        </li>
      ))}
    </ul>
  );
}

function DataStatusPanel() {
  const t = useT();
  const locale = useLocale();
  const toast = useToast();
  const status = useDataStatus();
  const cleanup = useCleanDataStorage();
  const data = status.data;
  const dataPath = data?.data_dir.path ?? null;
  const [cleanupTarget, setCleanupTarget] = useState<DataCleanupTarget | null>(null);
  const [lastCleanup, setLastCleanup] = useState<DataCleanupResult | null>(null);
  const activeCleanup = CLEANUP_TARGETS.find((target) => target.target === cleanupTarget) ?? null;
  const canClean = Boolean(
    dataPath &&
    data?.data_dir.exists &&
    data?.data_dir.is_directory &&
    data?.permissions.delete_probe_file.ok,
  );

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

  return (
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

          <section className="data-status-section" aria-labelledby="data-status-maintenance">
            <div className="data-status-section__head">
              <div>
                <h4 id="data-status-maintenance">{t('data.status.cleanup.title')}</h4>
                <p className="data-status-section__hint">{t('data.status.cleanup.body')}</p>
              </div>
            </div>
            <div className="data-status-cleanups">
              {CLEANUP_TARGETS.map((target) => {
                const usage = usageForTarget(data.usage.filesystem, target.target);
                return (
                  <article key={target.target} className="data-status-cleanup">
                    <div className="data-status-cleanup__body">
                      <h5>{t(target.title)}</h5>
                      <p>{t(target.body)}</p>
                      <p className="data-status-cleanup__metric">
                        <span className="mono">{formatBytes(usage?.bytes ?? 0, locale)}</span>{' '}
                        <span>
                          {t('data.status.cleanup.items', {
                            files: new Intl.NumberFormat(locale).format(usage?.file_count ?? 0),
                            directories: new Intl.NumberFormat(locale).format(
                              usage?.directory_count ?? 0,
                            ),
                          })}
                        </span>
                      </p>
                    </div>
                    <GateButton
                      perm="settings.manage"
                      type="button"
                      variant="secondary"
                      className="btn--danger"
                      icon={<Icon.Trash />}
                      disabled={!canClean || cleanup.isPending}
                      onClick={() => setCleanupTarget(target.target)}
                    >
                      {cleanup.isPending && cleanupTarget === target.target
                        ? t('data.status.cleanup.pending')
                        : t(target.button)}
                    </GateButton>
                  </article>
                );
              })}
            </div>
            {lastCleanup ? (
              <InlineWarning tone="info" title={t('data.status.cleanup.doneTitle')}>
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

          <section className="data-status-section" aria-labelledby="data-status-permissions">
            <h4 id="data-status-permissions">{t('data.status.permissions.title')}</h4>
            <ul className="data-status-permissions">
              {PERMISSION_ROWS.map((row) => {
                const check = data.permissions[row.key];
                return (
                  <li
                    key={row.key}
                    className={`data-status-probe data-status-probe--${permissionTone(check)}`}
                  >
                    <div className="data-status-probe__head">
                      <span>{t(row.label)}</span>
                      <Badge tone={permissionTone(check)}>{permissionLabel(check, t)}</Badge>
                    </div>
                    {check.message ? <p>{check.message}</p> : null}
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

            <div className="data-status-usage-groups">
              <div>
                <h5>{t('data.status.usage.filesystem')}</h5>
                <UsageList concerns={data.usage.filesystem} locale={locale} t={t} />
              </div>
              <div>
                <h5>{t('data.status.usage.sqliteLogical')}</h5>
                <UsageList concerns={data.usage.sqlite_logical} locale={locale} t={t} />
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
        </div>
      ) : null}

      <ConfirmActionModal
        open={activeCleanup !== null}
        onClose={() => setCleanupTarget(null)}
        title={activeCleanup ? t(activeCleanup.title) : ''}
        danger
        intro={activeCleanup ? t(activeCleanup.confirm) : ''}
        confirmLabel={activeCleanup ? t(activeCleanup.button) : ''}
        pendingLabel={t('data.status.cleanup.pending')}
        pending={cleanup.isPending}
        onConfirm={async () => {
          if (!activeCleanup) return;
          const result = await cleanup.mutateAsync({ target: activeCleanup.target });
          setLastCleanup(result);
          toast.success(t('data.status.cleanup.done'));
        }}
      />
    </Card>
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
  const close = () => setDialog('none');

  return (
    <div className="stack">
      <DataStatusPanel />

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
          <p className="field__hint">{t('data.startOver.body')}</p>
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
            {t('data.destructive.warnBody')}
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
