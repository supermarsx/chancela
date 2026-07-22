/**
 * "Livros & Integridade" — the Configurações sub-tab for chain integrity + per-book
 * portability + recovery (t54-E4, deliverable #1).
 *
 * It surfaces the multi-chain integrity report (per-chain status + the EXACT break
 * location + the permanent re-anchor disclosure, from `GET /v1/ledger/integrity`), the
 * per-book lifecycle (export the self-verifying bundle · import/restore a bundle with an
 * honest Verified|Quarantined verdict · per-book start-over), and — when a chain is broken
 * — the two recovery paths: whole-store restore (primary, never rewrites history) and the
 * last-resort re-anchor (step-up re-auth + required reason + honest "this rebuilds hashes
 * and is permanently disclosed" copy). Every destructive/sensitive action routes the shared
 * {@link ConfirmActionModal}; the server enforces the same gates.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import {
  useBooks,
  useEntities,
  useExportBook,
  useImportBook,
  useLedgerIntegrity,
  usePreflightImportBook,
  useReanchorLedger,
  useRestoreLedger,
  useRestoreLedgerPreflight,
} from '../../api/hooks';
import type {
  BookImportPreflightView,
  BookView,
  ChainStatusView,
  CollisionPolicy,
  Entity,
  ImportOutcomeView,
  RestorePreflightView,
} from '../../api/types';
import { useT } from '../../i18n';
import { bookStateLabels } from '../../api/labels';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import {
  Badge,
  Button,
  Card,
  ConfirmActionModal,
  Digest,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  Select,
  SkeletonText,
  TextArea,
  useToast,
} from '../../ui';
import { GateButton, scopeBook } from '../session/permissions';
import { StartOverBookModal } from './StartOverBookModal';

const MAX_PREFLIGHT_FINDINGS = 5;
const MAX_IMPORT_PREFLIGHT_ITEMS = 5;

type RestorePreflightReportView = Omit<RestorePreflightView, 'manifest'> & {
  manifest?: RestorePreflightView['manifest'] | null;
};

interface ImportPreflightSnapshot {
  file: File;
  policy: CollisionPolicy;
  report: BookImportPreflightView;
}

function redactSensitiveText(value: string): string {
  return value.replace(/[a-f0-9]{32,}/gi, '[redigido]');
}

function RestorePreflightReport({
  report,
  error,
}: {
  report: RestorePreflightReportView | null;
  error: unknown;
}) {
  const t = useT();

  if (error) {
    const message = error instanceof Error ? error.message : String(error);
    return (
      <InlineWarning tone="error" title={t('integrity.restore.preflight.errorTitle')}>
        <p>{redactSensitiveText(message)}</p>
      </InlineWarning>
    );
  }

  if (!report) return null;

  const allFindings = report.findings ?? [];
  const allErrors = report.errors ?? [];
  const findings = allFindings.slice(0, MAX_PREFLIGHT_FINDINGS);
  const errors = allErrors.slice(0, MAX_PREFLIGHT_FINDINGS);
  const hiddenFindings = Math.max(0, allFindings.length - findings.length);
  const hiddenErrors = Math.max(0, allErrors.length - errors.length);
  const manifest = report.manifest;
  const missingManifest = !manifest;
  const ready = report.ready && !missingManifest;
  const tone = ready ? 'info' : allErrors.length > 0 || missingManifest ? 'error' : 'warn';
  const status = ready ? 'ready' : report.ok && !missingManifest ? 'blocked' : 'error';
  const verdictWhy = ready
    ? t('integrity.restore.preflight.verdictReady')
    : tone === 'error'
      ? t('integrity.restore.preflight.verdictError')
      : t('integrity.restore.preflight.verdictBlocked');

  return (
    <InlineWarning
      tone={tone}
      title={
        ready
          ? t('integrity.restore.preflight.readyTitle')
          : t('integrity.restore.preflight.blockedTitle')
      }
    >
      <div className="preflight-verdict">
        <p className="preflight-verdict__why">
          <Badge tone={ready ? 'ok' : 'warn'}>{ready ? '✓' : '✗'}</Badge> {verdictWhy}
        </p>
        <p className="preflight-verdict__next">
          <strong>{t('integrity.restore.preflight.nextStep')}:</strong>{' '}
          {redactSensitiveText(report.next_step)}
        </p>
        <p className="field__hint">{t('integrity.restore.preflight.nonMutating')}</p>
      </div>
      <details className="preflight-evidence">
        <summary>{t('integrity.restore.preflight.evidenceToggle')}</summary>
        <dl className="deflist deflist--tight">
          <div>
            <dt>{t('integrity.restore.preflight.status')}</dt>
            <dd>
              <Badge tone={ready ? 'ok' : 'warn'}>{status}</Badge>
            </dd>
          </div>
          <div>
            <dt>{t('integrity.restore.preflight.encrypted')}</dt>
            <dd>{report.encrypted ? t('common.yes') : t('common.no')}</dd>
          </div>
          <div>
            <dt>{t('integrity.restore.preflight.ledgerVerified')}</dt>
            <dd>
              {report.ledger_verified && manifest?.ledger_verified
                ? t('common.yes')
                : t('common.no')}
            </dd>
          </div>
          {manifest ? (
            <>
              <div>
                <dt>{t('integrity.restore.preflight.ledgerLength')}</dt>
                <dd className="mono">{manifest.ledger_length}</dd>
              </div>
              <div>
                <dt>{t('integrity.restore.preflight.memberCount')}</dt>
                <dd className="mono">{manifest.member_count}</dd>
              </div>
              <div>
                <dt>{t('integrity.restore.preflight.sidecarMemberCount')}</dt>
                <dd className="mono">{manifest.sidecar_member_count}</dd>
              </div>
              <div>
                <dt>{t('integrity.restore.preflight.dbMemberPresent')}</dt>
                <dd>{manifest.db_member_present ? t('common.yes') : t('common.no')}</dd>
              </div>
              <div>
                <dt>{t('integrity.restore.preflight.schemaVersion')}</dt>
                <dd className="mono">{manifest.schema ?? 'n/a'}</dd>
              </div>
              <div>
                <dt>{t('integrity.restore.preflight.storeSchemaVersion')}</dt>
                <dd className="mono">{manifest.store_schema_version ?? 'n/a'}</dd>
              </div>
              <div>
                <dt>{t('integrity.restore.preflight.totalMemberBytes')}</dt>
                <dd className="mono">{manifest.total_member_bytes}</dd>
              </div>
            </>
          ) : null}
        </dl>
        <div className="stack--tight">
          {errors.length > 0 ? (
            <>
              <h5>{t('integrity.restore.preflight.errors')}</h5>
              <ul className="plain-list">
                {errors.map((item, index) => (
                  <li key={`error-${index}`}>{redactSensitiveText(item)}</li>
                ))}
              </ul>
              {hiddenErrors > 0 ? (
                <p className="field__hint">
                  {t('integrity.restore.preflight.errors.more', { count: hiddenErrors })}
                </p>
              ) : null}
            </>
          ) : null}
          <h5>{t('integrity.restore.preflight.findings')}</h5>
          {findings.length === 0 ? (
            <p className="field__hint">{t('integrity.restore.preflight.findings.none')}</p>
          ) : (
            <ul className="plain-list">
              {findings.map((finding, index) => (
                <li key={`finding-${index}`}>{redactSensitiveText(finding)}</li>
              ))}
            </ul>
          )}
          {hiddenFindings > 0 ? (
            <p className="field__hint">
              {t('integrity.restore.preflight.findings.more', { count: hiddenFindings })}
            </p>
          ) : null}
        </div>
      </details>
    </InlineWarning>
  );
}

function formatNullable(value: string | number | null | undefined): string {
  return value === null || value === undefined ? 'n/a' : String(value);
}

function BookImportPreflightReport({
  report,
  error,
}: {
  report: BookImportPreflightView | null;
  error: unknown;
}) {
  const t = useT();

  if (error) {
    const message = error instanceof Error ? error.message : String(error);
    return (
      <InlineWarning tone="error" title={t('integrity.import.preflight.errorTitle')}>
        <p>{redactSensitiveText(message)}</p>
      </InlineWarning>
    );
  }

  if (!report) return null;

  const errors = report.errors.slice(0, MAX_IMPORT_PREFLIGHT_ITEMS);
  const findings = report.findings.slice(0, MAX_IMPORT_PREFLIGHT_ITEMS);
  const hiddenErrors = Math.max(0, report.errors.length - errors.length);
  const hiddenFindings = Math.max(0, report.findings.length - findings.length);
  const tone = report.ready ? 'info' : report.errors.length > 0 ? 'error' : 'warn';

  return (
    <InlineWarning
      tone={tone}
      title={
        report.ready
          ? t('integrity.import.preflight.readyTitle')
          : t('integrity.import.preflight.blockedTitle')
      }
    >
      <dl className="deflist deflist--tight">
        <div>
          <dt>{t('integrity.restore.preflight.status')}</dt>
          <dd>
            <Badge tone={report.ready ? 'ok' : 'warn'}>{report.ready ? 'ready' : 'blocked'}</Badge>
          </dd>
        </div>
        <div>
          <dt>{t('integrity.import.preflight.wouldImport')}</dt>
          <dd>{report.would_import ? t('common.yes') : t('common.no')}</dd>
        </div>
        <div>
          <dt>{t('integrity.import.preflight.wouldRecordLedgerEvent')}</dt>
          <dd>{report.would_record_ledger_event ? t('common.yes') : t('common.no')}</dd>
        </div>
        <div>
          <dt>{t('integrity.import.preflight.wouldStoreImportRecord')}</dt>
          <dd>{report.would_store_import_record ? t('common.yes') : t('common.no')}</dd>
        </div>
        <div>
          <dt>{t('integrity.import.policyLabel')}</dt>
          <dd className="mono">{report.policy}</dd>
        </div>
        <div>
          <dt>{t('integrity.import.preflight.verdict')}</dt>
          <dd className="mono">{report.verdict?.status ?? 'Invalid'}</dd>
        </div>
        <div>
          <dt>{t('integrity.import.preflight.entityId')}</dt>
          <dd className="mono">{formatNullable(report.entity_id)}</dd>
        </div>
        <div>
          <dt>{t('integrity.import.preflight.bookId')}</dt>
          <dd className="mono">{formatNullable(report.book_id)}</dd>
        </div>
        <div>
          <dt>{t('integrity.import.preflight.sourceInstance')}</dt>
          <dd className="mono">{formatNullable(report.source_instance_id)}</dd>
        </div>
        <div>
          <dt>{t('integrity.import.digest')}</dt>
          <dd>
            {report.bundle_digest ? (
              <Digest value={report.bundle_digest} copyable={false} />
            ) : (
              'n/a'
            )}
          </dd>
        </div>
        <div>
          <dt>{t('integrity.import.collided')}</dt>
          <dd>{report.collided ? t('common.yes') : t('common.no')}</dd>
        </div>
        <div>
          <dt>{t('integrity.import.preflight.manifestFiles')}</dt>
          <dd className="mono">{formatNullable(report.manifest_file_count)}</dd>
        </div>
        <div>
          <dt>{t('integrity.import.preflight.zipMembers')}</dt>
          <dd className="mono">{formatNullable(report.zip_member_count)}</dd>
        </div>
        <div>
          <dt>{t('integrity.import.preflight.manifestBytes')}</dt>
          <dd className="mono">{formatNullable(report.manifest_total_bytes)}</dd>
        </div>
        <div>
          <dt>{t('integrity.import.preflight.eventCount')}</dt>
          <dd className="mono">{formatNullable(report.event_count)}</dd>
        </div>
        <div>
          <dt>{t('integrity.import.preflight.chainVerified')}</dt>
          <dd>
            {report.book_chain_verified === null
              ? 'n/a'
              : report.book_chain_verified
                ? t('common.yes')
                : t('common.no')}
          </dd>
        </div>
        <div>
          <dt>{t('integrity.import.preflight.signaturePresent')}</dt>
          <dd>
            {report.signature_present === null
              ? 'n/a'
              : report.signature_present
                ? t('common.yes')
                : t('common.no')}
          </dd>
        </div>
        <div>
          <dt>{t('integrity.restore.preflight.nextStep')}</dt>
          <dd>{redactSensitiveText(report.next_step)}</dd>
        </div>
      </dl>
      <div className="stack--tight">
        {errors.length > 0 ? (
          <>
            <h5>{t('integrity.restore.preflight.errors')}</h5>
            <ul className="plain-list">
              {errors.map((item, index) => (
                <li key={`import-error-${index}`}>{redactSensitiveText(item)}</li>
              ))}
            </ul>
            {hiddenErrors > 0 ? (
              <p className="field__hint">
                {t('integrity.restore.preflight.errors.more', { count: hiddenErrors })}
              </p>
            ) : null}
          </>
        ) : null}
        <h5>{t('integrity.restore.preflight.findings')}</h5>
        {findings.length === 0 ? (
          <p className="field__hint">{t('integrity.restore.preflight.findings.none')}</p>
        ) : (
          <ul className="plain-list">
            {findings.map((finding, index) => (
              <li key={`import-finding-${index}`}>{redactSensitiveText(finding)}</li>
            ))}
          </ul>
        )}
        {hiddenFindings > 0 ? (
          <p className="field__hint">
            {t('integrity.restore.preflight.findings.more', { count: hiddenFindings })}
          </p>
        ) : null}
      </div>
    </InlineWarning>
  );
}

/** A friendly label for a canonical chain id (`global` | `application` | `company:…` | `book:…`). */
function chainLabel(
  chain: string,
  books: BookView[],
  entities: Entity[],
  t: ReturnType<typeof useT>,
) {
  if (chain === 'global') return t('integrity.chain.global');
  if (chain === 'application') return t('integrity.chain.application');
  const [kind, id] = chain.split(':', 2);
  if (kind === 'book') {
    const book = books.find((b) => b.id === id);
    return book?.purpose
      ? t('integrity.chain.bookNamed', { purpose: book.purpose })
      : t('integrity.chain.book', { id: (id ?? '').slice(0, 8) });
  }
  if (kind === 'company') {
    const ent = entities.find((e) => e.id === id);
    return ent
      ? t('integrity.chain.companyNamed', { name: ent.name })
      : t('integrity.chain.company', { id: (id ?? '').slice(0, 8) });
  }
  return chain;
}

/** One chain's status row, expanding to the exact break detail when it fails to verify. */
function ChainStatusRow({ status, label }: { status: ChainStatusView; label: string }) {
  const t = useT();
  const b = status.first_break;
  return (
    <div className={`chainrow${status.verified ? '' : ' chainrow--broken'}`}>
      <div className="chainrow__head">
        <span className="chainrow__label">{label}</span>
        {status.verified ? (
          <Badge tone="ok">{t('integrity.chain.verified', { count: status.length })}</Badge>
        ) : (
          <Badge tone="error">{t('integrity.chain.broken')}</Badge>
        )}
      </div>
      {status.head ? (
        <p className="chainrow__meta">
          {t('integrity.chain.head')}: <Digest value={status.head} copyable={false} />
        </p>
      ) : null}
      {b ? (
        <div className="chainrow__break">
          <p className="chainrow__break-title">{t('integrity.break.title')}</p>
          <dl className="deflist deflist--tight">
            <div>
              <dt>{t('integrity.break.kind')}</dt>
              <dd className="mono">{b.kind}</dd>
            </div>
            {b.chain_seq !== null ? (
              <div>
                <dt>{t('integrity.break.chainSeq')}</dt>
                <dd className="mono">{b.chain_seq}</dd>
              </div>
            ) : null}
            {b.global_seq !== null ? (
              <div>
                <dt>{t('integrity.break.globalSeq')}</dt>
                <dd className="mono">{b.global_seq}</dd>
              </div>
            ) : null}
            {b.event_id ? (
              <div>
                <dt>{t('integrity.break.event')}</dt>
                <dd>
                  <Digest value={b.event_id} copyable={false} />
                </dd>
              </div>
            ) : null}
            {b.expected_hash ? (
              <div>
                <dt>{t('integrity.break.expected')}</dt>
                <dd>
                  <Digest value={b.expected_hash} copyable={false} />
                </dd>
              </div>
            ) : null}
            {b.actual_hash ? (
              <div>
                <dt>{t('integrity.break.actual')}</dt>
                <dd>
                  <Digest value={b.actual_hash} copyable={false} />
                </dd>
              </div>
            ) : null}
          </dl>
          <p className="chainrow__break-msg">{b.message}</p>
        </div>
      ) : null}
    </div>
  );
}

export function LivrosIntegridadeSection() {
  const t = useT();
  const toast = useToast();
  const integrity = useLedgerIntegrity();
  const books = useBooks();
  const entities = useEntities();
  const exportBook = useExportBook();
  const reanchor = useReanchorLedger();
  const restore = useRestoreLedger();
  const restorePreflight = useRestoreLedgerPreflight();

  // Modal + field state for the two recovery paths and per-book start-over.
  const [reanchorOpen, setReanchorOpen] = useState(false);
  const [reanchorReason, setReanchorReason] = useState('');
  const [restoreOpen, setRestoreOpen] = useState(false);
  const [restoreArchive, setRestoreArchive] = useState('');
  const [restoreKey, setRestoreKey] = useState('');
  const [restorePreflightReport, setRestorePreflightReport] = useState<RestorePreflightView | null>(
    null,
  );
  const [startOverBook, setStartOverBook] = useState<BookView | null>(null);

  // Import / per-book restore.
  const importBook = useImportBook();
  const importPreflight = usePreflightImportBook();
  const importRequestGeneration = useRef(0);
  const importFileRef = useRef<File | null>(null);
  const importPolicyRef = useRef<CollisionPolicy>('refuse');
  const [importPolicy, setImportPolicy] = useState<CollisionPolicy>('refuse');
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importPreflightPreview, setImportPreflightPreview] =
    useState<ImportPreflightSnapshot | null>(null);
  const [importPreflightError, setImportPreflightError] = useState<unknown>(null);
  const [importOutcome, setImportOutcome] = useState<ImportOutcomeView | null>(null);

  const bookList = books.data ?? [];
  const entityList = entities.data ?? [];
  const report = integrity.data;
  const broken = report ? !report.healthy : false;
  const currentImportPreflight =
    importFile &&
    importPreflightPreview?.file === importFile &&
    importPreflightPreview.policy === importPolicy
      ? importPreflightPreview.report
      : null;
  const canConfirmImport = Boolean(currentImportPreflight?.ready);

  const overallBadge = useMemo(() => {
    if (!report) return null;
    if (report.degraded) return <Badge tone="error">{t('integrity.report.degraded')}</Badge>;
    if (!report.healthy) return <Badge tone="error">{t('integrity.report.broken')}</Badge>;
    return <Badge tone="ok">{t('integrity.report.healthy')}</Badge>;
  }, [report, t]);

  useEffect(() => {
    return () => {
      importRequestGeneration.current += 1;
    };
  }, []);

  function showSaveResult(result: SaveBlobResult) {
    if (result.kind === 'cancelled') {
      toast.info(saveBlobResultMessage(result));
      return;
    }
    toast.success(saveBlobResultMessage(result));
  }

  async function onExport(book: BookView) {
    try {
      const { blob } = await exportBook.mutateAsync(book.id);
      showSaveResult(
        await saveBlobAs({
          blob,
          filename: `book-${book.id}.zip`,
          contentType: 'application/zip',
          preferBrowserSavePicker: true,
        }),
      );
    } catch (e) {
      toast.error(e);
    }
  }

  function clearImportPreview() {
    importRequestGeneration.current += 1;
    setImportPreflightPreview(null);
    setImportPreflightError(null);
    importPreflight.reset();
  }

  function onSelectImportFile(file: File) {
    importFileRef.current = file;
    setImportFile(file);
    setImportOutcome(null);
    clearImportPreview();
  }

  function isCurrentImportRequest(
    generation: number,
    file: File,
    policy: CollisionPolicy,
  ): boolean {
    return (
      importRequestGeneration.current === generation &&
      importFileRef.current === file &&
      importPolicyRef.current === policy
    );
  }

  async function onImportPreflight() {
    if (!importFile) return;
    const file = importFile;
    const policy = importPolicy;
    const generation = importRequestGeneration.current + 1;
    importRequestGeneration.current = generation;
    setImportPreflightPreview(null);
    setImportPreflightError(null);
    importPreflight.reset();
    try {
      const bytes = await file.arrayBuffer();
      if (!isCurrentImportRequest(generation, file, policy)) return;
      const preview = await importPreflight.mutateAsync({ bytes, policy });
      if (!isCurrentImportRequest(generation, file, policy)) return;
      setImportPreflightPreview({ file, policy, report: preview });
      if (preview.ready) {
        toast.success(t('integrity.import.preflight.done'));
      } else {
        toast.info(t('integrity.import.preflight.blockedToast'));
      }
    } catch (e) {
      if (!isCurrentImportRequest(generation, file, policy)) return;
      setImportPreflightError(e);
      toast.error(e);
    }
  }

  async function onConfirmImport() {
    if (!importFile || !canConfirmImport) return;
    const file = importFile;
    const policy = importPolicy;
    try {
      const bytes = await file.arrayBuffer();
      if (importFileRef.current !== file || importPolicyRef.current !== policy) return;
      const outcome = await importBook.mutateAsync({ bytes, policy });
      setImportOutcome(outcome);
      importFileRef.current = null;
      setImportFile(null);
      clearImportPreview();
      toast.success(t('integrity.import.done'));
    } catch (e) {
      toast.error(e);
    }
  }

  async function onRestorePreflight() {
    const archive = restoreArchive.trim();
    if (!archive) return;
    restorePreflight.reset();
    setRestorePreflightReport(null);
    try {
      const passphrase = restoreKey;
      const result = await restorePreflight.mutateAsync(
        passphrase.trim().length > 0 ? { archive, passphrase } : { archive },
      );
      setRestorePreflightReport(result);
      toast.success(t('integrity.restore.preflight.done'));
    } finally {
      setRestoreKey('');
    }
  }

  return (
    <div className="stack">
      {/* Integrity report ------------------------------------------------------- */}
      <Card title={t('integrity.report.title')} actions={overallBadge}>
        {integrity.isLoading ? (
          <SkeletonText lines={4} />
        ) : integrity.error ? (
          <ErrorNote error={integrity.error} />
        ) : report ? (
          <div className="stack--tight">
            <ChainStatusRow
              status={report.global}
              label={chainLabel(report.global.chain, bookList, entityList, t)}
            />
            {report.chains.map((c) => (
              <ChainStatusRow
                key={c.chain}
                status={c}
                label={chainLabel(c.chain, bookList, entityList, t)}
              />
            ))}
            {report.reanchored_segments.length > 0 ? (
              <InlineWarning tone="warn" title={t('integrity.reanchored.title')}>
                <p>{t('integrity.reanchored.note')}</p>
                <ul className="plain-list">
                  {report.reanchored_segments.map((r, i) => (
                    <li key={`${r.pre_reanchor_digest}-${i}`}>
                      {t('integrity.reanchored.by', { actor: r.actor, reason: r.reason })}
                    </li>
                  ))}
                </ul>
              </InlineWarning>
            ) : null}
          </div>
        ) : null}
      </Card>

      {/* Recovery — restore (primary) + re-anchor (last resort) ----------------- */}
      <Card title={t('integrity.recovery.title')}>
        <div className="stack--tight">
          <p className="field__hint">{t('integrity.recovery.note')}</p>
          <div className="row-wrap">
            <GateButton
              perm="ledger.restore"
              type="button"
              variant="secondary"
              icon={<Icon.Refresh />}
              onClick={() => {
                setRestoreArchive('');
                setRestoreKey('');
                setRestorePreflightReport(null);
                restorePreflight.reset();
                setRestoreOpen(true);
              }}
            >
              {t('integrity.restore.title')}
            </GateButton>
            <GateButton
              perm="ledger.reanchor"
              type="button"
              variant="secondary"
              className="btn--danger"
              icon={<Icon.Layers />}
              disabled={!broken}
              onClick={() => {
                setReanchorReason('');
                setReanchorOpen(true);
              }}
            >
              {t('integrity.reanchor.title')}
            </GateButton>
          </div>
          {!broken ? <p className="field__hint">{t('integrity.reanchor.onlyWhenBroken')}</p> : null}
        </div>
      </Card>

      {/* Per-book export + start-over ------------------------------------------- */}
      <Card title={t('integrity.books.title')}>
        {books.isLoading ? (
          <SkeletonText lines={3} />
        ) : books.error ? (
          <ErrorNote error={books.error} />
        ) : bookList.length === 0 ? (
          <EmptyState title={t('integrity.books.empty')} />
        ) : (
          <ul className="plain-list stack--tight">
            {bookList.map((book) => (
              <li key={book.id} className="bookrow">
                <div className="bookrow__id">
                  <span className="bookrow__purpose">{book.purpose ?? book.kind}</span>
                  <Badge tone={book.state === 'Open' ? 'ok' : 'neutral'}>
                    {bookStateLabels[book.state]}
                  </Badge>
                </div>
                <div className="bookrow__actions">
                  <GateButton
                    perm="book.export"
                    scope={scopeBook(book.id)}
                    type="button"
                    variant="ghost"
                    icon={<Icon.Archive />}
                    disabled={exportBook.isPending}
                    onClick={() => onExport(book)}
                  >
                    {exportBook.isPending
                      ? t('integrity.books.exporting')
                      : t('integrity.books.export')}
                  </GateButton>
                  <GateButton
                    perm="book.start_over"
                    scope={scopeBook(book.id)}
                    type="button"
                    variant="ghost"
                    icon={<Icon.BookPlus />}
                    onClick={() => setStartOverBook(book)}
                  >
                    {t('integrity.books.startOver')}
                  </GateButton>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>

      {/* Import / per-book restore ---------------------------------------------- */}
      <Card title={t('integrity.import.title')}>
        <div className="stack--tight">
          <p className="field__hint">{t('integrity.import.body')}</p>
          <Field label={t('integrity.import.policyLabel')} htmlFor="import-policy">
            <Select
              id="import-policy"
              value={importPolicy}
              onChange={(e) => {
                const policy = e.target.value as CollisionPolicy;
                importPolicyRef.current = policy;
                setImportPolicy(policy);
                clearImportPreview();
                setImportOutcome(null);
              }}
              options={[
                { value: 'refuse', label: t('integrity.import.policy.refuse') },
                { value: 'quarantine_copy', label: t('integrity.import.policy.quarantine') },
              ]}
            />
          </Field>
          {importFile ? (
            <p className="field__hint">
              {t('integrity.import.preflight.selectedFile', { name: importFile.name })}
            </p>
          ) : null}
          <div className="row-wrap">
            <label className="btn btn--secondary btn--icon file-btn">
              <span className="btn__icon">
                <Icon.Tray />
              </span>
              {importBook.isPending ? t('integrity.import.pending') : t('integrity.import.choose')}
              <input
                type="file"
                accept=".zip,application/zip"
                className="sr-only"
                disabled={importBook.isPending}
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) onSelectImportFile(file);
                  e.target.value = '';
                }}
              />
            </label>
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.Search />}
              disabled={!importFile || importPreflight.isPending || importBook.isPending}
              onClick={() => void onImportPreflight()}
            >
              {importPreflight.isPending
                ? t('integrity.import.preflight.pending')
                : t('integrity.import.preflight.submit')}
            </Button>
            <Button
              type="button"
              variant="primary"
              icon={<Icon.Check />}
              disabled={!importFile || !canConfirmImport || importBook.isPending}
              onClick={() => void onConfirmImport()}
            >
              {importBook.isPending ? t('integrity.import.pending') : t('integrity.import.confirm')}
            </Button>
          </div>
          <BookImportPreflightReport report={currentImportPreflight} error={importPreflightError} />
          {importOutcome ? (
            <InlineWarning
              tone={importOutcome.verdict.status === 'Verified' ? 'info' : 'error'}
              title={
                importOutcome.verdict.status === 'Verified'
                  ? t('integrity.import.verdict.verified')
                  : t('integrity.import.verdict.quarantined')
              }
            >
              <p>
                {importOutcome.verdict.status === 'Verified'
                  ? t('integrity.import.verifiedNote')
                  : t('integrity.import.quarantinedNote')}
              </p>
              {importOutcome.collided ? <p>{t('integrity.import.collided')}</p> : null}
              <p className="mono chainrow__meta">
                {t('integrity.import.digest')}:{' '}
                <Digest value={importOutcome.bundle_digest} copyable={false} />
              </p>
            </InlineWarning>
          ) : null}
        </div>
      </Card>

      {/* Re-anchor modal (last resort — reauth + reason, permanently disclosed) --- */}
      <ConfirmActionModal
        open={reanchorOpen}
        onClose={() => setReanchorOpen(false)}
        title={t('integrity.reanchor.title')}
        danger
        intro={t('integrity.reanchor.body')}
        confirmLabel={t('integrity.reanchor.confirm')}
        pendingLabel={t('integrity.reanchor.pending')}
        requireReauth
        pending={reanchor.isPending}
        canConfirm={reanchorReason.trim().length > 0}
        onConfirm={async ({ reauth }) => {
          await reanchor.mutateAsync({ reason: reanchorReason.trim(), reauth });
          toast.success(t('integrity.reanchor.done'));
        }}
      >
        <Field label={t('integrity.reanchor.reasonLabel')} htmlFor="reanchor-reason">
          <TextArea
            id="reanchor-reason"
            value={reanchorReason}
            placeholder={t('integrity.reanchor.reasonPlaceholder')}
            onChange={(e) => setReanchorReason(e.target.value)}
          />
        </Field>
      </ConfirmActionModal>

      {/* Restore modal (primary — verified backup, never rewrites history) ------- */}
      <ConfirmActionModal
        open={restoreOpen}
        onClose={() => setRestoreOpen(false)}
        title={t('integrity.restore.title')}
        intro={t('integrity.restore.body')}
        confirmLabel={t('integrity.restore.confirm')}
        pendingLabel={t('integrity.restore.pending')}
        pending={restore.isPending}
        canConfirm={restoreArchive.trim().length > 0}
        onConfirm={async () => {
          await restore.mutateAsync({ archive: restoreArchive.trim() });
          toast.success(t('integrity.restore.done'));
        }}
      >
        <Field
          label={t('integrity.restore.archiveLabel')}
          htmlFor="restore-archive"
          hint={t('integrity.restore.archiveHint')}
        >
          <Input
            id="restore-archive"
            value={restoreArchive}
            placeholder={t('integrity.restore.archivePlaceholder')}
            onChange={(e) => {
              setRestoreArchive(e.target.value);
              setRestorePreflightReport(null);
              restorePreflight.reset();
            }}
          />
        </Field>
        <Field
          label={t('integrity.restore.keyLabel')}
          htmlFor="restore-key"
          hint={t('integrity.restore.keyHint')}
        >
          <Input
            id="restore-key"
            type="password"
            value={restoreKey}
            autoComplete="off"
            placeholder={t('integrity.restore.keyPlaceholder')}
            onChange={(e) => {
              setRestoreKey(e.target.value);
              setRestorePreflightReport(null);
              restorePreflight.reset();
            }}
          />
        </Field>
        <p className="field__hint">{t('integrity.restore.preflight.secretHint')}</p>
        <div className="row-wrap">
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.Check />}
            disabled={restoreArchive.trim().length === 0 || restorePreflight.isPending}
            onClick={() => void onRestorePreflight()}
          >
            {restorePreflight.isPending
              ? t('integrity.restore.preflight.pending')
              : t('integrity.restore.preflight.submit')}
          </Button>
        </div>
        <RestorePreflightReport report={restorePreflightReport} error={restorePreflight.error} />
      </ConfirmActionModal>

      {/* Per-book start-over modal --------------------------------------------- */}
      {startOverBook ? (
        <StartOverBookModal book={startOverBook} onClose={() => setStartOverBook(null)} />
      ) : null}
    </div>
  );
}
