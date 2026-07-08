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
import { useMemo, useState } from 'react';
import {
  useBooks,
  useEntities,
  useExportBook,
  useImportBook,
  useLedgerIntegrity,
  useReanchorLedger,
  useRestoreLedger,
} from '../../api/hooks';
import type {
  BookView,
  ChainStatusView,
  CollisionPolicy,
  Entity,
  ImportOutcomeView,
} from '../../api/types';
import { useT } from '../../i18n';
import { bookStateLabels } from '../../api/labels';
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
import { StartOverBookModal } from './StartOverBookModal';

/** Trigger a browser download of a Blob with an explicit filename (mirrors ActDocumentPanel). */
function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
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

  // Modal + field state for the two recovery paths and per-book start-over.
  const [reanchorOpen, setReanchorOpen] = useState(false);
  const [reanchorReason, setReanchorReason] = useState('');
  const [restoreOpen, setRestoreOpen] = useState(false);
  const [restoreArchive, setRestoreArchive] = useState('');
  const [startOverBook, setStartOverBook] = useState<BookView | null>(null);

  // Import / per-book restore.
  const importBook = useImportBook();
  const [importPolicy, setImportPolicy] = useState<CollisionPolicy>('refuse');
  const [importOutcome, setImportOutcome] = useState<ImportOutcomeView | null>(null);

  const bookList = books.data ?? [];
  const entityList = entities.data ?? [];
  const report = integrity.data;
  const broken = report ? !report.healthy : false;

  const overallBadge = useMemo(() => {
    if (!report) return null;
    if (report.degraded) return <Badge tone="error">{t('integrity.report.degraded')}</Badge>;
    if (!report.healthy) return <Badge tone="error">{t('integrity.report.broken')}</Badge>;
    return <Badge tone="ok">{t('integrity.report.healthy')}</Badge>;
  }, [report, t]);

  async function onExport(book: BookView) {
    try {
      const { blob } = await exportBook.mutateAsync(book.id);
      triggerDownload(blob, `book-${book.id}.zip`);
      toast.success(t('integrity.books.exported'));
    } catch (e) {
      toast.error(e);
    }
  }

  async function onImportFile(file: File) {
    setImportOutcome(null);
    try {
      const bytes = await file.arrayBuffer();
      const outcome = await importBook.mutateAsync({ bytes, policy: importPolicy });
      setImportOutcome(outcome);
      toast.success(t('integrity.import.done'));
    } catch (e) {
      toast.error(e);
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
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.Refresh />}
              onClick={() => {
                setRestoreArchive('');
                setRestoreOpen(true);
              }}
            >
              {t('integrity.restore.title')}
            </Button>
            <Button
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
            </Button>
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
                  <Button
                    type="button"
                    variant="ghost"
                    icon={<Icon.Archive />}
                    disabled={exportBook.isPending}
                    onClick={() => onExport(book)}
                  >
                    {exportBook.isPending
                      ? t('integrity.books.exporting')
                      : t('integrity.books.export')}
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    icon={<Icon.BookPlus />}
                    onClick={() => setStartOverBook(book)}
                  >
                    {t('integrity.books.startOver')}
                  </Button>
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
              onChange={(e) => setImportPolicy(e.target.value as CollisionPolicy)}
              options={[
                { value: 'refuse', label: t('integrity.import.policy.refuse') },
                { value: 'quarantine_copy', label: t('integrity.import.policy.quarantine') },
              ]}
            />
          </Field>
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
                  if (file) void onImportFile(file);
                  e.target.value = '';
                }}
              />
            </label>
          </div>
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
            onChange={(e) => setRestoreArchive(e.target.value)}
          />
        </Field>
      </ConfirmActionModal>

      {/* Per-book start-over modal --------------------------------------------- */}
      {startOverBook ? (
        <StartOverBookModal book={startOverBook} onClose={() => setStartOverBook(null)} />
      ) : null}
    </div>
  );
}
