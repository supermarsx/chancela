/**
 * A single book, full width: its termo de abertura summary and the atas it holds (sealed
 * first by number, then drafts — the API orders them). While the book is Open, drafting an
 * ata (WFL-14) and closing the book (WFL-13) are neat buttons in the Atas panel header,
 * each opening its own route (`/livros/:id/nova-ata`, `/livros/:id/encerrar`) so the view
 * is no longer split by an aside (t13 item 7). The page header also exposes the read-only
 * Chancela internal preservation ZIP for this book.
 */
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  useBook,
  useBookActs,
  useBookLegalHold,
  useClearBookLegalHold,
  useDownloadBookArchivePackage,
  useDownloadPaperBookImport,
  usePaperBookImports,
  useSetBookLegalHold,
} from '../../api/hooks';
import type { PaperBookImportView } from '../../api/types';
import {
  actStateLabels,
  bookKindLabels,
  bookStateLabels,
  closingReasonLabels,
  meetingChannelLabels,
  numberingSchemeLabels,
} from '../../api/labels';
import { useT } from '../../i18n';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import {
  Badge,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  PageHeader,
  Skeleton,
  SkeletonDeflist,
  SkeletonTable,
  Table,
  TextArea,
  useToast,
} from '../../ui';
import { GateButton, GateButtonLink, scopeBook } from '../session/permissions';

function preservationPackageFilename(bookId: string): string {
  return `chancela-preservation-book-${bookId}.zip`;
}

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return '—';
  if (value < 1024) return `${value} bytes`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let amount = value;
  let unit = 'bytes';
  for (const candidate of units) {
    amount /= 1024;
    unit = candidate;
    if (amount < 1024) break;
  }
  const decimals = amount >= 10 || Number.isInteger(amount) ? 0 : 1;
  return `${amount.toFixed(decimals)} ${unit}`;
}

function paperBookImportFilename(row: PaperBookImportView): string {
  if (row.source_filename?.trim()) return row.source_filename.trim();
  const type = row.content_type.split(';')[0]?.trim().toLowerCase();
  const ext = type === 'application/pdf' ? 'pdf' : type === 'application/zip' ? 'zip' : 'bin';
  return `paper-book-import-${row.import_id}.${ext}`;
}

function LegalHoldPanel({ bookId }: { bookId: string }) {
  const toast = useToast();
  const hold = useBookLegalHold(bookId);
  const setHold = useSetBookLegalHold(bookId);
  const clearHold = useClearBookLegalHold(bookId);
  const [reason, setReason] = useState('');

  useEffect(() => {
    setReason(hold.data?.reason ?? '');
  }, [hold.data?.reason]);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = reason.trim();
    if (!trimmed) return;
    setHold.mutate(
      { reason: trimmed },
      {
        onSuccess: () => toast.success('Retenção legal aplicada.'),
        onError: (e) => toast.error(e),
      },
    );
  }

  function clear() {
    clearHold.mutate(undefined, {
      onSuccess: () => {
        setReason('');
        toast.success('Retenção legal removida.');
      },
      onError: (e) => toast.error(e),
    });
  }

  const active = hold.data?.legal_hold === true;
  const busy = setHold.isPending || clearHold.isPending;

  return (
    <Card title="Retenção legal">
      <div className="stack">
        {hold.isLoading ? (
          <SkeletonDeflist />
        ) : hold.error ? (
          <ErrorNote error={hold.error} />
        ) : (
          <>
            <InlineWarning
              tone={active ? 'warn' : 'info'}
              title={active ? 'Ativa' : 'Sem retenção'}
            >
              A retenção legal bloqueia o descarte por regras de retenção enquanto estiver ativa.
            </InlineWarning>
            <dl className="deflist">
              <div>
                <dt>Estado</dt>
                <dd>
                  <Badge tone={active ? 'warn' : 'neutral'}>
                    {active ? 'Retenção legal ativa' : 'Sem retenção legal'}
                  </Badge>
                </dd>
              </div>
              {hold.data?.actor ? (
                <div>
                  <dt>Ator</dt>
                  <dd>{hold.data.actor}</dd>
                </div>
              ) : null}
              {hold.data?.set_at ? (
                <div>
                  <dt>Definida em</dt>
                  <dd>{hold.data.set_at}</dd>
                </div>
              ) : null}
            </dl>
          </>
        )}

        <form className="form" onSubmit={submit}>
          <Field label="Motivo da retenção legal" htmlFor="book-legal-hold-reason">
            <TextArea
              id="book-legal-hold-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              placeholder="Ex.: litígio, auditoria ou pedido de autoridade"
            />
          </Field>
          <div className="form__actions">
            <GateButton
              perm="book.export"
              scope={scopeBook(bookId)}
              type="submit"
              variant="primary"
              icon={<Icon.Scale />}
              disabled={busy || reason.trim().length === 0}
            >
              {setHold.isPending ? 'A aplicar retenção' : 'Aplicar retenção legal'}
            </GateButton>
            <GateButton
              perm="book.export"
              scope={scopeBook(bookId)}
              type="button"
              variant="secondary"
              icon={<Icon.Trash />}
              disabled={busy || !active}
              onClick={clear}
            >
              {clearHold.isPending ? 'A remover' : 'Remover retenção'}
            </GateButton>
          </div>
        </form>
      </div>
    </Card>
  );
}

function PaperBookImportsPanel({ bookRef }: { bookRef: string }) {
  const toast = useToast();
  const imports = usePaperBookImports(bookRef);
  const download = useDownloadPaperBookImport();

  function onDownload(row: PaperBookImportView) {
    download.mutate(row.import_id, {
      onSuccess: async (blob) => {
        try {
          showSaveResult(
            await saveBlobAs({
              blob,
              filename: paperBookImportFilename(row),
              preferBrowserSavePicker: true,
            }),
          );
        } catch (e) {
          toast.error(e);
        }
      },
      onError: (e) => toast.error(e),
    });
  }

  function showSaveResult(result: SaveBlobResult) {
    if (result.kind === 'cancelled') {
      toast.info(saveBlobResultMessage(result));
      return;
    }
    toast.success(saveBlobResultMessage(result));
  }

  const rows = imports.data ?? [];

  return (
    <Card title="Importações de livro em papel preservadas">
      {imports.isLoading ? (
        <SkeletonTable cols={4} />
      ) : imports.error ? (
        <ErrorNote error={imports.error} />
      ) : rows.length === 0 ? (
        <EmptyState title="Sem importações preservadas">
          <p>Não há pacotes de livro em papel preservados para esta referência de livro.</p>
        </EmptyState>
      ) : (
        <div className="stack">
          <InlineWarning tone="warn" title="Evidência não canónica">
            Estes pacotes preservam cópias de livros em papel para consulta. Não substituem atas
            digitais canónicas e não declaram validade legal, PDF/A ou assinatura qualificada.
          </InlineWarning>
          <Table
            head={
              <tr>
                <th>Ficheiro</th>
                <th>Período</th>
                <th>Fixidez</th>
                <th />
              </tr>
            }
          >
            {rows.map((row) => (
              <tr key={row.import_id}>
                <td>
                  <div className="stack--tight">
                    <span>{row.source_filename ?? row.import_id}</span>
                    <span className="muted">
                      {formatBytes(row.size_bytes)} · {row.content_type} · {row.page_count} páginas
                    </span>
                  </div>
                </td>
                <td>
                  {row.date_from} a {row.date_to}
                </td>
                <td>
                  <div className="stack--tight">
                    <Badge tone={row.non_canonical ? 'warn' : 'neutral'}>
                      {row.non_canonical ? 'Não canónico' : 'Importado'}
                    </Badge>
                    <span className="mono">{row.sha256.slice(0, 16)}...</span>
                  </div>
                </td>
                <td>
                  <GateButton
                    perm="book.import"
                    type="button"
                    variant="ghost"
                    icon={<Icon.Tray />}
                    disabled={download.isPending}
                    onClick={() => onDownload(row)}
                  >
                    {download.isPending ? 'A descarregar' : 'Descarregar pacote'}
                  </GateButton>
                </td>
              </tr>
            ))}
          </Table>
        </div>
      )}
    </Card>
  );
}

export function BookDetailPage() {
  const t = useT();
  const toast = useToast();
  const { id = '' } = useParams();
  const book = useBook(id);
  const acts = useBookActs(id);
  const packageDownload = useDownloadBookArchivePackage(id);

  if (book.isLoading) {
    return (
      <div className="stack">
        <PageHeader
          crumbs={<Link to="/livros">{t('books.crumb')}</Link>}
          title={<Skeleton width="18rem" height="1.6rem" />}
        />
        <Card title={t('books.termoAbertura')}>
          <SkeletonDeflist />
        </Card>
      </div>
    );
  }
  if (book.error) return <ErrorNote error={book.error} />;
  if (!book.data) return null;

  const b = book.data;
  const isOpen = b.state === 'Open';

  function showSaveResult(result: SaveBlobResult) {
    if (result.kind === 'cancelled') {
      toast.info(saveBlobResultMessage(result));
      return;
    }
    toast.success(saveBlobResultMessage(result));
  }

  function onDownloadPackage() {
    packageDownload.mutate(undefined, {
      onSuccess: async (blob) => {
        try {
          showSaveResult(
            await saveBlobAs({
              blob,
              filename: preservationPackageFilename(b.id),
              preferBrowserSavePicker: true,
            }),
          );
        } catch (e) {
          toast.error(e);
        }
      },
      onError: (e) => toast.error(e),
    });
  }

  return (
    <div className="stack">
      <PageHeader
        crumbs={
          <>
            <Link to="/livros">{t('books.crumb')}</Link> · {bookKindLabels[b.kind]}
          </>
        }
        title={
          <>
            {bookKindLabels[b.kind]}{' '}
            <Badge tone={isOpen ? 'ok' : 'neutral'}>{bookStateLabels[b.state]}</Badge>
          </>
        }
        actions={
          <GateButton
            perm="book.export"
            scope={scopeBook(b.id)}
            type="button"
            variant="secondary"
            icon={<Icon.Archive />}
            disabled={packageDownload.isPending}
            onClick={onDownloadPackage}
          >
            {packageDownload.isPending
              ? t('books.preservationPackage.downloading')
              : t('books.preservationPackage.download')}
          </GateButton>
        }
      />

      <Card title={t('books.termoAbertura')}>
        <dl className="deflist">
          <div>
            <dt>{t('books.purpose')}</dt>
            <dd>{b.purpose ?? '—'}</dd>
          </div>
          <div>
            <dt>{t('books.numbering')}</dt>
            <dd>{b.numbering_scheme ? numberingSchemeLabels[b.numbering_scheme] : '—'}</dd>
          </div>
          <div>
            <dt>{t('books.openingDate')}</dt>
            <dd>{b.opening_date ?? '—'}</dd>
          </div>
          <div>
            <dt>{t('books.signatories')}</dt>
            <dd>{b.required_signatories_abertura?.join(', ') || '—'}</dd>
          </div>
          {b.predecessor ? (
            <div>
              <dt>{t('books.predecessor')}</dt>
              <dd>
                <Link to={`/livros/${b.predecessor}`}>{b.predecessor}</Link>
              </dd>
            </div>
          ) : null}
          {b.state === 'Closed' ? (
            <>
              <div>
                <dt>{t('books.closingReason')}</dt>
                <dd>{b.closing_reason ? closingReasonLabels[b.closing_reason] : '—'}</dd>
              </div>
              <div>
                <dt>{t('books.closingDate')}</dt>
                <dd>{b.closing_date ?? '—'}</dd>
              </div>
            </>
          ) : null}
        </dl>
      </Card>

      <LegalHoldPanel bookId={b.id} />

      <PaperBookImportsPanel bookRef={b.id} />

      <Card
        title={t('books.atas')}
        actions={
          isOpen ? (
            <div className="row-wrap">
              <GateButtonLink
                perm="book.close"
                scope={scopeBook(b.id)}
                to={`/livros/${b.id}/encerrar`}
                icon={<Icon.BookClosed />}
              >
                {t('books.closeBook')}
              </GateButtonLink>
              <GateButtonLink
                perm="act.draft"
                scope={scopeBook(b.id)}
                to={`/livros/${b.id}/nova-ata`}
                variant="primary"
                icon={<Icon.Plus />}
              >
                {t('books.newAta')}
              </GateButtonLink>
            </div>
          ) : null
        }
      >
        {acts.isLoading ? (
          <SkeletonTable cols={5} />
        ) : acts.error ? (
          <ErrorNote error={acts.error} />
        ) : !acts.data || acts.data.length === 0 ? (
          <EmptyState title={t('books.noAtas')}>
            {isOpen ? <p>{t('books.createFirstAta')}</p> : null}
          </EmptyState>
        ) : (
          <Table
            head={
              <tr>
                <th>{t('books.th.number')}</th>
                <th>{t('books.th.actTitle')}</th>
                <th>{t('books.th.channel')}</th>
                <th>{t('books.th.actState')}</th>
                <th />
              </tr>
            }
          >
            {acts.data.map((act) => (
              <tr key={act.id}>
                <td>{act.ata_number ?? '—'}</td>
                <td>{act.title}</td>
                <td>{meetingChannelLabels[act.channel]}</td>
                <td>
                  <Badge
                    tone={act.state === 'Sealed' || act.state === 'Archived' ? 'accent' : 'neutral'}
                  >
                    {actStateLabels[act.state]}
                  </Badge>
                </td>
                <td>
                  <Link to={`/atas/${act.id}`}>{t('common.open')}</Link>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
