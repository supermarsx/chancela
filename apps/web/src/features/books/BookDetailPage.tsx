/**
 * A single book, full width: its termo de abertura summary and the atas it holds (sealed
 * first by number, then drafts — the API orders them). While the book is Open, drafting an
 * ata (WFL-14) and closing the book (WFL-13) are neat buttons in the Atas panel header,
 * each opening its own route (`/livros/:id/nova-ata`, `/livros/:id/encerrar`) so the view
 * is no longer split by an aside (t13 item 7). The page header also exposes the read-only
 * Chancela internal preservation ZIP for this book.
 */
import { Fragment, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  useBook,
  useBookActs,
  useBookLegalHold,
  useCreatePaperBookOcrConversionDossier,
  useClearBookLegalHold,
  useCreatePaperBookOcrDraft,
  useCreatePaperBookOcrDraftActDraft,
  useDownloadBookArchivePackage,
  useDownloadBookLocalDglabInterchangeManifest,
  useDownloadPaperBookImport,
  useEntity,
  useEnqueuePaperBookImportOcr,
  usePaperBookOcrConversionDossiers,
  usePaperBookOcrDrafts,
  usePaperBookImports,
  usePreservePaperBookImport,
  useReviewPaperBookOcrDraft,
  useRunPaperBookImportOcr,
  useSetBookLegalHold,
  useValidatePaperBookImport,
} from '../../api/hooks';
import { PAPER_BOOK_OCR_DRAFT_REVIEW_STATUSES } from '../../api/types';
import type {
  BookView,
  BookTermoSignatory,
  LocalDglabInterchangeManifest,
  PaperBookImportPreservationReport,
  PaperBookImportReport,
  PaperBookImportView,
  PaperBookOcrConversionDossierView,
  PaperBookOcrConversionExecutionArtifactView,
  PaperBookOcrDraftCanonicalDraftResponse,
  PaperBookOcrDraftReviewPatchStatus,
  PaperBookOcrDraftView,
  PaperBookOcrStatus,
} from '../../api/types';
import {
  actStateLabels,
  bookKindLabels,
  bookStateLabels,
  closingReasonLabels,
  meetingChannelLabels,
  numberingSchemeLabels,
  signatoryCapacityLabels,
} from '../../api/labels';
import { useT } from '../../i18n';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  PageHeader,
  Select,
  Skeleton,
  SkeletonDeflist,
  SkeletonTable,
  Table,
  TextArea,
  useToast,
} from '../../ui';
import { ConfirmActionModal } from '../../ui/ConfirmActionModal';
import { GateButton, GateButtonLink, scopeBook } from '../session/permissions';

function preservationPackageFilename(bookId: string): string {
  return `chancela-preservation-book-${bookId}.zip`;
}

const LOCAL_DGLAB_MANIFEST_CONTENT_TYPE = 'application/json';

function localDglabInterchangeManifestFilename(bookId: string): string {
  return `chancela-local-dglab-interchange-manifest-book-${bookId}.json`;
}

function localDglabInterchangeManifestBlob(manifest: LocalDglabInterchangeManifest): Blob {
  return new Blob([`${JSON.stringify(manifest, null, 2)}\n`], {
    type: LOCAL_DGLAB_MANIFEST_CONTENT_TYPE,
  });
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

function formatBookTermoSignatory(signatory: BookTermoSignatory): string {
  return [
    signatory.name,
    signatory.capacity ? signatoryCapacityLabels[signatory.capacity] : '',
    signatory.email ?? '',
  ]
    .filter(Boolean)
    .join(' · ');
}

function formatBookSignatories(
  records: BookTermoSignatory[] | null | undefined,
  legacy: string[] | null,
): string {
  if (records?.length) return records.map(formatBookTermoSignatory).join(', ');
  return legacy?.join(', ') || '—';
}

function paperBookImportFilename(row: PaperBookImportView): string {
  if (row.source_filename?.trim()) return row.source_filename.trim();
  const type = row.content_type.split(';')[0]?.trim().toLowerCase();
  const ext = type === 'application/pdf' ? 'pdf' : type === 'application/zip' ? 'zip' : 'bin';
  return `paper-book-import-${row.import_id}.${ext}`;
}

function paperBookOcrStatusLabel(status: PaperBookOcrStatus): string {
  switch (status) {
    case 'disabled':
      return 'OCR desativado';
    case 'not_run':
    case 'not_started':
      return 'OCR não executado';
    case 'queued':
      return 'OCR em fila';
    case 'running':
      return 'OCR em curso';
    case 'completed':
      return 'OCR concluído';
    case 'failed':
      return 'OCR falhou';
    default:
      return status;
  }
}

function paperBookReviewStateLabel(row: PaperBookImportView): string {
  const state = row.manual_review_state?.trim();
  if (!state) return 'Revisão manual não exposta pela API';
  switch (state) {
    case 'pending':
    case 'needs_review':
      return 'Revisão manual pendente';
    case 'in_review':
      return 'Em revisão manual';
    case 'reviewed':
    case 'accepted':
      return 'Revisão manual concluída';
    case 'rejected':
      return 'Revisão manual rejeitada';
    default:
      return state;
  }
}

function paperBookReviewTone(row: PaperBookImportView): 'neutral' | 'warn' | 'ok' | 'error' {
  const state = row.manual_review_state?.trim();
  if (!state) return 'neutral';
  if (state === 'reviewed' || state === 'accepted') return 'ok';
  if (state === 'rejected') return 'error';
  return 'warn';
}

function paperBookPageRange(row: PaperBookImportView): string {
  const from = row.page_from;
  const to = row.page_to;
  if (typeof from === 'number' && typeof to === 'number') return `${from} a ${to}`;
  if (typeof from === 'number') return `desde ${from}`;
  if (typeof to === 'number') return `até ${to}`;
  return 'Intervalo de páginas não exposto pela API';
}

function canQueueOcr(status: PaperBookOcrStatus): boolean {
  return status === 'not_run' || status === 'not_started' || status === 'failed';
}

const PAPER_BOOK_OCR_REVIEW_NOTE_LIMIT = 2000;
const PAPER_BOOK_OCR_DRAFT_COPY =
  'Rascunhos OCR são auxiliares, não canónicos e destinam-se apenas à revisão. Não criam ata canónica, documento canónico, PDF/A, assinatura ou validade legal.';

const paperBookOcrReviewOptions = PAPER_BOOK_OCR_DRAFT_REVIEW_STATUSES.map((status) => ({
  value: status,
  label: paperBookOcrReviewStatusLabel(status),
}));

function trimmedOrNull(value: string): string | null {
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function paperBookOcrReviewStatusLabel(status: string): string {
  switch (status) {
    case 'unreviewed':
      return 'Sem revisão OCR';
    case 'accepted':
      return 'Aceite para referência auxiliar';
    case 'rejected':
      return 'Rejeitado como referência auxiliar';
    case 'superseded':
      return 'Substituído por outro rascunho';
    default:
      return status;
  }
}

function paperBookOcrReviewTone(status: string): 'neutral' | 'warn' | 'ok' | 'error' {
  switch (status) {
    case 'accepted':
      return 'ok';
    case 'rejected':
      return 'error';
    case 'superseded':
      return 'warn';
    default:
      return 'neutral';
  }
}

function paperBookOcrPageSpansLabel(draft: PaperBookOcrDraftView): string {
  return paperBookOcrPageSpanListLabel(draft.page_spans);
}

function paperBookOcrPageSpanListLabel(
  spans: Array<{ start_page: number; end_page: number }>,
): string {
  if (spans.length === 0) return '—';
  return spans
    .map((span) =>
      span.start_page === span.end_page
        ? `p. ${span.start_page}`
        : `pp. ${span.start_page}-${span.end_page}`,
    )
    .join(', ');
}

function paperBookOcrDossierPageSpansLabel(dossier: PaperBookOcrConversionDossierView): string {
  return paperBookOcrPageSpanListLabel(dossier.source_page_spans);
}

function paperBookOcrArtifactPageSpansLabel(
  artifact: PaperBookOcrConversionExecutionArtifactView,
): string {
  return paperBookOcrPageSpanListLabel(artifact.source_page_spans);
}

function noClaimLabel(value: boolean): string {
  return value ? 'sim' : 'não';
}

function paperBookOcrTextPreview(draft: PaperBookOcrDraftView): string {
  const text = draft.extracted_text?.trim();
  if (!text) return 'Texto OCR não armazenado; rever pelo digest indicado.';
  return text.length > 240 ? `${text.slice(0, 240)}...` : text;
}

function isPaperBookOcrReviewPatchStatus(
  value: string,
): value is PaperBookOcrDraftReviewPatchStatus {
  return (PAPER_BOOK_OCR_DRAFT_REVIEW_STATUSES as readonly string[]).includes(value);
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

async function sha256Hex(buffer: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
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

function PaperBookOcrDraftReviewForm({
  draft,
  importId,
}: {
  draft: PaperBookOcrDraftView;
  importId: string;
}) {
  const toast = useToast();
  const review = useReviewPaperBookOcrDraft();
  const initialStatus = isPaperBookOcrReviewPatchStatus(draft.review_status)
    ? draft.review_status
    : 'accepted';
  const [status, setStatus] = useState<PaperBookOcrDraftReviewPatchStatus>(initialStatus);
  const [note, setNote] = useState(draft.review_note ?? '');
  const [supersededBy, setSupersededBy] = useState(draft.superseded_by ?? '');
  const [acknowledged, setAcknowledged] = useState(false);

  useEffect(() => {
    setStatus(
      isPaperBookOcrReviewPatchStatus(draft.review_status) ? draft.review_status : 'accepted',
    );
    setNote(draft.review_note ?? '');
    setSupersededBy(draft.superseded_by ?? '');
    setAcknowledged(false);
  }, [draft.draft_id, draft.review_note, draft.review_status, draft.superseded_by]);

  const superseded = status === 'superseded';
  const supersededMissing = superseded && supersededBy.trim().length === 0;

  function submit(event: React.FormEvent) {
    event.preventDefault();
    review.mutate(
      {
        importId,
        draftId: draft.draft_id,
        body: {
          review_status: status,
          review_note: trimmedOrNull(note),
          superseded_by: superseded ? trimmedOrNull(supersededBy) : null,
        },
      },
      {
        onSuccess: () => toast.success('Revisão OCR guardada como metadado auxiliar não canónico.'),
        onError: (e) => toast.error(e),
      },
    );
  }

  return (
    <form className="form" aria-label="Revisão OCR auxiliar" onSubmit={submit}>
      <Field label="Estado da revisão OCR" htmlFor={`ocr-review-status-${draft.draft_id}`}>
        <Select
          id={`ocr-review-status-${draft.draft_id}`}
          value={status}
          options={paperBookOcrReviewOptions}
          onChange={(event) => setStatus(event.target.value as PaperBookOcrDraftReviewPatchStatus)}
        />
      </Field>
      {superseded ? (
        <Field
          label="Rascunho sucessor"
          htmlFor={`ocr-review-successor-${draft.draft_id}`}
          hint="Obrigatório apenas quando a revisão marca este rascunho como substituído."
        >
          <Input
            id={`ocr-review-successor-${draft.draft_id}`}
            value={supersededBy}
            onChange={(event) => setSupersededBy(event.target.value)}
          />
        </Field>
      ) : null}
      <Field
        label="Nota da revisão OCR"
        htmlFor={`ocr-review-note-${draft.draft_id}`}
        hint={`${note.length}/${PAPER_BOOK_OCR_REVIEW_NOTE_LIMIT} caracteres. Registe apenas a decisão de revisão auxiliar; não declare conversão, assinatura ou validade legal.`}
      >
        <TextArea
          id={`ocr-review-note-${draft.draft_id}`}
          rows={3}
          maxLength={PAPER_BOOK_OCR_REVIEW_NOTE_LIMIT}
          value={note}
          onChange={(event) => setNote(event.target.value)}
        />
      </Field>
      <label className="checkline" htmlFor={`ocr-review-ack-${draft.draft_id}`}>
        <input
          id={`ocr-review-ack-${draft.draft_id}`}
          type="checkbox"
          checked={acknowledged}
          onChange={(event) => setAcknowledged(event.target.checked)}
        />
        Confirmo que esta revisão é apenas metadado auxiliar de OCR e não cria ata canónica,
        documento canónico, assinatura ou validade legal.
      </label>
      {review.error ? <ErrorNote error={review.error} /> : null}
      <GateButton
        perm="book.import"
        type="submit"
        variant="secondary"
        icon={<Icon.Check />}
        disabled={review.isPending || !acknowledged || supersededMissing}
      >
        {review.isPending ? 'A guardar revisão OCR' : 'Guardar revisão OCR'}
      </GateButton>
    </form>
  );
}

function PaperBookOcrConversionExecutionArtifactPanel({
  artifact,
}: {
  artifact: PaperBookOcrConversionExecutionArtifactView;
}) {
  return (
    <section
      className="stack--tight"
      aria-label={`Evidência de execução de conversão revista ${artifact.artifact_id}`}
    >
      <div className="row-wrap">
        <Badge tone={artifact.reviewed_conversion_execution_artifact ? 'ok' : 'warn'}>
          Evidência revista
        </Badge>
        <Badge tone={artifact.mutable_draft_act_created ? 'neutral' : 'warn'}>
          Promoção para rascunho mutável
        </Badge>
        <Badge tone="warn">Não canónico</Badge>
      </div>
      <InlineWarning tone="info" title="Evidência de promoção para rascunho mutável">
        <p>{artifact.artifact_notice}</p>
        <p>{artifact.legal_notice}</p>
      </InlineWarning>
      <dl className="deflist deflist--tight">
        <div>
          <dt>Artefacto</dt>
          <dd>
            <span className="mono">{artifact.artifact_id}</span>
          </dd>
        </div>
        <div>
          <dt>Rascunho OCR aceite</dt>
          <dd>
            <span className="mono">{artifact.draft_id}</span>
          </dd>
        </div>
        <div>
          <dt>Dossier associado</dt>
          <dd>
            {artifact.dossier_id ? <span className="mono">{artifact.dossier_id}</span> : '—'}
          </dd>
        </div>
        <div>
          <dt>Ata mutável de destino</dt>
          <dd>
            <Link to={`/atas/${artifact.target_act_id}`}>abrir ata</Link> ·{' '}
            <span className="mono">{artifact.target_act_id}</span> · estado{' '}
            {artifact.target_act_state} · ata mutável criada:{' '}
            {noClaimLabel(artifact.mutable_draft_act_created)}
          </dd>
        </div>
        <div>
          <dt>Digest da fonte OCR</dt>
          <dd>
            {artifact.source_text_digest ? (
              <span className="mono">{artifact.source_text_digest}</span>
            ) : (
              '—'
            )}
          </dd>
        </div>
        <div>
          <dt>Páginas da fonte</dt>
          <dd>{paperBookOcrArtifactPageSpansLabel(artifact)}</dd>
        </div>
        <div>
          <dt>Revisão de origem</dt>
          <dd>
            {paperBookOcrReviewStatusLabel(artifact.source_review_status)}
            {artifact.source_reviewed_at ? (
              <>
                {' '}
                em{' '}
                <time className="mono" dateTime={artifact.source_reviewed_at}>
                  {artifact.source_reviewed_at}
                </time>{' '}
                por {artifact.source_reviewed_by ?? '—'}
              </>
            ) : null}
          </dd>
        </div>
        <div>
          <dt>Criado</dt>
          <dd>
            <time className="mono" dateTime={artifact.created_at}>
              {artifact.created_at}
            </time>{' '}
            por {artifact.created_by}
          </dd>
        </div>
        <div>
          <dt>Flags sem reivindicação</dt>
          <dd>
            conversão canónica: {noClaimLabel(artifact.canonical_conversion_claimed)} · minutas
            canónicas: {noClaimLabel(artifact.canonical_minutes_claimed)} · ata canónica:{' '}
            {noClaimLabel(artifact.canonical_act_created)} · documento canónico:{' '}
            {noClaimLabel(artifact.canonical_document_created)} · documento assinado:{' '}
            {noClaimLabel(artifact.signed_document_created)} · arquivo legal/pacote:{' '}
            {noClaimLabel(artifact.archive_package_created)} · certificação de arquivo:{' '}
            {noClaimLabel(artifact.archive_certification_claimed)} · PDF/A:{' '}
            {noClaimLabel(artifact.pdfa_created)} · PDF/UA:{' '}
            {noClaimLabel(artifact.pdfua_created)} · assinatura:{' '}
            {noClaimLabel(artifact.signature_created)} · selo: {noClaimLabel(artifact.seal_created)}{' '}
            · validade legal: {noClaimLabel(artifact.legal_validity_claimed)}
          </dd>
        </div>
        <div>
          <dt>Texto OCR bruto</dt>
          <dd>
            No artefacto: {noClaimLabel(artifact.source_extracted_text_in_artifact)} · no evento de
            ledger: {noClaimLabel(artifact.source_extracted_text_in_ledger_event)}
          </dd>
        </div>
      </dl>
    </section>
  );
}

function PaperBookOcrConversionDossierPanel({
  draft,
  dossier,
  loading,
  error,
  createPending,
  createError,
  onCreate,
}: {
  draft: PaperBookOcrDraftView;
  dossier: PaperBookOcrConversionDossierView | undefined;
  loading: boolean;
  error: unknown;
  createPending: boolean;
  createError: unknown;
  onCreate: (draft: PaperBookOcrDraftView) => void;
}) {
  if (dossier) {
    return (
      <section
        className="stack--tight"
        aria-label={`Dossier de conversão OCR ${dossier.dossier_id}`}
      >
        <div className="row-wrap">
          <Badge tone="ok">Dossier já registado</Badge>
          <Badge tone="warn">Só metadados</Badge>
          <Badge tone="warn">Não canónico</Badge>
        </div>
        <InlineWarning tone="info" title="Dossier de conversão só de metadados">
          <p>{dossier.dossier_notice}</p>
          <p>{dossier.legal_notice}</p>
        </InlineWarning>
        <dl className="deflist deflist--tight">
          <div>
            <dt>Dossier</dt>
            <dd>
              <span className="mono">{dossier.dossier_id}</span>
            </dd>
          </div>
          <div>
            <dt>Digest da fonte OCR</dt>
            <dd>
              {dossier.source_text_digest ? (
                <span className="mono">{dossier.source_text_digest}</span>
              ) : (
                '—'
              )}
            </dd>
          </div>
          <div>
            <dt>Páginas da fonte</dt>
            <dd>{paperBookOcrDossierPageSpansLabel(dossier)}</dd>
          </div>
          <div>
            <dt>Revisão de origem</dt>
            <dd>
              {paperBookOcrReviewStatusLabel(dossier.source_review_status)}
              {dossier.source_reviewed_at ? (
                <>
                  {' '}
                  em{' '}
                  <time className="mono" dateTime={dossier.source_reviewed_at}>
                    {dossier.source_reviewed_at}
                  </time>{' '}
                  por {dossier.source_reviewed_by ?? '—'}
                </>
              ) : null}
            </dd>
          </div>
          <div>
            <dt>Criado</dt>
            <dd>
              <time className="mono" dateTime={dossier.created_at}>
                {dossier.created_at}
              </time>{' '}
              por {dossier.created_by}
            </dd>
          </div>
          <div>
            <dt>Limites do dossier</dt>
            <dd>
              Ata criada: {noClaimLabel(dossier.act_created)} · ata canónica criada:{' '}
              {noClaimLabel(dossier.canonical_act_created)} · ata canónica reclamada:{' '}
              {noClaimLabel(dossier.canonical_minutes_claimed)} · documento canónico:{' '}
              {noClaimLabel(dossier.canonical_document_created)} · documento assinado:{' '}
              {noClaimLabel(dossier.signed_document_created)} · pacote de arquivo:{' '}
              {noClaimLabel(dossier.archive_package_created)} · PDF/A:{' '}
              {noClaimLabel(dossier.pdfa_created)} · PDF/UA: {noClaimLabel(dossier.pdfua_created)} ·
              assinatura: {noClaimLabel(dossier.signature_created)} · selo:{' '}
              {noClaimLabel(dossier.seal_created)} · validade legal:{' '}
              {noClaimLabel(dossier.legal_validity_claimed)}
            </dd>
          </div>
          <div>
            <dt>Texto OCR bruto</dt>
            <dd>
              Na resposta: {noClaimLabel(dossier.source_extracted_text_in_response)} · no evento de
              ledger: {noClaimLabel(dossier.source_extracted_text_in_ledger_event)}
            </dd>
          </div>
        </dl>
        {dossier.conversion_execution_artifacts?.length ? (
          <div
            className="stack--tight"
            aria-label={`Evidências de execução de conversão revista do dossier ${dossier.dossier_id}`}
          >
            <p className="card__label">Evidência de execução de conversão revista</p>
            {dossier.conversion_execution_artifacts.map((artifact) => (
              <PaperBookOcrConversionExecutionArtifactPanel
                key={artifact.artifact_id}
                artifact={artifact}
              />
            ))}
          </div>
        ) : null}
      </section>
    );
  }

  if (draft.review_status !== 'accepted') return null;

  return (
    <section
      className="stack--tight"
      aria-label={`Criar dossier de conversão OCR para ${draft.draft_id}`}
    >
      <InlineWarning tone="info" title="Dossier de conversão só de metadados">
        Cria ou devolve um dossier só com metadados, digest e evidência de revisão do rascunho OCR
        aceite. Não cria ata, documento, PDF/A, assinatura, selo, pacote de arquivo ou validade
        legal.
      </InlineWarning>
      {loading ? (
        <Skeleton height="3rem" />
      ) : error ? (
        <ErrorNote error={error} />
      ) : (
        <>
          {createError ? <ErrorNote error={createError} /> : null}
          <GateButton
            perm="book.import"
            type="button"
            variant="secondary"
            icon={<Icon.FileText />}
            disabled={createPending}
            onClick={() => onCreate(draft)}
          >
            {createPending
              ? 'A criar dossier só de metadados'
              : 'Criar dossier de conversão só de metadados'}
          </GateButton>
        </>
      )}
    </section>
  );
}

function PaperBookOcrDossierReviewSummary({
  dossiers,
  drafts,
  loading,
}: {
  dossiers: PaperBookOcrConversionDossierView[];
  drafts: PaperBookOcrDraftView[];
  loading: boolean;
}) {
  const acceptedDraft = drafts.find((draft) => draft.review_status === 'accepted') ?? null;
  const acceptedDossier = acceptedDraft
    ? (dossiers.find((dossier) => dossier.draft_id === acceptedDraft.draft_id) ?? null)
    : null;
  const reviewedDraft = acceptedDraft ?? drafts.find((draft) => draft.reviewed_at) ?? null;
  const acceptedWithoutCanonicalConversion =
    acceptedDraft !== null &&
    !acceptedDraft.canonical_act_created &&
    !acceptedDraft.canonical_document_created &&
    !acceptedDraft.canonical_minutes_claimed;
  const noRawOcrTextInDossier =
    acceptedDossier === null ||
    (!acceptedDossier.source_extracted_text_in_response &&
      !acceptedDossier.source_extracted_text_in_ledger_event);

  return (
    <section
      className="stack--tight"
      aria-label="Resumo de profundidade OCR e dossier do livro em papel"
    >
      <p className="card__label">Resumo OCR/dossier derivado</p>
      <dl className="deflist deflist--tight">
        <div>
          <dt>Rascunho revisto</dt>
          <dd>
            {reviewedDraft ? (
              <>
                {paperBookOcrReviewStatusLabel(reviewedDraft.review_status)} ·{' '}
                <span className="mono">{reviewedDraft.draft_id}</span>
              </>
            ) : (
              'Sem rascunho OCR revisto nos metadados carregados.'
            )}
          </dd>
        </div>
        <div>
          <dt>Rascunho aceite</dt>
          <dd>
            {acceptedDraft ? (
              <>
                Aceite para referência auxiliar
                {acceptedWithoutCanonicalConversion ? ', sem conversão canónica' : ''}.
              </>
            ) : (
              'Sem rascunho OCR aceite.'
            )}
          </dd>
        </div>
        <div>
          <dt>Dossier</dt>
          <dd>
            {loading
              ? 'A carregar metadados de dossier.'
              : acceptedDossier
                ? `Dossier só de metadados registado (${acceptedDossier.dossier_id}).`
                : acceptedDraft
                  ? 'Dossier só de metadados ainda não registado.'
                  : 'Sem dossier aplicável sem rascunho aceite.'}
          </dd>
        </div>
        <div>
          <dt>Texto OCR bruto no dossier</dt>
          <dd>{noRawOcrTextInDossier ? 'não' : 'sim'}</dd>
        </div>
        <div>
          <dt>Inclui</dt>
          <dd>
            Estado de revisão OCR, digest de texto quando indicado, páginas revistas, motor OCR e
            metadados de dossier quando existirem.
          </dd>
        </div>
        <div>
          <dt>Exclui</dt>
          <dd>
            Ata canónica, documento canónico, pacote de arquivo, assinatura, selo, PDF/A, PDF/UA e
            validade legal.
          </dd>
        </div>
        <div>
          <dt>Flags sem reivindicação</dt>
          <dd>
            Só metadados: sim · ata canónica: não · documento canónico: não · pacote de arquivo: não
            · assinatura: não · selo: não · PDF/A: não · PDF/UA: não · validade legal: não.
          </dd>
        </div>
      </dl>
    </section>
  );
}

function PaperBookOcrDraftPanel({ row }: { row: PaperBookImportView }) {
  const toast = useToast();
  const drafts = usePaperBookOcrDrafts(row.import_id);
  const dossiers = usePaperBookOcrConversionDossiers(row.import_id);
  const create = useCreatePaperBookOcrDraft();
  const createActDraft = useCreatePaperBookOcrDraftActDraft(row.book_ref);
  const createDossier = useCreatePaperBookOcrConversionDossier();
  const [extractedText, setExtractedText] = useState('');
  const [textDigest, setTextDigest] = useState('');
  const [startPage, setStartPage] = useState('1');
  const [endPage, setEndPage] = useState(String(Math.max(row.page_count, 1)));
  const [confidence, setConfidence] = useState('');
  const [engineName, setEngineName] = useState('operator-supplied-ocr');
  const [engineVersion, setEngineVersion] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [formError, setFormError] = useState<unknown>(null);
  const [createdActDrafts, setCreatedActDrafts] = useState<
    Record<string, PaperBookOcrDraftCanonicalDraftResponse>
  >({});

  useEffect(() => {
    setStartPage('1');
    setEndPage(String(Math.max(row.page_count, 1)));
  }, [row.import_id, row.page_count]);

  function submit(event: React.FormEvent) {
    event.preventDefault();
    setFormError(null);
    try {
      const text = trimmedOrNull(extractedText);
      const digest = trimmedOrNull(textDigest);
      if (!text && !digest) {
        throw new Error('Indique texto OCR auxiliar ou o digest SHA-256 desse texto.');
      }
      const engine = trimmedOrNull(engineName);
      if (!engine) throw new Error('Indique o motor OCR usado para produzir o rascunho.');
      const parsedStart = Number(startPage);
      const parsedEnd = Number(endPage);
      if (
        !Number.isInteger(parsedStart) ||
        !Number.isInteger(parsedEnd) ||
        parsedStart <= 0 ||
        parsedEnd < parsedStart
      ) {
        throw new Error('Indique um intervalo de páginas válido, com páginas positivas.');
      }
      const confidenceText = trimmedOrNull(confidence);
      const parsedConfidence = confidenceText === null ? null : Number(confidenceText);
      if (parsedConfidence !== null && !Number.isFinite(parsedConfidence)) {
        throw new Error('A confiança OCR deve ser um número entre 0 e 1.');
      }
      create.mutate(
        {
          importId: row.import_id,
          body: {
            extracted_text: text,
            text_digest: digest,
            page_spans: [{ start_page: parsedStart, end_page: parsedEnd }],
            confidence: parsedConfidence,
            engine_name: engine,
            engine_version: trimmedOrNull(engineVersion),
          },
        },
        {
          onSuccess: () => {
            setExtractedText('');
            setTextDigest('');
            setConfidence('');
            setAcknowledged(false);
            toast.success('Rascunho OCR guardado como metadado auxiliar não canónico.');
          },
          onError: (e) => toast.error(e),
        },
      );
    } catch (e) {
      setFormError(e);
      toast.error(e);
    }
  }

  const rows = drafts.data ?? [];
  const dossierByDraftId = new Map(
    (dossiers.data ?? []).map((dossier) => [dossier.draft_id, dossier]),
  );

  function onCreateActDraft(draft: PaperBookOcrDraftView) {
    createActDraft.mutate(
      { importId: row.import_id, draftId: draft.draft_id },
      {
        onSuccess: (result) => {
          setCreatedActDrafts((current) => ({ ...current, [draft.draft_id]: result }));
          toast.success(
            'Rascunho de ata criado sem documento canónico, PDF/A, assinatura ou selo.',
          );
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  function onCreateDossier(draft: PaperBookOcrDraftView) {
    createDossier.mutate(
      { importId: row.import_id, draftId: draft.draft_id },
      {
        onSuccess: () =>
          toast.success(
            'Dossier de conversão só de metadados registado; não criou ata, documento, PDF/A, assinatura ou selo.',
          ),
        onError: (e) => toast.error(e),
      },
    );
  }

  return (
    <section className="stack--tight" aria-label={`Rascunhos OCR da importação ${row.import_id}`}>
      <InlineWarning tone="info" title="Rascunhos OCR e revisão auxiliar">
        {PAPER_BOOK_OCR_DRAFT_COPY}
      </InlineWarning>
      <PaperBookOcrDossierReviewSummary
        dossiers={dossiers.data ?? []}
        drafts={rows}
        loading={dossiers.isLoading}
      />
      <form className="form" aria-label="Criar rascunho OCR auxiliar" onSubmit={submit}>
        <Field
          label="Texto OCR auxiliar"
          htmlFor={`ocr-text-${row.import_id}`}
          hint="Opcional se indicar digest; este texto é auxiliar e não é texto legal nem ata canónica."
        >
          <TextArea
            id={`ocr-text-${row.import_id}`}
            rows={4}
            value={extractedText}
            onChange={(event) => setExtractedText(event.target.value)}
          />
        </Field>
        <div className="form-grid">
          <Field
            label="Digest SHA-256 do texto"
            htmlFor={`ocr-digest-${row.import_id}`}
            hint="Opcional; use quando não quiser armazenar o texto OCR auxiliar."
          >
            <Input
              id={`ocr-digest-${row.import_id}`}
              value={textDigest}
              onChange={(event) => setTextDigest(event.target.value)}
              placeholder="64 caracteres hexadecimais"
            />
          </Field>
          <Field label="Página inicial" htmlFor={`ocr-start-page-${row.import_id}`}>
            <Input
              id={`ocr-start-page-${row.import_id}`}
              type="number"
              min="1"
              value={startPage}
              onChange={(event) => setStartPage(event.target.value)}
            />
          </Field>
          <Field label="Página final" htmlFor={`ocr-end-page-${row.import_id}`}>
            <Input
              id={`ocr-end-page-${row.import_id}`}
              type="number"
              min="1"
              value={endPage}
              onChange={(event) => setEndPage(event.target.value)}
            />
          </Field>
          <Field
            label="Confiança"
            htmlFor={`ocr-confidence-${row.import_id}`}
            hint="Opcional; valor decimal de 0 a 1."
          >
            <Input
              id={`ocr-confidence-${row.import_id}`}
              type="number"
              min="0"
              max="1"
              step="0.01"
              value={confidence}
              onChange={(event) => setConfidence(event.target.value)}
            />
          </Field>
          <Field label="Motor OCR" htmlFor={`ocr-engine-${row.import_id}`}>
            <Input
              id={`ocr-engine-${row.import_id}`}
              value={engineName}
              onChange={(event) => setEngineName(event.target.value)}
            />
          </Field>
          <Field label="Versão do motor" htmlFor={`ocr-engine-version-${row.import_id}`}>
            <Input
              id={`ocr-engine-version-${row.import_id}`}
              value={engineVersion}
              onChange={(event) => setEngineVersion(event.target.value)}
            />
          </Field>
        </div>
        <label className="checkline" htmlFor={`ocr-create-ack-${row.import_id}`}>
          <input
            id={`ocr-create-ack-${row.import_id}`}
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
          />
          Confirmo que este rascunho OCR é auxiliar, não canónico e não cria ata, documento,
          assinatura ou validade legal.
        </label>
        {formError ? <ErrorNote error={formError} /> : null}
        <GateButton
          perm="book.import"
          type="submit"
          variant="secondary"
          icon={<Icon.Save />}
          disabled={create.isPending || !acknowledged}
        >
          {create.isPending ? 'A guardar rascunho OCR' : 'Guardar rascunho OCR'}
        </GateButton>
      </form>

      {drafts.isLoading ? (
        <Skeleton height="6rem" />
      ) : drafts.error ? (
        <ErrorNote error={drafts.error} />
      ) : rows.length === 0 ? (
        <EmptyState title="Sem rascunhos OCR registados">
          <p>Esta importação preservada ainda não tem OCR auxiliar para revisão.</p>
        </EmptyState>
      ) : (
        <ul className="plain-list" aria-label="Rascunhos OCR não canónicos">
          {rows.map((draft) => (
            <li key={draft.draft_id} className="chainrow">
              <div className="stack--tight">
                <div className="row-wrap">
                  <Badge tone="warn">Não canónico</Badge>
                  <Badge tone={paperBookOcrReviewTone(draft.review_status)}>
                    {paperBookOcrReviewStatusLabel(draft.review_status)}
                  </Badge>
                  <span className="mono">{draft.draft_id}</span>
                </div>
                <InlineWarning tone="info" title="Aviso do rascunho OCR">
                  {draft.draft_notice || PAPER_BOOK_OCR_DRAFT_COPY}
                </InlineWarning>
                <dl className="deflist deflist--tight">
                  <div>
                    <dt>Texto extraído</dt>
                    <dd>{paperBookOcrTextPreview(draft)}</dd>
                  </div>
                  <div>
                    <dt>Digest do texto</dt>
                    <dd>
                      {draft.text_digest ? <span className="mono">{draft.text_digest}</span> : '—'}
                    </dd>
                  </div>
                  <div>
                    <dt>Páginas revistas</dt>
                    <dd>{paperBookOcrPageSpansLabel(draft)}</dd>
                  </div>
                  <div>
                    <dt>Motor</dt>
                    <dd>
                      {draft.engine.name}
                      {draft.engine.version ? ` ${draft.engine.version}` : ''}
                      {draft.confidence !== null ? ` · confiança ${draft.confidence}` : ''}
                    </dd>
                  </div>
                  <div>
                    <dt>Criado</dt>
                    <dd>
                      <time className="mono" dateTime={draft.created_at}>
                        {draft.created_at}
                      </time>{' '}
                      por {draft.created_by}
                    </dd>
                  </div>
                  <div>
                    <dt>Revisto</dt>
                    <dd>
                      {draft.reviewed_at ? (
                        <>
                          <time className="mono" dateTime={draft.reviewed_at}>
                            {draft.reviewed_at}
                          </time>{' '}
                          por {draft.reviewed_by ?? '—'}
                        </>
                      ) : (
                        '—'
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt>Nota</dt>
                    <dd>{draft.review_note ?? '—'}</dd>
                  </div>
                  <div>
                    <dt>Limites</dt>
                    <dd>
                      Texto autoritativo: {draft.authoritative_text_claimed ? 'sim' : 'não'} · ata
                      canónica: {draft.canonical_act_created ? 'sim' : 'não'} · documento canónico:{' '}
                      {draft.canonical_document_created ? 'sim' : 'não'} · assinatura:{' '}
                      {draft.signature_created ? 'sim' : 'não'} · validade legal:{' '}
                      {draft.legal_validity_claimed ? 'sim' : 'não'}
                    </dd>
                  </div>
                </dl>
                <PaperBookOcrConversionDossierPanel
                  draft={draft}
                  dossier={dossierByDraftId.get(draft.draft_id)}
                  loading={dossiers.isLoading}
                  error={dossiers.error}
                  createPending={createDossier.isPending}
                  createError={createDossier.error}
                  onCreate={onCreateDossier}
                />
                {draft.review_status === 'accepted' ? (
                  <div className="stack--tight">
                    <InlineWarning tone="info" title="Criar rascunho de ata">
                      Cria uma ata em estado Draft com o texto OCR como apoio de deliberações. Não
                      cria documento canónico, PDF/A, assinatura, selo nem aceitação de validade
                      legal.
                    </InlineWarning>
                    {createdActDrafts[draft.draft_id] ? (
                      <p className="muted">
                        Rascunho criado:{' '}
                        <Link to={`/atas/${createdActDrafts[draft.draft_id].act.id}`}>
                          abrir ata
                        </Link>
                        . Documento canónico:{' '}
                        {createdActDrafts[draft.draft_id].canonical_document_created
                          ? 'sim'
                          : 'não'}{' '}
                        · PDF/A: {createdActDrafts[draft.draft_id].pdfa_created ? 'sim' : 'não'} ·
                        assinatura:{' '}
                        {createdActDrafts[draft.draft_id].signature_created ? 'sim' : 'não'} · selo:{' '}
                        {createdActDrafts[draft.draft_id].seal_created ? 'sim' : 'não'} · validade
                        legal:{' '}
                        {createdActDrafts[draft.draft_id].legal_validity_claimed ? 'sim' : 'não'}
                      </p>
                    ) : null}
                    {createdActDrafts[draft.draft_id]?.conversion_execution_artifact ? (
                      <PaperBookOcrConversionExecutionArtifactPanel
                        artifact={createdActDrafts[draft.draft_id].conversion_execution_artifact}
                      />
                    ) : null}
                    {createActDraft.error ? <ErrorNote error={createActDraft.error} /> : null}
                    <GateButton
                      perm="act.draft"
                      type="button"
                      variant="secondary"
                      icon={<Icon.Plus />}
                      disabled={
                        createActDraft.isPending ||
                        !draft.extracted_text ||
                        Boolean(createdActDrafts[draft.draft_id])
                      }
                      onClick={() => onCreateActDraft(draft)}
                    >
                      {createActDraft.isPending
                        ? 'A criar rascunho de ata'
                        : draft.extracted_text
                          ? 'Criar rascunho de ata'
                          : 'Texto OCR necessário'}
                    </GateButton>
                  </div>
                ) : null}
                <PaperBookOcrDraftReviewForm draft={draft} importId={row.import_id} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function PaperBookImportsPanel({ book }: { book: BookView }) {
  const toast = useToast();
  const entity = useEntity(book.entity_id);
  const imports = usePaperBookImports(book.id);
  const validate = useValidatePaperBookImport();
  const preserve = usePreservePaperBookImport();
  const download = useDownloadPaperBookImport();
  const enqueueOcr = useEnqueuePaperBookImportOcr(book.id);
  const runOcr = useRunPaperBookImportOcr(book.id);
  const [file, setFile] = useState<File | null>(null);
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [pageCount, setPageCount] = useState('');
  const [sourceFilename, setSourceFilename] = useState('');
  const [notes, setNotes] = useState('');
  const [report, setReport] = useState<
    PaperBookImportReport | PaperBookImportPreservationReport | null
  >(null);
  const [formError, setFormError] = useState<unknown>(null);
  const [localOcrCandidate, setLocalOcrCandidate] = useState<PaperBookImportView | null>(null);
  const ocrMutationPending = enqueueOcr.isPending || runOcr.isPending;

  function onDownload(row: PaperBookImportView) {
    download.mutate(row.import_id, {
      onSuccess: async (blob) => {
        try {
          showSaveResult(
            await saveBlobAs({
              blob,
              filename: paperBookImportFilename(row),
              contentType: row.content_type || blob.type,
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

  function onQueueOcr(row: PaperBookImportView) {
    enqueueOcr.mutate(row.import_id, {
      onSuccess: () => toast.success('OCR colocado em fila como metadado não canónico.'),
      onError: (e) => toast.error(e),
    });
  }

  async function confirmRunLocalOcr() {
    if (!localOcrCandidate) return;
    const result = await runOcr.mutateAsync(localOcrCandidate.import_id);
    if (result.ocr_status !== 'completed' || !result.draft) {
      throw new Error(
        result.failure_reason
          ? `OCR local falhou (${result.failure_reason}); nenhum rascunho auxiliar foi criado.`
          : 'OCR local não criou rascunho auxiliar; nenhum rascunho foi criado.',
      );
    }
    toast.success(
      'OCR local concluído: rascunho OCR auxiliar não canónico criado e disponível para revisão.',
    );
  }

  function showSaveResult(result: SaveBlobResult) {
    if (result.kind === 'cancelled') {
      toast.info(saveBlobResultMessage(result));
      return;
    }
    toast.success(saveBlobResultMessage(result));
  }

  const rows = imports.data ?? [];
  const entityName = entity.data?.name ?? '';
  const entityNipc = entity.data?.nipc ?? '';

  function resetCandidate() {
    setReport(null);
    setFormError(null);
  }

  async function candidateBody() {
    if (!file) throw new Error('Escolha o pacote digitalizado antes de validar.');
    const bytes = await file.arrayBuffer();
    const digest = await sha256Hex(bytes);
    return {
      entity_ref: book.entity_id,
      entity_name: entityName,
      entity_nipc: entityNipc,
      book_ref: book.id,
      date_from: dateFrom,
      date_to: dateTo,
      page_count: Number(pageCount),
      source_filename: sourceFilename.trim() || file.name || null,
      digest,
      notes: notes.trim() || null,
    };
  }

  async function onValidate() {
    setFormError(null);
    try {
      const body = await candidateBody();
      setReport(await validate.mutateAsync(body));
    } catch (e) {
      setFormError(e);
      toast.error(e);
    }
  }

  async function onPreserve() {
    setFormError(null);
    try {
      if (!file) throw new Error('Escolha o pacote digitalizado antes de preservar.');
      const bytes = await file.arrayBuffer();
      const digest = await sha256Hex(bytes);
      const body = await candidateBody();
      setReport(
        await preserve.mutateAsync({
          ...body,
          digest,
          content_base64: arrayBufferToBase64(bytes),
          content_type: file.type || 'application/octet-stream',
          declared_sha256: digest,
          size_bytes: bytes.byteLength,
        }),
      );
      toast.success('Pacote de livro em papel preservado como evidência não canónica.');
    } catch (e) {
      setFormError(e);
      toast.error(e);
    }
  }

  return (
    <Card title="Importações de livro em papel preservadas">
      <div className="stack">
        <ConfirmActionModal
          open={localOcrCandidate !== null}
          onClose={() => setLocalOcrCandidate(null)}
          title="Executar OCR local"
          intro={
            <div className="stack--tight">
              <p>
                O resultado será um rascunho OCR auxiliar não canónico para revisão da importação
                preservada.
              </p>
              <p>
                Esta ação não cria ata canónica, documento canónico, PDF/A, assinatura ou validade
                legal.
              </p>
            </div>
          }
          confirmLabel="Confirmar execução de OCR local"
          pendingLabel="A executar OCR local"
          pending={runOcr.isPending}
          onConfirm={confirmRunLocalOcr}
        />
        <InlineWarning tone="warn" title="Evidência não canónica">
          Estes pacotes preservam cópias de livros em papel para consulta. Não substituem atas
          digitais canónicas e não declaram validade legal, PDF/A, validade de assinatura ou
          assinatura qualificada.
        </InlineWarning>
        <InlineWarning tone="info" title="Orientação para revisão">
          Valide datas, contagem de páginas, fixidez e contexto do livro antes de preservar. A
          ligação exibida aqui é apenas contextual: não cria nem altera cadeias de atas, nem
          transforma a importação em ata digital canónica.
        </InlineWarning>

        <form className="form">
          <Field label="Pacote digitalizado" htmlFor="paper-import-file">
            <Input
              id="paper-import-file"
              type="file"
              accept="application/pdf,application/zip,application/octet-stream,.pdf,.zip"
              onChange={(e) => {
                const next = e.target.files?.[0] ?? null;
                setFile(next);
                setSourceFilename(next?.name ?? '');
                resetCandidate();
              }}
            />
          </Field>
          <div className="form-grid">
            <Field label="Data inicial" htmlFor="paper-import-from">
              <Input
                id="paper-import-from"
                type="date"
                value={dateFrom}
                onChange={(e) => {
                  setDateFrom(e.target.value);
                  resetCandidate();
                }}
              />
            </Field>
            <Field label="Data final" htmlFor="paper-import-to">
              <Input
                id="paper-import-to"
                type="date"
                value={dateTo}
                onChange={(e) => {
                  setDateTo(e.target.value);
                  resetCandidate();
                }}
              />
            </Field>
            <Field label="Páginas" htmlFor="paper-import-pages">
              <Input
                id="paper-import-pages"
                type="number"
                min="1"
                value={pageCount}
                onChange={(e) => {
                  setPageCount(e.target.value);
                  resetCandidate();
                }}
              />
            </Field>
            <Field
              label="Intervalo no pacote"
              htmlFor="paper-import-page-range"
              hint="A API atual preserva a contagem de páginas; intervalo inicial/final fica apenas como orientação local."
            >
              <Input
                id="paper-import-page-range"
                value={pageCount ? `1 a ${pageCount}` : 'Defina a contagem de páginas'}
                disabled
                readOnly
              />
            </Field>
            <Field label="Nome do ficheiro" htmlFor="paper-import-filename">
              <Input
                id="paper-import-filename"
                value={sourceFilename}
                onChange={(e) => {
                  setSourceFilename(e.target.value);
                  resetCandidate();
                }}
              />
            </Field>
          </div>
          <Field label="Notas" htmlFor="paper-import-notes">
            <TextArea
              id="paper-import-notes"
              rows={3}
              value={notes}
              placeholder="Ex.: digitalizado a partir do livro encadernado guardado no arquivo físico"
              onChange={(e) => {
                setNotes(e.target.value);
                resetCandidate();
              }}
            />
          </Field>
          <p className="field__hint">
            A entidade e o livro são preenchidos a partir deste detalhe: {entityName || '—'} ·{' '}
            {entityNipc || '—'} · {book.id}
          </p>
          <div className="form__actions">
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.Search />}
              disabled={validate.isPending || preserve.isPending || entity.isLoading}
              onClick={onValidate}
            >
              {validate.isPending ? 'A validar' : 'Validar sem preservar'}
            </Button>
            <GateButton
              perm="book.import"
              type="button"
              variant="primary"
              icon={<Icon.Tray />}
              disabled={preserve.isPending || entity.isLoading}
              onClick={onPreserve}
            >
              {preserve.isPending ? 'A preservar' : 'Preservar pacote'}
            </GateButton>
          </div>
        </form>

        {formError ? <ErrorNote error={formError} /> : null}
        {report ? (
          <InlineWarning tone="info" title="Relatório não canónico">
            <p>{report.legal_notice}</p>
            <p>
              Estado: {report.candidate_classification.preservation_status}. Validade legal
              declarada: não.
            </p>
          </InlineWarning>
        ) : null}

        {imports.isLoading ? (
          <SkeletonTable cols={4} />
        ) : imports.error ? (
          <ErrorNote error={imports.error} />
        ) : rows.length === 0 ? (
          <EmptyState title="Sem importações preservadas">
            <p>Não há pacotes de livro em papel preservados para esta referência de livro.</p>
          </EmptyState>
        ) : (
          <Table
            head={
              <tr>
                <th>Ficheiro</th>
                <th>Contexto</th>
                <th>Revisão e fixidez</th>
                <th />
              </tr>
            }
          >
            {rows.map((row) => (
              <Fragment key={row.import_id}>
                <tr>
                  <td>
                    <div className="stack--tight">
                      <span>{row.source_filename ?? row.import_id}</span>
                      <span className="muted">
                        {formatBytes(row.size_bytes)} · {row.content_type} · {row.page_count}{' '}
                        páginas
                      </span>
                    </div>
                  </td>
                  <td>
                    <div className="stack--tight">
                      <span>
                        {row.date_from} a {row.date_to}
                      </span>
                      <span className="muted">Intervalo: {paperBookPageRange(row)}</span>
                      <span className="muted">
                        Livro: <Link to={`/livros/${row.book_ref}`}>{row.book_ref}</Link> ·
                        Entidade: {row.entity_name || row.entity_ref}
                      </span>
                      <span className="muted">
                        Âmbito de arquivo: paper-book-import:{row.import_id}
                      </span>
                    </div>
                  </td>
                  <td>
                    <div className="stack--tight">
                      <Badge tone={row.non_canonical ? 'warn' : 'neutral'}>
                        {row.non_canonical ? 'Não canónico' : 'Importado'}
                      </Badge>
                      <Badge tone={paperBookReviewTone(row)}>
                        {paperBookReviewStateLabel(row)}
                      </Badge>
                      <Badge tone={row.ocr_status === 'completed' ? 'ok' : 'neutral'}>
                        {paperBookOcrStatusLabel(row.ocr_status)}
                      </Badge>
                      <span className="muted">
                        OCR: metadado apenas; texto armazenado:{' '}
                        {row.ocr_text_stored ? 'sim' : 'não'}; texto autoritativo:{' '}
                        {row.authoritative_text_claimed ? 'sim' : 'não'}
                      </span>
                      <span className="mono">{row.sha256.slice(0, 16)}...</span>
                    </div>
                  </td>
                  <td>
                    <div className="row-wrap">
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
                      <GateButton
                        perm="book.import"
                        type="button"
                        variant="ghost"
                        icon={<Icon.Search />}
                        disabled={ocrMutationPending || !canQueueOcr(row.ocr_status)}
                        onClick={() => onQueueOcr(row)}
                      >
                        {enqueueOcr.isPending ? 'A colocar em fila' : 'Colocar OCR em fila'}
                      </GateButton>
                      <GateButton
                        perm="book.import"
                        type="button"
                        variant="ghost"
                        icon={<Icon.Search />}
                        disabled={ocrMutationPending || !canQueueOcr(row.ocr_status)}
                        onClick={() => setLocalOcrCandidate(row)}
                      >
                        {runOcr.isPending ? 'A executar OCR local' : 'Executar OCR local'}
                      </GateButton>
                    </div>
                  </td>
                </tr>
                <tr>
                  <td colSpan={4}>
                    <PaperBookOcrDraftPanel row={row} />
                  </td>
                </tr>
              </Fragment>
            ))}
          </Table>
        )}
      </div>
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
  const localDglabManifestDownload = useDownloadBookLocalDglabInterchangeManifest(id);

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
              contentType: 'application/zip',
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

  function onDownloadLocalDglabManifest() {
    localDglabManifestDownload.mutate(undefined, {
      onSuccess: async (manifest) => {
        try {
          showSaveResult(
            await saveBlobAs({
              blob: localDglabInterchangeManifestBlob(manifest),
              filename: localDglabInterchangeManifestFilename(b.id),
              contentType: LOCAL_DGLAB_MANIFEST_CONTENT_TYPE,
              filters: [{ name: 'JSON', extensions: ['json'] }],
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
          <div className="row-wrap">
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
            <GateButton
              perm="book.export"
              scope={scopeBook(b.id)}
              type="button"
              variant="secondary"
              icon={<Icon.FileText />}
              disabled={localDglabManifestDownload.isPending}
              onClick={onDownloadLocalDglabManifest}
            >
              {localDglabManifestDownload.isPending
                ? 'A descarregar manifesto DGLAB local'
                : 'Manifesto DGLAB local (metadados JSON)'}
            </GateButton>
          </div>
        }
      />

      <InlineWarning tone="info" title="Manifesto DGLAB local: só metadados">
        O manifesto DGLAB local é um scaffold JSON derivado do pacote interno. Não é exportação
        oficial DGLAB, submissão governamental, certificação arquivística legal, certificação PDF/A,
        PAdES ou PDF-UA, nem registo de descarte destrutivo.
      </InlineWarning>

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
            <dd>
              {formatBookSignatories(
                b.required_signatory_records_abertura,
                b.required_signatories_abertura,
              )}
            </dd>
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
              <div>
                <dt>{t('books.close.signatories')}</dt>
                <dd>
                  {formatBookSignatories(
                    b.required_signatory_records_encerramento,
                    b.required_signatories_encerramento,
                  )}
                </dd>
              </div>
            </>
          ) : null}
        </dl>
      </Card>

      <LegalHoldPanel bookId={b.id} />

      <PaperBookImportsPanel book={b} />

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
