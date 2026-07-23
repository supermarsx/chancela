/**
 * A single book, full width. The surface splits into four sub-tabs (t25) — Atas ·
 * Termo de abertura · Retenção legal · Importações — reusing the SHARED `<SubNav>` and the
 * path-segment deep-link convention already established by Configurações (`SettingsPage.tsx`),
 * so there is exactly one sub-tab idiom in the app — `/books/:id/opening`. `Atas` is the default
 * and carries no segment, so `/books/:id` still lands on the minutes.
 *
 * Like the Ferramentas/Configurações pill, `<SubNav>` is a `role="group"` of `aria-pressed`
 * buttons rather than an ARIA tablist — deliberately matched here rather than forked.
 *
 * Atas are sealed first by number, then drafts (the API orders them). While the book is
 * Open, drafting an ata (WFL-14) and closing the book (WFL-13) are neat buttons in the Atas
 * panel header, each opening its own route (`/books/:id/new-act`, `/books/:id/close`)
 * so the view is no longer split by an aside (t13 item 7). The page header (outside the
 * tabs, because it applies to the whole book) exposes the read-only Chancela internal
 * preservation ZIP and the local DGLAB interchange manifest.
 */
import { Fragment, useEffect, useState, type ReactNode } from 'react';
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
  usePaperBookOcrCanonicalRehearsal,
  usePaperBookOcrConversionDossiers,
  usePaperBookOcrDrafts,
  usePaperBookImports,
  usePreservePaperBookImport,
  usePrivacyRetentionDueCandidates,
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
  PaperBookOcrCanonicalRehearsalReport,
  PaperBookOcrConversionDossierView,
  PaperBookOcrConversionExecutionArtifactView,
  PaperBookOcrDraftCanonicalDraftResponse,
  PaperBookOcrDraftReviewPatchStatus,
  PaperBookOcrDraftView,
  PaperBookOcrStatus,
  RetentionDueCandidate,
} from '../../api/types';
import {
  bookKindLabels,
  bookStateLabels,
  closingReasonLabels,
  numberingSchemeLabels,
  signatoryCapacityLabels,
} from '../../api/labels';
import { useUnsavedChanges } from '../../hooks/useUnsavedChanges';
import { t as translateNow, useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import {
  Badge,
  Button,
  Card,
  DateOnly,
  DateTime,
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
  SubNav,
  Table,
  TextArea,
  useToast,
} from '../../ui';
import { useSectionNav } from '../../app/navPath';
import { ConfirmActionModal } from '../../ui/ConfirmActionModal';
import {
  GateButton,
  GateButtonLink,
  PermissionDeniedNote,
  scopeBook,
  useCan,
} from '../session/permissions';
import { BookActsList } from './BookActsList';
import { TermoAberturaEditor } from './TermoAberturaEditor';
import { TermoEncerramentoEditor } from './TermoEncerramentoEditor';
import { useEncerramentoT } from './termoEncerramentoStrings';

/**
 * The book sub-tabs, in the order the operator asked for. Labels reuse the section titles
 * they head (identical text), exactly as the Configurações sub-nav does.
 */
type BookSection = 'acts' | 'opening' | 'retention' | 'imports';

const BOOK_SECTIONS: { id: BookSection; label: MessageKey; icon: ReactNode }[] = [
  { id: 'acts', label: 'books.atas', icon: <Icon.Layers /> },
  { id: 'opening', label: 'books.termoAbertura', icon: <Icon.BookPlus /> },
  { id: 'retention', label: 'books.detail.legalHold.title', icon: <Icon.Scale /> },
  // Short label: the imports card title is a full sentence, too long for a pill.
  { id: 'imports', label: 'books.detail.subnav.imports', icon: <Icon.Tray /> },
];

const isBookSection = (value: string | undefined): value is BookSection =>
  BOOK_SECTIONS.some((section) => section.id === value);

/** An unknown segment falls back to Atas rather than blanking the panel. */
const parseBookSection = (raw: string | undefined): BookSection =>
  isBookSection(raw) ? raw : 'acts';

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

function paperBookRehearsalStatusLabel(status: string): string {
  switch (status) {
    case 'local_rehearsal_ready':
      return 'evidência local reunida';
    case 'blocked':
      return 'bloqueado por metadados locais';
    default:
      return status;
  }
}

const PAPER_BOOK_REHEARSAL_NO_CLAIM_FLAGS: Array<
  keyof PaperBookOcrCanonicalRehearsalReport['no_claims']
> = [
  'records_mutated',
  'external_ocr_called',
  'external_validator_called',
  'external_legal_service_called',
  'canonical_conversion_claimed',
  'ocr_accuracy_claimed',
  'legal_review_claimed',
  'legal_validity_claimed',
  'canonical_minutes_claimed',
  'canonical_act_created',
  'canonical_document_created',
  'sealed_document_created',
  'signed_document_created',
  'archive_package_created',
  'archive_certification_claimed',
  'pdfa_created',
  'pdfa_certification_claimed',
  'pdfua_created',
  'pdfua_certification_claimed',
  'signature_created',
  'signing_requested',
  'signature_validity_claimed',
  'qualified_signature_claimed',
  'dglab_certification_claimed',
  'raw_ocr_text_in_report',
];

function paperBookRehearsalNoClaimText(
  noClaims: PaperBookOcrCanonicalRehearsalReport['no_claims'],
): string {
  return PAPER_BOOK_REHEARSAL_NO_CLAIM_FLAGS.map(
    (flag) => `${flag}: ${String(noClaims[flag])}`,
  ).join(' · ');
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
  const t = useT();
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
  const workflow = hold.data?.operator_workflow;

  return (
    <Card title={t('books.detail.legalHold.title')}>
      <div className="stack">
        {hold.isLoading ? (
          <SkeletonDeflist />
        ) : hold.error ? (
          <ErrorNote error={hold.error} />
        ) : (
          <>
            <InlineWarning
              tone={active ? 'warn' : 'info'}
              title={
                active
                  ? t('books.detail.legalHold.stateActive')
                  : t('books.detail.legalHold.stateNone')
              }
            >
              {' '}
              {t('uiLiteral.bookDetailPage.aRetencaoLegalBloqueiaODescartePorRegras')}{' '}
            </InlineWarning>
            <dl className="deflist">
              <div>
                <dt>{t('uiLiteral.bookDetailPage.estado')}</dt>
                <dd>
                  <Badge tone={active ? 'warn' : 'neutral'}>
                    {active ? 'Retenção legal ativa' : 'Sem retenção legal'}
                  </Badge>
                </dd>
              </div>
              {hold.data?.actor ? (
                <div>
                  <dt>{t('uiLiteral.bookDetailPage.ator')}</dt>
                  <dd>{hold.data.actor}</dd>
                </div>
              ) : null}
              {hold.data?.set_at ? (
                <div>
                  <dt>{t('uiLiteral.bookDetailPage.definidaEm')}</dt>
                  {/* When the hold was placed is part of the retention audit trail — evidentiary. */}
                  <dd>
                    <DateTime value={hold.data.set_at} evidentiary />
                  </dd>
                </div>
              ) : null}
              {workflow ? (
                <>
                  <div>
                    <dt>{t('uiLiteral.bookDetailPage.fluxoOperador')}</dt>
                    <dd>{workflow.status}</dd>
                  </div>
                  <div>
                    <dt>{t('uiLiteral.bookDetailPage.bloqueiaRevisaoDeDescarte')}</dt>
                    <dd>{String(workflow.disposal_review_blocked)}</dd>
                  </div>
                  <div>
                    <dt>{t('uiLiteral.bookDetailPage.proximoPasso')}</dt>
                    <dd>{workflow.next_step}</dd>
                  </div>
                  <div>
                    <dt>{t('uiLiteral.bookDetailPage.flagsSemExecucao')}</dt>
                    <dd>
                      destructive_disposal_completed:{' '}
                      {String(workflow.destructive_disposal_completed)}{' '}
                      {t('uiLiteral.bookDetailPage.disposalApproved')}{' '}
                      {String(workflow.disposal_approved)}{' '}
                      {t('uiLiteral.bookDetailPage.legalComplianceClaimed')}{' '}
                      {String(workflow.legal_compliance_claimed)}
                    </dd>
                  </div>
                </>
              ) : null}
            </dl>
            {workflow ? <p className="field__hint">{workflow.review_note}</p> : null}
          </>
        )}

        <form className="form" onSubmit={submit}>
          <Field label={t('books.detail.legalHold.reasonLabel')} htmlFor="book-legal-hold-reason">
            <TextArea
              id="book-legal-hold-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              placeholder={t('books.detail.legalHold.reasonPlaceholder')}
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

/**
 * Retention information for THIS book, alongside the legal hold that blocks its disposal.
 *
 * There is no per-book retention endpoint: retention lives instance-wide under
 * `/v1/privacy/retention-*`. What IS per-book is the read-only due-candidate scanner
 * (`GET /v1/privacy/retention-due-candidates`), whose rows carry a `book_id` — so this
 * panel loads that report and shows only the candidates naming this book, saying plainly
 * that the policies themselves are managed in Configurações → Privacidade.
 *
 * The scanner is gated `user.manage|settings.manage@Global`, which a book reader may well
 * not hold; rather than firing a request that 403s, the query is only enabled when the
 * permission is held and an honest note replaces the table otherwise. Nothing here mutates.
 */
function BookRetentionPanel({ bookId }: { bookId: string }) {
  const t = useT();
  const can = useCan();
  const canReadRetention = can('user.manage') || can('settings.manage');
  const candidates = usePrivacyRetentionDueCandidates(canReadRetention);
  const rows: RetentionDueCandidate[] = (candidates.data?.candidates ?? []).filter(
    (candidate) => candidate.book_id === bookId,
  );

  return (
    <Card title={t('settings.privacy.dueCandidates.title')}>
      <div className="stack">
        <InlineWarning tone="info" title={t('settings.privacy.retention.notice.title')}>
          {t('books.detail.retention.scopeNote')}
        </InlineWarning>

        {!canReadRetention ? (
          <PermissionDeniedNote />
        ) : candidates.isLoading ? (
          <SkeletonTable cols={3} />
        ) : candidates.error ? (
          <ErrorNote error={candidates.error} />
        ) : rows.length === 0 ? (
          <EmptyState title={t('settings.privacy.dueCandidates.empty.title')}>
            <p>{t('settings.privacy.dueCandidates.empty.body')}</p>
          </EmptyState>
        ) : (
          <Table
            head={
              <tr>
                <th>{t('settings.privacy.dueCandidates.column.record')}</th>
                <th>{t('settings.privacy.dueCandidates.column.policy')}</th>
                <th>{t('settings.privacy.dueCandidates.column.due')}</th>
              </tr>
            }
          >
            {rows.map((candidate) => (
              <tr key={candidate.candidate_id}>
                <td data-label={t('settings.privacy.dueCandidates.column.record')}>
                  <div className="stack--tight">
                    <span className="mono">{candidate.record_id}</span>
                    <span className="muted">
                      {candidate.scope} / {candidate.category}
                    </span>
                  </div>
                </td>
                <td data-label={t('settings.privacy.dueCandidates.column.policy')}>
                  <div className="stack--tight">
                    <span>{candidate.policy_name}</span>
                    <span className="muted">
                      {candidate.schedule_id} · {candidate.retention_period}
                    </span>
                    <span>{candidate.disposal_action}</span>
                  </div>
                </td>
                <td data-label={t('settings.privacy.dueCandidates.column.due')}>
                  <div className="stack--tight">
                    <span>
                      {t('settings.privacy.dueCandidates.due')}:{' '}
                      {candidate.due_date ? (
                        <DateOnly value={candidate.due_date} />
                      ) : (
                        t('settings.privacy.dueCandidates.noDueDate')
                      )}
                    </span>
                    <Badge tone={candidate.overdue ? 'warn' : 'neutral'}>
                      {candidate.overdue
                        ? t('settings.privacy.advisory.overdue')
                        : t('settings.privacy.retention.active.true')}
                    </Badge>
                    <span className="muted">
                      {t('settings.privacy.dueCandidates.evidenceNextStep')}:{' '}
                      {candidate.evidence_next_step}
                    </span>
                  </div>
                </td>
              </tr>
            ))}
          </Table>
        )}
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
  const t = useT();
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
    <form className="form" aria-label={t('books.detail.ocrReview.formLabel')} onSubmit={submit}>
      <Field
        label={t('books.detail.ocrReview.statusLabel')}
        htmlFor={`ocr-review-status-${draft.draft_id}`}
      >
        <Select
          id={`ocr-review-status-${draft.draft_id}`}
          value={status}
          options={paperBookOcrReviewOptions}
          onChange={(event) => setStatus(event.target.value as PaperBookOcrDraftReviewPatchStatus)}
        />
      </Field>
      {superseded ? (
        <Field
          label={t('books.detail.ocrReview.successorLabel')}
          htmlFor={`ocr-review-successor-${draft.draft_id}`}
          hint={t('books.detail.ocrReview.successorHint')}
        >
          <Input
            id={`ocr-review-successor-${draft.draft_id}`}
            value={supersededBy}
            onChange={(event) => setSupersededBy(event.target.value)}
          />
        </Field>
      ) : null}
      <Field
        label={t('books.detail.ocrReview.noteLabel')}
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
        />{' '}
        {t('uiLiteral.bookDetailPage.confirmoQueEstaRevisaoEApenasMetadadoAuxiliar')}{' '}
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
  const t = useT();
  return (
    <section
      className="stack--tight"
      aria-label={t('books.detail.ocrArtifact.sectionLabel', { id: artifact.artifact_id })}
    >
      <div className="row-wrap">
        <Badge tone={artifact.reviewed_conversion_execution_artifact ? 'ok' : 'warn'}>
          {' '}
          {t('uiLiteral.bookDetailPage.evidenciaRevista')}{' '}
        </Badge>
        <Badge tone={artifact.mutable_draft_act_created ? 'neutral' : 'warn'}>
          {' '}
          {t('uiLiteral.bookDetailPage.promocaoParaRascunhoMutavel')}{' '}
        </Badge>
        <Badge tone="warn">{t('uiLiteral.bookDetailPage.naoCanonico')}</Badge>
      </div>
      <InlineWarning tone="info" title={t('books.detail.ocrArtifact.promotionTitle')}>
        <p>{artifact.artifact_notice}</p>
        <p>{artifact.legal_notice}</p>
      </InlineWarning>
      <dl className="deflist deflist--tight">
        <div>
          <dt>{t('uiLiteral.bookDetailPage.artefacto')}</dt>
          <dd>
            <span className="mono">{artifact.artifact_id}</span>
          </dd>
        </div>
        <div>
          <dt>{t('uiLiteral.bookDetailPage.rascunhoOcrAceite')}</dt>
          <dd>
            <span className="mono">{artifact.draft_id}</span>
          </dd>
        </div>
        <div>
          <dt>{t('uiLiteral.bookDetailPage.dossierAssociado')}</dt>
          <dd>{artifact.dossier_id ? <span className="mono">{artifact.dossier_id}</span> : '—'}</dd>
        </div>
        <div>
          <dt>{t('uiLiteral.bookDetailPage.ataMutavelDeDestino')}</dt>
          <dd>
            <Link to={`/acts/${artifact.target_act_id}`}>
              {t('uiLiteral.bookDetailPage.abrirAta')}
            </Link>{' '}
            · <span className="mono">{artifact.target_act_id}</span>{' '}
            {t('uiLiteral.bookDetailPage.estado.1528o1')} {artifact.target_act_state}{' '}
            {t('uiLiteral.bookDetailPage.ataMutavelCriada')}{' '}
            {noClaimLabel(artifact.mutable_draft_act_created)}
          </dd>
        </div>
        <div>
          <dt>{t('uiLiteral.bookDetailPage.digestDaFonteOcr')}</dt>
          <dd>
            {artifact.source_text_digest ? (
              <span className="mono">{artifact.source_text_digest}</span>
            ) : (
              '—'
            )}
          </dd>
        </div>
        <div>
          <dt>{t('uiLiteral.bookDetailPage.paginasDaFonte')}</dt>
          <dd>{paperBookOcrArtifactPageSpansLabel(artifact)}</dd>
        </div>
        <div>
          <dt>{t('uiLiteral.bookDetailPage.revisaoDeOrigem')}</dt>
          <dd>
            {paperBookOcrReviewStatusLabel(artifact.source_review_status)}
            {artifact.source_reviewed_at ? (
              <>
                {' '}
                {t('uiLiteral.bookDetailPage.em')}{' '}
                <DateTime value={artifact.source_reviewed_at} evidentiary className="mono" />{' '}
                {t('uiLiteral.bookDetailPage.por')} {artifact.source_reviewed_by ?? '—'}
              </>
            ) : null}
          </dd>
        </div>
        <div>
          <dt>{t('uiLiteral.bookDetailPage.criado')}</dt>
          <dd>
            {/* Conversion-evidence artefacts are audit records: seconds + zone. */}
            <DateTime value={artifact.created_at} evidentiary className="mono" />{' '}
            {t('uiLiteral.bookDetailPage.por')} {artifact.created_by}
          </dd>
        </div>
        <div>
          <dt>{t('uiLiteral.bookDetailPage.flagsSemReivindicacao')}</dt>
          <dd>
            {' '}
            {t('uiLiteral.bookDetailPage.conversaoCanonica')}{' '}
            {noClaimLabel(artifact.canonical_conversion_claimed)}{' '}
            {t('uiLiteral.bookDetailPage.minutasCanonicas')}{' '}
            {noClaimLabel(artifact.canonical_minutes_claimed)}{' '}
            {t('uiLiteral.bookDetailPage.ataCanonica')}{' '}
            {noClaimLabel(artifact.canonical_act_created)}{' '}
            {t('uiLiteral.bookDetailPage.documentoCanonico')}{' '}
            {noClaimLabel(artifact.canonical_document_created)}{' '}
            {t('uiLiteral.bookDetailPage.documentoAssinado')}{' '}
            {noClaimLabel(artifact.signed_document_created)}{' '}
            {t('uiLiteral.bookDetailPage.arquivoLegalPacote')}{' '}
            {noClaimLabel(artifact.archive_package_created)}{' '}
            {t('uiLiteral.bookDetailPage.certificacaoDeArquivo')}{' '}
            {noClaimLabel(artifact.archive_certification_claimed)}{' '}
            {t('uiLiteral.bookDetailPage.pdfA')} {noClaimLabel(artifact.pdfa_created)}{' '}
            {t('uiLiteral.bookDetailPage.pdfUa')} {noClaimLabel(artifact.pdfua_created)}{' '}
            {t('uiLiteral.bookDetailPage.assinatura')} {noClaimLabel(artifact.signature_created)}{' '}
            {t('uiLiteral.bookDetailPage.selo')} {noClaimLabel(artifact.seal_created)}{' '}
            {t('uiLiteral.bookDetailPage.validadeLegal')}{' '}
            {noClaimLabel(artifact.legal_validity_claimed)}
          </dd>
        </div>
        <div>
          <dt>{t('uiLiteral.bookDetailPage.textoOcrBruto')}</dt>
          <dd>
            {' '}
            {t('uiLiteral.bookDetailPage.noArtefacto')}{' '}
            {noClaimLabel(artifact.source_extracted_text_in_artifact)}{' '}
            {t('uiLiteral.bookDetailPage.noEventoDeLedger')}{' '}
            {noClaimLabel(artifact.source_extracted_text_in_ledger_event)}
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
  const t = useT();
  if (dossier) {
    return (
      <section
        className="stack--tight"
        aria-label={t('books.detail.ocrDossier.sectionLabel', { id: dossier.dossier_id })}
      >
        <div className="row-wrap">
          <Badge tone="ok">{t('uiLiteral.bookDetailPage.dossierJaRegistado')}</Badge>
          <Badge tone="warn">{t('uiLiteral.bookDetailPage.soMetadados')}</Badge>
          <Badge tone="warn">{t('uiLiteral.bookDetailPage.naoCanonico')}</Badge>
        </div>
        <InlineWarning tone="info" title={t('books.detail.ocrDossier.metadataTitle')}>
          <p>{dossier.dossier_notice}</p>
          <p>{dossier.legal_notice}</p>
        </InlineWarning>
        <dl className="deflist deflist--tight">
          <div>
            <dt>{t('uiLiteral.bookDetailPage.dossier')}</dt>
            <dd>
              <span className="mono">{dossier.dossier_id}</span>
            </dd>
          </div>
          <div>
            <dt>{t('uiLiteral.bookDetailPage.digestDaFonteOcr')}</dt>
            <dd>
              {dossier.source_text_digest ? (
                <span className="mono">{dossier.source_text_digest}</span>
              ) : (
                '—'
              )}
            </dd>
          </div>
          <div>
            <dt>{t('uiLiteral.bookDetailPage.paginasDaFonte')}</dt>
            <dd>{paperBookOcrDossierPageSpansLabel(dossier)}</dd>
          </div>
          <div>
            <dt>{t('uiLiteral.bookDetailPage.revisaoDeOrigem')}</dt>
            <dd>
              {paperBookOcrReviewStatusLabel(dossier.source_review_status)}
              {dossier.source_reviewed_at ? (
                <>
                  {' '}
                  {t('uiLiteral.bookDetailPage.em')}{' '}
                  <DateTime value={dossier.source_reviewed_at} evidentiary className="mono" />{' '}
                  {t('uiLiteral.bookDetailPage.por')} {dossier.source_reviewed_by ?? '—'}
                </>
              ) : null}
            </dd>
          </div>
          <div>
            <dt>{t('uiLiteral.bookDetailPage.criado')}</dt>
            <dd>
              <DateTime value={dossier.created_at} evidentiary className="mono" />{' '}
              {t('uiLiteral.bookDetailPage.por')} {dossier.created_by}
            </dd>
          </div>
          <div>
            <dt>{t('uiLiteral.bookDetailPage.limitesDoDossier')}</dt>
            <dd>
              {' '}
              {t('uiLiteral.bookDetailPage.ataCriada')} {noClaimLabel(dossier.act_created)}{' '}
              {t('uiLiteral.bookDetailPage.ataCanonicaCriada')}{' '}
              {noClaimLabel(dossier.canonical_act_created)}{' '}
              {t('uiLiteral.bookDetailPage.ataCanonicaReclamada')}{' '}
              {noClaimLabel(dossier.canonical_minutes_claimed)}{' '}
              {t('uiLiteral.bookDetailPage.documentoCanonico')}{' '}
              {noClaimLabel(dossier.canonical_document_created)}{' '}
              {t('uiLiteral.bookDetailPage.documentoAssinado')}{' '}
              {noClaimLabel(dossier.signed_document_created)}{' '}
              {t('uiLiteral.bookDetailPage.pacoteDeArquivo')}{' '}
              {noClaimLabel(dossier.archive_package_created)} {t('uiLiteral.bookDetailPage.pdfA')}{' '}
              {noClaimLabel(dossier.pdfa_created)} {t('uiLiteral.bookDetailPage.pdfUa')}{' '}
              {noClaimLabel(dossier.pdfua_created)} {t('uiLiteral.bookDetailPage.assinatura')}{' '}
              {noClaimLabel(dossier.signature_created)} {t('uiLiteral.bookDetailPage.selo')}{' '}
              {noClaimLabel(dossier.seal_created)} {t('uiLiteral.bookDetailPage.validadeLegal')}{' '}
              {noClaimLabel(dossier.legal_validity_claimed)}
            </dd>
          </div>
          <div>
            <dt>{t('uiLiteral.bookDetailPage.textoOcrBruto')}</dt>
            <dd>
              {' '}
              {t('uiLiteral.bookDetailPage.naResposta')}{' '}
              {noClaimLabel(dossier.source_extracted_text_in_response)}{' '}
              {t('uiLiteral.bookDetailPage.noEventoDeLedger')}{' '}
              {noClaimLabel(dossier.source_extracted_text_in_ledger_event)}
            </dd>
          </div>
        </dl>
        {dossier.conversion_execution_artifacts?.length ? (
          <div
            className="stack--tight"
            aria-label={t('books.detail.ocrDossier.artifactsLabel', { id: dossier.dossier_id })}
          >
            <p className="card__label">
              {t('uiLiteral.bookDetailPage.evidenciaDeExecucaoDeConversaoRevista')}
            </p>
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
      aria-label={t('books.detail.ocrDossier.createSectionLabel', { id: draft.draft_id })}
    >
      <InlineWarning tone="info" title={t('books.detail.ocrDossier.metadataTitle')}>
        {' '}
        {t('uiLiteral.bookDetailPage.criaOuDevolveUmDossierSoComMetadados')}{' '}
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
  const t = useT();
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
    <section className="stack--tight" aria-label={t('books.detail.ocrSummary.sectionLabel')}>
      <p className="card__label">{t('uiLiteral.bookDetailPage.resumoOcrDossierDerivado')}</p>
      <dl className="deflist deflist--tight">
        <div>
          <dt>{t('uiLiteral.bookDetailPage.rascunhoRevisto')}</dt>
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
          <dt>{t('uiLiteral.bookDetailPage.rascunhoAceite')}</dt>
          <dd>
            {acceptedDraft
              ? acceptedWithoutCanonicalConversion
                ? t('uiLiteral.bookDetailPage.acceptedWithoutCanonicalConversion')
                : t('uiLiteral.bookDetailPage.aceiteParaReferenciaAuxiliar')
              : t('uiLiteral.bookDetailPage.noAcceptedOcrDraft')}
          </dd>
        </div>
        <div>
          <dt>{t('uiLiteral.bookDetailPage.dossier')}</dt>
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
          <dt>{t('uiLiteral.bookDetailPage.textoOcrBrutoNoDossier')}</dt>
          <dd>{noRawOcrTextInDossier ? 'não' : 'sim'}</dd>
        </div>
        <div>
          <dt>{t('uiLiteral.bookDetailPage.inclui')}</dt>
          <dd> {t('uiLiteral.bookDetailPage.estadoDeRevisaoOcrDigestDeTextoQuando')} </dd>
        </div>
        <div>
          <dt>{t('uiLiteral.bookDetailPage.exclui')}</dt>
          <dd>
            {' '}
            {t(
              'uiLiteral.bookDetailPage.ataCanonicaDocumentoCanonicoPacoteDeArquivoAssinatura',
            )}{' '}
          </dd>
        </div>
        <div>
          <dt>{t('uiLiteral.bookDetailPage.flagsSemReivindicacao')}</dt>
          <dd> {t('uiLiteral.bookDetailPage.soMetadadosSimAtaCanonicaNaoDocumentoCanonico')} </dd>
        </div>
      </dl>
    </section>
  );
}

function PaperBookOcrCanonicalRehearsalPanel({
  report,
  loading,
  error,
  importId,
}: {
  report: PaperBookOcrCanonicalRehearsalReport | undefined;
  loading: boolean;
  error: unknown;
  importId: string;
}) {
  const t = useT();
  const blockers = report?.readiness.blockers.map((blocker) => blocker.code) ?? [];

  return (
    <section
      className="stack--tight"
      aria-label={t('books.detail.preflight.sectionLabel', { id: importId })}
    >
      <p className="card__label">{t('uiLiteral.bookDetailPage.relatorioOcrCanonicoLocal')}</p>
      <InlineWarning tone="info" title={t('books.detail.preflight.metadataOnlyTitle')}>
        {' '}
        {t('uiLiteral.bookDetailPage.rehearsalLocalCalculadoAPartirDeMetadadosPreservados')}{' '}
      </InlineWarning>
      {loading ? (
        <SkeletonDeflist rows={6} />
      ) : error ? (
        <ErrorNote error={error} />
      ) : report ? (
        <dl className="deflist deflist--tight">
          <div>
            <dt>{t('uiLiteral.bookDetailPage.estado')}</dt>
            <dd>{paperBookRehearsalStatusLabel(report.readiness.status)}</dd>
          </div>
          <div>
            <dt>{t('uiLiteral.bookDetailPage.ambito')}</dt>
            <dd>{report.rehearsal_scope}</dd>
          </div>
          <div>
            <dt>{t('uiLiteral.bookDetailPage.importacaoPreservada')}</dt>
            <dd>
              <span className="mono">{report.import_id}</span>{' '}
              {t('uiLiteral.bookDetailPage.paginas')} {report.source_import.source_page_range.from}{' '}
              {t('uiLiteral.bookDetailPage.a')} {report.source_import.source_page_range.to}{' '}
              {t('uiLiteral.bookDetailPage.digestPresente')}{' '}
              {noClaimLabel(report.source_import.package_digest_present)}
            </dd>
          </div>
          <div>
            <dt>{t('uiLiteral.bookDetailPage.rascunhosOcr')}</dt>
            <dd>
              {' '}
              {t('uiLiteral.bookDetailPage.total')} {report.ocr_evidence.draft_count}{' '}
              {t('uiLiteral.bookDetailPage.aceites')} {report.ocr_evidence.accepted_draft_count}{' '}
              {t('uiLiteral.bookDetailPage.desconhecidos')}{' '}
              {report.ocr_evidence.confidence_buckets.unknown_count}
              {report.ocr_evidence.selected_accepted_draft_id ? (
                <>
                  {' '}
                  · <span className="mono">{report.ocr_evidence.selected_accepted_draft_id}</span>
                </>
              ) : null}
            </dd>
          </div>
          <div>
            <dt>{t('uiLiteral.bookDetailPage.dossier')}</dt>
            <dd>
              {' '}
              {t('uiLiteral.bookDetailPage.total')} {report.dossier_evidence.dossier_count}{' '}
              {t('uiLiteral.bookDetailPage.metadados')}{' '}
              {noClaimLabel(report.dossier_evidence.metadata_only_dossier_present)}
              {report.dossier_evidence.selected_dossier_id ? (
                <>
                  {' '}
                  · <span className="mono">{report.dossier_evidence.selected_dossier_id}</span>
                </>
              ) : null}
            </dd>
          </div>
          <div>
            <dt>{t('uiLiteral.bookDetailPage.artefactos')}</dt>
            <dd>
              {' '}
              {t('uiLiteral.bookDetailPage.draftMutavel')}{' '}
              {noClaimLabel(report.dossier_evidence.mutable_draft_act_artifact_present)}
              {' · '}
              {t('uiLiteral.bookDetailPage.execucoesLigadas')}{' '}
              {report.dossier_evidence.bound_execution_artifact_count}
            </dd>
          </div>
          <div>
            <dt>{t('uiLiteral.bookDetailPage.bloqueios')}</dt>
            <dd>{blockers.length ? blockers.join(', ') : 'nenhum bloqueio local no relatório'}</dd>
          </div>
          <div>
            <dt>{t('uiLiteral.bookDetailPage.semReivindicacao')}</dt>
            <dd>{paperBookRehearsalNoClaimText(report.no_claims)}</dd>
          </div>
        </dl>
      ) : (
        <EmptyState title={t('uiLiteral.bookDetailPage.relatorioLocalIndisponivel')}>
          {' '}
          {t('uiLiteral.bookDetailPage.aImportacaoPreservadaAindaNaoDevolveuRelatorioOcr')}{' '}
        </EmptyState>
      )}
    </section>
  );
}

function PaperBookOcrDraftPanel({ row }: { row: PaperBookImportView }) {
  const t = useT();
  const toast = useToast();
  const drafts = usePaperBookOcrDrafts(row.import_id);
  const dossiers = usePaperBookOcrConversionDossiers(row.import_id);
  const rehearsal = usePaperBookOcrCanonicalRehearsal(row.import_id);
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

  // Unsaved-work guard (t52). The transcription itself is the only expensive field here —
  // page range, engine name and confidence are seeded defaults or a few characters, so
  // arming the prompt on them would make the warning meaningless.
  useUnsavedChanges(extractedText.trim() !== '');

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
    <section
      className="stack--tight"
      aria-label={t('books.detail.ocrDraft.sectionLabel', { id: row.import_id })}
    >
      <InlineWarning tone="info" title={t('books.detail.ocrDraft.reviewTitle')}>
        {PAPER_BOOK_OCR_DRAFT_COPY}
      </InlineWarning>
      <PaperBookOcrDossierReviewSummary
        dossiers={dossiers.data ?? []}
        drafts={rows}
        loading={dossiers.isLoading}
      />
      <PaperBookOcrCanonicalRehearsalPanel
        report={rehearsal.data}
        loading={rehearsal.isLoading}
        error={rehearsal.error}
        importId={row.import_id}
      />
      <form
        className="form"
        aria-label={t('books.detail.ocrDraft.createFormLabel')}
        onSubmit={submit}
      >
        <Field
          label={t('books.detail.ocrDraft.textLabel')}
          htmlFor={`ocr-text-${row.import_id}`}
          hint={t('books.detail.ocrDraft.textHint')}
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
            label={t('books.detail.ocrDraft.digestLabel')}
            htmlFor={`ocr-digest-${row.import_id}`}
            hint={t('books.detail.ocrDraft.digestHint')}
          >
            <Input
              id={`ocr-digest-${row.import_id}`}
              value={textDigest}
              onChange={(event) => setTextDigest(event.target.value)}
              placeholder={t('books.detail.ocrDraft.digestPlaceholder')}
            />
          </Field>
          <Field
            label={t('books.detail.ocrDraft.startPageLabel')}
            htmlFor={`ocr-start-page-${row.import_id}`}
          >
            <Input
              id={`ocr-start-page-${row.import_id}`}
              type="number"
              min="1"
              value={startPage}
              onChange={(event) => setStartPage(event.target.value)}
            />
          </Field>
          <Field
            label={t('books.detail.ocrDraft.endPageLabel')}
            htmlFor={`ocr-end-page-${row.import_id}`}
          >
            <Input
              id={`ocr-end-page-${row.import_id}`}
              type="number"
              min="1"
              value={endPage}
              onChange={(event) => setEndPage(event.target.value)}
            />
          </Field>
          <Field
            label={t('books.detail.ocrDraft.confidenceLabel')}
            htmlFor={`ocr-confidence-${row.import_id}`}
            hint={t('books.detail.ocrDraft.confidenceHint')}
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
          <Field
            label={t('books.detail.ocrDraft.engineLabel')}
            htmlFor={`ocr-engine-${row.import_id}`}
          >
            <Input
              id={`ocr-engine-${row.import_id}`}
              value={engineName}
              onChange={(event) => setEngineName(event.target.value)}
            />
          </Field>
          <Field
            label={t('books.detail.ocrDraft.engineVersionLabel')}
            htmlFor={`ocr-engine-version-${row.import_id}`}
          >
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
          />{' '}
          {t('uiLiteral.bookDetailPage.confirmoQueEsteRascunhoOcrEAuxiliarNao')}{' '}
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
        <EmptyState title={t('books.detail.ocrDraft.emptyTitle')}>
          <p>{t('uiLiteral.bookDetailPage.estaImportacaoPreservadaAindaNaoTemOcrAuxiliar')}</p>
        </EmptyState>
      ) : (
        <ul className="plain-list" aria-label={t('books.detail.ocrDraft.listLabel')}>
          {rows.map((draft) => (
            <li key={draft.draft_id} className="chainrow">
              <div className="stack--tight">
                <div className="row-wrap">
                  <Badge tone="warn">{translateNow('uiLiteral.bookDetailPage.naoCanonico')}</Badge>
                  <Badge tone={paperBookOcrReviewTone(draft.review_status)}>
                    {paperBookOcrReviewStatusLabel(draft.review_status)}
                  </Badge>
                  <span className="mono">{draft.draft_id}</span>
                </div>
                <InlineWarning tone="info" title={t('books.detail.ocrDraft.noticeTitle')}>
                  {draft.draft_notice || PAPER_BOOK_OCR_DRAFT_COPY}
                </InlineWarning>
                <dl className="deflist deflist--tight">
                  <div>
                    <dt>{translateNow('uiLiteral.bookDetailPage.textoExtraido')}</dt>
                    <dd>{paperBookOcrTextPreview(draft)}</dd>
                  </div>
                  <div>
                    <dt>{translateNow('uiLiteral.bookDetailPage.digestDoTexto')}</dt>
                    <dd>
                      {draft.text_digest ? <span className="mono">{draft.text_digest}</span> : '—'}
                    </dd>
                  </div>
                  <div>
                    <dt>{translateNow('uiLiteral.bookDetailPage.paginasRevistas')}</dt>
                    <dd>{paperBookOcrPageSpansLabel(draft)}</dd>
                  </div>
                  <div>
                    <dt>{translateNow('uiLiteral.bookDetailPage.motor')}</dt>
                    <dd>
                      {draft.engine.name}
                      {draft.engine.version ? ` ${draft.engine.version}` : ''}
                      {draft.confidence !== null ? ` · confiança ${draft.confidence}` : ''}
                    </dd>
                  </div>
                  <div>
                    <dt>{translateNow('uiLiteral.bookDetailPage.criado')}</dt>
                    <dd>
                      <DateTime value={draft.created_at} evidentiary className="mono" />{' '}
                      {translateNow('uiLiteral.bookDetailPage.por')} {draft.created_by}
                    </dd>
                  </div>
                  <div>
                    <dt>{translateNow('uiLiteral.bookDetailPage.revisto')}</dt>
                    <dd>
                      {draft.reviewed_at ? (
                        <>
                          <DateTime value={draft.reviewed_at} evidentiary className="mono" />{' '}
                          {translateNow('uiLiteral.bookDetailPage.por')} {draft.reviewed_by ?? '—'}
                        </>
                      ) : (
                        '—'
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt>{translateNow('uiLiteral.bookDetailPage.nota')}</dt>
                    <dd>{draft.review_note ?? '—'}</dd>
                  </div>
                  <div>
                    <dt>{translateNow('uiLiteral.bookDetailPage.limites')}</dt>
                    <dd>
                      {' '}
                      {translateNow('uiLiteral.bookDetailPage.textoAutoritativo')}{' '}
                      {draft.authoritative_text_claimed ? 'sim' : 'não'}{' '}
                      {translateNow('uiLiteral.bookDetailPage.ataCanonica')}{' '}
                      {draft.canonical_act_created ? 'sim' : 'não'}{' '}
                      {translateNow('uiLiteral.bookDetailPage.documentoCanonico')}{' '}
                      {draft.canonical_document_created ? 'sim' : 'não'}{' '}
                      {translateNow('uiLiteral.bookDetailPage.assinatura')}{' '}
                      {draft.signature_created ? 'sim' : 'não'}{' '}
                      {translateNow('uiLiteral.bookDetailPage.validadeLegal')}{' '}
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
                    <InlineWarning tone="info" title={t('books.detail.ocrDraft.createActTitle')}>
                      {' '}
                      {translateNow('uiLiteral.bookDetailPage.criaUmaAtaEmEstadoDraftComO')}{' '}
                    </InlineWarning>
                    {createdActDrafts[draft.draft_id] ? (
                      <p className="muted">
                        {' '}
                        {translateNow('uiLiteral.bookDetailPage.rascunhoCriado')}{' '}
                        <Link to={`/acts/${createdActDrafts[draft.draft_id].act.id}`}>
                          {' '}
                          {translateNow('uiLiteral.bookDetailPage.abrirAta')}{' '}
                        </Link>{' '}
                        {translateNow('uiLiteral.bookDetailPage.documentoCanonico.19tw3h')}{' '}
                        {createdActDrafts[draft.draft_id].canonical_document_created
                          ? 'sim'
                          : 'não'}{' '}
                        {translateNow('uiLiteral.bookDetailPage.pdfA')}{' '}
                        {createdActDrafts[draft.draft_id].pdfa_created ? 'sim' : 'não'}{' '}
                        {translateNow('uiLiteral.bookDetailPage.assinatura')}{' '}
                        {createdActDrafts[draft.draft_id].signature_created ? 'sim' : 'não'}{' '}
                        {translateNow('uiLiteral.bookDetailPage.selo')}{' '}
                        {createdActDrafts[draft.draft_id].seal_created ? 'sim' : 'não'}{' '}
                        {translateNow('uiLiteral.bookDetailPage.validadeLegal')}{' '}
                        {createdActDrafts[draft.draft_id].legal_validity_claimed ? 'sim' : 'não'}
                      </p>
                    ) : null}
                    {renderPaperBookOcrConversionExecutionArtifactPanel(
                      createdActDrafts[draft.draft_id]?.conversion_execution_artifact,
                    )}
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

function renderPaperBookOcrConversionExecutionArtifactPanel(
  artifact: PaperBookOcrConversionExecutionArtifactView | undefined,
) {
  if (!artifact) return null;
  return <PaperBookOcrConversionExecutionArtifactPanel artifact={artifact} />;
}

function PaperBookImportsPanel({ book }: { book: BookView }) {
  const t = useT();
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
    <Card title={t('books.detail.imports.title')}>
      <div className="stack">
        <ConfirmActionModal
          open={localOcrCandidate !== null}
          onClose={() => setLocalOcrCandidate(null)}
          title={t('books.detail.imports.runOcrTitle')}
          intro={
            <div className="stack--tight">
              <p> {t('uiLiteral.bookDetailPage.oResultadoSeraUmRascunhoOcrAuxiliarNao')} </p>
              <p> {t('uiLiteral.bookDetailPage.estaAcaoNaoCriaAtaCanonicaDocumentoCanonico')} </p>
            </div>
          }
          confirmLabel={t('books.detail.imports.runOcrConfirm')}
          pendingLabel={t('books.detail.imports.runOcrPending')}
          pending={runOcr.isPending}
          onConfirm={confirmRunLocalOcr}
        />
        <InlineWarning tone="warn" title={t('books.detail.imports.nonCanonicalTitle')}>
          {' '}
          {t('uiLiteral.bookDetailPage.estesPacotesPreservamCopiasDeLivrosEmPapel')}{' '}
        </InlineWarning>
        <InlineWarning tone="info" title={t('books.detail.imports.reviewGuidanceTitle')}>
          {' '}
          {t('uiLiteral.bookDetailPage.valideDatasContagemDePaginasFixidezEContexto')}{' '}
        </InlineWarning>

        <form className="form">
          <Field label={t('books.detail.imports.fileLabel')} htmlFor="paper-import-file">
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
            <Field label={t('books.detail.imports.dateFromLabel')} htmlFor="paper-import-from">
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
            <Field label={t('books.detail.imports.dateToLabel')} htmlFor="paper-import-to">
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
            <Field label={t('books.detail.imports.pagesLabel')} htmlFor="paper-import-pages">
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
              label={t('books.detail.imports.pageRangeLabel')}
              htmlFor="paper-import-page-range"
              hint={t('books.detail.imports.pageRangeHint')}
            >
              <Input
                id="paper-import-page-range"
                value={pageCount ? `1 a ${pageCount}` : 'Defina a contagem de páginas'}
                disabled
                readOnly
              />
            </Field>
            <Field label={t('books.detail.imports.filenameLabel')} htmlFor="paper-import-filename">
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
          <Field label={t('books.detail.imports.notesLabel')} htmlFor="paper-import-notes">
            <TextArea
              id="paper-import-notes"
              rows={3}
              value={notes}
              placeholder={t('books.detail.imports.notesPlaceholder')}
              onChange={(e) => {
                setNotes(e.target.value);
                resetCandidate();
              }}
            />
          </Field>
          <p className="field__hint">
            {' '}
            {t('uiLiteral.bookDetailPage.aEntidadeEOLivroSaoPreenchidosA')} {entityName || '—'} ·{' '}
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
          <InlineWarning tone="info" title={t('books.detail.imports.reportTitle')}>
            <p>{report.legal_notice}</p>
            <p>
              {' '}
              {t('uiLiteral.bookDetailPage.estado.kzwel3')}{' '}
              {report.candidate_classification.preservation_status}
              {t('uiLiteral.bookDetailPage.validadeLegalDeclaradaNao')}{' '}
            </p>
          </InlineWarning>
        ) : null}

        {imports.isLoading ? (
          <SkeletonTable cols={4} />
        ) : imports.error ? (
          <ErrorNote error={imports.error} />
        ) : rows.length === 0 ? (
          <EmptyState title={t('books.detail.imports.emptyTitle')}>
            <p>{t('uiLiteral.bookDetailPage.naoHaPacotesDeLivroEmPapelPreservados')}</p>
          </EmptyState>
        ) : (
          <Table
            head={
              <tr>
                <th>{t('uiLiteral.bookDetailPage.ficheiro')}</th>
                <th>{t('uiLiteral.bookDetailPage.contexto')}</th>
                <th>{t('uiLiteral.bookDetailPage.revisaoEFixidez')}</th>
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
                        {translateNow('uiLiteral.bookDetailPage.paginas')}{' '}
                      </span>
                    </div>
                  </td>
                  <td>
                    <div className="stack--tight">
                      <span>
                        <DateOnly value={row.date_from} />{' '}
                        {translateNow('uiLiteral.bookDetailPage.a')}{' '}
                        <DateOnly value={row.date_to} />
                      </span>
                      <span className="muted">
                        {translateNow('uiLiteral.bookDetailPage.intervalo')}{' '}
                        {paperBookPageRange(row)}
                      </span>
                      <span className="muted">
                        {' '}
                        {translateNow('uiLiteral.bookDetailPage.livro')}{' '}
                        <Link to={`/books/${row.book_ref}`}>{row.book_ref}</Link>{' '}
                        {translateNow('uiLiteral.bookDetailPage.entidade')}{' '}
                        {row.entity_name || row.entity_ref}
                      </span>
                      <span className="muted">
                        {' '}
                        {translateNow('uiLiteral.bookDetailPage.ambitoDeArquivoPaperBookImport')}
                        {row.import_id}
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
                        {' '}
                        {translateNow(
                          'uiLiteral.bookDetailPage.ocrMetadadoApenasTextoArmazenado',
                        )}{' '}
                        {row.ocr_text_stored ? 'sim' : 'não'}
                        {translateNow('uiLiteral.bookDetailPage.textoAutoritativo.9xkq63')}{' '}
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
  const et = useEncerramentoT();
  const toast = useToast();
  const { id = '' } = useParams();
  // Atas is the default and carries no segment (so `/books/:id` lands on it) — the exact
  // convention Configurações uses for its own sub-nav. The base is sliced off the pathname,
  // so the id in it is never re-encoded.
  const { section, select: selectSection } = useSectionNav<BookSection>({
    depth: 2,
    parse: parseBookSection,
    fallback: 'acts',
    replace: true,
  });
  const book = useBook(id);
  const acts = useBookActs(id);
  const packageDownload = useDownloadBookArchivePackage(id);
  const localDglabManifestDownload = useDownloadBookLocalDglabInterchangeManifest(id);

  if (book.isLoading) {
    return (
      <div className="stack">
        <PageHeader
          crumbs={<Link to="/books">{t('books.crumb')}</Link>}
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
            <Link to="/books">{t('books.crumb')}</Link> · {bookKindLabels[b.kind]}
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
      >
        <SubNav
          items={BOOK_SECTIONS.map((s) => ({ id: s.id, label: t(s.label), icon: s.icon }))}
          active={section}
          onSelect={selectSection}
          ariaLabel={t('books.detail.subnav.aria')}
        />
      </PageHeader>

      <InlineWarning tone="info" title={t('books.detail.dglab.warningTitle')}>
        {' '}
        {t('uiLiteral.bookDetailPage.oManifestoDglabLocalEUmScaffoldJson')}{' '}
      </InlineWarning>

      {/* One section at a time; the panel replays the route-enter fade on each switch, as
          the Configurações sub-nav does.

          No sub-tab here takes `wide-page` (the shell opt-out the Livros list and Arquivo
          use), and that is measured rather than an omission. `atas` is the only tabular
          panel, but its Título cell WRAPS: at the 1080px measure it is 72ch, already at
          this design system's `--measure: 68ch`, and it never scrolls at any viewport.
          Widening pushes it to 114ch — a worse read, not a better one. `termo` is a
          definition list, `retenção` and `importações` are three-column tables of stacked
          prose. The book LIST is where the columns are, and that page is wide. */}
      <div className="route-transition stack" key={section}>
        {section === 'opening' ? (
          <>
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
                  {/* A book opens on a DAY, not at an instant — date-only, and `<DateOnly>`
                      already renders the em dash when the book carries no date. */}
                  <dd>
                    <DateOnly value={b.opening_date} />
                  </dd>
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
                      <Link to={`/books/${b.predecessor}`}>{b.predecessor}</Link>
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
                      <dd>
                        <DateOnly value={b.closing_date} />
                      </dd>
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
            {/* The termo de abertura is now a signable ata in its own right (t23): a book opened
                two-phase carries a Draft termo that is drafted, signed and only then sealed to open
                the book. The editor renders the right phase (Draft/Signing/Sealed), or an honest
                "no separately editable termo" note for a one-shot/legacy book. */}
            <TermoAberturaEditor bookId={b.id} />
            {/* The termo de encerramento is likewise a signable ata (t44): a book being closed
                two-phase carries a Draft termo that is drafted, signed and only then sealed to close
                the book; a Closed book shows its Sealed termo. The editor renders nothing for a
                one-shot/legacy book with no separately editable encerramento. */}
            <TermoEncerramentoEditor bookId={b.id} />
          </>
        ) : null}

        {section === 'retention' ? (
          <>
            <LegalHoldPanel bookId={b.id} />
            <BookRetentionPanel bookId={b.id} />
          </>
        ) : null}

        {section === 'imports' ? <PaperBookImportsPanel book={b} /> : null}

        {section === 'acts' ? (
          <>
            {/* A capacity-exhausted book stays Open and merely refuses new atas (§6.1 — block, never
                auto-close); this prompt is the honest "livro esgotado → close it" signal. Closing
                fixity is assurance, never framed as discharging the encadernação duty. */}
            {isOpen && b.capacity_exhausted ? (
              <InlineWarning tone="warn" title={et('books.encerramento.capacity.exhaustedTitle')}>
                <p>{et('books.encerramento.capacity.exhaustedBody')}</p>
                <div className="row-wrap">
                  <GateButtonLink
                    perm="book.close"
                    scope={scopeBook(b.id)}
                    to={`/books/${b.id}/close`}
                    icon={<Icon.BookClosed />}
                  >
                    {et('books.encerramento.capacity.close')}
                  </GateButtonLink>
                </div>
              </InlineWarning>
            ) : null}
            <Card
              title={t('books.atas')}
              actions={
                isOpen ? (
                  <div className="row-wrap">
                    <GateButtonLink
                      perm="book.close"
                      scope={scopeBook(b.id)}
                      to={`/books/${b.id}/close`}
                      icon={<Icon.BookClosed />}
                    >
                      {t('books.closeBook')}
                    </GateButtonLink>
                    <GateButtonLink
                      perm="act.draft"
                      scope={scopeBook(b.id)}
                      to={`/books/${b.id}/new-act`}
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
                <BookActsList acts={acts.data} />
              )}
            </Card>
          </>
        ) : null}
      </div>
    </div>
  );
}
