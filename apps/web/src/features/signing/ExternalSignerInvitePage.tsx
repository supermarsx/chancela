import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { ApiError, api } from '../../api/client';
import type {
  ExternalSignerInviteDecision,
  ExternalSignerInvitePublicView,
  ExternalSignerInviteStatus,
  ExternalSignerSlotStatus,
} from '../../api/types';
import {
  Badge,
  Button,
  Digest,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  Loading,
  useToast,
} from '../../ui';
import { TitleBar } from '../../desktop/TitleBar';
import { useT, type TFunction } from '../../i18n';

type LoadState =
  | { kind: 'missing' }
  | { kind: 'loading' }
  | { kind: 'ready'; envelope: ExternalSignerInvitePublicView }
  | { kind: 'error'; error: unknown };

type ArtifactState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'ready'; text: string }
  | { kind: 'error'; error: unknown };

// Raw PDF bytes; the backend route has a larger JSON/base64 envelope limit for this cap.
export const EXTERNAL_INVITE_SIGNED_PDF_RAW_MAX_BYTES = 16 * 1024 * 1024;

export function formatExternalInviteDateTime(value?: string): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date);
}

export function externalInviteStatusBadge(status: ExternalSignerInviteStatus, t: TFunction) {
  if (status === 'pending')
    return <Badge tone="accent">{t('externalInvite.status.pending')}</Badge>;
  if (status === 'accepted') return <Badge tone="ok">{t('externalInvite.status.accepted')}</Badge>;
  if (status === 'declined')
    return <Badge tone="warn">{t('externalInvite.status.declined')}</Badge>;
  if (status === 'expired') return <Badge tone="warn">{t('externalInvite.status.expired')}</Badge>;
  return <Badge tone="neutral">{t('externalInvite.status.revoked')}</Badge>;
}

export function externalInviteSlotStatusLabel(
  status: ExternalSignerSlotStatus,
  t: TFunction,
): string {
  if (status === 'pending') return t('signing.envelopes.slot.status.pending');
  if (status === 'initiated') return t('signing.envelopes.slot.status.initiated');
  if (status === 'signed') return t('signing.envelopes.slot.status.signed');
  if (status === 'declined') return t('signing.envelopes.slot.status.declined');
  if (status === 'revoked') return t('signing.envelopes.slot.status.revoked');
  return t('signing.envelopes.slot.status.expired');
}

export function externalInviteSlotStatusBadge(status: ExternalSignerSlotStatus, t: TFunction) {
  if (status === 'signed') return <Badge tone="ok">{slotStatusLabel(status, t)}</Badge>;
  if (status === 'pending' || status === 'initiated')
    return <Badge tone="accent">{slotStatusLabel(status, t)}</Badge>;
  return <Badge tone="warn">{slotStatusLabel(status, t)}</Badge>;
}

export function externalInviteUnavailableMessage(error: unknown, t: TFunction) {
  if (error instanceof ApiError && error.status === 404) {
    return (
      <InlineWarning tone="error" title={t('externalInvite.unavailable.title')}>
        {t('externalInvite.unavailable.body')}
      </InlineWarning>
    );
  }
  return <ErrorNote error={error} />;
}

export async function externalInviteFileToBase64(file: File): Promise<string> {
  const buffer =
    typeof file.arrayBuffer === 'function'
      ? await file.arrayBuffer()
      : await new Promise<ArrayBuffer>((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = () => {
            if (reader.result instanceof ArrayBuffer) {
              resolve(reader.result);
            } else {
              reject(new Error('Could not read the selected PDF.'));
            }
          };
          reader.onerror = () =>
            reject(reader.error ?? new Error('Could not read the selected PDF.'));
          reader.readAsArrayBuffer(file);
        });
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

export function formatExternalInviteBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return 'unknown';
  if (value < 1024) return `${value} bytes`;
  const units = ['KB', 'MB', 'GB'];
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

export function externalInviteSignedPdfSizeError(file: File, t: TFunction): Error | null {
  if (file.size <= EXTERNAL_INVITE_SIGNED_PDF_RAW_MAX_BYTES) return null;
  return new Error(
    t('externalInvite.upload.file.tooLarge', {
      max: formatBytes(EXTERNAL_INVITE_SIGNED_PDF_RAW_MAX_BYTES),
    }),
  );
}

export function canUploadExternalInviteSignedPdf(
  envelope: ExternalSignerInvitePublicView,
): boolean {
  return envelope.workflow === 'external_envelope' && Boolean(envelope.external_envelope);
}

const formatDateTime = formatExternalInviteDateTime;
const statusBadge = externalInviteStatusBadge;
const slotStatusLabel = externalInviteSlotStatusLabel;
const slotStatusBadge = externalInviteSlotStatusBadge;
const unavailableMessage = externalInviteUnavailableMessage;
const fileToBase64 = externalInviteFileToBase64;
const formatBytes = formatExternalInviteBytes;
const signedPdfSizeError = externalInviteSignedPdfSizeError;
const canUploadSignedPdf = canUploadExternalInviteSignedPdf;

export function ExternalSignerInvitePage() {
  const t = useT();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const toast = useToast();
  const [token] = useState(() => searchParams.get('token')?.trim() ?? '');
  const [load, setLoad] = useState<LoadState>(() =>
    token ? { kind: 'loading' } : { kind: 'missing' },
  );
  const [action, setAction] = useState<ExternalSignerInviteDecision | null>(null);
  const [artifact, setArtifact] = useState<ArtifactState>({ kind: 'idle' });
  const [signedPdfFile, setSignedPdfFile] = useState<File | null>(null);
  const [signedPdfAcknowledged, setSignedPdfAcknowledged] = useState(false);
  const [signedPdfError, setSignedPdfError] = useState<unknown | null>(null);

  useEffect(() => {
    if (searchParams.has('token')) {
      navigate('/assinatura-externa', { replace: true });
    }
  }, [navigate, searchParams]);

  useEffect(() => {
    if (!token) {
      setLoad({ kind: 'missing' });
      return;
    }
    let cancelled = false;
    setLoad({ kind: 'loading' });
    api
      .lookupExternalSignerInvite(token)
      .then((envelope) => {
        if (!cancelled) {
          setLoad({ kind: 'ready', envelope });
          setArtifact({ kind: 'idle' });
          setSignedPdfFile(null);
          setSignedPdfAcknowledged(false);
          setSignedPdfError(null);
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) setLoad({ kind: 'error', error });
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  async function respond(decision: ExternalSignerInviteDecision) {
    if (!token || load.kind !== 'ready') return;
    if (decision === 'accept' && canUploadSignedPdf(load.envelope) && signedPdfFile) {
      const sizeError = signedPdfSizeError(signedPdfFile, t);
      if (sizeError) {
        setSignedPdfError(sizeError);
        return;
      }
    }
    setAction(decision);
    setSignedPdfError(null);
    try {
      const options =
        decision === 'accept' && canUploadSignedPdf(load.envelope)
          ? {
              signed_pdf_base64: await fileToBase64(signedPdfFile!),
              filename: signedPdfFile?.name,
            }
          : undefined;
      const envelope = await api.respondExternalSignerInvite(token, decision, options);
      setLoad({ kind: 'ready', envelope });
      setSignedPdfFile(null);
      setSignedPdfAcknowledged(false);
      toast.success(
        decision === 'accept'
          ? t('externalInvite.toast.accepted')
          : t('externalInvite.toast.declined'),
      );
    } catch (error) {
      if (decision === 'accept' && canUploadSignedPdf(load.envelope)) {
        setSignedPdfError(error);
      }
      toast.error(error);
    } finally {
      setAction(null);
    }
  }

  async function previewWorkingCopy() {
    if (!token || load.kind !== 'ready' || !load.envelope.document?.artifact) return;
    setArtifact({ kind: 'loading' });
    try {
      const result = await api.fetchExternalSignerInviteWorkingCopy(token);
      setArtifact({ kind: 'ready', text: result.text });
    } catch (error) {
      setArtifact({ kind: 'error', error });
    }
  }

  const envelope = load.kind === 'ready' ? load.envelope : null;
  const answered = envelope?.status === 'accepted' || envelope?.status === 'declined';
  const showSignedPdfUpload = envelope ? canUploadSignedPdf(envelope) && !answered : false;
  const canSubmitSignedPdf = Boolean(signedPdfFile) && signedPdfAcknowledged && !action;

  return (
    <>
      <TitleBar />
      <div className="external-signature-page">
        <main className="external-signature-shell">
          <p className="crumbs">{t('externalInvite.crumbs')}</p>
          <h1>{t('externalInvite.title')}</h1>

          {load.kind === 'missing' ? (
            <InlineWarning tone="error" title={t('externalInvite.missingToken.title')}>
              {t('externalInvite.missingToken.body')}
            </InlineWarning>
          ) : null}

          {load.kind === 'loading' ? <Loading label={t('externalInvite.loading')} /> : null}
          {load.kind === 'error' ? unavailableMessage(load.error, t) : null}

          {envelope ? (
            <section className="panel">
              <header className="panel__head">
                <h2 className="panel__title">{envelope.act.title}</h2>
                {statusBadge(envelope.status, t)}
              </header>
              <div className="panel__body stack--tight">
                <InlineWarning tone="info" title={t('externalInvite.tracking.title')}>
                  {t('externalInvite.tracking.body')}
                </InlineWarning>

                <dl className="deflist external-signature-deflist">
                  <div>
                    <dt>{t('externalInvite.field.entity')}</dt>
                    <dd>{envelope.act.entity_name}</dd>
                  </div>
                  <div>
                    <dt>{t('externalInvite.field.book')}</dt>
                    <dd>{envelope.act.book_kind}</dd>
                  </div>
                  <div>
                    <dt>{t('externalInvite.field.act')}</dt>
                    <dd>
                      {envelope.act.ata_number
                        ? t('externalInvite.actNumber', { number: envelope.act.ata_number })
                        : '-'}
                    </dd>
                  </div>
                  <div>
                    <dt>{t('externalInvite.field.meeting')}</dt>
                    <dd>{envelope.act.meeting_date ?? '-'}</dd>
                  </div>
                  <div>
                    <dt>{t('externalInvite.field.recipient')}</dt>
                    <dd>{envelope.recipient_name}</dd>
                  </div>
                  <div>
                    <dt>{t('externalInvite.field.purpose')}</dt>
                    <dd>{envelope.purpose}</dd>
                  </div>
                  {envelope.provider_hint ? (
                    <div>
                      <dt>{t('externalInvite.field.reference')}</dt>
                      <dd>{envelope.provider_hint}</dd>
                    </div>
                  ) : null}
                  <div>
                    <dt>{t('externalInvite.field.expiresAt')}</dt>
                    <dd>{formatDateTime(envelope.expires_at)}</dd>
                  </div>
                  {envelope.responded_at ? (
                    <div>
                      <dt>{t('externalInvite.field.response')}</dt>
                      <dd>{formatDateTime(envelope.responded_at)}</dd>
                    </div>
                  ) : null}
                </dl>

                {envelope.document ? (
                  <div className="stack--tight">
                    <dl className="deflist external-signature-deflist">
                      <div>
                        <dt>{t('externalInvite.document.id')}</dt>
                        <dd className="mono">{envelope.document.id}</dd>
                      </div>
                      <div>
                        <dt>{t('externalInvite.document.template')}</dt>
                        <dd className="mono">{envelope.document.template_id}</dd>
                      </div>
                      <div>
                        <dt>{t('externalInvite.document.profile')}</dt>
                        <dd className="mono">{envelope.document.profile}</dd>
                      </div>
                      <div>
                        <dt>{t('externalInvite.document.digest')}</dt>
                        <dd>
                          <Digest value={envelope.document.pdf_digest} copyable={false} />
                        </dd>
                      </div>
                    </dl>

                    <InlineWarning tone="info" title={t('externalInvite.workingCopy.title')}>
                      {t('externalInvite.workingCopy.body')}
                    </InlineWarning>

                    <div className="form__actions">
                      <Button
                        type="button"
                        variant="secondary"
                        icon={<Icon.FileText />}
                        disabled={artifact.kind === 'loading'}
                        onClick={() => void previewWorkingCopy()}
                      >
                        {artifact.kind === 'loading'
                          ? t('externalInvite.workingCopy.loading')
                          : t('externalInvite.workingCopy.preview')}
                      </Button>
                    </div>

                    {artifact.kind === 'ready' ? (
                      <pre className="preview mono" data-testid="external-working-copy-preview">
                        {artifact.text}
                      </pre>
                    ) : null}
                    {artifact.kind === 'error' ? <ErrorNote error={artifact.error} /> : null}
                  </div>
                ) : (
                  <InlineWarning tone="warn" title={t('externalInvite.documentUnavailable.title')}>
                    {t('externalInvite.documentUnavailable.body')}
                  </InlineWarning>
                )}

                {envelope.external_envelope || envelope.signed_artifact ? (
                  <div className="stack--tight" data-testid="external-invite-technical-result">
                    <p className="card__label">{t('externalInvite.technical.title')}</p>
                    {envelope.external_envelope ? (
                      <dl className="deflist external-signature-deflist">
                        <div>
                          <dt>{t('externalInvite.technical.envelope')}</dt>
                          <dd className="mono">{envelope.external_envelope.id}</dd>
                        </div>
                        <div>
                          <dt>{t('externalInvite.technical.slot')}</dt>
                          <dd className="mono">{envelope.external_envelope.slot_id}</dd>
                        </div>
                        {envelope.external_envelope.slot_status ? (
                          <div>
                            <dt>{t('externalInvite.technical.slotStatus')}</dt>
                            <dd>{slotStatusBadge(envelope.external_envelope.slot_status, t)}</dd>
                          </div>
                        ) : null}
                      </dl>
                    ) : null}
                    {envelope.external_envelope?.technical_upload_auto_sign?.status ===
                    'blocked' ? (
                      <InlineWarning
                        tone="warn"
                        title={t('externalInvite.technical.blocked.title')}
                      >
                        {envelope.external_envelope.technical_upload_auto_sign.reason}
                      </InlineWarning>
                    ) : null}
                    {envelope.signed_artifact ? (
                      <>
                        <InlineWarning
                          tone="info"
                          title={t('externalInvite.technical.artifact.title')}
                        >
                          {envelope.signed_artifact.notice}
                        </InlineWarning>
                        <dl className="deflist external-signature-deflist">
                          <div>
                            <dt>{t('externalInvite.technical.evidenceLevel')}</dt>
                            <dd>{envelope.signed_artifact.evidentiary_level}</dd>
                          </div>
                          <div>
                            <dt>{t('externalInvite.technical.scope')}</dt>
                            <dd>{envelope.signed_artifact.status_scope}</dd>
                          </div>
                          <div>
                            <dt>{t('externalInvite.technical.digest')}</dt>
                            <dd>
                              <Digest
                                value={envelope.signed_artifact.signed_pdf_digest}
                                copyable={false}
                              />
                            </dd>
                          </div>
                          <div>
                            <dt>{t('externalInvite.technical.timestamp')}</dt>
                            <dd>
                              {envelope.signed_artifact.timestamp_token
                                ? t('common.yes')
                                : t('common.no')}
                            </dd>
                          </div>
                          <div>
                            <dt>{t('externalInvite.technical.qualificationClaimed')}</dt>
                            <dd>
                              {envelope.signed_artifact.qualification_claimed
                                ? t('common.yes')
                                : t('common.no')}
                            </dd>
                          </div>
                          <div>
                            <dt>{t('externalInvite.technical.legalStatusClaimed')}</dt>
                            <dd>
                              {envelope.signed_artifact.legal_status_claimed
                                ? t('common.yes')
                                : t('common.no')}
                            </dd>
                          </div>
                        </dl>
                      </>
                    ) : null}
                  </div>
                ) : null}

                {answered ? (
                  <p className="field__hint">{t('externalInvite.alreadyAnswered')}</p>
                ) : showSignedPdfUpload ? (
                  <form
                    className="form"
                    onSubmit={(event) => {
                      event.preventDefault();
                      if (canSubmitSignedPdf) void respond('accept');
                    }}
                  >
                    <InlineWarning tone="warn" title={t('externalInvite.upload.guardrail.title')}>
                      {t('externalInvite.upload.guardrail.body')}
                    </InlineWarning>
                    <Field
                      label={t('externalInvite.upload.file.label')}
                      htmlFor="external-signed-pdf"
                      hint={t('externalInvite.upload.file.hint')}
                    >
                      <Input
                        id="external-signed-pdf"
                        type="file"
                        accept="application/pdf,.pdf"
                        disabled={!!action}
                        onChange={(event) => {
                          const file = event.target.files?.[0] ?? null;
                          const sizeError = file ? signedPdfSizeError(file, t) : null;
                          setSignedPdfFile(sizeError ? null : file);
                          setSignedPdfAcknowledged(false);
                          setSignedPdfError(null);
                          if (sizeError) {
                            event.target.value = '';
                            setSignedPdfError(sizeError);
                          }
                        }}
                      />
                    </Field>
                    <label className="checkline" htmlFor="external-signed-pdf-ack">
                      <input
                        id="external-signed-pdf-ack"
                        type="checkbox"
                        checked={signedPdfAcknowledged}
                        disabled={!!action}
                        onChange={(event) => setSignedPdfAcknowledged(event.target.checked)}
                      />
                      {t('externalInvite.upload.ack')}
                    </label>
                    {signedPdfError ? <ErrorNote error={signedPdfError} /> : null}
                    <div className="form__actions">
                      <Button
                        type="submit"
                        variant="primary"
                        icon={<Icon.FileText />}
                        disabled={!canSubmitSignedPdf}
                      >
                        {action === 'accept'
                          ? t('externalInvite.registering')
                          : t('externalInvite.upload.submit')}
                      </Button>
                      <Button
                        type="button"
                        variant="secondary"
                        icon={<Icon.Close />}
                        disabled={!!action}
                        onClick={() => void respond('decline')}
                      >
                        {action === 'decline'
                          ? t('externalInvite.registering')
                          : t('externalInvite.decline')}
                      </Button>
                    </div>
                  </form>
                ) : (
                  <div className="form__actions">
                    <Button
                      type="button"
                      variant="primary"
                      icon={<Icon.Check />}
                      disabled={!!action}
                      onClick={() => void respond('accept')}
                    >
                      {action === 'accept'
                        ? t('externalInvite.registering')
                        : t('externalInvite.accept')}
                    </Button>
                    <Button
                      type="button"
                      variant="secondary"
                      icon={<Icon.Close />}
                      disabled={!!action}
                      onClick={() => void respond('decline')}
                    >
                      {action === 'decline'
                        ? t('externalInvite.registering')
                        : t('externalInvite.decline')}
                    </Button>
                  </div>
                )}
              </div>
            </section>
          ) : null}
        </main>
      </div>
    </>
  );
}
