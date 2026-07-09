import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { ApiError, api } from '../../api/client';
import type {
  ExternalSignerInviteDecision,
  ExternalSignerInvitePublicView,
  ExternalSignerInviteStatus,
} from '../../api/types';
import { Badge, Button, Digest, ErrorNote, Icon, InlineWarning, Loading, useToast } from '../../ui';
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

function formatDateTime(value?: string): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date);
}

function statusBadge(status: ExternalSignerInviteStatus, t: TFunction) {
  if (status === 'pending')
    return <Badge tone="accent">{t('externalInvite.status.pending')}</Badge>;
  if (status === 'accepted') return <Badge tone="ok">{t('externalInvite.status.accepted')}</Badge>;
  if (status === 'declined')
    return <Badge tone="warn">{t('externalInvite.status.declined')}</Badge>;
  if (status === 'expired') return <Badge tone="warn">{t('externalInvite.status.expired')}</Badge>;
  return <Badge tone="neutral">{t('externalInvite.status.revoked')}</Badge>;
}

function unavailableMessage(error: unknown, t: TFunction) {
  if (error instanceof ApiError && error.status === 404) {
    return (
      <InlineWarning tone="error" title={t('externalInvite.unavailable.title')}>
        {t('externalInvite.unavailable.body')}
      </InlineWarning>
    );
  }
  return <ErrorNote error={error} />;
}

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
    setAction(decision);
    try {
      const envelope = await api.respondExternalSignerInvite(token, decision);
      setLoad({ kind: 'ready', envelope });
      toast.success(
        decision === 'accept'
          ? t('externalInvite.toast.accepted')
          : t('externalInvite.toast.declined'),
      );
    } catch (error) {
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

                {answered ? (
                  <p className="field__hint">{t('externalInvite.alreadyAnswered')}</p>
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
