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

function statusBadge(status: ExternalSignerInviteStatus) {
  if (status === 'pending') return <Badge tone="accent">Pendente</Badge>;
  if (status === 'accepted') return <Badge tone="ok">Aceite</Badge>;
  if (status === 'declined') return <Badge tone="warn">Declinado</Badge>;
  if (status === 'expired') return <Badge tone="warn">Expirado</Badge>;
  return <Badge tone="neutral">Revogado</Badge>;
}

function unavailableMessage(error: unknown) {
  if (error instanceof ApiError && error.status === 404) {
    return (
      <InlineWarning tone="error" title="Convite indisponível">
        A ligação expirou, foi revogada ou não corresponde a um convite externo ativo.
      </InlineWarning>
    );
  }
  return <ErrorNote error={error} />;
}

export function ExternalSignerInvitePage() {
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
      toast.success(decision === 'accept' ? 'Resposta aceite registada.' : 'Declinação registada.');
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
          <p className="crumbs">Assinatura externa</p>
          <h1>Convite externo</h1>

          {load.kind === 'missing' ? (
            <InlineWarning tone="error" title="Ligação sem token">
              Abra a ligação completa enviada pelo operador da ata.
            </InlineWarning>
          ) : null}

          {load.kind === 'loading' ? <Loading label="A validar convite..." /> : null}
          {load.kind === 'error' ? unavailableMessage(load.error) : null}

          {envelope ? (
            <section className="panel">
              <header className="panel__head">
                <h2 className="panel__title">{envelope.act.title}</h2>
                {statusBadge(envelope.status)}
              </header>
              <div className="panel__body stack--tight">
                <InlineWarning tone="info" title="Acompanhamento apenas">
                  Este ecrã regista só a resposta ao convite externo. A aceitação é um
                  reconhecimento de acompanhamento, não assina o PDF e não conclui assinatura
                  qualificada.
                </InlineWarning>

                <dl className="deflist external-signature-deflist">
                  <div>
                    <dt>Entidade</dt>
                    <dd>{envelope.act.entity_name}</dd>
                  </div>
                  <div>
                    <dt>Livro</dt>
                    <dd>{envelope.act.book_kind}</dd>
                  </div>
                  <div>
                    <dt>Ata</dt>
                    <dd>{envelope.act.ata_number ? `n.º ${envelope.act.ata_number}` : '-'}</dd>
                  </div>
                  <div>
                    <dt>Reunião</dt>
                    <dd>{envelope.act.meeting_date ?? '-'}</dd>
                  </div>
                  <div>
                    <dt>Destinatário</dt>
                    <dd>{envelope.recipient_name}</dd>
                  </div>
                  <div>
                    <dt>Finalidade</dt>
                    <dd>{envelope.purpose}</dd>
                  </div>
                  {envelope.provider_hint ? (
                    <div>
                      <dt>Referência</dt>
                      <dd>{envelope.provider_hint}</dd>
                    </div>
                  ) : null}
                  <div>
                    <dt>Expira em</dt>
                    <dd>{formatDateTime(envelope.expires_at)}</dd>
                  </div>
                  {envelope.responded_at ? (
                    <div>
                      <dt>Resposta</dt>
                      <dd>{formatDateTime(envelope.responded_at)}</dd>
                    </div>
                  ) : null}
                </dl>

                {envelope.document ? (
                  <div className="stack--tight">
                    <dl className="deflist external-signature-deflist">
                      <div>
                        <dt>Documento</dt>
                        <dd className="mono">{envelope.document.id}</dd>
                      </div>
                      <div>
                        <dt>Modelo</dt>
                        <dd className="mono">{envelope.document.template_id}</dd>
                      </div>
                      <div>
                        <dt>Perfil</dt>
                        <dd className="mono">{envelope.document.profile}</dd>
                      </div>
                      <div>
                        <dt>Digest PDF/A</dt>
                        <dd>
                          <Digest value={envelope.document.pdf_digest} copyable={false} />
                        </dd>
                      </div>
                    </dl>

                    <InlineWarning tone="info" title="Cópia não probatória">
                      A pré-visualização disponível é Markdown não canónico. O PDF/A preservado e
                      qualquer PDF assinado não são disponibilizados por este convite.
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
                          ? 'A carregar cópia...'
                          : 'Pré-visualizar cópia .md'}
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
                  <InlineWarning tone="warn" title="Documento indisponível">
                    Este convite permite ver os metadados do ato, mas não há cópia de trabalho
                    disponível para pré-visualização.
                  </InlineWarning>
                )}

                {answered ? (
                  <p className="field__hint">
                    Resposta já registada para este convite. Este estado não é assinatura
                    qualificada.
                  </p>
                ) : (
                  <div className="form__actions">
                    <Button
                      type="button"
                      variant="primary"
                      icon={<Icon.Check />}
                      disabled={!!action}
                      onClick={() => void respond('accept')}
                    >
                      {action === 'accept' ? 'A registar...' : 'Aceitar acompanhamento'}
                    </Button>
                    <Button
                      type="button"
                      variant="secondary"
                      icon={<Icon.Close />}
                      disabled={!!action}
                      onClick={() => void respond('decline')}
                    >
                      {action === 'decline' ? 'A registar...' : 'Declinar'}
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
