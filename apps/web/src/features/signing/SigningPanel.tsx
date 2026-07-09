/**
 * SigningPanel — the qualified signing surface on a sealed act (plans t57 + t58 + t59).
 *
 * A sealed act's unsigned PDF/A can be turned into a **qualified** signed PDF through a chosen
 * signing method. The panel presents a provider picker and routes each choice to the right flow:
 *
 *   • **Chave Móvel Digital (CMD)** — an honest two-phase flow (t57), remote-capable:
 *       1. «Assinar com Chave Móvel Digital» → collect the mobile number + signature PIN →
 *          `cmd/initiate` (the server dispatches an SMS OTP);
 *       2. collect the OTP received by SMS → `cmd/confirm` → the act is signed.
 *
 *   • **Cartão de Cidadão (CC)** — a SYNCHRONOUS single call (t58), desktop-only. «Assinar com
 *     Cartão de Cidadão» → an honest prompt (insert the card; the PIN is entered AT THE READER
 *     via the Autenticação.gov middleware, never here) → `cc/sign` blocks while the card signs →
 *     the act is signed. CC only works when the API is co-located with the reader (the desktop
 *     app); a remote/browser server refuses with **409**, which we surface as an honest note.
 *
 *   • **A configured CSC QTSP** (Multicert / DigitalSign / … by label, t59) — the SAME two-phase
 *     activation flow as CMD, driven through the GENERIC endpoints
 *     `remote/{provider}/initiate|confirm` (provider = the chosen id): collect the user reference
 *     + credential → `initiate` (the QTSP dispatches an OTP/SAD) → enter the activation code →
 *     `confirm` → the act is signed. Only **configured** QTSPs are offered; an unconfigured one is
 *     shown disabled with an honest «não configurado» note.
 *
 * The picker is fed by `GET /v1/signature/providers`; CMD and CC are always offered (each has a
 * dedicated flow that does not depend on the list), and every configured CSC QTSP is appended. The
 * settings `preferred_family` marks the recommended method. When the list is unavailable (an older
 * server, or a principal without `signing.perform`) the panel simply offers CMD + CC.
 *
 * States are honest end-to-end (unsigned → pending/aguarda-OTP → signed): a 410 expired session
 * restarts cleanly, a rejected OTP surfaces a clear retry. The two-phase credential/OTP (CMD) and
 * user-reference/credential/activation (CSC) are TRANSIENT — held only in this component's form
 * state for the duration of the request that consumes them, cleared the instant they are sent, and
 * never stored client-side. The CC PIN never enters the web app at all (it is entered at the
 * reader). All produce a qualified electronic signature; the copy labels it accurately per method
 * (never "valor probatório").
 *
 * Read errors render inline; the mutations follow the toast idiom (success + error) per
 * CONVENTIONS §2/§3. The sign actions are gated with `useCan('signing.perform', <act's book
 * scope>)` (disable-with-explanation); the server re-enforces the permission regardless.
 */
import { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type {
  ActView,
  ExternalSignerInviteView,
  Settings,
  SignatureEvidenceStatus,
  SignatureFamily,
} from '../../api/types';
import { ApiError } from '../../api/client';
import { signatureFamilyLabels } from '../../api/labels';
import {
  keys,
  useActSignature,
  useCcSignSignature,
  useCmdConfirmSignature,
  useCmdInitiateSignature,
  useCreateExternalSignerInvite,
  useDownloadSignedDocument,
  useExternalSignerInvites,
  useRemoteConfirmSignature,
  useRemoteInitiateSignature,
  useRevokeExternalSignerInvite,
  useSignatureProviders,
} from '../../api/hooks';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import { GateButton, scopeBook, useCan, type CanScope } from '../session/permissions';
import { useLocale, useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  Digest,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  Skeleton,
  Table,
  TextArea,
  useToast,
} from '../../ui';

/** The serialized signing family a Cartão de Cidadão signature reports (t58-e2). */
const FAMILY_CC = 'CartaoDeCidadao';
/** The serialized signing family a CSC QTSP signature reports (t59-S3). */
const FAMILY_CSC = 'QualifiedCertificate';
/** The built-in Chave Móvel Digital provider id (its `{provider}` path segment). */
const CMD_PROVIDER_ID = 'cmd';

/** Slugify an entity/title fragment for a filesystem-friendly download name. */
function slug(value: string): string {
  return (
    value
      .normalize('NFD')
      .replace(/[̀-ͯ]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'documento'
  );
}

/** Localised date+time for the signing timestamps (falls back to the raw ISO on a parse miss). */
function useDateTime(): (iso: string) => string {
  const locale = useLocale();
  return (iso: string) => {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(d);
  };
}

function evidenceLevelLabel(level: string): string {
  if (level === 'Unsigned') return 'Sem assinatura';
  if (level === 'B-B') return 'PAdES B-B';
  if (level === 'B-T') return 'PAdES B-T';
  return level;
}

function longTermEvidenceLabel(status: string): string {
  if (status === 'timestamped') return 'carimbo temporal presente';
  if (status === 'not_configured') return 'carimbo temporal não configurado';
  if (status === 'lt_not_implemented') return 'B-LT não implementado';
  if (status === 'lta_not_implemented') return 'B-LTA não implementado';
  return status;
}

function dssEvidenceLabel(evidence: SignatureEvidenceStatus): string {
  if (evidence.dss_revocation_evidence_present) return 'presente';
  if (evidence.dss_revocation_evidence_status === 'unsupported') return 'não suportado';
  return evidence.dss_revocation_evidence_status;
}

function toLocalDateTimeInput(date: Date): string {
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

function defaultInviteExpiryInput(): string {
  return toLocalDateTimeInput(new Date(Date.now() + 2 * 24 * 60 * 60 * 1000));
}

function dateTimeInputToIso(value: string): string {
  return new Date(value).toISOString();
}

function externalInviteLink(token: string): string {
  const path = `/assinatura-externa?token=${encodeURIComponent(token)}`;
  if (typeof window === 'undefined') return path;
  return new URL(path, window.location.origin).toString();
}

/**
 * The chosen two-phase provider: `cmd` drives the dedicated `/signature/cmd/*` path; `csc`
 * drives the generic `/signature/remote/{id}/*` path. `label` names it in the prompts.
 */
type SigningProvider = { id: string; kind: 'cmd' | 'csc'; label: string };

/** The built-in CMD provider descriptor (its labels are fixed; `label` is unused for CMD). */
const CMD_PROVIDER: SigningProvider = { id: CMD_PROVIDER_ID, kind: 'cmd', label: 'CMD' };

/**
 * The active step of the local flow (server-authoritative status backs the rest). CMD and CSC
 * are two-phase (`credentials` → `otp`); CC is a single synchronous prompt (`cc`).
 */
type Step =
  | { kind: 'view' }
  | { kind: 'credentials'; provider: SigningProvider }
  | { kind: 'otp'; provider: SigningProvider; sessionId: string; hint: string }
  | { kind: 'cc' };

function SignatureEvidenceSummary({ evidence }: { evidence: SignatureEvidenceStatus }) {
  return (
    <InlineWarning tone="info" title="Evidência técnica da assinatura">
      <div className="stack--tight">
        <dl className="deflist">
          <div>
            <dt>Nível observado</dt>
            <dd>{evidenceLevelLabel(evidence.current_level)}</dd>
          </div>
          <div>
            <dt>Carimbo temporal</dt>
            <dd>{evidence.timestamp_evidence_present ? 'presente' : 'ausente'}</dd>
          </div>
          <div>
            <dt>DSS / revogação</dt>
            <dd>{dssEvidenceLabel(evidence)}</dd>
          </div>
          <div>
            <dt>Longo prazo</dt>
            <dd>{evidence.long_term_status.map(longTermEvidenceLabel).join('; ')}</dd>
          </div>
        </dl>
        <p className="field__hint">
          Apenas evidência técnica: Chancela não declara suporte B-LT/B-LTA nem validação legal de
          longo prazo quando DSS/revogação está “não suportado”.
        </p>
      </div>
    </InlineWarning>
  );
}

function inviteStatusBadge(invite: ExternalSignerInviteView) {
  if (invite.status === 'pending') return <Badge tone="accent">Pendente</Badge>;
  if (invite.status === 'accepted') return <Badge tone="ok">Aceite</Badge>;
  if (invite.status === 'declined') return <Badge tone="warn">Declinado</Badge>;
  if (invite.status === 'expired') return <Badge tone="warn">Expirado</Badge>;
  return <Badge tone="neutral">Revogado</Badge>;
}

function workflowLabel(workflow: string): string {
  if (workflow === 'tracking_only') return 'Acompanhamento apenas';
  return workflow;
}

function ExternalInviteSecretPanel({ token, onDone }: { token: string; onDone: () => void }) {
  const toast = useToast();
  const link = externalInviteLink(token);

  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      toast.success('Copiado.');
    } catch (err) {
      toast.error(err);
    }
  }

  return (
    <InlineWarning tone="warn" title="Token do convite emitido uma vez">
      <div className="stack--tight">
        <p>
          Copie o token ou a ligação agora. A lista guarda só o identificador redigido; este convite
          acompanha uma entrega externa e não conclui a assinatura.
        </p>
        <div className="api-key-secret__value">
          <code className="mono">{token}</code>
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.Copy />}
            onClick={() => copy(token)}
          >
            Copiar token
          </Button>
        </div>
        <div className="api-key-secret__value">
          <code className="mono">{link}</code>
          <Button type="button" variant="secondary" icon={<Icon.Copy />} onClick={() => copy(link)}>
            Copiar ligação
          </Button>
        </div>
        <div className="form__actions">
          <Button type="button" variant="primary" icon={<Icon.Check />} onClick={onDone}>
            Fechar aviso
          </Button>
        </div>
      </div>
    </InlineWarning>
  );
}

function ExternalInviteRow({
  actId,
  invite,
  bookScope,
  formatDateTime,
}: {
  actId: string;
  invite: ExternalSignerInviteView;
  bookScope: CanScope;
  formatDateTime: (iso: string) => string;
}) {
  const t = useT();
  const toast = useToast();
  const revoke = useRevokeExternalSignerInvite(actId);
  const [confirming, setConfirming] = useState(false);

  function doRevoke() {
    revoke.mutate(invite.id, {
      onSuccess: () => {
        toast.success('Convite revogado.');
        setConfirming(false);
      },
      onError: (err) => {
        toast.error(err);
        setConfirming(false);
      },
    });
  }

  return (
    <tr>
      <td>
        <strong>{invite.recipient_name}</strong>
        <br />
        <span className="muted">{invite.recipient_email}</span>
      </td>
      <td>{inviteStatusBadge(invite)}</td>
      <td>{workflowLabel(invite.workflow)}</td>
      <td>
        <code className="mono">{invite.token_hint}</code>
      </td>
      <td>{formatDateTime(invite.expires_at)}</td>
      <td className="users-actions">
        {invite.status !== 'pending' ? (
          <span className="muted">—</span>
        ) : confirming ? (
          <span className="row-wrap">
            <Button
              type="button"
              variant="ghost"
              disabled={revoke.isPending}
              onClick={() => setConfirming(false)}
            >
              {t('common.cancel')}
            </Button>
            <GateButton
              perm="signing.perform"
              scope={bookScope}
              type="button"
              variant="primary"
              icon={<Icon.Trash />}
              disabled={revoke.isPending}
              onClick={doRevoke}
            >
              {revoke.isPending ? 'A revogar…' : 'Confirmar revogação'}
            </GateButton>
          </span>
        ) : (
          <GateButton
            perm="signing.perform"
            scope={bookScope}
            type="button"
            variant="ghost"
            icon={<Icon.Trash />}
            disabled={revoke.isPending}
            onClick={() => setConfirming(true)}
          >
            Revogar
          </GateButton>
        )}
      </td>
    </tr>
  );
}

function ExternalSignerInvitesSection({
  act,
  formatDateTime,
}: {
  act: ActView;
  formatDateTime: (iso: string) => string;
}) {
  const t = useT();
  const toast = useToast();
  const can = useCan();
  const bookScope = scopeBook(act.book_id);
  const canManageInvites = can('signing.perform', bookScope);
  const invites = useExternalSignerInvites(act.id, canManageInvites);
  const create = useCreateExternalSignerInvite(act.id);
  const [creating, setCreating] = useState(false);
  const [issuedToken, setIssuedToken] = useState<string | null>(null);
  const [recipientName, setRecipientName] = useState('');
  const [recipientEmail, setRecipientEmail] = useState('');
  const [providerHint, setProviderHint] = useState('');
  const [purpose, setPurpose] = useState('Assinar a ata como signatário externo');
  const [expiresAt, setExpiresAt] = useState(() => defaultInviteExpiryInput());

  if (!canManageInvites) {
    return (
      <InlineWarning tone="info" title="Convites externos">
        A gestão de convites externos usa a mesma permissão de assinatura deste livro.
      </InlineWarning>
    );
  }

  const canSubmit =
    recipientName.trim().length > 0 &&
    recipientEmail.trim().length > 0 &&
    purpose.trim().length > 0 &&
    expiresAt.length > 0 &&
    !create.isPending;

  function resetForm() {
    setRecipientName('');
    setRecipientEmail('');
    setProviderHint('');
    setPurpose('Assinar a ata como signatário externo');
    setExpiresAt(defaultInviteExpiryInput());
  }

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    create.mutate(
      {
        recipient_name: recipientName.trim(),
        recipient_email: recipientEmail.trim(),
        provider_hint: providerHint.trim() || undefined,
        expires_at: dateTimeInputToIso(expiresAt),
        purpose: purpose.trim(),
      },
      {
        onSuccess: (result) => {
          setIssuedToken(result.token);
          setCreating(false);
          resetForm();
          create.reset();
          toast.success('Convite externo criado.');
        },
        onError: (err) => toast.error(err),
      },
    );
  }

  const list = invites.data ?? [];

  return (
    <div className="stack--tight">
      <div className="rowline">
        <strong>Convites de assinatura externa</strong>
        {!creating ? (
          <GateButton
            perm="signing.perform"
            scope={bookScope}
            type="button"
            variant="secondary"
            icon={<Icon.Plus />}
            onClick={() => setCreating(true)}
          >
            Criar convite
          </GateButton>
        ) : null}
      </div>
      <p className="field__hint">
        Regista uma entrega externa e um token de acompanhamento. Não contacta um prestador, não
        assina o PDF e não altera o nível de evidência.
      </p>

      {issuedToken ? (
        <ExternalInviteSecretPanel token={issuedToken} onDone={() => setIssuedToken(null)} />
      ) : null}

      {creating ? (
        <form className="form" onSubmit={onSubmit}>
          <div className="form__grid">
            <Field label="Nome do signatário" htmlFor="external-invite-name">
              <Input
                id="external-invite-name"
                value={recipientName}
                autoComplete="name"
                onChange={(e) => setRecipientName(e.target.value)}
              />
            </Field>
            <Field label="Email" htmlFor="external-invite-email">
              <Input
                id="external-invite-email"
                type="email"
                value={recipientEmail}
                autoComplete="email"
                onChange={(e) => setRecipientEmail(e.target.value)}
              />
            </Field>
            <Field label="Prestador ou referência" htmlFor="external-invite-provider">
              <Input
                id="external-invite-provider"
                value={providerHint}
                placeholder="opcional"
                onChange={(e) => setProviderHint(e.target.value)}
              />
            </Field>
            <Field label="Expira em" htmlFor="external-invite-expires">
              <Input
                id="external-invite-expires"
                type="datetime-local"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
              />
            </Field>
          </div>
          <Field label="Finalidade" htmlFor="external-invite-purpose">
            <TextArea
              id="external-invite-purpose"
              rows={3}
              value={purpose}
              onChange={(e) => setPurpose(e.target.value)}
            />
          </Field>
          {create.error ? <ErrorNote error={create.error} /> : null}
          <div className="form__actions">
            <Button
              type="button"
              variant="ghost"
              disabled={create.isPending}
              onClick={() => {
                setCreating(false);
                create.reset();
              }}
            >
              {t('common.cancel')}
            </Button>
            <GateButton
              perm="signing.perform"
              scope={bookScope}
              type="submit"
              variant="primary"
              icon={<Icon.Plus />}
              disabled={!canSubmit}
            >
              {create.isPending ? 'A criar…' : 'Criar convite'}
            </GateButton>
          </div>
        </form>
      ) : null}

      {invites.isLoading ? (
        <Skeleton height="4rem" />
      ) : invites.error ? (
        <ErrorNote error={invites.error} />
      ) : list.length === 0 ? (
        <EmptyState title="Sem convites externos">
          <p>Ainda não há convites externos registados para esta ata.</p>
        </EmptyState>
      ) : (
        <Table
          head={
            <tr>
              <th>Signatário</th>
              <th>Estado</th>
              <th>Fluxo</th>
              <th>Token</th>
              <th>Expiração</th>
              <th>Ações</th>
            </tr>
          }
        >
          {list.map((invite) => (
            <ExternalInviteRow
              key={invite.id}
              actId={act.id}
              invite={invite}
              bookScope={bookScope}
              formatDateTime={formatDateTime}
            />
          ))}
        </Table>
      )}
    </div>
  );
}

export function SigningPanel({ act, entityName }: { act: ActView; entityName?: string }) {
  const t = useT();
  const toast = useToast();
  const formatDateTime = useDateTime();

  const sealed = act.state === 'Sealed' || act.state === 'Archived';
  const status = useActSignature(act.id, sealed);
  const providers = useSignatureProviders(sealed);
  // The preferred signing family (for the «Recomendada» hint) is read from the already-loaded
  // settings cache — never a fresh fetch here, so a non-sealed act triggers no request at all.
  const qc = useQueryClient();
  const initiate = useCmdInitiateSignature(act.id);
  const confirm = useCmdConfirmSignature(act.id);
  const remoteInitiate = useRemoteInitiateSignature(act.id);
  const remoteConfirm = useRemoteConfirmSignature(act.id);
  const ccSign = useCcSignSignature(act.id);
  const download = useDownloadSignedDocument(act.id);
  // The sign actions are gated at the act's book scope (disable-with-explanation, t64-E5).
  const bookScope = scopeBook(act.book_id);

  const [step, setStep] = useState<Step>({ kind: 'view' });
  // The two-phase secrets are transient: they live here only while the form is filled and are
  // cleared the instant they are sent. `identifier` is the CMD phone / CSC user_ref; `secret` the
  // CMD PIN / CSC credential; `activation` the CMD OTP / CSC OTP-SAD. Nothing persists them (no
  // localStorage, no query cache, no logging).
  const [identifier, setIdentifier] = useState('');
  const [secret, setSecret] = useState('');
  const [activation, setActivation] = useState('');
  const [expired, setExpired] = useState(false);
  // Set once a CC sign attempt 409s: the API is not co-located with a card reader (browser /
  // remote server). We then swap the CC affordance for an honest note rather than fake it.
  const [ccBlocked, setCcBlocked] = useState(false);

  const data = status.data;
  // Only CSC QTSPs come from the picker list — CMD + CC always have their own always-available
  // entry actions and do not depend on the list resolving (older server / no `signing.perform`).
  const cscProviders = (providers.data ?? []).filter((p) => p.id !== CMD_PROVIDER_ID);
  const preferred = qc.getQueryData<Settings>(keys.settings)?.signing.preferred_family;

  /** Whether the settings `preferred_family` recommends a given entry method. */
  function isRecommended(target: 'cmd' | 'cc' | 'csc'): boolean {
    if (preferred === 'ChaveMovelDigital') return target === 'cmd';
    if (preferred === 'CartaoCidadao') return target === 'cc';
    if (preferred === 'OtherQualified') return target === 'csc';
    return false;
  }

  // Adopt a server-known pending session (e.g. after a reload mid-flow) into the OTP step, but
  // only from the neutral «view» step so a deliberate restart is never snapped back. The status
  // view does not carry the provider, so an adopted session is driven as CMD (its dedicated path).
  useEffect(() => {
    if (step.kind === 'view' && data?.status === 'pending' && data.pending) {
      setStep({
        kind: 'otp',
        provider: CMD_PROVIDER,
        sessionId: data.pending.session_id,
        hint: data.pending.masked_phone,
      });
    }
  }, [data, step.kind]);

  if (!sealed) return null;

  /** Enter phase 1 for a chosen provider. */
  function onPick(provider: SigningProvider) {
    setExpired(false);
    setIdentifier('');
    setSecret('');
    setActivation('');
    setStep({ kind: 'credentials', provider });
  }

  function onInitiate(e: React.FormEvent, provider: SigningProvider) {
    e.preventDefault();
    setExpired(false);
    const onSuccess = (sessionId: string, hint: string) => {
      setSecret(''); // credential consumed — drop it immediately
      setActivation('');
      setStep({ kind: 'otp', provider, sessionId, hint });
      toast.success(t('toast.signing.otpSent'));
    };
    if (provider.kind === 'cmd') {
      initiate.mutate(
        { phone: identifier.trim(), pin: secret },
        {
          onSuccess: (res) => onSuccess(res.session_id, res.masked_phone),
          onError: (err) => toast.error(err),
        },
      );
    } else {
      remoteInitiate.mutate(
        { provider: provider.id, body: { user_ref: identifier.trim(), credential: secret } },
        {
          onSuccess: (res) => onSuccess(res.session_id, res.activation_hint),
          onError: (err) => toast.error(err),
        },
      );
    }
  }

  function onConfirm(e: React.FormEvent, sessionId: string, provider: SigningProvider) {
    e.preventDefault();
    const onSuccess = () => {
      setActivation('');
      setIdentifier('');
      setSecret('');
      setStep({ kind: 'view' });
      toast.success(t('toast.signing.signed'));
    };
    const onError = (err: unknown) => {
      toast.error(err);
      // A 410 is an expired single-use session — restart cleanly at the credentials step.
      if (err instanceof ApiError && err.status === 410) {
        setActivation('');
        setExpired(true);
        setStep({ kind: 'credentials', provider });
      }
    };
    if (provider.kind === 'cmd') {
      confirm.mutate({ session_id: sessionId, otp: activation }, { onSuccess, onError });
    } else {
      remoteConfirm.mutate(
        { provider: provider.id, body: { session_id: sessionId, activation } },
        { onSuccess, onError },
      );
    }
  }

  function onCcSign() {
    // No secret in the body — the PIN is entered at the reader by the Autenticação.gov
    // middleware. The call BLOCKS while the card signs; the button shows «A assinar…».
    ccSign.mutate(
      {},
      {
        onSuccess: () => {
          setStep({ kind: 'view' });
          toast.success(t('toast.signing.signed'));
        },
        onError: (err) => {
          toast.error(err);
          // 409 = the API is not co-located with a reader (browser / remote server). Surface
          // the honest co-location note and drop the CC affordance rather than retry blindly.
          if (err instanceof ApiError && err.status === 409) {
            setCcBlocked(true);
            setStep({ kind: 'view' });
          }
          // A 422 provider error (no card / wrong PIN / not activated / no reader) STAYS on the
          // CC step so the honest server message renders inline for a retry.
        },
      },
    );
  }

  function showSaveResult(result: SaveBlobResult) {
    if (result.kind === 'cancelled') {
      toast.info(saveBlobResultMessage(result));
      return;
    }
    toast.success(saveBlobResultMessage(result));
  }

  function onDownloadSigned() {
    const base = entityName ? `${slug(entityName)}-` : '';
    const n = act.ata_number != null ? String(act.ata_number) : act.id;
    download.mutate(undefined, {
      onSuccess: async (blob) => {
        try {
          showSaveResult(
            await saveBlobAs({
              blob,
              filename: `${base}ata-${n}-assinada.pdf`,
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

  function familyLabel(family: string): string {
    return signatureFamilyLabels[family as SignatureFamily] ?? family;
  }

  /** The honest, method-accurate qualified-signature label for a signed record. */
  function qualifiedLabel(family: string): string {
    if (family === FAMILY_CC) return t('signing.signed.qualifiedLabelCc');
    if (family === FAMILY_CSC) return t('signing.signed.qualifiedLabelCsc');
    return t('signing.signed.qualifiedLabel');
  }

  return (
    <Card title={t('signing.title')}>
      <div className="stack--tight">
        {status.isLoading ? (
          <Skeleton height="6rem" />
        ) : status.error ? (
          <ErrorNote error={status.error} />
        ) : data?.status === 'signed' && data.signed ? (
          // --- SIGNED: the qualified-signature record + the signed-PDF download ----------------
          <div className="stack--tight">
            <InlineWarning tone="info" title={t('signing.signed.title')}>
              {qualifiedLabel(data.signed.family)}
            </InlineWarning>
            <dl className="deflist">
              <div>
                <dt>{t('signing.signed.signer')}</dt>
                <dd className="mono">{data.signed.signer_cert_subject ?? '—'}</dd>
              </div>
              <div>
                <dt>{t('signing.signed.family')}</dt>
                <dd>{familyLabel(data.signed.family)}</dd>
              </div>
              <div>
                <dt>{t('signing.signed.signingTime')}</dt>
                <dd>{formatDateTime(data.signed.signing_time)}</dd>
              </div>
              {data.signed.trusted_list_status ? (
                <div>
                  <dt>{t('signing.signed.trustedList')}</dt>
                  <dd>
                    <Badge tone={data.signed.trusted_list_status === 'Granted' ? 'ok' : 'warn'}>
                      {data.signed.trusted_list_status}
                    </Badge>
                  </dd>
                </div>
              ) : null}
              <div>
                <dt>{t('signing.signed.timestamp')}</dt>
                <dd>
                  {data.signed.timestamp_token
                    ? t('signing.signed.timestampPresent')
                    : t('signing.signed.timestampAbsent')}
                </dd>
              </div>
              <div>
                <dt>{t('signing.signed.digest')}</dt>
                <dd>
                  <Digest value={data.signed.signed_pdf_digest} />
                </dd>
              </div>
            </dl>
            <Button
              type="button"
              variant="primary"
              icon={<Icon.FileText />}
              disabled={download.isPending}
              onClick={onDownloadSigned}
            >
              {download.isPending ? t('documents.download.pending') : t('signing.download')}
            </Button>
          </div>
        ) : step.kind === 'credentials' ? (
          // --- PHASE 1: collect the identifier + credential (CMD phone/PIN; CSC user_ref/credential)
          (() => {
            const p = step.provider;
            const isCmd = p.kind === 'cmd';
            const initiating = isCmd ? initiate.isPending : remoteInitiate.isPending;
            const initiateError = isCmd ? initiate.error : remoteInitiate.error;
            return (
              <form className="form" onSubmit={(e) => onInitiate(e, p)}>
                {expired ? (
                  <InlineWarning tone="warn" title={t('signing.expired')}>
                    {isCmd ? t('signing.credentials.intro') : t('signing.csc.credentials.intro')}
                  </InlineWarning>
                ) : (
                  <p className="field__hint">
                    {isCmd ? t('signing.credentials.intro') : t('signing.csc.credentials.intro')}
                  </p>
                )}
                <Field
                  label={isCmd ? t('signing.phone.label') : t('signing.csc.userRef.label')}
                  htmlFor="sign-identifier"
                  hint={isCmd ? undefined : t('signing.csc.userRef.hint')}
                >
                  <Input
                    id="sign-identifier"
                    type={isCmd ? 'tel' : 'text'}
                    autoComplete="off"
                    value={identifier}
                    placeholder={isCmd ? t('signing.phone.placeholder') : undefined}
                    onChange={(e) => setIdentifier(e.target.value)}
                  />
                </Field>
                <Field
                  label={isCmd ? t('signing.pin.label') : t('signing.csc.credential.label')}
                  htmlFor="sign-secret"
                  hint={isCmd ? t('signing.pin.hint') : t('signing.csc.credential.hint')}
                >
                  <Input
                    id="sign-secret"
                    type="password"
                    inputMode={isCmd ? 'numeric' : 'text'}
                    autoComplete="off"
                    value={secret}
                    onChange={(e) => setSecret(e.target.value)}
                  />
                </Field>
                {initiateError ? <ErrorNote error={initiateError} /> : null}
                <div className="rowline">
                  <Button
                    type="submit"
                    variant="primary"
                    icon={<Icon.PenNib />}
                    disabled={initiating || !identifier.trim() || (isCmd && secret.length === 0)}
                  >
                    {isCmd
                      ? initiating
                        ? t('signing.initiate.pending')
                        : t('signing.initiate')
                      : initiating
                        ? t('signing.csc.initiate.pending')
                        : t('signing.csc.initiate')}
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    icon={<Icon.Refresh />}
                    disabled={initiating}
                    onClick={() => setStep({ kind: 'view' })}
                  >
                    {t('signing.cc.cancel')}
                  </Button>
                </div>
              </form>
            );
          })()
        ) : step.kind === 'otp' ? (
          // --- PHASE 2: collect the activation code (SMS OTP for CMD; OTP/SAD for CSC) and confirm
          (() => {
            const p = step.provider;
            const isCmd = p.kind === 'cmd';
            const confirming = isCmd ? confirm.isPending : remoteConfirm.isPending;
            const confirmError = isCmd ? confirm.error : remoteConfirm.error;
            return (
              <form className="form" onSubmit={(e) => onConfirm(e, step.sessionId, p)}>
                {isCmd ? (
                  <p className="field__hint">{t('signing.otp.sent', { phone: step.hint })}</p>
                ) : (
                  <>
                    <p className="field__hint">{t('signing.csc.otp.sent')}</p>
                    {step.hint ? <p className="field__hint">{step.hint}</p> : null}
                  </>
                )}
                <Field
                  label={isCmd ? t('signing.otp.label') : t('signing.csc.otp.label')}
                  htmlFor="sign-activation"
                  hint={isCmd ? t('signing.otp.hint') : t('signing.csc.otp.hint')}
                >
                  <Input
                    id="sign-activation"
                    inputMode={isCmd ? 'numeric' : 'text'}
                    autoComplete="one-time-code"
                    value={activation}
                    placeholder={isCmd ? t('signing.otp.placeholder') : undefined}
                    onChange={(e) => setActivation(e.target.value)}
                  />
                </Field>
                {confirmError ? <ErrorNote error={confirmError} /> : null}
                <div className="rowline">
                  <Button
                    type="submit"
                    variant="primary"
                    icon={<Icon.Check />}
                    disabled={confirming || activation.trim().length === 0}
                  >
                    {confirming ? t('signing.confirm.pending') : t('signing.confirm')}
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    icon={<Icon.Refresh />}
                    disabled={confirming}
                    onClick={() => {
                      setActivation('');
                      setSecret('');
                      setStep({ kind: 'credentials', provider: p });
                    }}
                  >
                    {t('signing.restart')}
                  </Button>
                </div>
              </form>
            );
          })()
        ) : step.kind === 'cc' ? (
          // --- CC: the honest synchronous prompt (PIN is entered at the reader) -----------------
          <div className="stack--tight">
            <InlineWarning tone="info" title={t('signing.cc.prompt.title')}>
              {t('signing.cc.prompt.body')}
            </InlineWarning>
            {ccSign.error ? <ErrorNote error={ccSign.error} /> : null}
            <div className="rowline">
              <Button
                type="button"
                variant="primary"
                icon={<Icon.IdCard />}
                disabled={ccSign.isPending}
                onClick={onCcSign}
              >
                {ccSign.isPending ? t('signing.cc.signing') : t('signing.cc.sign')}
              </Button>
              <Button
                type="button"
                variant="ghost"
                icon={<Icon.Refresh />}
                disabled={ccSign.isPending}
                onClick={() => setStep({ kind: 'view' })}
              >
                {t('signing.cc.cancel')}
              </Button>
            </div>
          </div>
        ) : (
          // --- UNSIGNED: the honest state + the provider picker (CMD + CC + configured CSC QTSPs) -
          <div className="stack--tight">
            <InlineWarning
              tone={data?.require_qualified_for_seal ? 'warn' : 'info'}
              title={t('signing.unsigned.title')}
            >
              {data?.require_qualified_for_seal
                ? t('signing.required.body')
                : t('signing.unsigned.body')}
            </InlineWarning>
            <div className="stack--tight">
              {/* Chave Móvel Digital — always offered (its dedicated two-phase path). */}
              <div className="rowline">
                <GateButton
                  perm="signing.perform"
                  scope={bookScope}
                  type="button"
                  variant="primary"
                  icon={<Icon.PenNib />}
                  onClick={() => onPick(CMD_PROVIDER)}
                >
                  {t('signing.start')}
                </GateButton>
                {isRecommended('cmd') ? (
                  <Badge tone="accent">{t('signing.recommended')}</Badge>
                ) : null}
              </div>
              {/* Cartão de Cidadão — always offered unless a 409 proved this server is not co-located. */}
              {ccBlocked ? null : (
                <div className="rowline">
                  <GateButton
                    perm="signing.perform"
                    scope={bookScope}
                    type="button"
                    variant="secondary"
                    icon={<Icon.IdCard />}
                    onClick={() => setStep({ kind: 'cc' })}
                  >
                    {t('signing.cc.start')}
                  </GateButton>
                  {isRecommended('cc') ? (
                    <Badge tone="accent">{t('signing.recommended')}</Badge>
                  ) : null}
                </div>
              )}
              {/* Every configured CSC QTSP (Multicert / DigitalSign / …) — the generic two-phase path.
                An unconfigured provider is shown disabled with an honest «não configurado» note. */}
              {cscProviders.map((provider) =>
                provider.configured ? (
                  <div className="rowline" key={provider.id}>
                    <GateButton
                      perm="signing.perform"
                      scope={bookScope}
                      type="button"
                      variant="secondary"
                      icon={<Icon.PenNib />}
                      onClick={() =>
                        onPick({ id: provider.id, kind: 'csc', label: provider.label })
                      }
                    >
                      {t('signing.csc.start', { provider: provider.label })}
                    </GateButton>
                    {isRecommended('csc') ? (
                      <Badge tone="accent">{t('signing.recommended')}</Badge>
                    ) : null}
                  </div>
                ) : (
                  <div className="rowline" key={provider.id}>
                    <Button
                      type="button"
                      variant="secondary"
                      icon={<Icon.PenNib />}
                      aria-disabled="true"
                      disabled
                    >
                      {t('signing.csc.start', { provider: provider.label })}
                    </Button>
                    <span className="field__hint">{t('signing.csc.notConfigured')}</span>
                  </div>
                ),
              )}
            </div>
            {ccBlocked ? (
              <InlineWarning tone="info" title={t('signing.cc.coLocation.title')}>
                {t('signing.cc.coLocation.body')}
              </InlineWarning>
            ) : null}
          </div>
        )}
        {data?.evidence ? <SignatureEvidenceSummary evidence={data.evidence} /> : null}
        <ExternalSignerInvitesSection act={act} formatDateTime={formatDateTime} />
      </div>
    </Card>
  );
}
