/**
 * SigningPanel — the qualified signing surface on a sealed act (plans t57 + t58).
 *
 * A sealed act's unsigned PDF/A can be turned into a **qualified** signed PDF through either of
 * two methods, offered side by side:
 *
 *   • **Chave Móvel Digital (CMD)** — an honest two-phase flow (t57), remote-capable:
 *       1. «Assinar com Chave Móvel Digital» → collect the mobile number + signature PIN →
 *          `initiate` (the server dispatches an SMS OTP);
 *       2. collect the OTP received by SMS → `confirm` → the act is signed.
 *
 *   • **Cartão de Cidadão (CC)** — a SYNCHRONOUS single call (t58), desktop-only. «Assinar com
 *     Cartão de Cidadão» → an honest prompt (insert the card; the PIN is entered AT THE READER
 *     via the Autenticação.gov middleware, never here) → `cc/sign` blocks while the card signs →
 *     the act is signed. CC only works when the API is co-located with the reader (the desktop
 *     app); a remote/browser server refuses with **409**, which we surface as an honest note.
 *     A provider failure (no card / wrong PIN / card not activated / no reader) is an honest
 *     **422** whose PT message is surfaced verbatim.
 *
 * States are honest end-to-end (unsigned → pending/aguarda-OTP → signed): a 410 expired CMD
 * session restarts cleanly, a rejected OTP surfaces a clear retry. The CMD PIN/OTP are TRANSIENT —
 * held only in this component's form state for the duration of the request that consumes them,
 * cleared the instant they are sent, and never stored client-side. The CC PIN never enters the
 * web app at all (it is entered at the reader). Both produce a qualified electronic signature; the
 * copy labels it accurately per method (never "valor probatório").
 *
 * Read errors render inline; the mutations follow the toast idiom (success + error) per
 * CONVENTIONS §2/§3. The CC action is gated with `useCan('signing.perform', <act's book scope>)`
 * (disable-with-explanation); the server re-enforces the permission regardless.
 */
import { useEffect, useState } from 'react';
import type { ActView, SignatureFamily } from '../../api/types';
import { ApiError } from '../../api/client';
import { signatureFamilyLabels } from '../../api/labels';
import {
  useActSignature,
  useCcSignSignature,
  useCmdConfirmSignature,
  useCmdInitiateSignature,
  useDownloadSignedDocument,
} from '../../api/hooks';
import { GateButton, scopeBook } from '../session/permissions';
import { useLocale, useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  Digest,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  Skeleton,
  useToast,
} from '../../ui';

/** The serialized signing family a Cartão de Cidadão signature reports (t58-e2). */
const FAMILY_CC = 'CartaoDeCidadao';

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

/** Trigger a browser download of a Blob with an explicit filename. */
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

/** Localised date+time for the signing timestamps (falls back to the raw ISO on a parse miss). */
function useDateTime(): (iso: string) => string {
  const locale = useLocale();
  return (iso: string) => {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(d);
  };
}

/**
 * The active step of the local flow (server-authoritative status backs the rest). CMD is
 * two-phase (`credentials` → `otp`); CC is a single synchronous prompt (`cc`).
 */
type Step =
  | { kind: 'view' }
  | { kind: 'credentials' }
  | { kind: 'otp'; sessionId: string; maskedPhone: string }
  | { kind: 'cc' };

export function SigningPanel({ act, entityName }: { act: ActView; entityName?: string }) {
  const t = useT();
  const toast = useToast();
  const formatDateTime = useDateTime();

  const sealed = act.state === 'Sealed' || act.state === 'Archived';
  const status = useActSignature(act.id, sealed);
  const initiate = useCmdInitiateSignature(act.id);
  const confirm = useCmdConfirmSignature(act.id);
  const ccSign = useCcSignSignature(act.id);
  const download = useDownloadSignedDocument(act.id);
  // The CC action is gated at the act's book scope (disable-with-explanation, t64-E5).
  const bookScope = scopeBook(act.book_id);

  const [step, setStep] = useState<Step>({ kind: 'view' });
  // PIN + OTP are transient: they live here only while the form is filled and are cleared the
  // instant they are sent. Nothing persists them (no localStorage, no query cache, no logging).
  const [phone, setPhone] = useState('');
  const [pin, setPin] = useState('');
  const [otp, setOtp] = useState('');
  const [expired, setExpired] = useState(false);
  // Set once a CC sign attempt 409s: the API is not co-located with a card reader (browser /
  // remote server). We then swap the CC affordance for an honest note rather than fake it.
  const [ccBlocked, setCcBlocked] = useState(false);

  const data = status.data;

  // Adopt a server-known pending session (e.g. after a reload mid-flow) into the OTP step, but
  // only from the neutral «view» step so a deliberate restart is never snapped back.
  useEffect(() => {
    if (step.kind === 'view' && data?.status === 'pending' && data.pending) {
      setStep({
        kind: 'otp',
        sessionId: data.pending.session_id,
        maskedPhone: data.pending.masked_phone,
      });
    }
  }, [data, step.kind]);

  if (!sealed) return null;

  function onInitiate(e: React.FormEvent) {
    e.preventDefault();
    setExpired(false);
    initiate.mutate(
      { phone: phone.trim(), pin },
      {
        onSuccess: (res) => {
          setPin(''); // secret consumed — drop it immediately
          setOtp('');
          setStep({ kind: 'otp', sessionId: res.session_id, maskedPhone: res.masked_phone });
          toast.success(t('toast.signing.otpSent'));
        },
        onError: (err) => toast.error(err),
      },
    );
  }

  function onConfirm(e: React.FormEvent, sessionId: string) {
    e.preventDefault();
    confirm.mutate(
      { session_id: sessionId, otp },
      {
        onSuccess: () => {
          setOtp('');
          setPhone('');
          setStep({ kind: 'view' });
          toast.success(t('toast.signing.signed'));
        },
        onError: (err) => {
          toast.error(err);
          // A 410 is an expired single-use session — restart cleanly at the credentials step.
          if (err instanceof ApiError && err.status === 410) {
            setOtp('');
            setExpired(true);
            setStep({ kind: 'credentials' });
          }
        },
      },
    );
  }

  function onRestart() {
    setOtp('');
    setPin('');
    setStep({ kind: 'credentials' });
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

  function onDownloadSigned() {
    const base = entityName ? `${slug(entityName)}-` : '';
    const n = act.ata_number != null ? String(act.ata_number) : act.id;
    download.mutate(undefined, {
      onSuccess: (blob) => {
        triggerDownload(blob, `${base}ata-${n}-assinada.pdf`);
        toast.success(t('toast.signing.downloaded'));
      },
      onError: (e) => toast.error(e),
    });
  }

  function familyLabel(family: string): string {
    return signatureFamilyLabels[family as SignatureFamily] ?? family;
  }

  return (
    <Card title={t('signing.title')}>
      {status.isLoading ? (
        <Skeleton height="6rem" />
      ) : status.error ? (
        <ErrorNote error={status.error} />
      ) : data?.status === 'signed' && data.signed ? (
        // --- SIGNED: the qualified-signature record + the signed-PDF download ----------------
        <div className="stack--tight">
          <InlineWarning tone="info" title={t('signing.signed.title')}>
            {data.signed.family === FAMILY_CC
              ? t('signing.signed.qualifiedLabelCc')
              : t('signing.signed.qualifiedLabel')}
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
        // --- PHASE 1: collect the mobile number + signature PIN ------------------------------
        <form className="form" onSubmit={onInitiate}>
          {expired ? (
            <InlineWarning tone="warn" title={t('signing.expired')}>
              {t('signing.credentials.intro')}
            </InlineWarning>
          ) : (
            <p className="field__hint">{t('signing.credentials.intro')}</p>
          )}
          <Field label={t('signing.phone.label')} htmlFor="sign-phone">
            <Input
              id="sign-phone"
              type="tel"
              autoComplete="off"
              value={phone}
              placeholder={t('signing.phone.placeholder')}
              onChange={(e) => setPhone(e.target.value)}
            />
          </Field>
          <Field label={t('signing.pin.label')} htmlFor="sign-pin" hint={t('signing.pin.hint')}>
            <Input
              id="sign-pin"
              type="password"
              inputMode="numeric"
              autoComplete="off"
              value={pin}
              onChange={(e) => setPin(e.target.value)}
            />
          </Field>
          {initiate.error ? <ErrorNote error={initiate.error} /> : null}
          <div className="form__actions">
            <Button
              type="submit"
              variant="primary"
              icon={<Icon.PenNib />}
              disabled={initiate.isPending || !phone.trim() || pin.length === 0}
            >
              {initiate.isPending ? t('signing.initiate.pending') : t('signing.initiate')}
            </Button>
          </div>
        </form>
      ) : step.kind === 'otp' ? (
        // --- PHASE 2: collect the SMS OTP and confirm ----------------------------------------
        <form className="form" onSubmit={(e) => onConfirm(e, step.sessionId)}>
          <p className="field__hint">{t('signing.otp.sent', { phone: step.maskedPhone })}</p>
          <Field label={t('signing.otp.label')} htmlFor="sign-otp" hint={t('signing.otp.hint')}>
            <Input
              id="sign-otp"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={otp}
              placeholder={t('signing.otp.placeholder')}
              onChange={(e) => setOtp(e.target.value)}
            />
          </Field>
          {confirm.error ? <ErrorNote error={confirm.error} /> : null}
          <div className="rowline">
            <Button
              type="submit"
              variant="primary"
              icon={<Icon.Check />}
              disabled={confirm.isPending || otp.trim().length === 0}
            >
              {confirm.isPending ? t('signing.confirm.pending') : t('signing.confirm')}
            </Button>
            <Button
              type="button"
              variant="ghost"
              icon={<Icon.Refresh />}
              disabled={confirm.isPending}
              onClick={onRestart}
            >
              {t('signing.restart')}
            </Button>
          </div>
        </form>
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
        // --- UNSIGNED: the honest state + the entry actions (CMD + CC) ------------------------
        <div className="stack--tight">
          <InlineWarning
            tone={data?.require_qualified_for_seal ? 'warn' : 'info'}
            title={t('signing.unsigned.title')}
          >
            {data?.require_qualified_for_seal
              ? t('signing.required.body')
              : t('signing.unsigned.body')}
          </InlineWarning>
          <div className="rowline">
            <Button
              type="button"
              variant="primary"
              icon={<Icon.PenNib />}
              onClick={() => setStep({ kind: 'credentials' })}
            >
              {t('signing.start')}
            </Button>
            {ccBlocked ? null : (
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
            )}
          </div>
          {ccBlocked ? (
            <InlineWarning tone="info" title={t('signing.cc.coLocation.title')}>
              {t('signing.cc.coLocation.body')}
            </InlineWarning>
          ) : null}
        </div>
      )}
    </Card>
  );
}
