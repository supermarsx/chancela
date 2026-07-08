/**
 * SigningPanel — the qualified Chave Móvel Digital signing surface on a sealed act (plan t57).
 *
 * A sealed act's unsigned PDF/A can be turned into a **qualified** CMD-signed PDF through an
 * honest two-phase flow:
 *   1. «Assinar com Chave Móvel Digital» → collect the mobile number + signature PIN → `initiate`
 *      (the server dispatches an SMS OTP);
 *   2. collect the OTP received by SMS → `confirm` → the act is signed.
 *
 * States are honest end-to-end (unsigned → pending/aguarda-OTP → signed): a 410 expired session
 * restarts cleanly, a rejected OTP surfaces a clear retry. The PIN and OTP are TRANSIENT — held
 * only in this component's form state for the duration of the request that consumes them, cleared
 * the instant they are sent, and never stored client-side beyond that. It is a qualified
 * electronic signature; the copy labels it accurately (never "valor probatório").
 *
 * Read errors render inline; the mutations follow the toast idiom (success + error) per
 * CONVENTIONS §2/§3. RBAC (t64) will later gate the signing ACTION via a `signing.perform`
 * permission — the server already session-gates it, so this UI does not build a parallel gate.
 */
import { useEffect, useState } from 'react';
import type { ActView, SignatureFamily } from '../../api/types';
import { ApiError } from '../../api/client';
import { signatureFamilyLabels } from '../../api/labels';
import {
  useActSignature,
  useCmdConfirmSignature,
  useCmdInitiateSignature,
  useDownloadSignedDocument,
} from '../../api/hooks';
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

/** The active step of the local two-phase flow (server-authoritative status backs the rest). */
type Step =
  | { kind: 'view' }
  | { kind: 'credentials' }
  | { kind: 'otp'; sessionId: string; maskedPhone: string };

export function SigningPanel({ act, entityName }: { act: ActView; entityName?: string }) {
  const t = useT();
  const toast = useToast();
  const formatDateTime = useDateTime();

  const sealed = act.state === 'Sealed' || act.state === 'Archived';
  const status = useActSignature(act.id, sealed);
  const initiate = useCmdInitiateSignature(act.id);
  const confirm = useCmdConfirmSignature(act.id);
  const download = useDownloadSignedDocument(act.id);

  const [step, setStep] = useState<Step>({ kind: 'view' });
  // PIN + OTP are transient: they live here only while the form is filled and are cleared the
  // instant they are sent. Nothing persists them (no localStorage, no query cache, no logging).
  const [phone, setPhone] = useState('');
  const [pin, setPin] = useState('');
  const [otp, setOtp] = useState('');
  const [expired, setExpired] = useState(false);

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
            {t('signing.signed.qualifiedLabel')}
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
      ) : (
        // --- UNSIGNED: the honest state + the entry action -----------------------------------
        <div className="stack--tight">
          <InlineWarning
            tone={data?.require_qualified_for_seal ? 'warn' : 'info'}
            title={t('signing.unsigned.title')}
          >
            {data?.require_qualified_for_seal
              ? t('signing.required.body')
              : t('signing.unsigned.body')}
          </InlineWarning>
          <Button
            type="button"
            variant="primary"
            icon={<Icon.PenNib />}
            onClick={() => setStep({ kind: 'credentials' })}
          >
            {t('signing.start')}
          </Button>
        </div>
      )}
    </Card>
  );
}
