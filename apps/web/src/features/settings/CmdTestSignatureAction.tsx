/**
 * The CMD PRODUCTION test-signature trigger (t51-e3/t69), wired into the CMD credential's
 * `ProviderCredentialsSection` entry row.
 *
 * This is NOT {@link ProviderCredentialProbeResult} / `useProbeProviderCredentialEntry` — that is
 * a safe, non-document connectivity check. A completed run of THIS flow produces one real, legally
 * binding qualified electronic signature against AMA's live production service (see
 * `crates/chancela-api/src/cmd_test_signature.rs`'s module docs for why there is no rehearsal
 * mode). The two are kept visually and behaviourally distinct on purpose, and this control is
 * floored server-side at `ConfirmWithReauthAndPhrase` — the request is refused with a 403 unless
 * both an in-app re-auth proof AND the exact typed phrase ride along, on EACH of the two phases.
 * `ConfirmActionModal` already implements that gate end to end (phrase + step-up, inline 403
 * handling), so both phases reuse it verbatim rather than re-deriving the mechanics.
 *
 * Every failure the server can return here is diagnostic by design: the module refuses closed and
 * NAMES what is wrong (an unconfigured field, a preprod environment, a gone pinned entry, a
 * simulated transport, nowhere to retain the result…). `ConfirmActionModal` already surfaces a
 * non-403 mutation error's exact server message inline (and toasts it); a 403 is deliberately
 * generic ("confirm.reauth.required") the same way every other reauth-gated action in this app
 * renders it. Nothing here re-derives or narrows that server text.
 */
import { useState } from 'react';
import type {
  CmdTestSignatureConfirmResult,
  CmdTestSignatureInitiateResult,
  ProviderCredentialEntryView,
} from '../../api/types';
import { ApiError } from '../../api/client';
import {
  useConfirmCmdTestSignature,
  useDownloadCmdTestSignatureDocument,
  useInitiateCmdTestSignature,
} from '../../api/hooks';
import { useProviderCredentialsT } from '../../i18n/providerCredentialsFallback';
import { Badge, Button, Field, Input, useToast } from '../../ui';
import { ConfirmActionModal } from '../../ui/ConfirmActionModal';
import { saveBlobAs, saveBlobResultMessage } from '../../desktop/saveFile';

/**
 * The typed phrase `ConfirmationAction::CmdTestSignature` is floored at (`confirmation.rs`). Fixed
 * and non-localised by the server's own decision — this constant must reproduce it exactly, not
 * translate it; the confirmation input in `ConfirmActionModal` asks the operator to type this
 * literal string regardless of locale, and the server test suite pins it byte-for-byte.
 */
const CMD_TEST_CONFIRM_PHRASE = 'ASSINAR TESTE';

function CmdTestSignatureResultPanel({
  result,
  pt,
}: {
  result: CmdTestSignatureConfirmResult;
  pt: ReturnType<typeof useProviderCredentialsT>;
}) {
  const toast = useToast();
  const download = useDownloadCmdTestSignatureDocument();
  const yesNo = (value: boolean) => (value ? pt('providerCredentials.probe.yes') : pt('providerCredentials.probe.no'));

  function onDownload() {
    download.mutate(result.test_id, {
      onSuccess: async (blob) => {
        try {
          const saved = await saveBlobAs({
            blob,
            filename: `cmd-teste-${result.test_id}.pdf`,
            contentType: 'application/pdf',
            preferBrowserSavePicker: true,
          });
          toast.success(saveBlobResultMessage(saved));
        } catch (e) {
          toast.error(e);
        }
      },
      onError: (e) => toast.error(e),
    });
  }

  return (
    <section className="stack stack--tight" aria-live="polite" data-testid="cmd-test-signature-result">
      <div>
        <Badge tone="ok">{pt('providerCredentials.cmdTest.resultSigned')}</Badge>
      </div>
      <dl className="detail-grid">
        <div>
          <dt>{pt('providerCredentials.cmdTest.legalEffect')}</dt>
          <dd>{pt('providerCredentials.cmdTest.legalEffectNone')}</dd>
        </div>
        <div>
          <dt>{pt('providerCredentials.cmdTest.countsBookOpening')}</dt>
          <dd>{yesNo(result.counts_toward_book_opening)}</dd>
        </div>
        <div>
          <dt>{pt('providerCredentials.cmdTest.countsActSignature')}</dt>
          <dd>{yesNo(result.counts_toward_act_signature)}</dd>
        </div>
        <div>
          <dt>{pt('providerCredentials.cmdTest.digest')}</dt>
          <dd className="mono">{result.signed_pdf_digest}</dd>
        </div>
        <div>
          <dt>{pt('providerCredentials.cmdTest.signedAt')}</dt>
          <dd>
            <time dateTime={result.signed_at}>{result.signed_at}</time>
          </dd>
        </div>
        <div>
          <dt>{pt('providerCredentials.cmdTest.credentialSource')}</dt>
          <dd>
            {result.credential_source === 'stored_entry'
              ? pt('providerCredentials.cmdTest.credentialSourceStored')
              : pt('providerCredentials.cmdTest.credentialSourceEnv')}
          </dd>
        </div>
        {result.trusted_list_status ? (
          <div>
            <dt>{pt('providerCredentials.cmdTest.trustedList')}</dt>
            <dd className="mono">{result.trusted_list_status}</dd>
          </div>
        ) : null}
        <div>
          <dt>{pt('providerCredentials.cmdTest.timestamped')}</dt>
          <dd>{yesNo(result.timestamped)}</dd>
        </div>
      </dl>
      <p className="field__hint">{pt('providerCredentials.cmdTest.disclaimer')}</p>
      <Button type="button" variant="secondary" disabled={download.isPending} onClick={onDownload}>
        {download.isPending
          ? pt('providerCredentials.cmdTest.downloadPending')
          : pt('providerCredentials.cmdTest.download')}
      </Button>
    </section>
  );
}

export function CmdTestSignatureAction({
  entry,
  canPerform,
}: {
  entry: ProviderCredentialEntryView;
  canPerform: boolean;
}) {
  const pt = useProviderCredentialsT();
  const toast = useToast();
  const initiate = useInitiateCmdTestSignature();
  const confirm = useConfirmCmdTestSignature();

  const [initiateOpen, setInitiateOpen] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [phone, setPhone] = useState('');
  const [pin, setPin] = useState('');
  const [otp, setOtp] = useState('');
  const [session, setSession] = useState<CmdTestSignatureInitiateResult | null>(null);
  const [result, setResult] = useState<CmdTestSignatureConfirmResult | null>(null);

  const disabled = !canPerform || !entry.enabled;
  const entryLabel = entry.label || entry.entry_id;

  function openInitiate() {
    setPhone('');
    setPin('');
    setResult(null);
    setInitiateOpen(true);
  }

  function openConfirm() {
    setOtp('');
    setConfirmOpen(true);
  }

  return (
    <div className="stack stack--tight">
      <Button
        type="button"
        variant="ghost"
        disabled={disabled}
        title={!canPerform ? pt('providerCredentials.cmdTest.permission') : undefined}
        onClick={openInitiate}
      >
        {result ? pt('providerCredentials.cmdTest.newTest') : pt('providerCredentials.cmdTest.button')}
      </Button>

      {session ? (
        <div className="stack--tight" role="status">
          <Badge tone="warn">{pt('providerCredentials.cmdTest.pending')}</Badge>
          <p className="field__hint">
            {pt('providerCredentials.cmdTest.pendingBody', { phone: session.masked_phone })}
          </p>
          <Button type="button" variant="secondary" onClick={openConfirm}>
            {pt('providerCredentials.cmdTest.confirmButton')}
          </Button>
        </div>
      ) : null}

      {result ? <CmdTestSignatureResultPanel result={result} pt={pt} /> : null}

      {/* Phase 1 — dispatches a real OTP to the citizen's device. Nothing is signed yet. */}
      <ConfirmActionModal
        open={initiateOpen}
        onClose={() => setInitiateOpen(false)}
        title={pt('providerCredentials.cmdTest.initiateTitle')}
        intro={
          <>
            <p>{pt('providerCredentials.cmdTest.initiateIntro1')}</p>
            <p>{pt('providerCredentials.cmdTest.initiateIntro2', { label: entryLabel })}</p>
          </>
        }
        confirmLabel={pt('providerCredentials.cmdTest.initiateConfirm')}
        pendingLabel={pt('providerCredentials.cmdTest.initiatePending')}
        danger
        phrase={CMD_TEST_CONFIRM_PHRASE}
        requireReauth
        pending={initiate.isPending}
        canConfirm={phone.trim().length > 0 && pin.trim().length > 0}
        onConfirm={async ({ reauth }) => {
          const res = await initiate.mutateAsync({
            phone: phone.trim(),
            pin,
            entry_id: entry.entry_id,
            confirmation: { reauth, confirm_phrase: CMD_TEST_CONFIRM_PHRASE },
          });
          setPin(''); // consumed — drop the PIN the instant the request returns
          setSession(res);
          toast.success(pt('providerCredentials.cmdTest.otpSentToast'));
        }}
      >
        <Field
          label={pt('providerCredentials.cmdTest.phoneLabel')}
          htmlFor="cmd-test-phone"
          hint={pt('providerCredentials.cmdTest.phoneHint')}
        >
          <Input
            id="cmd-test-phone"
            value={phone}
            autoComplete="off"
            placeholder="+351 912345678"
            onChange={(e) => setPhone(e.target.value)}
          />
        </Field>
        <Field label={pt('providerCredentials.cmdTest.pinLabel')} htmlFor="cmd-test-pin">
          <Input
            id="cmd-test-pin"
            type="password"
            value={pin}
            autoComplete="off"
            onChange={(e) => setPin(e.target.value)}
          />
        </Field>
      </ConfirmActionModal>

      {/* Phase 2 — the point at which the real qualified signature comes into existence. Carries
          its own confirmation proof; the server does not trust phase 1's. */}
      <ConfirmActionModal
        open={confirmOpen && session !== null}
        onClose={() => setConfirmOpen(false)}
        title={pt('providerCredentials.cmdTest.confirmTitle')}
        intro={pt('providerCredentials.cmdTest.confirmIntro', {
          phone: session?.masked_phone ?? '',
        })}
        confirmLabel={pt('providerCredentials.cmdTest.confirmConfirm')}
        pendingLabel={pt('providerCredentials.cmdTest.confirmPending')}
        danger
        phrase={CMD_TEST_CONFIRM_PHRASE}
        requireReauth
        pending={confirm.isPending}
        canConfirm={otp.trim().length > 0}
        onConfirm={async ({ reauth }) => {
          if (!session) return;
          try {
            const res = await confirm.mutateAsync({
              session_id: session.session_id,
              otp: otp.trim(),
              confirmation: { reauth, confirm_phrase: CMD_TEST_CONFIRM_PHRASE },
            });
            setOtp(''); // consumed — drop the OTP the instant the request returns
            setSession(null);
            setResult(res);
            toast.success(pt('providerCredentials.cmdTest.signedToast'));
          } catch (err) {
            // A 410 is the single-use session aging out (5 minutes): drop it so the panel falls
            // back to the initiate button rather than re-offering a confirm that can only 410
            // again. `ConfirmActionModal` still renders the server's own message inline.
            if (err instanceof ApiError && err.status === 410) {
              setSession(null);
            }
            throw err;
          }
        }}
      >
        <Field label={pt('providerCredentials.cmdTest.otpLabel')} htmlFor="cmd-test-otp">
          <Input
            id="cmd-test-otp"
            value={otp}
            autoComplete="off"
            inputMode="numeric"
            onChange={(e) => setOtp(e.target.value)}
          />
        </Field>
      </ConfirmActionModal>
    </div>
  );
}
