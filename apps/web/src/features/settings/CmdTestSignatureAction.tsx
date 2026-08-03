/**
 * The CMD PRODUCTION test-signature flow (t51-e3/t69/t82/t94), launched from the CMD credential's
 * row in `ProviderCredentialsSection` and from `ProviderCredentialPage`.
 *
 * This is NOT {@link ProviderCredentialProbeResult} / `useProbeProviderCredentialEntry` — that is
 * a safe, non-document connectivity check. A completed run of THIS flow produces one real, legally
 * binding qualified electronic signature against AMA's live production service (see
 * `crates/chancela-api/src/cmd_test_signature.rs`'s module docs for why there is no rehearsal
 * mode). The two are kept visually and behaviourally distinct on purpose.
 *
 * # Why one stepped dialog, and why it still confirms twice
 *
 * The flow used to be two separate `ConfirmActionModal`s with the pending state and the whole
 * result panel spilled into the table cell between them, which read as three unrelated things
 * happening to a row. It is now ONE dialog that walks four steps — credentials, authorisation,
 * signature, result — with {@link Stepper} (the app's existing STATUS stepper, not a set of
 * controls) showing where the run is.
 *
 * What a naive single dialog would break: `ConfirmationAction::CmdTestSignature` is FLOORED (not
 * defaulted) at `ConfirmWithReauthAndPhrase`, and `initiate` and `confirm` each demand their own
 * proof — the server does not trust the first one. So the phrase and the step-up are collected
 * once per phase, here inside the step body rather than in a nested dialog: the step IS the
 * confirmation surface. {@link useConfirmationGate} (extracted from `ConfirmActionModal`, which
 * still uses it) supplies exactly the same fields, ids and copy, and its `resetKey` is the PHASE,
 * so crossing a phase boundary clears the proof — the UI can never imply that one confirmation
 * covered two requests. A rejected OTP does not reset it: that would cost the operator their
 * phrase and password for a mistake in a different field.
 *
 * # Failures stay individually recognisable
 *
 * Every failure the server can return here is diagnostic by design: the module refuses closed and
 * NAMES what is wrong (an unconfigured field, a preprod environment, a gone pinned entry, a
 * simulated transport, an untrusted trust anchor, nowhere to retain the result…). That exact
 * server text is rendered verbatim, inline, in the step it happened in — the stepper never
 * summarises a failure as "step N failed". A 403 is deliberately generic
 * (`confirm.reauth.required`) the same way every other reauth-gated action in this app renders
 * it. A 410 is not an error at all but a phase that aged out, and gets its own note. And a
 * negative self-validation verdict is rendered as prominently as a positive one, on the result
 * step, with the validator's own reason.
 */
import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import type {
  CmdTestSelfValidation,
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
import { useActiveLocale, useT } from '../../i18n';
import { formatDateTime } from '../../format';
import { useProviderCredentialsT } from '../../i18n/providerCredentialsFallback';
import {
  Badge,
  Button,
  ErrorNote,
  Field,
  Icon,
  IconButton,
  Input,
  Stepper,
  useToast,
  type StepperStep,
} from '../../ui';
import { useConfirmationGate } from '../../ui/ConfirmationGate';
import { useFocusTrap } from '../../ui/useFocusTrap';
import { saveBlobAs, saveBlobResultMessage } from '../../desktop/saveFile';
import './cmdTestSignature.css';

/**
 * The typed phrase `ConfirmationAction::CmdTestSignature` is floored at (`confirmation.rs`). Fixed
 * and non-localised by the server's own decision — this constant must reproduce it exactly, not
 * translate it; the gate's phrase input asks the operator to type this literal string regardless
 * of locale, and the server test suite pins it byte-for-byte. It is supplied here at the call
 * site rather than read back out of {@link useConfirmationGate}, which deliberately does not
 * expose the typed value — the literal at the call site is what pins the byte-exact string the
 * server compares against.
 */
const CMD_TEST_CONFIRM_PHRASE = 'ASSINAR TESTE';

/**
 * The coverage verdicts the server emits as stable tokens. A token outside this set is a server
 * newer than this build; it renders as the `unrecognised` sentence rather than as a raw token or,
 * worse, as one of the verdicts it is not.
 */
const COVERAGE_KEYS = [
  'whole_document',
  'ltv_augmented_signed_revision',
  'altered_after_signing',
  'malformed',
  'unrecognised',
  'unavailable',
] as const;

type CoverageKey = (typeof COVERAGE_KEYS)[number];

function coverageKey(coverage: string): CoverageKey {
  return (COVERAGE_KEYS as readonly string[]).includes(coverage)
    ? (coverage as CoverageKey)
    : 'unrecognised';
}

/**
 * The four steps of a run, in order. They are the stages that are genuinely distinguishable from
 * the client: what the operator supplies, what the operator's phone is waiting for, the one
 * request that both signs and self-validates, and what came back. Nothing here invents a stage
 * the client cannot observe.
 */
const FLOW_STEPS = ['credentials', 'authorisation', 'signature', 'result'] as const;

type FlowStep = (typeof FLOW_STEPS)[number];

/**
 * Whether the application's own validator was satisfied by the bytes it produced.
 *
 * ONE definition, read by the result panel and by the row summary, so the two can never disagree
 * about whether a completed test verified. An ABSENT verdict is not a failure — it is a server
 * older than `self_validation` — so it does not colour the summary as one.
 */
function selfValidationOk(validation: CmdTestSelfValidation | null | undefined): boolean {
  return !validation || (validation.signature_verifies && validation.covers_rendered_document);
}

/**
 * What the application's own validator said about the bytes it just produced.
 *
 * This is the half of "end to end" that the provider cannot answer for us: AMA returning a CMS
 * proves AMA answered, not that the result is a PAdES signature this product can verify over the
 * document it generated. A negative verdict is rendered as prominently as a positive one — the
 * signature is real and retained either way, and hiding a failure here would make the test worth
 * less than not running it.
 */
function CmdTestSelfValidationPanel({
  validation,
  pt,
  yesNo,
}: {
  validation: CmdTestSelfValidation;
  pt: ReturnType<typeof useProviderCredentialsT>;
  yesNo: (value: boolean) => string;
}) {
  const ok = selfValidationOk(validation);
  return (
    <section className="stack stack--tight" data-testid="cmd-test-self-validation">
      <div>
        <Badge tone={ok ? 'ok' : 'warn'}>{pt('providerCredentials.cmdTest.selfValidation')}</Badge>
      </div>
      <p className="field__hint">{pt('providerCredentials.cmdTest.selfValidationHint')}</p>
      <dl className="detail-grid">
        <div>
          <dt>{pt('providerCredentials.cmdTest.selfValidationVerifies')}</dt>
          <dd>{yesNo(validation.signature_verifies)}</dd>
        </div>
        <div>
          <dt>{pt('providerCredentials.cmdTest.selfValidationCovers')}</dt>
          <dd>{yesNo(validation.covers_rendered_document)}</dd>
        </div>
        <div>
          <dt>{pt('providerCredentials.cmdTest.selfValidationCoverage')}</dt>
          <dd>{pt(`providerCredentials.cmdTest.coverage.${coverageKey(validation.coverage)}`)}</dd>
        </div>
        <div>
          <dt>{pt('providerCredentials.cmdTest.selfValidationTimestamp')}</dt>
          <dd>{yesNo(validation.signature_timestamp_present)}</dd>
        </div>
        {/* The server's own explanation, rendered verbatim — it names what the validator refused. */}
        {validation.error ? (
          <div>
            <dt>{pt('providerCredentials.cmdTest.selfValidationError')}</dt>
            <dd>{validation.error}</dd>
          </div>
        ) : null}
      </dl>
      <p className="field__hint">
        {ok
          ? pt('providerCredentials.cmdTest.selfValidationOk')
          : pt('providerCredentials.cmdTest.selfValidationBad')}
      </p>
    </section>
  );
}

function CmdTestSignatureResultPanel({
  result,
  pt,
}: {
  result: CmdTestSignatureConfirmResult;
  pt: ReturnType<typeof useProviderCredentialsT>;
}) {
  const toast = useToast();
  const download = useDownloadCmdTestSignatureDocument();
  const yesNo = (value: boolean) =>
    value ? pt('providerCredentials.probe.yes') : pt('providerCredentials.probe.no');

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
    <section
      className="stack stack--tight"
      aria-live="polite"
      data-testid="cmd-test-signature-result"
    >
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
      {/* Older servers predate `self_validation`; render nothing rather than inventing a verdict. */}
      {result.self_validation ? (
        <CmdTestSelfValidationPanel validation={result.self_validation} pt={pt} yesNo={yesNo} />
      ) : null}
      <p className="field__hint">{pt('providerCredentials.cmdTest.disclaimer')}</p>
      <Button type="button" variant="secondary" disabled={download.isPending} onClick={onDownload}>
        {download.isPending
          ? pt('providerCredentials.cmdTest.downloadPending')
          : pt('providerCredentials.cmdTest.download')}
      </Button>
    </section>
  );
}

/**
 * The stepped flow. One dialog, four steps, TWO confirmations — see the module docs for why the
 * second one cannot be optimised away.
 *
 * The visible step is derived, never assigned: `result` wins, then an in-flight confirm, then a
 * live session. That is what makes the expiry path work without a second state machine — a 410
 * drops the session, so the flow lands back on `credentials` by construction and can only offer
 * a fresh initiate, never a confirm that could just 410 again.
 */
function CmdTestSignatureFlowModal({
  entry,
  open,
  onClose,
  session,
  result,
  expired,
  onInitiated,
  onSigned,
  onExpired,
  onRestart,
}: {
  entry: ProviderCredentialEntryView;
  open: boolean;
  onClose: () => void;
  session: CmdTestSignatureInitiateResult | null;
  result: CmdTestSignatureConfirmResult | null;
  expired: boolean;
  onInitiated: (session: CmdTestSignatureInitiateResult) => void;
  onSigned: (result: CmdTestSignatureConfirmResult) => void;
  onExpired: () => void;
  onRestart: () => void;
}) {
  const pt = useProviderCredentialsT();
  const t = useT();
  const locale = useActiveLocale();
  const toast = useToast();
  const initiate = useInitiateCmdTestSignature();
  const confirm = useConfirmCmdTestSignature();

  const [phone, setPhone] = useState('');
  const [pin, setPin] = useState('');
  const [otp, setOtp] = useState('');
  // Two shapes of failure, kept distinct rather than flattened to one string. A `reauth` refusal is
  // deliberately generic (the server refuses to say which proof was wrong); a `request` failure
  // carries the server's own `ApiError`, which `ErrorNote` resolves to a translated, per-code
  // headline — so a PIN/credential rejection (`cmd_service_rejected`) reads as "the PIN was
  // rejected" rather than the same generic line an untrusted anchor or a transport error would show.
  const [error, setError] = useState<
    { kind: 'reauth' } | { kind: 'request'; error: unknown } | null
  >(null);

  const bodyRef = useRef<HTMLFormElement>(null);
  const titleId = useRef(`cmd-test-${Math.random().toString(36).slice(2)}`).current;
  const trapRef = useFocusTrap<HTMLDivElement>(open);

  /**
   * Which request the next proof is for — NOT the same thing as the visible step. The in-flight
   * `signature` step still belongs to the confirm phase, and a rejected OTP must not cost the
   * operator the phrase and password they already typed for that same request.
   */
  const phase: 'initiate' | 'confirm' = session ? 'confirm' : 'initiate';

  const step: FlowStep = result
    ? 'result'
    : confirm.isPending
      ? 'signature'
      : session
        ? 'authorisation'
        : 'credentials';

  // Keyed on the phase: crossing a phase boundary clears the proof, because that is exactly
  // where the server stops accepting the previous one.
  const gate = useConfirmationGate({
    resetKey: `${open}:${phase}`,
    phrase: CMD_TEST_CONFIRM_PHRASE,
    requireReauth: true,
    idPrefix: `${titleId}-${phase}`,
    onProofKindChange: () => setError(null),
  });

  const busy = initiate.isPending || confirm.isPending;
  const canSubmit =
    step === 'credentials'
      ? phone.trim().length > 0 && pin.trim().length > 0
      : step === 'authorisation'
        ? otp.trim().length > 0
        : false;
  const ready = gate.ready && canSubmit && !busy;

  // A reopened dialog starts with no inherited secrets and no stale error. The RUN's own state
  // (a dispatched OTP, a finished result) deliberately survives a close — it exists on the
  // server either way, and a signed PDF that vanished with a dialog would be a real loss.
  useEffect(() => {
    if (!open) return;
    setPhone('');
    setPin('');
    setOtp('');
    setError(null);
  }, [open]);

  // Put focus on each step's first field as it arrives; without this the OTP box is several
  // tab stops away from where attention just moved.
  useEffect(() => {
    if (!open) return;
    const id = window.setTimeout(() => {
      bodyRef.current?.querySelector<HTMLElement>('input:not([type=checkbox]), textarea')?.focus();
    }, 0);
    return () => window.clearTimeout(id);
  }, [open, step]);

  // Escape closes — never mid-request, so a production signature is not abandoned in an
  // unknown state.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, busy, onClose]);

  if (!open) return null;

  const steps: StepperStep<FlowStep>[] = FLOW_STEPS.map((id) => ({
    id,
    label: pt(`providerCredentials.cmdTest.step.${id}`),
  }));

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!ready) return;
    setError(null);
    try {
      if (step === 'credentials') {
        const res = await initiate.mutateAsync({
          phone: phone.trim(),
          pin,
          entry_id: entry.entry_id,
          confirmation: { reauth: gate.reauth, confirm_phrase: CMD_TEST_CONFIRM_PHRASE },
        });
        setPin(''); // consumed — drop the PIN the instant the request returns
        onInitiated(res);
        toast.success(pt('providerCredentials.cmdTest.otpSentToast'));
      } else {
        if (!session) return;
        const res = await confirm.mutateAsync({
          session_id: session.session_id,
          otp: otp.trim(),
          confirmation: { reauth: gate.reauth, confirm_phrase: CMD_TEST_CONFIRM_PHRASE },
        });
        setOtp(''); // consumed — drop the OTP the instant the request returns
        onSigned(res);
        toast.success(pt('providerCredentials.cmdTest.signedToast'));
      }
    } catch (err) {
      // A 410 is the single-use session ageing out (5 minutes), not a failure of the test: drop
      // the session so the flow falls back to a fresh initiate rather than re-offering a confirm
      // that can only 410 again, and label it as a phase that expired. It is not an error surface —
      // the expired note carries the meaning — so clear any stale error and stop here.
      if (err instanceof ApiError && err.status === 410) {
        setError(null);
        onExpired();
        return;
      }
      if (err instanceof ApiError && err.status === 403) {
        // Deliberately generic, exactly as every other reauth-gated action renders it: saying
        // which proof was wrong would answer a question the server refuses to answer.
        setError({ kind: 'reauth' });
      } else {
        // The server's own diagnostic, resolved to a per-code headline by `ErrorNote`: a PIN
        // rejection (`cmd_service_rejected`), a preprod refusal, an untrusted anchor and a transport
        // error each get their own sentence, with the server's English detail demoted, not dropped.
        setError({ kind: 'request', error: err });
        toast.error(err);
      }
    }
  }

  return createPortal(
    <div
      className="modal-backdrop"
      onClick={() => {
        if (!busy) onClose();
      }}
    >
      <div
        ref={trapRef}
        className="modal modal--danger modal--flow"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="modal__head">
          <h2 className="modal__title" id={titleId}>
            {pt('providerCredentials.cmdTest.flowTitle')}
          </h2>
        </header>
        <form className="modal__body" onSubmit={submit} ref={bodyRef}>
          <Stepper
            steps={steps}
            current={step}
            ariaLabel={pt('providerCredentials.cmdTest.stepperLabel')}
          />

          {step === 'credentials' ? (
            <div className="cmd-test-step" data-testid="cmd-test-step-credentials">
              {/* An expired phase is its own fact, not a generic failure: it says that nothing
                  was signed and why the flow is back at the first step. */}
              {expired ? (
                <div className="cmd-test-expired" role="status">
                  <Badge tone="warn">{pt('providerCredentials.cmdTest.expiredTitle')}</Badge>
                  <p>{pt('providerCredentials.cmdTest.expiredBody')}</p>
                </div>
              ) : null}
              <div className="modal__intro">
                <p>{pt('providerCredentials.cmdTest.initiateIntro1')}</p>
                <p>
                  {pt('providerCredentials.cmdTest.initiateIntro2', {
                    label: entry.label || entry.entry_id,
                  })}
                </p>
                {/* WHICH environment this will run against, before the operator commits (t113).
                    The run is production-only and the server refuses anything else, so an entry
                    marked preprod is a refusal the operator should see coming rather than meet
                    after typing a phrase and a password. Read straight off the entry's own `env`
                    selector — the value the server now treats as authoritative. */}
                <p
                  className={entry.selectors.env === 'preprod' ? 'field__error' : 'field__hint'}
                  data-testid="cmd-test-environment-notice"
                >
                  {entry.selectors.env === 'prod'
                    ? pt('providerCredentials.cmdTest.envEntryProd')
                    : entry.selectors.env === 'preprod'
                      ? pt('providerCredentials.cmdTest.envEntryPreprod')
                      : pt('providerCredentials.cmdTest.envEntryInherited')}
                </p>
              </div>
              <Field
                label={pt('providerCredentials.cmdTest.phoneLabel')}
                htmlFor={`${titleId}-phone`}
                hint={pt('providerCredentials.cmdTest.phoneHint')}
              >
                <Input
                  id={`${titleId}-phone`}
                  value={phone}
                  autoComplete="off"
                  placeholder="+351 912345678"
                  onChange={(e) => setPhone(e.target.value)}
                />
              </Field>
              <Field label={pt('providerCredentials.cmdTest.pinLabel')} htmlFor={`${titleId}-pin`}>
                <Input
                  id={`${titleId}-pin`}
                  type="password"
                  value={pin}
                  autoComplete="off"
                  onChange={(e) => setPin(e.target.value)}
                />
              </Field>
              <p className="cmd-test-gate-note">
                {pt('providerCredentials.cmdTest.gateNoteInitiate')}
              </p>
              {gate.fields}
            </div>
          ) : null}

          {step === 'authorisation' && session ? (
            <div className="cmd-test-step" data-testid="cmd-test-step-authorisation">
              {/* The PIN-accepted checkpoint. The operator asked to check that the PIN works; this
                  is where the answer is made explicit — a confirmed step, not something inferred
                  from the flow advancing. Rendered only when the server states it as a value, so an
                  older server without the field shows no checkpoint rather than a claimed one. The
                  ceremony note keeps it honest: reaching here is not a free probe. */}
              {session.pin_accepted ? (
                <div
                  className="cmd-test-pin-accepted"
                  role="status"
                  data-testid="cmd-test-pin-accepted"
                >
                  <Badge tone="ok">{pt('providerCredentials.cmdTest.pinAccepted')}</Badge>
                  <p>
                    {pt('providerCredentials.cmdTest.pinAcceptedBody', {
                      phone: session.masked_phone,
                    })}
                  </p>
                  <p className="cmd-test-gate-note">
                    {pt('providerCredentials.cmdTest.pinAcceptedCeremony')}
                  </p>
                </div>
              ) : null}
              {/* The long step, and the only one where nothing is happening on either side of
                  the wire: the product is waiting on the PERSON. It says so, rather than
                  animating something that would imply work in progress. */}
              <div className="cmd-test-wait" role="status">
                <span className="cmd-test-wait__pulse" aria-hidden="true">
                  <span />
                  <span />
                  <span />
                </span>
                <div className="cmd-test-wait__body">
                  <p className="cmd-test-wait__title">
                    {pt('providerCredentials.cmdTest.waitingTitle')}
                  </p>
                  <p>
                    {pt('providerCredentials.cmdTest.pendingBody', {
                      phone: session.masked_phone,
                    })}
                  </p>
                  <p>{pt('providerCredentials.cmdTest.waitingNote')}</p>
                  <p>
                    {pt('providerCredentials.cmdTest.waitingExpiry', {
                      time: formatDateTime(session.expires_at, locale),
                    })}
                  </p>
                </div>
              </div>
              <Field label={pt('providerCredentials.cmdTest.otpLabel')} htmlFor={`${titleId}-otp`}>
                <Input
                  id={`${titleId}-otp`}
                  value={otp}
                  autoComplete="off"
                  inputMode="numeric"
                  onChange={(e) => setOtp(e.target.value)}
                />
              </Field>
              <p className="cmd-test-gate-note">
                {pt('providerCredentials.cmdTest.gateNoteConfirm')}
              </p>
              {gate.fields}
            </div>
          ) : null}

          {step === 'signature' ? (
            <div
              className="cmd-test-step"
              role="status"
              aria-live="polite"
              data-testid="cmd-test-step-signature"
            >
              <p className="cmd-test-wait__title">
                {pt('providerCredentials.cmdTest.signingTitle')}
              </p>
              <p className="field__hint">{pt('providerCredentials.cmdTest.signingBody')}</p>
            </div>
          ) : null}

          {step === 'result' && result ? (
            <CmdTestSignatureResultPanel result={result} pt={pt} />
          ) : null}

          {/* The server's own diagnostic, in the step it happened in. Never summarised, never
              narrowed — an untrusted trust anchor and a wrong PIN do not read alike. A reauth
              refusal stays generic; every other failure is routed through `ErrorNote`, which turns
              the stable `code` into a translated, per-fault headline (a PIN rejection names the
              signing PIN) and keeps the server's English detail in the technical-details block. */}
          {error?.kind === 'reauth' ? (
            <p className="field__error" role="alert">
              {t('confirm.reauth.required')}
            </p>
          ) : error?.kind === 'request' ? (
            <ErrorNote error={error.error} />
          ) : null}

          <div className="modal__foot">
            <Button type="button" variant="ghost" disabled={busy} onClick={onClose}>
              {step === 'result' ? pt('providerCredentials.cmdTest.close') : t('common.cancel')}
            </Button>
            {step === 'result' ? (
              <Button type="button" variant="secondary" onClick={onRestart}>
                {pt('providerCredentials.cmdTest.newTest')}
              </Button>
            ) : (
              <Button type="submit" variant="primary" className="btn--danger" disabled={!ready}>
                {step === 'credentials'
                  ? initiate.isPending
                    ? pt('providerCredentials.cmdTest.initiatePending')
                    : pt('providerCredentials.cmdTest.initiateConfirm')
                  : confirm.isPending
                    ? pt('providerCredentials.cmdTest.confirmPending')
                    : pt('providerCredentials.cmdTest.confirmConfirm')}
              </Button>
            )}
          </div>
        </form>
      </div>
    </div>,
    document.body,
  );
}

/**
 * How the launcher presents itself, which depends entirely on where it is placed.
 *
 * - `'icon'` — inside the credential table, alongside move/edit/probe/remove. Labels there would
 *   crowd a cell that already holds four other controls, and the accessible name carries the whole
 *   sentence instead.
 * - `'labelled'` — under the *Teste de ponta a ponta em produção* heading, where this is the only
 *   control on screen. See {@link CmdTestSignatureAction} for why that one is the exception.
 */
export type CmdTestSignaturePresentation = 'icon' | 'labelled';

/**
 * The launcher, and the owner of a run's state.
 *
 * State lives here rather than in the dialog so that closing the dialog is not the same as
 * throwing a run away: a dispatched OTP is live on the server for five minutes, and a completed
 * test owns a retained signed PDF. The row therefore carries one control whose label says where
 * the run stands, and reopening resumes it at the step it is actually on — instead of the
 * previous arrangement, which grew a pending block and the whole result panel inside a table cell.
 *
 * # Why this control is the exception to icon-only
 *
 * Everything else on this surface was made icon-only (t112) because it sits in a dense row where
 * five labels would not fit and the glyphs are unambiguous. This one is placed twice, and the two
 * placements are not the same control in the same context:
 *
 * - In the table it is one of five, and it keeps the pen nib.
 * - Under the end-to-end section heading it stands **alone**, and it is the most consequential
 *   control anywhere in the settings: a completed run costs one real qualified electronic
 *   signature against AMA's production service, billed and legally effective. There is no crowding
 *   argument there, and a bare pen nib made the page's gravest action its least legible one — the
 *   glyph cannot say "a real qualified signature" and nothing but the surrounding paragraph did.
 *
 * So `'labelled'` states the consequence in the button itself. An operator should not have to have
 * read the paragraph above to know what they are about to start.
 */
export function CmdTestSignatureAction({
  entry,
  canPerform,
  presentation = 'icon',
}: {
  entry: ProviderCredentialEntryView;
  canPerform: boolean;
  presentation?: CmdTestSignaturePresentation;
}) {
  const t = useT();
  const pt = useProviderCredentialsT();

  const [open, setOpen] = useState(false);
  const [session, setSession] = useState<CmdTestSignatureInitiateResult | null>(null);
  const [result, setResult] = useState<CmdTestSignatureConfirmResult | null>(null);
  const [expired, setExpired] = useState(false);

  const disabled = !canPerform || !entry.enabled;
  const validated = result ? selfValidationOk(result.self_validation) : true;
  const labelled = presentation === 'labelled';

  /**
   * What the control is called, in whichever state the run is in.
   *
   * In the icon presentation this is also the accessible NAME and the tooltip, so it has to carry
   * everything a label would: which action this is, and where the run stands.
   *
   * The idle label differs between the two presentations, and only the idle one does. Alone under
   * its heading the button says what it will do and what it costs; in the table it keeps the
   * shorter row wording, because the accessible name of an icon competes with four siblings and
   * the section paragraph is not there to lean on either way. The pending and completed states are
   * already full sentences and read correctly in both places.
   */
  const actionLabel = !canPerform
    ? labelled
      ? t('settings.providerCredentials.cmdTest.runEndToEnd')
      : pt('providerCredentials.cmdTest.permission')
    : result
      ? pt('providerCredentials.cmdTest.viewResult')
      : session
        ? pt('providerCredentials.cmdTest.confirmButton')
        : labelled
          ? t('settings.providerCredentials.cmdTest.runEndToEnd')
          : pt('providerCredentials.cmdTest.button');

  return (
    <div className="stack stack--tight">
      <span className="row-wrap">
        {labelled ? (
          // The icon stays: a primary button with a leading glyph is this app's idiom (the form's
          // own submit, `provider.addEntry`), and the pen nib is the mark this action already owns.
          <Button
            type="button"
            variant="primary"
            icon={<Icon.PenNib />}
            disabled={disabled}
            // An inert button must still say why. `!entry.enabled` is visible on the row itself;
            // the missing permission is not, so it is named here rather than swallowed.
            title={!canPerform ? pt('providerCredentials.cmdTest.permission') : undefined}
            data-testid="cmd-test-signature-open"
            onClick={() => setOpen(true)}
          >
            {actionLabel}
          </Button>
        ) : (
          <IconButton
            icon={<Icon.PenNib />}
            label={actionLabel}
            disabled={disabled}
            data-testid="cmd-test-signature-open"
            onClick={() => setOpen(true)}
          />
        )}
        {session ? <Badge tone="warn">{pt('providerCredentials.cmdTest.pending')}</Badge> : null}
        {/* A test whose signature the application could NOT verify does not get to look like a
            clean pass from the table either. */}
        {result ? (
          <Badge tone={validated ? 'ok' : 'warn'}>
            {validated
              ? pt('providerCredentials.cmdTest.rowDone')
              : pt('providerCredentials.cmdTest.rowDoneUnverified')}
          </Badge>
        ) : null}
      </span>

      <CmdTestSignatureFlowModal
        entry={entry}
        open={open}
        onClose={() => setOpen(false)}
        session={session}
        result={result}
        expired={expired}
        onInitiated={(s) => {
          setSession(s);
          setExpired(false);
        }}
        onSigned={(r) => {
          setSession(null);
          setResult(r);
        }}
        onExpired={() => {
          setSession(null);
          setExpired(true);
        }}
        onRestart={() => {
          setResult(null);
          setExpired(false);
        }}
      />
    </div>
  );
}
