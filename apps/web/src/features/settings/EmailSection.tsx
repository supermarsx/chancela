/**
 * Email (SMTP) — operator configuration of outbound mail (t23).
 *
 * This section is a hybrid, because the configuration genuinely has two halves:
 *
 * - The **non-secret** half (host, port, encryption, username, sender identity) is part of the
 *   settings document. It edits the page's working copy through `onChange` and rides the same
 *   debounced autosave as every other settings section — there is no separate save button here.
 * - The **password** is not, and must not be. It is write-only: `type="password"`, never
 *   pre-filled (the API has no field that could return it), held only in component-local state,
 *   and cleared the moment it is submitted so it never reaches the react-query cache. What the
 *   server reports back is a single boolean, `password_configured`.
 *
 * The **test send** exists because SMTP settings that cannot be verified are settings that
 * silently do not work. It reports the relay's real answer — stage, SMTP code, enhanced status
 * code and the server's own words — rather than a generic failure, because `535 5.7.8 Error:
 * authentication failed` and `554 5.7.1 Relay access denied` need completely different fixes.
 *
 * Mirrors the `ProviderCredentialsSection` idioms: `Card`/`Field`/`Input`, disabled+pending
 * mutating controls, inline error + toast, and RBAC-gated on `settings.manage`.
 */
import { useState } from 'react';
import type { EmailDeliveryView, EmailSettings, SmtpEncryption } from '../../api/types';
import { EMAIL_DELIVERIES_LIMIT, SMTP_ENCRYPTIONS } from '../../api/types';
import {
  useClearEmailPassword,
  useEmailDeliveries,
  useEmailStatus,
  useResendEmailDelivery,
  useSetEmailPassword,
  useTestEmail,
} from '../../api/hooks';
import { useT, type TFunction } from '../../i18n';
import type { MessageKey } from '../../i18n';
import {
  Badge,
  Card,
  ColumnHead,
  DateTime,
  EmptyState,
  ErrorNote,
  Field,
  FieldHelp,
  Icon,
  InlineWarning,
  Input,
  Select,
  SkeletonRegion,
  SkeletonTable,
  Table,
  Toggle,
  useToast,
} from '../../ui';
import { GateButton, useCan } from '../session/permissions';
import { emailFieldHelp } from './fieldHelp';
import { EmailTestDetail } from './EmailTestDetail';
import './emailDeliveries.css';

type Props = {
  /** The working copy's email slice, owned by `SettingsPage`. */
  email: EmailSettings;
  /** Writes back into the working copy; the page autosaves it. */
  onChange: <K extends keyof EmailSettings>(key: K, value: EmailSettings[K]) => void;
};

/** i18n key for an encryption mode's label. */
function encryptionLabel(mode: SmtpEncryption): MessageKey {
  switch (mode) {
    case 'starttls':
      return 'settings.email.encryption.starttls';
    case 'implicit_tls':
      return 'settings.email.encryption.implicitTls';
    case 'none':
      return 'settings.email.encryption.none';
  }
}

/** i18n key naming the stage a failed session died at. */
function stageLabel(stage: string): MessageKey {
  switch (stage) {
    case 'connect':
      return 'settings.email.stage.connect';
    case 'tls':
      return 'settings.email.stage.tls';
    case 'greeting':
      return 'settings.email.stage.greeting';
    case 'ehlo':
      return 'settings.email.stage.ehlo';
    case 'starttls':
      return 'settings.email.stage.starttls';
    case 'auth':
      return 'settings.email.stage.auth';
    case 'mail_from':
      return 'settings.email.stage.mailFrom';
    case 'rcpt_to':
      return 'settings.email.stage.rcptTo';
    case 'data':
      return 'settings.email.stage.data';
    default:
      return 'settings.email.stage.quit';
  }
}

/** i18n key for the operator's next step, per failure kind. This is the difference between a
 *  useful diagnostic and "sending failed". */
function remedyLabel(kind: string): MessageKey {
  switch (kind) {
    case 'dns':
      return 'settings.email.remedy.dns';
    case 'unreachable':
      return 'settings.email.remedy.unreachable';
    case 'tls':
      return 'settings.email.remedy.tls';
    case 'tls_unsupported':
      return 'settings.email.remedy.tlsUnsupported';
    case 'timeout':
      return 'settings.email.remedy.timeout';
    case 'configuration':
      return 'settings.email.remedy.configuration';
    case 'protocol':
      return 'settings.email.remedy.protocol';
    default:
      return 'settings.email.remedy.rejected';
  }
}

/**
 * i18n key naming the stage a recorded delivery died at (t108).
 *
 * Deliberately NOT [`stageLabel`]: that one is for a test send, whose failure always came from a
 * real SMTP session, so folding an unknown token into "session close" is harmless there. A recorded
 * delivery can also carry `not_configured` — the stage of a send that never reached a socket — and
 * calling that "session close" would be a fabrication. `undefined` means "no sentence for this
 * token", and the caller renders it verbatim as an identifier rather than inventing one.
 */
function deliveryStageLabel(stage: string): MessageKey | undefined {
  switch (stage) {
    case 'connect':
      return 'settings.email.stage.connect';
    case 'tls':
      return 'settings.email.stage.tls';
    case 'greeting':
      return 'settings.email.stage.greeting';
    case 'ehlo':
      return 'settings.email.stage.ehlo';
    case 'starttls':
      return 'settings.email.stage.starttls';
    case 'auth':
      return 'settings.email.stage.auth';
    case 'mail_from':
      return 'settings.email.stage.mailFrom';
    case 'rcpt_to':
      return 'settings.email.stage.rcptTo';
    case 'data':
      return 'settings.email.stage.data';
    case 'quit':
      return 'settings.email.stage.quit';
    case 'not_configured':
      return 'settings.email.deliveries.stage.notConfigured';
    default:
      return undefined;
  }
}

/** i18n key naming what a recorded message WAS, for the two templates this build actually sends.
 *  An id with no sentence renders verbatim in `mono`: an unnamed identifier is honest, a guessed
 *  name is not. */
function templateLabel(templateId: string): MessageKey | undefined {
  switch (templateId) {
    case 'user.welcome':
      return 'settings.email.deliveries.template.welcome';
    case 'device.pairing_code':
      return 'settings.email.deliveries.template.pairingCode';
    default:
      return undefined;
  }
}

export function EmailSection({ email, onChange }: Props) {
  const t = useT();
  const toast = useToast();
  const can = useCan();
  const editable = can('settings.manage');

  const status = useEmailStatus();
  const setPassword = useSetEmailPassword();
  const clearPassword = useClearEmailPassword();
  const test = useTestEmail();

  // Write-only: the plaintext lives here and nowhere else, and is wiped on submit.
  const [password, setPasswordDraft] = useState('');
  const [testTo, setTestTo] = useState('');

  const passwordConfigured = status.data?.password_configured ?? false;
  const busy = setPassword.isPending || clearPassword.isPending;

  // The email service's health, surfaced at the top of the section the way the API and MCP tabs
  // surface their per-service status. `deliverable` already folds in enabled + host + sender +
  // a password backing any username (EmailStatusView, smtp_settings.rs), so it is the single
  // readiness signal; the disabled state is read from the working copy so the badge tracks the
  // toggle live rather than only after a save round-trip.
  const emailStatus: { label: MessageKey; tone: 'ok' | 'warn' | 'neutral' } = !email.enabled
    ? { label: 'settings.email.status.off', tone: 'neutral' }
    : status.data?.deliverable
      ? { label: 'settings.email.status.ready', tone: 'ok' }
      : { label: 'settings.email.status.notReady', tone: 'warn' };

  function submitPassword() {
    if (!password) return;
    setPassword.mutate(password, {
      onSuccess: () => {
        setPasswordDraft('');
        toast.success(t('settings.email.password.savedToast'));
      },
      onError: (e) => toast.error(e),
    });
  }

  function submitClear() {
    clearPassword.mutate(undefined, {
      onSuccess: () => {
        setPasswordDraft('');
        toast.success(t('settings.email.password.clearedToast'));
      },
      onError: (e) => toast.error(e),
    });
  }

  return (
    <>
      <Card
        title={t('settings.email.cardTitle')}
        actions={<Badge tone={emailStatus.tone}>{t(emailStatus.label)}</Badge>}
      >
        <p className="lede">{t('settings.email.lede')}</p>

        <div className="form settings-rows">
          {/* A boolean row, not a `Field` wrapping one: the `Field` label was a second copy of
              the switch's own text (and, having no control of its own to point at, an orphan
              `<label>`). `.settings-rows > .toggle` puts the switch in the control column and
              keeps the hint attached to it — same row shape, one label. */}
          <Toggle
            id="set-email-enabled"
            checked={email.enabled}
            disabled={!editable}
            label={
              <>
                {t('settings.email.enabled.label')} <FieldHelp text={emailFieldHelp.enabled} />
              </>
            }
            onChange={(v) => onChange('enabled', v)}
          />
          <p className="field__hint">{t('settings.email.enabled.hint')}</p>

          <Field
            label={t('settings.email.host.label')}
            htmlFor="set-email-host"
            hint={t('settings.email.host.hint')}
            help={emailFieldHelp.host}
          >
            <Input
              id="set-email-host"
              value={email.host ?? ''}
              disabled={!editable}
              placeholder={t('settings.email.host.placeholder')}
              onChange={(e) => onChange('host', e.target.value)}
            />
          </Field>

          <Field
            label={t('settings.email.port.label')}
            htmlFor="set-email-port"
            hint={t('settings.email.port.hint')}
            help={emailFieldHelp.port}
          >
            <Input
              id="set-email-port"
              type="number"
              min={1}
              max={65535}
              value={String(email.port)}
              disabled={!editable}
              onChange={(e) => onChange('port', Number(e.target.value))}
            />
          </Field>

          <Field
            label={t('settings.email.encryptionField.label')}
            htmlFor="set-email-encryption"
            hint={t('settings.email.encryptionField.hint')}
            help={emailFieldHelp.encryption}
          >
            <Select
              id="set-email-encryption"
              value={email.encryption}
              disabled={!editable}
              options={SMTP_ENCRYPTIONS.map((mode) => ({
                value: mode,
                label: t(encryptionLabel(mode)),
              }))}
              onChange={(e) => {
                const next = e.target.value as SmtpEncryption;
                onChange('encryption', next);
                // Re-enabling encryption retires the acknowledgement, so turning it off again is a
                // fresh, deliberate decision rather than a stale flag nobody remembers setting.
                if (next !== 'none') onChange('allow_insecure', false);
              }}
            />
          </Field>

          {email.encryption === 'none' ? (
            <InlineWarning tone="error" title={t('settings.email.insecure.title')}>
              <p>{t('settings.email.insecure.body')}</p>
              <Toggle
                id="set-email-allow-insecure"
                checked={email.allow_insecure}
                disabled={!editable}
                label={t('settings.email.insecure.confirm')}
                onChange={(v) => onChange('allow_insecure', v)}
              />
            </InlineWarning>
          ) : null}

          <Field
            label={t('settings.email.username.label')}
            htmlFor="set-email-username"
            hint={t('settings.email.username.hint')}
            help={emailFieldHelp.username}
          >
            <Input
              id="set-email-username"
              value={email.username ?? ''}
              disabled={!editable}
              autoComplete="off"
              onChange={(e) => onChange('username', e.target.value)}
            />
          </Field>

          <Field
            label={t('settings.email.fromAddress.label')}
            htmlFor="set-email-from-address"
            hint={t('settings.email.fromAddress.hint')}
            help={emailFieldHelp.from_address}
          >
            <Input
              id="set-email-from-address"
              type="email"
              value={email.from_address ?? ''}
              disabled={!editable}
              placeholder={t('settings.email.fromAddress.placeholder')}
              onChange={(e) => onChange('from_address', e.target.value)}
            />
          </Field>

          <Field
            label={t('settings.email.fromName.label')}
            htmlFor="set-email-from-name"
            hint={t('settings.email.fromName.hint')}
            help={emailFieldHelp.from_name}
          >
            <Input
              id="set-email-from-name"
              value={email.from_name ?? ''}
              disabled={!editable}
              onChange={(e) => onChange('from_name', e.target.value)}
            />
          </Field>

          <Field
            label={t('settings.email.heloName.label')}
            htmlFor="set-email-helo-name"
            hint={t('settings.email.heloName.hint')}
            help={emailFieldHelp.helo_name}
          >
            <Input
              id="set-email-helo-name"
              value={email.helo_name ?? ''}
              disabled={!editable}
              onChange={(e) => onChange('helo_name', e.target.value)}
            />
          </Field>
        </div>
      </Card>

      {/* Password — its own card because it is its own endpoint and its own security posture. */}
      <Card
        className="email-card"
        title={t('settings.email.password.cardTitle')}
        actions={
          <Badge tone={passwordConfigured ? 'ok' : 'neutral'}>
            {passwordConfigured
              ? t('settings.email.password.configured')
              : t('settings.email.password.notConfigured')}
          </Badge>
        }
      >
        <p className="lede">{t('settings.email.password.lede')}</p>
        {status.error ? <ErrorNote error={status.error} /> : null}
        {setPassword.error ? <ErrorNote error={setPassword.error} /> : null}
        {clearPassword.error ? <ErrorNote error={clearPassword.error} /> : null}

        <div className="form settings-rows">
          <Field
            label={t('settings.email.password.label')}
            htmlFor="set-email-password"
            hint={t('settings.email.password.hint')}
            help={emailFieldHelp.password}
          >
            <Input
              id="set-email-password"
              type="password"
              autoComplete="off"
              value={password}
              disabled={!editable || busy}
              placeholder={t('settings.email.password.placeholder')}
              onChange={(e) => setPasswordDraft(e.target.value)}
            />
          </Field>
        </div>
        <div className="form__actions">
          <GateButton
            perm="settings.manage"
            type="button"
            icon={<Icon.Save />}
            disabled={!password || busy}
            onClick={submitPassword}
          >
            {t('settings.email.password.save')}
          </GateButton>
          <GateButton
            perm="settings.manage"
            type="button"
            icon={<Icon.Trash />}
            disabled={!passwordConfigured || busy}
            onClick={submitClear}
          >
            {t('settings.email.password.clear')}
          </GateButton>
        </div>
      </Card>

      {/* Test send — the only way to tell "configured" from "configured and actually working". */}
      <Card className="email-card" title={t('settings.email.test.cardTitle')}>
        <p className="lede">{t('settings.email.test.lede')}</p>

        {(status.data?.warnings ?? []).map((warning) => (
          <InlineWarning key={warning} tone="warn" title={t('settings.email.test.warningTitle')}>
            <p>{warning}</p>
          </InlineWarning>
        ))}

        <div className="form settings-rows">
          <Field
            label={t('settings.email.test.to.label')}
            htmlFor="set-email-test-to"
            hint={t('settings.email.test.to.hint')}
          >
            <Input
              id="set-email-test-to"
              type="email"
              value={testTo}
              disabled={!editable || test.isPending}
              placeholder={t('settings.email.test.to.placeholder')}
              onChange={(e) => setTestTo(e.target.value)}
            />
          </Field>
        </div>
        <div className="form__actions">
          <GateButton
            perm="settings.manage"
            type="button"
            icon={<Icon.Refresh />}
            disabled={!testTo || test.isPending}
            onClick={() => test.mutate(testTo, { onError: (e) => toast.error(e) })}
          >
            {t('settings.email.test.action')}
          </GateButton>
        </div>

        {/* A request-level failure (no permission, mail not configured) is an ErrorNote... */}
        {test.error ? <ErrorNote error={test.error} /> : null}
        {/* ...while a RELAY-level failure arrives as a successful response describing a failure. */}
        {test.data ? <TestOutcome result={test.data} t={t} /> : null}
        {/* t70: the full protocol trace, collapsed beneath the plain-language verdict above. Kept
            in its own component so this file owns the summary and that one owns the detail. */}
        {test.data ? <EmailTestDetail result={test.data} /> : null}
      </Card>

      {/* The delivery record — what actually went out, and what the relay said about it. */}
      <EmailDeliveriesCard />
    </>
  );
}

/**
 * The recorded outcome of every outbound message (t108).
 *
 * ## This is a record, not a queue
 *
 * Nothing drains a queue in this build. `status` is `sent` or `failed` and never `queued`, so there
 * is no pending state to render and no "retrying…" to animate — every row is already over. Calling
 * this a queue, or showing a spinner per row, would assert a mechanism that does not exist.
 *
 * ## Resend is narrower than it looks, and the UI says why
 *
 * Only a message whose body is fully derivable from durable NON-SECRET state can be re-sent —
 * today exactly the welcome mail. Anything that carried a one-time credential is refused, and the
 * refusal is cryptographic rather than a policy setting: the secret was never stored and cannot be
 * recovered. Minting a fresh one would GRANT ACCESS, which belongs to the flow that owns the token
 * and its permission, not to whoever administers the mail relay. So the disabled button carries the
 * sentence naming the alternative (re-issue), and never reads as "you are not allowed to".
 *
 * ## A refused resend is a 200
 *
 * The endpoint answers with the NEW attempt's row, which may itself be `failed`. That is a
 * successful request describing an unsuccessful send — the same shape the test-send card handles —
 * so it is surfaced as a warning carrying the relay's own words, not swallowed as a success.
 */
function EmailDeliveriesCard() {
  const t = useT();
  const toast = useToast();
  const deliveries = useEmailDeliveries();
  const resend = useResendEmailDelivery();
  // The row a resend produced when the relay refused it. Held here rather than read off
  // `resend.data` so it survives the list refetch and clears on the next attempt.
  const [refused, setRefused] = useState<EmailDeliveryView | null>(null);

  const rows = deliveries.data ?? [];
  // No pagination parameters exist on this endpoint, so a full page is the ONLY signal that older
  // attempts were cut off. Saying nothing here would present a window as the whole history.
  const capped = rows.length >= EMAIL_DELIVERIES_LIMIT;

  function submitResend(id: string) {
    setRefused(null);
    resend.mutate(id, {
      onSuccess: (row) => {
        if (row.status === 'failed') setRefused(row);
        else toast.success(t('settings.email.deliveries.resentToast'));
      },
      onError: (e) => toast.error(e),
    });
  }

  return (
    <Card className="email-card" title={t('settings.email.deliveries.cardTitle')}>
      <p className="lede">{t('settings.email.deliveries.lede')}</p>

      {deliveries.error ? <ErrorNote error={deliveries.error} /> : null}
      {resend.error ? <ErrorNote error={resend.error} /> : null}
      {refused ? <ResendRefused row={refused} t={t} /> : null}

      {deliveries.isLoading ? (
        <SkeletonRegion>
          <SkeletonTable cols={7} />
        </SkeletonRegion>
      ) : deliveries.error ? null : rows.length === 0 ? (
        // An empty record and a failed request are different facts: this instance may simply keep
        // no delivery history, which the API reports as `[]` rather than as an error.
        <EmptyState title={t('settings.email.deliveries.empty')}>
          <p>{t('settings.email.deliveries.emptyBody')}</p>
        </EmptyState>
      ) : (
        <>
          {capped ? (
            <InlineWarning tone="info" title={t('settings.email.deliveries.cappedTitle')}>
              <p>{t('settings.email.deliveries.cappedBody', { count: EMAIL_DELIVERIES_LIMIT })}</p>
            </InlineWarning>
          ) : null}

          <Table
            className="email-deliveries"
            caption={t('settings.email.deliveries.caption')}
            head={
              <tr>
                <ColumnHead
                  label={t('settings.email.deliveries.col.when')}
                  help={t('settings.email.deliveries.help.when')}
                />
                <ColumnHead
                  label={t('settings.email.deliveries.col.template')}
                  help={t('settings.email.deliveries.help.template')}
                />
                <ColumnHead
                  label={t('settings.email.deliveries.col.recipient')}
                  help={t('settings.email.deliveries.help.recipient')}
                />
                <ColumnHead
                  label={t('settings.email.deliveries.col.status')}
                  help={t('settings.email.deliveries.help.status')}
                />
                <ColumnHead
                  label={t('settings.email.deliveries.col.attempt')}
                  help={t('settings.email.deliveries.help.attempt')}
                />
                <ColumnHead
                  label={t('settings.email.deliveries.col.failure')}
                  help={t('settings.email.deliveries.help.failure')}
                />
                <ColumnHead
                  label={t('settings.email.deliveries.col.action')}
                  help={t('settings.email.deliveries.help.action')}
                />
              </tr>
            }
          >
            {rows.map((row) => (
              <DeliveryRow
                key={row.id}
                row={row}
                t={t}
                busy={resend.isPending}
                onResend={submitResend}
              />
            ))}
          </Table>
        </>
      )}
    </Card>
  );
}

/** One recorded attempt. */
function DeliveryRow({
  row,
  t,
  busy,
  onResend,
}: {
  row: EmailDeliveryView;
  t: TFunction;
  busy: boolean;
  onResend: (id: string) => void;
}) {
  const template = templateLabel(row.template_id);
  const failed = row.status === 'failed';

  return (
    <tr data-email-delivery={row.id}>
      <td>
        <DateTime value={row.created_at} />
      </td>
      <td>{template ? t(template) : <code className="mono">{row.template_id}</code>}</td>
      {/* The full address, exactly as the server chose to expose it. Monospace because it is an
          identifier an operator reads character by character when chasing a bounce. */}
      <td className="mono">{row.recipient}</td>
      <td>
        <Badge tone={failed ? 'error' : 'ok'}>
          {failed
            ? t('settings.email.deliveries.status.failed')
            : t('settings.email.deliveries.status.sent')}
        </Badge>
      </td>
      <td>
        <span className="email-deliveries__attempt">
          <span>{row.attempt}</span>
          {/* `previous_id` is the chain the API preserves rather than overwriting; without this
              marker two rows for the same message read as two unrelated sends. */}
          {row.previous_id ? (
            <Badge tone="neutral">{t('settings.email.deliveries.retry')}</Badge>
          ) : null}
        </span>
      </td>
      <td>{failed ? <FailureDetail row={row} t={t} /> : null}</td>
      <td>
        <span className="email-deliveries__action">
          <GateButton
            perm="settings.manage"
            type="button"
            icon={<Icon.Refresh />}
            data-testid={`email-delivery-resend-${row.id}`}
            disabled={!row.resendable || busy}
            onClick={() => onResend(row.id)}
          >
            {t('settings.email.deliveries.resend')}
          </GateButton>
          {/* A disabled control with no reason reads as an arbitrary restriction. This one is not:
              the credential is unrecoverable, and the sentence names the operation that IS
              available. `FieldHelp` rather than a tooltip on the button because a disabled button
              is not a tab stop, and an explanation only a mouse can reach is decoration. */}
          {row.resendable ? null : (
            <FieldHelp text={t('settings.email.deliveries.notResendable')} />
          )}
        </span>
      </td>
    </tr>
  );
}

/** Why a recorded send failed: the stage it stopped at, the relay's code, and the relay's own
 *  words. An unmapped stage token is shown verbatim rather than folded into a neighbouring
 *  sentence, so a vocabulary the UI has not caught up with is visible instead of mislabelled. */
function FailureDetail({ row, t }: { row: EmailDeliveryView; t: TFunction }) {
  const stageKey = row.failure_stage ? deliveryStageLabel(row.failure_stage) : undefined;
  return (
    <div className="email-deliveries__failure">
      {row.failure_stage ? (
        stageKey ? (
          <span>{t(stageKey)}</span>
        ) : (
          <code className="mono">{row.failure_stage}</code>
        )
      ) : null}
      {row.failure_code === undefined ? null : <code className="mono">{row.failure_code}</code>}
      {row.failure_detail ? <code className="mono">{row.failure_detail}</code> : null}
    </div>
  );
}

/** A resend the relay refused. The request succeeded — this is the new attempt's own row, already
 *  recorded as `failed` — so it must not be reported as a send that went out. */
function ResendRefused({ row, t }: { row: EmailDeliveryView; t: TFunction }) {
  const stageKey = row.failure_stage ? deliveryStageLabel(row.failure_stage) : undefined;
  return (
    <InlineWarning tone="error" title={t('settings.email.deliveries.resendFailedTitle')}>
      <p>{t('settings.email.deliveries.resendFailedBody')}</p>
      <dl className="deflist">
        {row.failure_stage ? (
          <>
            <dt>{t('settings.email.test.stage')}</dt>
            <dd>{stageKey ? t(stageKey) : <code className="mono">{row.failure_stage}</code>}</dd>
          </>
        ) : null}
        {row.failure_code === undefined ? null : (
          <>
            <dt>{t('settings.email.test.code')}</dt>
            <dd>
              <code>{row.failure_code}</code>
            </dd>
          </>
        )}
        {row.failure_detail ? (
          <>
            <dt>{t('settings.email.test.serverReply')}</dt>
            <dd>
              <code>{row.failure_detail}</code>
            </dd>
          </>
        ) : null}
      </dl>
    </InlineWarning>
  );
}

/** Render the test-send outcome. On failure this deliberately shows the raw SMTP reply: an
 *  operator debugging mail needs the server's actual words, not a translated paraphrase of them. */
function TestOutcome({
  result,
  t,
}: {
  result: NonNullable<ReturnType<typeof useTestEmail>['data']>;
  t: TFunction;
}) {
  if (result.ok) {
    return (
      <InlineWarning tone="info" title={t('settings.email.test.okTitle')}>
        <p>{t('settings.email.test.okBody')}</p>
        <dl className="deflist">
          <dt>{t('settings.email.test.tls')}</dt>
          <dd>{result.tls ? t('common.yes') : t('common.no')}</dd>
          <dt>{t('settings.email.test.authenticated')}</dt>
          <dd>{result.authenticated ? t('common.yes') : t('common.no')}</dd>
          {result.accepted_detail ? (
            <>
              <dt>{t('settings.email.test.relayReply')}</dt>
              <dd>
                <code>{result.accepted_detail}</code>
              </dd>
            </>
          ) : null}
        </dl>
      </InlineWarning>
    );
  }

  const failure = result.failure;
  if (!failure) {
    return (
      <InlineWarning tone="error" title={t('settings.email.test.failTitle')}>
        <p>{t('settings.email.test.failUnknown')}</p>
      </InlineWarning>
    );
  }

  return (
    <InlineWarning tone="error" title={t('settings.email.test.failTitle')}>
      <dl className="deflist">
        <dt>{t('settings.email.test.stage')}</dt>
        <dd>{t(stageLabel(failure.stage))}</dd>
        {failure.code ? (
          <>
            <dt>{t('settings.email.test.code')}</dt>
            <dd>
              <code>
                {failure.code}
                {failure.enhanced_code ? ` ${failure.enhanced_code}` : ''}
              </code>
            </dd>
          </>
        ) : null}
        <dt>{t('settings.email.test.serverReply')}</dt>
        <dd>
          <code>{failure.detail}</code>
        </dd>
        <dt>{t('settings.email.test.remedy')}</dt>
        <dd>{t(remedyLabel(failure.kind))}</dd>
      </dl>
    </InlineWarning>
  );
}
