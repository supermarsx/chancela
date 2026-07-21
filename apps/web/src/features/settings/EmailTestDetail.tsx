/**
 * The SMTP test-send's technical detail (t70) — the expandable half of the test result.
 *
 * ## Why this is a separate component from `EmailSection`'s `TestOutcome`
 *
 * The two answer different questions for different people at different moments. `TestOutcome`
 * (t69, in `EmailSection.tsx`) is the plain-language verdict: did it work, and if not, what should
 * I change. That is what an operator wants ninety-nine times out of a hundred, and burying it under
 * a protocol dump would be a regression.
 *
 * This is the hundredth time: the relay is doing something the remedy text does not cover, and the
 * operator needs the actual conversation. It renders **beneath** the summary, collapsed, in a
 * native `<details>` — so it costs nothing until it is wanted, and needs no state, no library and
 * no ARIA of its own to be keyboard-accessible and screen-reader-announced.
 *
 * Keeping it in its own file is also the coordination boundary agreed with t69, who owns
 * `EmailSection.tsx`: they render the summary and drop `<EmailTestDetail>` under it, and neither of
 * us edits the other's rendering.
 *
 * ## Why this much detail exists at all
 *
 * Chancela is self-hosted. The person debugging "mail does not work" is frequently not the person
 * who can read the server's logs — there may not *be* anyone with a shell on that box. If the
 * answer is not in this panel, the answer is not available. So the panel carries what a `swaks`
 * run would have told them:
 *
 * - every protocol stage reached, with its outcome and its own duration (a hang and a refusal look
 *   identical in a single "failed", and are opposite problems);
 * - the relay's **verbatim** reply code and text at the stage that failed;
 * - the address the hostname actually resolved to, whether TLS was really established, with what
 *   protocol version, and whose certificate;
 * - what the client itself refused to do, and why, when the refusal was ours;
 * - the conversation as a transcript.
 *
 * ## The password
 *
 * It is not here, and the guarantee is server-side rather than a filter applied in this file — see
 * `SmtpTrace` in `api/types.ts` and `Recorder` in `crates/chancela-api/src/smtp.rs`. This component
 * renders whatever the API sends; it is deliberately *not* the thing standing between the secret
 * and the screen, because a redaction that lives in the view is one `console.log` away from being
 * bypassed. The transcript note tells the operator that, so they can paste it into a ticket without
 * having to audit it first.
 */
import { useState } from 'react';
import type { EmailTestResult, SmtpTraceStep, SmtpStepOutcome } from '../../api/types';
import { useT, type TFunction } from '../../i18n';
import type { MessageKey } from '../../i18n';
import { Badge, Table } from '../../ui';

/** Stage label keys, reusing the catalog t23 already established for the failure summary. */
const STAGE_LABEL = {
  connect: 'settings.email.stage.connect',
  tls: 'settings.email.stage.tls',
  greeting: 'settings.email.stage.greeting',
  ehlo: 'settings.email.stage.ehlo',
  starttls: 'settings.email.stage.starttls',
  auth: 'settings.email.stage.auth',
  mail_from: 'settings.email.stage.mailFrom',
  rcpt_to: 'settings.email.stage.rcptTo',
  data: 'settings.email.stage.data',
  quit: 'settings.email.stage.quit',
} as const satisfies Record<string, MessageKey>;

const OUTCOME_LABEL = {
  ok: 'settings.email.trace.outcome.ok',
  failed: 'settings.email.trace.outcome.failed',
  skipped: 'settings.email.trace.outcome.skipped',
  refused: 'settings.email.trace.outcome.refused',
} as const satisfies Record<SmtpStepOutcome, MessageKey>;

/** Durations are milliseconds from the API. Sub-second values stay in ms — rounding 19ms to "0.0s"
 *  would destroy exactly the distinction this panel exists to show. */
function duration(ms: number): string {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

/** The outcome badge tone. `refused` is `warn` rather than `error`: the relay is fine and the fix
 *  is on this side, which is a materially different message from "the server said no". */
const OUTCOME_TONE = {
  ok: 'ok',
  failed: 'error',
  skipped: 'neutral',
  refused: 'warn',
} as const satisfies Record<SmtpStepOutcome, string>;

function StepRow({ step, t }: { step: SmtpTraceStep; t: TFunction }) {
  return (
    <tr>
      <th scope="row">{t(STAGE_LABEL[step.stage])}</th>
      <td>
        <Badge tone={OUTCOME_TONE[step.outcome]}>{t(OUTCOME_LABEL[step.outcome])}</Badge>
      </td>
      <td>{duration(step.duration_ms)}</td>
      <td>
        {/* The relay's own code and words, verbatim and monospaced. This is the single most useful
            field in the whole payload, which is why it is a column rather than a tooltip. */}
        {step.code ? (
          <code>
            {step.code}
            {step.enhanced_code ? ` ${step.enhanced_code}` : ''}
            {step.detail ? ` ${step.detail}` : ''}
          </code>
        ) : step.detail ? (
          <span className="muted">{step.detail}</span>
        ) : (
          <span className="muted">—</span>
        )}
      </td>
    </tr>
  );
}

export function EmailTestDetail({ result }: { result: EmailTestResult }) {
  const t = useT();
  const [copied, setCopied] = useState(false);
  const trace = result.trace;

  // The whole payload, for a support ticket. Copying the JSON rather than a re-formatted rendering
  // keeps what is pasted identical to what the server said.
  async function copyPayload() {
    try {
      await navigator.clipboard.writeText(JSON.stringify(trace, null, 2));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard access can be denied or unavailable (insecure context, permissions policy).
      // The transcript is on screen and selectable, so a failed copy is a minor inconvenience
      // rather than something worth interrupting the operator with an error.
      setCopied(false);
    }
  }

  return (
    <details className="trace-detail">
      <summary>{t('settings.email.trace.summary')}</summary>

      <div className="stack">
        <p className="muted">{t('settings.email.trace.lede')}</p>

        {/* --- Connection ------------------------------------------------------------------- */}
        <section>
          <h4>{t('settings.email.trace.connection')}</h4>
          <dl className="deflist">
            <dt>{t('settings.email.trace.relay')}</dt>
            <dd>
              <code>
                {trace.host}:{trace.port}
              </code>
            </dd>

            {/* The resolution result. A hostname pointing at an unexpected address — a stale hosts
                entry, a split-horizon DNS answer — is invisible without this. */}
            {trace.resolved_address ? (
              <>
                <dt>{t('settings.email.trace.resolved')}</dt>
                <dd>
                  <code>{trace.resolved_address}</code>
                </dd>
              </>
            ) : null}

            <dt>{t('settings.email.trace.helo')}</dt>
            <dd>
              <code>{trace.helo_name}</code>
            </dd>

            {/* What was actually established, not what was configured. */}
            <dt>{t('settings.email.trace.tlsEstablished')}</dt>
            <dd>{trace.tls_established ? t('common.yes') : t('common.no')}</dd>

            {trace.tls?.protocol ? (
              <>
                <dt>{t('settings.email.trace.tlsProtocol')}</dt>
                <dd>
                  <code>{trace.tls.protocol}</code>
                </dd>
              </>
            ) : null}
            {trace.tls?.cipher_suite ? (
              <>
                <dt>{t('settings.email.trace.cipher')}</dt>
                <dd>
                  <code>{trace.tls.cipher_suite}</code>
                </dd>
              </>
            ) : null}
            {/* Whose certificate. This is what tells a self-signed certificate or an interception
                box apart from the relay the operator thinks they are talking to. */}
            {trace.tls?.peer_subject ? (
              <>
                <dt>{t('settings.email.trace.certSubject')}</dt>
                <dd>
                  <code>{trace.tls.peer_subject}</code>
                </dd>
              </>
            ) : null}
            {trace.tls?.peer_issuer ? (
              <>
                <dt>{t('settings.email.trace.certIssuer')}</dt>
                <dd>
                  <code>{trace.tls.peer_issuer}</code>
                </dd>
              </>
            ) : null}

            {trace.auth_mechanism ? (
              <>
                <dt>{t('settings.email.trace.authMechanism')}</dt>
                <dd>
                  <code>{trace.auth_mechanism}</code>
                </dd>
              </>
            ) : null}

            <dt>{t('settings.email.trace.total')}</dt>
            <dd>{duration(trace.total_ms)}</dd>
          </dl>
        </section>

        {/* --- Advertised capabilities ------------------------------------------------------ */}
        {trace.advertised_capabilities.length > 0 ? (
          <section>
            <h4>{t('settings.email.trace.capabilities')}</h4>
            {/* "The relay offered no AUTH" and "the relay offered only CRAM-MD5" produce the same
                symptom and need different fixes; this is the only place the difference shows. */}
            <ul className="trace-capabilities">
              {trace.advertised_capabilities.map((capability, index) => (
                <li key={`${capability}-${index}`}>
                  <code>{capability}</code>
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        {/* --- The stage timeline ----------------------------------------------------------- */}
        <section>
          <h4>{t('settings.email.trace.timeline')}</h4>
          {/* Genuinely tabular: repeated rows of the same four homogeneous facts, which is the
              case t60 ruled a table is actually for. */}
          <Table
            caption={t('settings.email.trace.timelineCaption')}
            head={
              <tr>
                <th>{t('settings.email.trace.col.stage')}</th>
                <th>{t('settings.email.trace.col.outcome')}</th>
                <th>{t('settings.email.trace.col.duration')}</th>
                <th>{t('settings.email.trace.col.reply')}</th>
              </tr>
            }
          >
            {trace.steps.map((step, index) => (
              <StepRow key={`${step.stage}-${index}`} step={step} t={t} />
            ))}
          </Table>
        </section>

        {/* --- The transcript --------------------------------------------------------------- */}
        {trace.transcript.length > 0 ? (
          <section>
            <h4>{t('settings.email.trace.transcript')}</h4>
            {/* Stated plainly so the operator can paste this into a ticket without auditing it. */}
            <p className="muted">{t('settings.email.trace.transcriptNote')}</p>
            <pre className="trace-transcript">
              {trace.transcript
                .map((line) => `${line.direction === 'client' ? '>' : '<'} ${line.text}`)
                .join('\n')}
            </pre>
            <button type="button" className="btn" onClick={() => void copyPayload()}>
              {copied ? t('settings.email.trace.copied') : t('settings.email.trace.copy')}
            </button>
          </section>
        ) : null}
      </div>
    </details>
  );
}
