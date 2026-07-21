/**
 * Tests for the SMTP test-send technical detail panel (t70).
 *
 * What is worth locking down here is not the layout but the diagnostic contract: an operator with
 * no shell on the server must be able to read the relay's own answer, tell a hang from a refusal,
 * and tell "the relay rejected us" from "we declined to proceed". And the transcript must never
 * show a credential.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen, within } from '@testing-library/react';
import { EmailTestDetail } from './EmailTestDetail';
import type { EmailTestResult, SmtpTrace } from '../../api/types';
import { renderWithProviders } from '../../test/utils';

function trace(overrides: Partial<SmtpTrace> = {}): SmtpTrace {
  return {
    host: 'smtp.encosto-estrategico.pt',
    port: 587,
    resolved_address: '203.0.113.25:587',
    encryption: 'starttls',
    helo_name: 'chancela.encosto-estrategico.pt',
    tls_established: true,
    tls: {
      protocol: 'TLSv1.3',
      cipher_suite: 'TLS13_AES_256_GCM_SHA384',
      peer_subject: 'CN=smtp.encosto-estrategico.pt',
      peer_issuer: 'CN=Example Root CA,O=Example',
    },
    advertised_capabilities: ['PIPELINING', 'STARTTLS', 'AUTH PLAIN LOGIN'],
    auth_mechanism: 'PLAIN',
    steps: [
      { stage: 'connect', outcome: 'ok', started_ms: 0, duration_ms: 4 },
      { stage: 'ehlo', outcome: 'ok', code: 250, started_ms: 4, duration_ms: 6 },
      {
        stage: 'auth',
        outcome: 'failed',
        code: 535,
        enhanced_code: '5.7.8',
        detail: 'Error: authentication failed',
        started_ms: 10,
        duration_ms: 2400,
      },
    ],
    transcript: [
      { direction: 'server', text: '220 smtp ready', at_ms: 4 },
      { direction: 'client', text: 'EHLO chancela.encosto-estrategico.pt', at_ms: 5 },
      { direction: 'client', text: 'AUTH PLAIN <redacted>', at_ms: 10 },
      { direction: 'server', text: '535 5.7.8 Error: authentication failed', at_ms: 2410 },
    ],
    total_ms: 2415,
    ...overrides,
  };
}

function result(overrides: Partial<EmailTestResult> = {}): EmailTestResult {
  return {
    ok: false,
    tls: true,
    authenticated: false,
    failure: {
      stage: 'auth',
      kind: 'rejected',
      code: 535,
      enhanced_code: '5.7.8',
      detail: 'Error: authentication failed',
      tls: true,
    },
    trace: trace(),
    ...overrides,
  };
}

afterEach(cleanup);

describe('EmailTestDetail', () => {
  /** The single most useful field in the payload, and the reason a generic error is useless. */
  it("shows the relay's verbatim reply code and text at the failing stage", () => {
    renderWithProviders(<EmailTestDetail result={result()} />);
    // In the timeline, against the stage it belongs to — "it failed at AUTH" and "it failed at
    // RCPT TO" point at completely different fixes.
    const timeline = within(screen.getByRole('table'));
    expect(timeline.getByText(/535 5\.7\.8 Error: authentication failed/)).toBeTruthy();
    expect(timeline.getByText('Autenticação')).toBeTruthy();
    // And again in the transcript, as the raw line the relay actually sent.
    expect(screen.getByText(/< 535 5\.7\.8 Error: authentication failed/)).toBeTruthy();
  });

  /** A hang and a refusal look identical in a single "failed" and are opposite problems. */
  it('gives every stage its own duration so a hang is distinguishable from a refusal', () => {
    renderWithProviders(<EmailTestDetail result={result()} />);
    // Scoped to the timeline: the total duration is also rendered, in the connection block.
    const timeline = within(screen.getByRole('table'));
    // Sub-second stages stay in milliseconds; rounding 4ms to "0.0s" would destroy the contrast.
    expect(timeline.getByText('4 ms')).toBeTruthy();
    expect(timeline.getByText('6 ms')).toBeTruthy();
    // The slow stage reads as seconds, so a 2.4s AUTH stands out against a 4ms connect.
    expect(timeline.getByText('2.4 s')).toBeTruthy();
  });

  it('reports the resolved address, the negotiated TLS version and the peer certificate', () => {
    renderWithProviders(<EmailTestDetail result={result()} />);
    // A hostname resolving somewhere unexpected is invisible without this.
    expect(screen.getByText('203.0.113.25:587')).toBeTruthy();
    expect(screen.getByText('TLSv1.3')).toBeTruthy();
    expect(screen.getByText('TLS13_AES_256_GCM_SHA384')).toBeTruthy();
    // Whose certificate — what tells a self-signed cert or an interception box from the real relay.
    expect(screen.getByText('CN=smtp.encosto-estrategico.pt')).toBeTruthy();
    expect(screen.getByText('CN=Example Root CA,O=Example')).toBeTruthy();
  });

  /** "Offered no AUTH" and "offered only CRAM-MD5" have the same symptom and different fixes. */
  it('lists the extensions the relay advertised, and the AUTH mechanism chosen', () => {
    renderWithProviders(<EmailTestDetail result={result()} />);
    expect(screen.getByText('AUTH PLAIN LOGIN')).toBeTruthy();
    expect(screen.getByText('STARTTLS')).toBeTruthy();
    expect(screen.getByText('PLAIN')).toBeTruthy();
  });

  /**
   * A client-side refusal is not the relay erroring, and the operator must not be sent to look at
   * the server. The two outcomes have to read differently.
   */
  it('distinguishes a client-side refusal from a relay failure', () => {
    renderWithProviders(
      <EmailTestDetail
        result={result({
          trace: trace({
            steps: [
              { stage: 'connect', outcome: 'ok', started_ms: 0, duration_ms: 4 },
              {
                stage: 'starttls',
                outcome: 'refused',
                detail: 'the server did not advertise STARTTLS',
                started_ms: 4,
                duration_ms: 1,
              },
            ],
          }),
        })}
      />,
    );
    const table = screen.getByRole('table');
    const refused = within(table).getByText('Recusada pelo cliente');
    expect(refused).toBeTruthy();
    expect(screen.getByText(/did not advertise STARTTLS/)).toBeTruthy();
  });

  /** A stage that was never attempted is shown as not-applicable rather than silently dropped, so
   *  the timeline reads as the whole protocol instead of a subset. */
  it('shows a skipped stage rather than omitting it', () => {
    renderWithProviders(
      <EmailTestDetail
        result={result({
          trace: trace({
            steps: [
              {
                stage: 'starttls',
                outcome: 'skipped',
                detail: 'not applicable: implicit TLS',
                started_ms: 0,
                duration_ms: 0,
              },
            ],
          }),
        })}
      />,
    );
    expect(screen.getByText(/not applicable: implicit TLS/)).toBeTruthy();
  });

  /**
   * The transcript is meant to be pasted into a support ticket, so the panel has to say plainly
   * that the credential is not in it — and, of course, not show one.
   */
  it('renders the transcript with credentials shown as placeholders', () => {
    renderWithProviders(<EmailTestDetail result={result()} />);
    const transcript = screen.getByText(/AUTH PLAIN <redacted>/);
    expect(transcript).toBeTruthy();
    expect(transcript.textContent).not.toMatch(/[A-Za-z0-9+/]{24,}={0,2}/);
    // The non-secret half of the conversation is still verbatim — that is the point of a transcript.
    expect(transcript.textContent).toContain('EHLO chancela.encosto-estrategico.pt');
    expect(transcript.textContent).toContain('535 5.7.8 Error: authentication failed');
  });

  /** The panel is collapsed by default: the plain-language verdict above it is what an operator
   *  wants almost every time, and burying that under a protocol dump would be a regression. */
  it('is collapsed by default', () => {
    const { container } = renderWithProviders(<EmailTestDetail result={result()} />);
    const details = container.querySelector('details');
    expect(details).not.toBeNull();
    expect(details!.hasAttribute('open')).toBe(false);
  });

  /** The trace is present on success too — a send that works but ran unencrypted, or took 19
   *  seconds, is worth seeing. */
  it('renders for a successful send as well as a failed one', () => {
    renderWithProviders(
      <EmailTestDetail
        result={result({
          ok: true,
          authenticated: true,
          accepted_detail: '2.0.0 Ok: queued as 8F2A1',
          failure: undefined,
          trace: trace({
            tls_established: false,
            tls: undefined,
            steps: [{ stage: 'data', outcome: 'ok', code: 250, started_ms: 0, duration_ms: 19000 }],
          }),
        })}
      />,
    );
    expect(screen.getByText('19.0 s')).toBeTruthy();
  });
});
