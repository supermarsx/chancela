/**
 * The stage a recorded delivery died at, one token at a time.
 *
 * `EmailSection.test.tsx` proves the two ends of this mapping: a known stage reads as a sentence,
 * and an unknown token is shown verbatim rather than mislabelled. What it does not do is walk the
 * vocabulary, and the middle is where the damage is: `auth`, `tls` and `rcpt_to` are three
 * different problems with three different fixes, and a copy-paste slip that files one under
 * another's sentence tells the operator to change the wrong setting. Nothing else in the suite
 * would notice.
 *
 * `not_configured` is the one that is not an SMTP stage at all — it is the stage of a send that
 * never reached a socket — so it must have its own sentence and must not be folded into the
 * session-close arm.
 *
 * The assertion is `rendered === ptPT[key]`: it pins the KEY each token resolves to, and the
 * pt-PT wording stays free to change.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, screen, waitFor } from '@testing-library/react';
import { EmailSection } from './EmailSection';
import { DEFAULT_SETTINGS, type EmailDeliveryView } from '../../api/types';
import { ptPT } from '../../i18n/locales/pt-PT';
import { renderWithProviders } from '../../test/utils';

/** Every stage token the stored vocabulary can carry, and the catalog key it must resolve to. */
const STAGES: [string, keyof typeof ptPT][] = [
  ['connect', 'settings.email.stage.connect'],
  ['tls', 'settings.email.stage.tls'],
  ['greeting', 'settings.email.stage.greeting'],
  ['ehlo', 'settings.email.stage.ehlo'],
  ['starttls', 'settings.email.stage.starttls'],
  ['auth', 'settings.email.stage.auth'],
  ['mail_from', 'settings.email.stage.mailFrom'],
  ['rcpt_to', 'settings.email.stage.rcptTo'],
  ['data', 'settings.email.stage.data'],
  ['quit', 'settings.email.stage.quit'],
  ['not_configured', 'settings.email.deliveries.stage.notConfigured'],
];

function failedDelivery(stage: string): EmailDeliveryView {
  return {
    id: `del-${stage}`,
    template_id: 'user.welcome',
    user_id: '11111111-1111-4111-8111-111111111111',
    recipient: 'amelia.marques@encosto-estrategico.pt',
    status: 'failed',
    attempt: 1,
    created_at: '2026-07-20T10:15:00Z',
    actor: 'sistema',
    resendable: true,
    failure_stage: stage,
  };
}

function stubFetch(deliveries: EmailDeliveryView[]) {
  const json = (body: unknown) =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.includes('/deliveries')) return Promise.resolve(json(deliveries));
    return Promise.resolve(
      json({ password_configured: false, deliverable: false, encrypted: true, warnings: [] }),
    );
  }) as typeof fetch);
}

/** The failure cell's own text, per rendered row. */
function failureTexts(): string[] {
  return [...document.querySelectorAll('.email-deliveries__failure')].map(
    (cell) => cell.textContent?.trim() ?? '',
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('recorded delivery failure stages', () => {
  it('gives every stage in the vocabulary its own sentence', async () => {
    stubFetch(STAGES.map(([stage]) => failedDelivery(stage)));
    renderWithProviders(<EmailSection email={DEFAULT_SETTINGS.email} onChange={vi.fn()} />);

    await waitFor(() => expect(failureTexts()).toHaveLength(STAGES.length));
    const rendered = failureTexts();

    for (const [index, [stage, key]] of STAGES.entries()) {
      expect(rendered[index], `${stage} must resolve to ${key}`).toBe(ptPT[key]);
    }
  });

  it('keeps every one of those sentences distinct from the others', async () => {
    stubFetch(STAGES.map(([stage]) => failedDelivery(stage)));
    renderWithProviders(<EmailSection email={DEFAULT_SETTINGS.email} onChange={vi.fn()} />);

    await waitFor(() => expect(failureTexts()).toHaveLength(STAGES.length));
    // Two stages sharing a sentence would be a mapping bug the per-token check above cannot see
    // if the catalog itself duplicated a string.
    expect(new Set(failureTexts()).size).toBe(STAGES.length);
  });

  it('does not describe a send that never reached a socket as a closed session', async () => {
    stubFetch([failedDelivery('not_configured')]);
    renderWithProviders(<EmailSection email={DEFAULT_SETTINGS.email} onChange={vi.fn()} />);

    await waitFor(() => expect(failureTexts()).toHaveLength(1));
    expect(failureTexts()[0]).toBe(ptPT['settings.email.deliveries.stage.notConfigured']);
    expect(failureTexts()[0]).not.toBe(ptPT['settings.email.stage.quit']);
  });

  it('renders no failure cell at all for a delivery that went out', async () => {
    stubFetch([{ ...failedDelivery('auth'), status: 'sent', failure_stage: undefined }]);
    renderWithProviders(<EmailSection email={DEFAULT_SETTINGS.email} onChange={vi.fn()} />);

    await waitFor(() => expect(screen.queryAllByRole('row').length).toBeGreaterThan(1));
    // A successful send has no stage; a cell rendered empty would read as an unnamed failure.
    expect(failureTexts().every((text) => text.length === 0)).toBe(true);
  });
});
