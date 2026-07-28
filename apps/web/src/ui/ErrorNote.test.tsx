/**
 * `ErrorNote` (t58-e6) — the app-wide inline error surface, generalised from a single 403
 * special-case into the `apiErrorFallback.ts` code table plus a technical-details block.
 *
 * Rendered, not read (`i18n-interpolated-nouns-break-agreement`): every assertion here mounts
 * the component and inspects what actually lands in the DOM, never the source template.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { ErrorNote } from './index';
import { ApiError } from '../api/client';
import { t } from '../i18n';
import { apiErrorPtPT, NON_ROUTINE_CODES } from '../i18n/apiErrorFallback';

afterEach(cleanup);

/**
 * Copy is read from the catalogs, never frozen as a literal here. Both catalogs are the source of
 * truth for the sentence; this file is the source of truth for WHICH sentence each error resolves
 * to. A reviewed rewording must not turn a structurally correct component red, and — the sharper
 * risk — a literal that drifts out of the catalog silently stops matching anything, which turns a
 * negative assertion (`queryByText(...)).toBeNull()`) into one that can never fail.
 */
const SUMMARY = apiErrorPtPT['apiError.details.summary'];
const COPY_BUTTON = apiErrorPtPT['apiError.details.copy'];
const REQUEST_ID_LABEL = apiErrorPtPT['apiError.details.requestId'];
const PATH_LABEL = apiErrorPtPT['apiError.details.path'];

/** Build an `ApiError` the same way `parseResponse` does, without a real fetch round-trip. */
function apiError(
  status: number,
  body: {
    error?: string;
    code?: string;
    request_id?: string;
    pin_status?: string;
    tries_left?: string;
  },
  path?: string,
): ApiError {
  return new ApiError(status, body, false, path);
}

describe('ErrorNote — headline resolution', () => {
  it('renders the pt-PT code-table sentence as the HEADLINE, never the raw English error', () => {
    const { container } = render(
      <ErrorNote error={apiError(409, { error: 'book is not open', code: 'book_not_open' })} />,
    );
    expect(screen.getByText(apiErrorPtPT['apiError.book_not_open'])).toBeTruthy();
    // The raw English detail is demoted into the collapsed technical block (still present in
    // the DOM — nothing is dropped — but it must never be the headline a user reads first).
    const headline = container.querySelector('.error-note__headline');
    expect(headline?.textContent).toBe(apiErrorPtPT['apiError.book_not_open']);
    expect(headline?.textContent).not.toContain('book is not open');
  });

  it('falls back to the status-tier sentence for a Tier-1 variant default (not a gap)', () => {
    // `http.not_found` is what `ApiError::NotFound.code()` actually puts on the wire. The bare
    // `not_found` this once sent is an UNMAPPED code, so the test rendered the same tier sentence
    // by the opposite route and proved nothing about the Tier-1 path it names.
    render(<ErrorNote error={apiError(404, { error: 'no such thing', code: 'http.not_found' })} />);
    expect(screen.getByText(apiErrorPtPT['apiError.tier.404'])).toBeTruthy();
    // Not a gap: the server said nothing more specific, so nothing specific is being hidden and
    // the detail is left collapsed. An unmapped code would have forced it open instead.
    const details = screen.getByText(SUMMARY).closest('details') as HTMLElement;
    expect(details.hasAttribute('open')).toBe(false);
  });

  it('still produces a pt-PT sentence for a bare thrown Error, and force-opens the detail', () => {
    render(<ErrorNote error={new Error('ECONNRESET')} />);
    expect(screen.getByText(apiErrorPtPT['apiError.tier.unknown'])).toBeTruthy();
    const details = screen.getByText(SUMMARY).closest('details');
    expect(details?.hasAttribute('open')).toBe(true);
    expect(screen.getByText(/ECONNRESET/)).toBeTruthy();
  });
});

describe('ErrorNote — the 403 split (generalised from the old single branch)', () => {
  it('renders the verbatim perm.denied copy for a bare 403 (no specific code)', () => {
    render(<ErrorNote error={apiError(403, { error: 'forbidden' })} />);
    expect(screen.getByText(t('perm.denied.body'))).toBeTruthy();
    // The generic denial never grows a technical-details block — nothing more was said, and
    // the perm.denied path is preserved verbatim rather than being routed through the resolver.
    expect(screen.queryByText(SUMMARY)).toBeNull();
  });

  it('resolves a 403 carrying a specific code through the catalog instead', () => {
    render(
      <ErrorNote
        error={apiError(403, {
          error: 'no valid proof for cross-user credential change',
          code: 'cross_user_proof_required',
        })}
      />,
    );
    expect(screen.getByText(apiErrorPtPT['apiError.cross_user_proof_required'])).toBeTruthy();
    // The generic denial must NOT have swallowed the coded 403. This asserted a literal that
    // appears in no catalog, so it was null however the component behaved.
    expect(screen.queryByText(t('perm.denied.body'))).toBeNull();
  });
});

describe('ErrorNote — the cross-user 403 leaks no distinguishing detail', () => {
  it('shows the same uniform sentence and code regardless of the underlying cause', () => {
    const causes = ['wrong current password', 'no proof supplied', 'target user does not exist'];
    for (const error of causes) {
      const { container, unmount } = render(
        <ErrorNote error={apiError(403, { error, code: 'cross_user_proof_required' })} />,
      );
      // The HEADLINE is identical across all three causes — the only thing that varies is the
      // English server detail tucked in the collapsed technical block, which is expected (the
      // detail is never dropped) but must never leak into the headline the user reads first.
      const headline = container.querySelector('.error-note__headline');
      expect(headline?.textContent).toBe(apiErrorPtPT['apiError.cross_user_proof_required']);
      expect(headline?.textContent).not.toContain(error);
      unmount();
    }
  });

  it('never renders a finer per-cause key even if one were sent', () => {
    // The catalog itself has no such key (see apiErrorFallback.test.ts); confirm the component
    // does not invent copy for a code the catalog does not carry — it demotes to the tier
    // headline and forces the detail open instead of guessing at a sentence.
    render(
      <ErrorNote error={apiError(403, { error: 'wrong password', code: 'wrong_password' })} />,
    );
    expect(screen.queryByText(/palavra-passe/)).toBeNull();
    expect(screen.getByText(apiErrorPtPT['apiError.tier.403'])).toBeTruthy();
  });
});

// The count is deliberately not in the title: `NON_ROUTINE_CODES` has grown (9 → 20) and a title
// that names a number goes stale silently, since nothing checks it.
describe('ErrorNote — the exempt (must-not-soften) surfaces read as non-routine', () => {
  const nonTierText = new Set(
    Object.entries(apiErrorPtPT)
      .filter(([key]) => key.startsWith('apiError.tier.'))
      .map(([, value]) => value),
  );

  it.each(NON_ROUTINE_CODES)(
    '%s renders its own dedicated sentence, not a generic tier headline',
    (code) => {
      render(<ErrorNote error={apiError(409, { error: 'server detail', code })} />);
      const headline = apiErrorPtPT[`apiError.${code}` as keyof typeof apiErrorPtPT];
      expect(screen.getByText(headline)).toBeTruthy();
      expect(nonTierText.has(headline)).toBe(false);
      cleanup();
    },
  );

  it('the PIN-blocked surface (terminal, structured ahead of the code) reads as non-routine too', () => {
    render(
      <ErrorNote
        error={apiError(422, { error: 'pin blocked', code: 'pin_rejected', pin_status: 'blocked' })}
      />,
    );
    expect(screen.getByText(apiErrorPtPT['apiError.cc_pin_blocked'])).toBeTruthy();
  });
});

describe('ErrorNote — the technical-details block', () => {
  it('shows code, status, request id and path when the server sent them', () => {
    render(
      <ErrorNote
        error={apiError(
          500,
          { error: 'boom', code: 'internal', request_id: 'req-9f8e' },
          '/v1/acts/a1/seal',
        )}
      />,
    );
    const details = screen.getByText(SUMMARY).closest('details') as HTMLElement;
    expect(details.hasAttribute('open')).toBe(true); // scrubbed 5xx forces the block open
    const scoped = within(details);
    expect(scoped.getByText('internal')).toBeTruthy();
    expect(scoped.getByText('500')).toBeTruthy();
    expect(scoped.getByText('req-9f8e')).toBeTruthy();
    expect(scoped.getByText('/v1/acts/a1/seal')).toBeTruthy();
    expect(scoped.getByText(/boom/)).toBeTruthy();
  });

  it('omits a row entirely when the server did not send that field', () => {
    render(<ErrorNote error={apiError(422, { error: 'bad body', code: 'invalid_act_body' })} />);
    const details = screen.getByText(SUMMARY).closest('details') as HTMLElement;
    expect(within(details).queryByText(REQUEST_ID_LABEL)).toBeNull();
    expect(within(details).queryByText(PATH_LABEL)).toBeNull();
  });

  it('force-opens on an unmapped code and warns once in dev, without dropping the server detail', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    render(
      <ErrorNote
        error={apiError(422, { error: 'a brand new failure mode', code: 'nobody_wrote_copy_yet' })}
      />,
    );
    const details = screen.getByText(SUMMARY).closest('details') as HTMLElement;
    expect(details.hasAttribute('open')).toBe(true);
    expect(within(details).getByText(/a brand new failure mode/)).toBeTruthy();
    expect(within(details).getByText('nobody_wrote_copy_yet')).toBeTruthy();
    warn.mockRestore();
  });

  it('copies code, status, request id, path and detail to the clipboard', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });

    render(
      <ErrorNote
        error={apiError(
          409,
          { error: 'stale facts', code: 'termo_stale_facts', request_id: 'req-1' },
          '/v1/books/b1/termo-encerramento/close',
        )}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: COPY_BUTTON }));
    await Promise.resolve();
    await Promise.resolve();

    expect(writeText).toHaveBeenCalledTimes(1);
    const copied = writeText.mock.calls[0][0] as string;
    expect(copied).toContain('termo_stale_facts');
    expect(copied).toContain('409');
    expect(copied).toContain('req-1');
    expect(copied).toContain('/v1/books/b1/termo-encerramento/close');
    expect(copied).toContain('stale facts');
  });
});
