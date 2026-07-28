/**
 * The `InlineWarning` dismiss capability (t75).
 *
 * The load-bearing test here is the FIRST one: a banner that named no registry key cannot be
 * dismissed. That is not a styling detail — most of this component's call sites are fail-closed
 * ("this act cannot be signed", "this book is sealed"), and a dismissable fail-closed banner is an
 * operator hiding the reason an evidentiary operation was refused.
 *
 * Assertions are on structure and stable identifiers (`data-notice`, roles, the persisted PUT
 * body), never on rendered pt-PT prose: copy varies by locale and by variant, and a test that
 * matches a sentence passes for the wrong reason the moment the sentence is reworded.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { renderWithProviders } from '../test/utils';
import type { UserPreferences } from '../api/types';
import { InlineWarning } from './InlineWarning';

const FAIL_CLOSED = 'fail-closed-region';
const LOG_SCOPE = 'log-scope-region';
const CITATIONS = 'citations-region';

interface Call {
  url: string;
  method: string;
  body?: string;
}

/**
 * A server that actually stores the preferences document, so "stays dismissed" is answered by a
 * fresh mount re-reading what the PUT persisted rather than by surviving component state.
 */
function preferencesServer(initial: UserPreferences = { table_columns: {} }) {
  const calls: Call[] = [];
  let stored: UserPreferences = initial;
  const fetchStub = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    calls.push({ url, method, body: init?.body ? String(init.body) : undefined });
    const json = (body: unknown) =>
      Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    if (url.includes('/v1/me/preferences')) {
      if (method === 'PUT') stored = JSON.parse(String(init?.body)) as UserPreferences;
      return json(stored);
    }
    if (url.includes('/v1/settings')) {
      return json({ ui: { external_signature_notice_snooze_days: 30 } });
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  return {
    calls,
    fetchStub,
    preferenceWrites: () =>
      calls.filter((call) => call.url.includes('/v1/me/preferences') && call.method === 'PUT'),
  };
}

/**
 * One fail-closed banner beside two dismissable ones, on the same page and the same registry —
 * so "cannot be dismissed" and "does not dismiss its neighbour" are observed under identical
 * conditions rather than in separate, friendlier renders.
 */
function Banners() {
  return (
    <>
      <section aria-label={FAIL_CLOSED}>
        <InlineWarning tone="error" title="titulo-selado">
          corpo-selado
        </InlineWarning>
      </section>
      <section aria-label={LOG_SCOPE}>
        <InlineWarning tone="info" notice="platform_log_scope" title="titulo-logs">
          corpo-logs
        </InlineWarning>
      </section>
      <section aria-label={CITATIONS}>
        <InlineWarning tone="info" notice="leg_citations" title="titulo-citacoes">
          corpo-citacoes
        </InlineWarning>
      </section>
    </>
  );
}

function region(label: string): HTMLElement {
  return screen.getByRole('region', { name: label });
}

/** The dismiss controls of one banner, addressed structurally rather than by their prose. */
function dismissButtons(label: string): HTMLElement[] {
  return within(region(label)).queryAllByRole('button');
}

describe('InlineWarning dismiss capability', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    cleanup();
  });

  it('cannot dismiss a banner that named no notice key, even while its neighbours are dismissed', async () => {
    const server = preferencesServer();
    vi.stubGlobal('fetch', server.fetchStub);
    renderWithProviders(<Banners />);

    // Wait for the registry to arrive, so the dismissable banners are fully armed: asserting the
    // fail-closed banner before that would pass for the wrong reason.
    await waitFor(() => expect(dismissButtons(LOG_SCOPE).length).toBe(2));

    // 1. No control. The fail-closed banner offers nothing to press, and carries no registry
    //    identity — there is no key under which a dismissal could even be stored.
    const failClosed = region(FAIL_CLOSED);
    expect(within(failClosed).queryAllByRole('button')).toHaveLength(0);
    expect(within(failClosed).queryAllByRole('group')).toHaveLength(0);
    expect(failClosed.querySelectorAll('[data-notice]')).toHaveLength(0);
    expect(failClosed.querySelector('.inline-warning')).toBeTruthy();

    // 2. No dismissal is persisted. Press every control the page does offer — both dismissable
    //    banners, in both modes — and the fail-closed banner is still standing, with no registry
    //    entry of its own on the wire.
    for (const button of [...dismissButtons(LOG_SCOPE), ...dismissButtons(CITATIONS)]) {
      fireEvent.click(button);
    }
    await waitFor(() => expect(server.preferenceWrites().length).toBeGreaterThan(0));

    for (const write of server.preferenceWrites()) {
      const sent = JSON.parse(String(write.body)) as UserPreferences;
      // Only the two banners that named a key may ever appear in the registry.
      for (const key of Object.keys(sent.notice_dismissals ?? {})) {
        expect(['platform_log_scope', 'leg_citations']).toContain(key);
      }
    }
    expect(region(FAIL_CLOSED).querySelector('.inline-warning')).toBeTruthy();
    expect(within(region(FAIL_CLOSED)).queryAllByRole('button')).toHaveLength(0);
  });

  it('keeps a dismissed banner dismissed for that user across a fresh mount', async () => {
    const server = preferencesServer();
    vi.stubGlobal('fetch', server.fetchStub);
    renderWithProviders(<Banners />);

    await waitFor(() => expect(dismissButtons(LOG_SCOPE).length).toBe(2));
    // The second control is the permanent one (secondary = snooze, ghost = permanent).
    fireEvent.click(dismissButtons(LOG_SCOPE)[1]);

    await waitFor(() => {
      const write = server.preferenceWrites().at(-1);
      expect(JSON.parse(String(write?.body)).notice_dismissals).toEqual({
        platform_log_scope: { mode: 'permanent' },
      });
    });
    await waitFor(() =>
      expect(region(LOG_SCOPE).querySelectorAll('[data-notice]')).toHaveLength(0),
    );

    cleanup();
    renderWithProviders(<Banners />);
    // Still hidden after a remount that re-read the document, and the way back is the only
    // control the region now offers.
    await waitFor(() => expect(dismissButtons(CITATIONS).length).toBe(2));
    expect(region(LOG_SCOPE).querySelectorAll('[data-notice]')).toHaveLength(0);
    expect(dismissButtons(LOG_SCOPE)).toHaveLength(1);
    expect(region(LOG_SCOPE).querySelector('.notice-restore')).toBeTruthy();
  });

  it('dismisses one notice without dismissing another', async () => {
    const server = preferencesServer();
    vi.stubGlobal('fetch', server.fetchStub);
    renderWithProviders(<Banners />);

    await waitFor(() => expect(dismissButtons(CITATIONS).length).toBe(2));
    fireEvent.click(dismissButtons(CITATIONS)[1]);

    await waitFor(() =>
      expect(region(CITATIONS).querySelectorAll('[data-notice]')).toHaveLength(0),
    );
    // Its neighbour is untouched: still a banner, still armed with both dismiss controls.
    expect(region(LOG_SCOPE).querySelector('[data-notice="platform_log_scope"]')).toBeTruthy();
    expect(dismissButtons(LOG_SCOPE)).toHaveLength(2);

    const write = server.preferenceWrites().at(-1);
    expect(JSON.parse(String(write?.body)).notice_dismissals).toEqual({
      leg_citations: { mode: 'permanent' },
    });
  });

  it('restores a dismissed notice, clearing only its own registry entry', async () => {
    const server = preferencesServer({
      table_columns: { books: ['Kind'] },
      notice_dismissals: {
        platform_log_scope: { mode: 'permanent' },
        leg_citations: { mode: 'permanent' },
      },
    });
    vi.stubGlobal('fetch', server.fetchStub);
    renderWithProviders(<Banners />);

    await waitFor(() => expect(dismissButtons(LOG_SCOPE).length).toBe(1));
    fireEvent.click(dismissButtons(LOG_SCOPE)[0]);

    await waitFor(() => {
      const write = server.preferenceWrites().at(-1);
      const sent = JSON.parse(String(write?.body)) as UserPreferences;
      expect(sent.notice_dismissals).toEqual({ leg_citations: { mode: 'permanent' } });
      // Unrelated personal state rides the same whole-document PUT and must survive it.
      expect(sent.table_columns).toEqual({ books: ['Kind'] });
    });
    await waitFor(() =>
      expect(region(LOG_SCOPE).querySelector('[data-notice="platform_log_scope"]')).toBeTruthy(),
    );
    expect(region(CITATIONS).querySelectorAll('[data-notice]')).toHaveLength(0);
  });

  it('shows a dismissable banner with no controls, and writes nothing, when the registry fails to load', async () => {
    const calls: Call[] = [];
    const fetchStub = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      calls.push({ url, method: (init?.method ?? 'GET').toUpperCase() });
      if (url.includes('/v1/me/preferences')) {
        return Promise.resolve(new Response('{}', { status: 500 }));
      }
      return Promise.resolve(
        new Response(JSON.stringify({ ui: { external_signature_notice_snooze_days: 30 } }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }) as typeof fetch;
    vi.stubGlobal('fetch', fetchStub);
    renderWithProviders(<Banners />);

    // The caveat still reaches the operator — a failed preferences read must never suppress it —
    // but nothing offers to hide it, because a PUT built on a document we never read would
    // silently discard the rest of their personal state.
    await waitFor(() =>
      expect(region(LOG_SCOPE).querySelector('[data-notice="platform_log_scope"]')).toBeTruthy(),
    );
    expect(dismissButtons(LOG_SCOPE)).toHaveLength(0);
    expect(
      calls.some((call) => call.url.includes('/v1/me/preferences') && call.method === 'PUT'),
    ).toBe(false);
  });
});
