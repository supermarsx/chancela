/**
 * Tests for Aparência → Idioma da interface (t69, on t71's `language` field). 10 tests.
 *
 * The property this control exists to hold, and the one a regression would break silently:
 * **`auto` stays `auto`.** A control that shows the *resolved* locale as its selection makes a
 * standing instruction ("follow my browser") indistinguishable from a pinned choice, and the next
 * save writes the resolved value back — freezing a user to whatever locale they happened to load
 * once. The server cannot make that mistake (`UserLanguage::fixed()` returns `None` for `Auto`);
 * these close the same hole on the client.
 *
 * Both halves were mutation-checked before the tree was lost: injecting
 * `value={preference === LANGUAGE_AUTO ? resolvedByAuto : preference}` failed exactly
 * "keeps automatic selected as itself"; resolving `auto` before the PATCH failed exactly
 * "stores automatic as automatic when chosen". Each killed its own test and no other.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { LanguagePreferenceSection } from './LanguagePreferenceSection';
import { DEFAULT_SETTINGS, LANGUAGE_AUTO } from '../../api/types';
import type { UserLanguage, UserView } from '../../api/types';
import { renderWithProviders } from '../../test/utils';

interface Call {
  url: string;
  method: string;
  body: string | null;
}

function user(overrides: Partial<UserView> = {}): UserView {
  return {
    id: 'u-1',
    username: 'amelia.marques',
    display_name: 'Amélia Marques',
    created_at: '2026-01-05T09:00:00Z',
    active: true,
    has_secret: true,
    has_attestation_key: false,
    has_recovery_phrase: false,
    language: LANGUAGE_AUTO,
    ...overrides,
  };
}

function stubFetch(opts: { user?: UserView | null } = {}): { fn: typeof fetch; calls: Call[] } {
  const { user: sessionUser = user() } = opts;
  const calls: Call[] = [];
  const json = (body: unknown, code = 200) =>
    new Response(JSON.stringify(body), {
      status: code,
      headers: { 'Content-Type': 'application/json' },
    });
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });
    if (url.includes('/v1/session'))
      return Promise.resolve(json({ user: sessionUser, permissions: [] }));
    if (url.includes('/v1/users/')) {
      const patched = JSON.parse((init?.body as string) ?? '{}') as { language?: UserLanguage };
      return Promise.resolve(json({ ...sessionUser, ...patched }));
    }
    return Promise.resolve(json(DEFAULT_SETTINGS));
  }) as typeof fetch;
  return { fn, calls };
}

/** Pretend the browser announces these languages, for the `auto` negotiation. */
function withBrowserLanguages(languages: string[]) {
  vi.stubGlobal('navigator', { ...globalThis.navigator, languages, language: languages[0] });
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('LanguagePreferenceSection', () => {
  it('keeps “automatic” selected as itself, never as the locale it currently resolves to', async () => {
    // THE invariant. The browser here asks for German, so `auto` renders the UI in German — but
    // the *stored preference* is still `auto`, and the control must say so. Showing "Alemão"
    // selected would make a standing instruction look like a pinned one.
    withBrowserLanguages(['de-DE']);
    vi.stubGlobal('fetch', stubFetch().fn);
    renderWithProviders(<LanguagePreferenceSection />);

    const select = (await screen.findByLabelText('Idioma')) as HTMLSelectElement;
    expect(select.value).toBe(LANGUAGE_AUTO);
    expect(select.value).not.toBe('de-DE');
  });

  it('says what “automatic” currently produces as a sentence, not as the selection', async () => {
    // The operator still needs to know what it resolves to right now — otherwise `auto` is
    // opaque. It is told in prose, alongside the fact that the stored choice has not changed.
    withBrowserLanguages(['de-DE']);
    vi.stubGlobal('fetch', stubFetch().fn);
    renderWithProviders(<LanguagePreferenceSection />);

    await screen.findByLabelText('Idioma');
    const resolved = screen.getByText(/«automático» mostra/i);
    expect(resolved.textContent).toContain('Alemão');
    // And it says the stored value is untouched, which is the whole point.
    expect(resolved.textContent).toMatch(/continua a ser «automático»/i);
  });

  it('stores “automatic” as “automatic” when chosen — never the negotiated locale', async () => {
    // The write half of the same invariant: a client that resolved before saving would pin the
    // user to today's browser language forever, and the bug would be invisible until they moved.
    withBrowserLanguages(['de-DE']);
    const stub = stubFetch({ user: user({ language: 'pt-PT' }) });
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<LanguagePreferenceSection />);

    fireEvent.change(await screen.findByLabelText('Idioma'), { target: { value: LANGUAGE_AUTO } });

    await waitFor(() => {
      const patch = stub.calls.find((c) => c.method === 'PATCH');
      expect(patch, 'a language PATCH was issued').toBeTruthy();
      expect(patch!.url).toContain('/v1/users/u-1');
      const body = JSON.parse(patch!.body ?? '{}') as { language?: string };
      expect(body.language).toBe(LANGUAGE_AUTO);
      expect(body.language).not.toBe('de-DE');
    });
  });

  it('pins a chosen locale on the user record, not on the settings document', async () => {
    // This is a per-USER preference. Writing it into the instance-wide settings document would
    // change the language for everyone, which is precisely the confusion the separate card exists
    // to prevent.
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<LanguagePreferenceSection />);

    fireEvent.change(await screen.findByLabelText('Idioma'), { target: { value: 'en-GB' } });

    await waitFor(() => {
      const patch = stub.calls.find((c) => c.method === 'PATCH');
      expect(JSON.parse(patch?.body ?? '{}').language).toBe('en-GB');
    });
    // Nothing was written to the settings document.
    expect(stub.calls.some((c) => c.method === 'PUT' && c.url.includes('/v1/settings'))).toBe(false);
  });

  it('offers no “what automatic resolves to” line once a locale is pinned', async () => {
    // With a fixed choice the sentence would be noise at best and misleading at worst: nothing is
    // being negotiated, so there is no resolution to report.
    withBrowserLanguages(['de-DE']);
    vi.stubGlobal('fetch', stubFetch({ user: user({ language: 'en-GB' }) }).fn);
    renderWithProviders(<LanguagePreferenceSection />);

    const select = (await screen.findByLabelText('Idioma')) as HTMLSelectElement;
    expect(select.value).toBe('en-GB');
    expect(screen.queryByText(/mostra/i)).toBeNull();
  });

  it('distinguishes itself from the theme’s “system” and from the document language', async () => {
    // Two mechanisms that read as synonyms sitting inches apart (theme follows the OS, language
    // follows the browser), and one that would silently change what language a company's atas are
    // WRITTEN in. Both distinctions are copy, and copy is the deliverable here.
    vi.stubGlobal('fetch', stubFetch().fn);
    renderWithProviders(<LanguagePreferenceSection />);

    await screen.findByLabelText('Idioma');
    expect(screen.getByText(/sistema operativo.*navegador/i)).toBeTruthy();
    expect(screen.getByText(/não altera o idioma dos documentos gerados/i)).toBeTruthy();
    expect(screen.getByText(/Documentos/)).toBeTruthy();
  });

  it('says the sign-in screen is not covered, because detection needs a user', async () => {
    // t71's decision, and one an operator would otherwise read as a bug: they set German, sign
    // out, and the sign-in screen is still Portuguese.
    vi.stubGlobal('fetch', stubFetch().fn);
    renderWithProviders(<LanguagePreferenceSection />);

    await screen.findByLabelText('Idioma');
    expect(screen.getByText(/ecrã de início de sessão/i)).toBeTruthy();
  });

  it('explains itself rather than offering a broken control when signed out', async () => {
    // There is no user to store a preference on, so the control is absent by construction — and
    // no request can be issued against an empty user id.
    const stub = stubFetch({ user: null });
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<LanguagePreferenceSection />);

    expect(await screen.findByText('Sem sessão iniciada')).toBeTruthy();
    expect(screen.queryByLabelText('Idioma')).toBeNull();
    expect(stub.calls.some((c) => c.method === 'PATCH')).toBe(false);
  });

  it('does not re-save the preference that is already stored', async () => {
    // Selecting the current value is a no-op, not a write: an idle PATCH would show up in the
    // audit ledger as a change nobody made.
    const stub = stubFetch({ user: user({ language: 'en-GB' }) });
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<LanguagePreferenceSection />);

    fireEvent.change(await screen.findByLabelText('Idioma'), { target: { value: 'en-GB' } });
    expect(stub.calls.some((c) => c.method === 'PATCH')).toBe(false);
  });

  it('falls back to the document locale when the browser asks for nothing we ship', async () => {
    // `auto` must always resolve to something. An unshipped language lands on the instance's
    // configured locale — the floor — rather than on an empty UI.
    withBrowserLanguages(['ja-JP']);
    vi.stubGlobal('fetch', stubFetch().fn);
    renderWithProviders(<LanguagePreferenceSection />);

    await screen.findByLabelText('Idioma');
    // DEFAULT_SETTINGS.documents.locale is pt-PT, so that is what auto reports.
    expect(screen.getByText(/«automático» mostra/i).textContent).toContain('Português');
  });
});
