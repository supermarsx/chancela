/**
 * The live locale switch: when the settings document's locale changes (as it does on a
 * settings PUT, which optimistically updates the shared query cache), `AppearanceEffects`
 * pushes it into the i18n store and the UI chrome re-renders in the new language with no
 * reload. Uses the same `useSettings` query the app uses, seeded directly so no network
 * is touched, and the real `AppearanceEffects` as the driver.
 */
import { afterEach, describe, it, expect } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, act } from '@testing-library/react';
import { keys } from '../api/hooks';
import { DEFAULT_SETTINGS, type Settings, type UserView } from '../api/types';
import { AppearanceEffects } from '../theme/AppearanceEffects';
import { i18nStore } from './store';
import { useT } from './useT';

function Probe() {
  const t = useT();
  return <span data-testid="probe">{t('nav.dashboard')}</span>;
}

function withLocale(locale: Settings['documents']['locale']): Settings {
  return { ...DEFAULT_SETTINGS, documents: { ...DEFAULT_SETTINGS.documents, locale } };
}

/** A signed-in user carrying a language preference (t71). */
function userWithLanguage(language: UserView['language']): UserView {
  return {
    id: 'u1',
    username: 'amelia.marques',
    display_name: 'Amelia Marques',
    created_at: '2026-07-07T12:00:00Z',
    active: true,
    has_secret: true,
    has_attestation_key: false,
    has_recovery_phrase: false,
    language,
    role_assignments: [],
  };
}

afterEach(() => {
  // Unmount between tests — this file grew past one case (t71), and without cleanup the probes
  // accumulate in the DOM and every `screen` query matches several.
  cleanup();
  // The store is a module singleton; reset the active locale to the source between tests.
  i18nStore.setActiveLocale('pt-PT');
});

describe('useT live locale switch', () => {
  it('renders pt-PT by default and swaps to en-US when the settings locale flips', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    // Seed the settings cache fresh so useSettings serves it without a fetch.
    qc.setQueryData(keys.settings, withLocale('pt-PT'));

    render(
      <QueryClientProvider client={qc}>
        <AppearanceEffects />
        <Probe />
      </QueryClientProvider>,
    );

    expect(screen.getByTestId('probe').textContent).toBe('Painel');

    // Flip the locale the way a settings PUT does (optimistic cache update); the
    // AppearanceEffects layer syncs it into the store.
    act(() => {
      qc.setQueryData(keys.settings, withLocale('en-US'));
    });

    // The en-US catalog is code-split; the string swaps once its chunk resolves.
    await screen.findByText('Dashboard');
    expect(screen.getByTestId('probe').textContent).toBe('Dashboard');

    // And back to the source locale.
    act(() => {
      qc.setQueryData(keys.settings, withLocale('pt-PT'));
    });
    await screen.findByText('Painel');
    expect(screen.getByTestId('probe').textContent).toBe('Painel');
  });

  // t71: the per-user language preference. Before this, the UI locale came ONLY from the
  // instance-wide setting and nothing read a user preference — a control offering one would
  // have changed nothing a user could see.
  it("renders a signed-in user's pinned language, overriding the instance locale", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    qc.setQueryData(keys.settings, withLocale('pt-PT'));
    qc.setQueryData(keys.session, { user: userWithLanguage('en-US'), permissions: [] });

    render(
      <QueryClientProvider client={qc}>
        <AppearanceEffects />
        <Probe />
      </QueryClientProvider>,
    );

    await screen.findByText('Dashboard');
    expect(screen.getByTestId('probe').textContent).toBe('Dashboard');
  });

  it('leaves the instance locale governing when signed out', async () => {
    // `auto` is a USER's standing instruction; with no user there is none to honour, so the
    // language the instance operator configured governs the sign-in screen. Detecting here would
    // let a visitor's browser headers override a deliberate instance choice.
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    qc.setQueryData(keys.settings, withLocale('pt-PT'));
    qc.setQueryData(keys.session, { user: null, permissions: [] });

    render(
      <QueryClientProvider client={qc}>
        <AppearanceEffects />
        <Probe />
      </QueryClientProvider>,
    );

    expect(screen.getByTestId('probe').textContent).toBe('Painel');
  });

  it('never writes a UI preference back into the document locale', async () => {
    // `settings.documents.locale` is the language generated LEGAL INSTRUMENTS are written in.
    // A Portuguese company's atas must stay pt-PT however its operator reads the interface, so
    // rendering the UI in English must leave the settings cache untouched.
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    qc.setQueryData(keys.settings, withLocale('pt-PT'));
    qc.setQueryData(keys.session, { user: userWithLanguage('en-US'), permissions: [] });

    render(
      <QueryClientProvider client={qc}>
        <AppearanceEffects />
        <Probe />
      </QueryClientProvider>,
    );

    await screen.findByText('Dashboard');
    const settings = qc.getQueryData(keys.settings) as Settings;
    expect(settings.documents.locale, 'the document locale must be untouched').toBe('pt-PT');
  });
});
