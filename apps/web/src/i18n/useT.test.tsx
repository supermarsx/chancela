/**
 * The live locale switch: when the settings document's locale changes (as it does on a
 * settings PUT, which optimistically updates the shared query cache), `AppearanceEffects`
 * pushes it into the i18n store and the UI chrome re-renders in the new language with no
 * reload. Uses the same `useSettings` query the app uses, seeded directly so no network
 * is touched, and the real `AppearanceEffects` as the driver.
 */
import { afterEach, describe, it, expect } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, act } from '@testing-library/react';
import { keys } from '../api/hooks';
import { DEFAULT_SETTINGS, type Settings } from '../api/types';
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

afterEach(() => {
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
});
