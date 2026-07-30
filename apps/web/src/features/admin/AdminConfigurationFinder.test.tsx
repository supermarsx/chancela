import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { i18nStore } from '../../i18n';
import { keys } from '../../api/hooks';
import { DEFAULT_SETTINGS, type ServerEnvResponse, type Settings } from '../../api/types';
import { permissionsValue, StaticPermissionsProvider } from '../session/permissions';
import { AdminConfigurationFinder } from './AdminConfigurationFinder';
import {
  buildAdminConfigurationSearchEntries,
  type AdminConfigurationAreaDefinition,
} from './adminConfigurationIndex';

function LocationProbe() {
  const location = useLocation();
  return <span data-testid="location">{location.pathname}</span>;
}

/** A Tier B variable whose value the server has (hypothetically) leaked onto the wire. */
const TIER_B_SECRET = 'zgq7-tier-b-fixture-passphrase';

const SERVER_ENV: ServerEnvResponse = {
  vars: [
    {
      name: 'CHANCELA_DB_PASSWORD',
      group: 'credentials',
      tier: 'B',
      editable: false,
      secret: true,
      boundary: false,
      narrow_only: false,
      acknowledgement_required: false,
      excluded_typed_slice: null,
      external_reader: null,
      source: 'env',
      configured: true,
      effective_value: TIER_B_SECRET,
      override_value: TIER_B_SECRET,
      default_value: TIER_B_SECRET,
      restart_pending: false,
      validator: { kind: 'free_text', allowed: null },
    },
    {
      name: 'CHANCELA_BIND',
      group: 'network',
      tier: 'A',
      editable: true,
      secret: false,
      boundary: false,
      narrow_only: false,
      acknowledgement_required: false,
      excluded_typed_slice: null,
      external_reader: null,
      source: 'override',
      configured: true,
      effective_value: '0.0.0.0:8080',
      override_value: '0.0.0.0:8080',
      default_value: '127.0.0.1:8080',
      restart_pending: false,
      validator: { kind: 'free_text', allowed: null },
    },
  ],
  restart_pending: false,
  overrides_path: '/data/env-overrides.json',
  generated_at: '2026-07-30T00:00:00Z',
};

const SETTINGS: Settings = {
  ...DEFAULT_SETTINGS,
  email: { ...DEFAULT_SETTINGS.email, host: 'smtp.fixture.invalid', port: 2525 },
};

/** Seeded caches, so the index has live values without the finder ever issuing a request. */
function renderFinder(...permissions: string[]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(keys.settings, SETTINGS);
  client.setQueryData(keys.serverEnv, SERVER_ENV);
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/admin']}>
        <StaticPermissionsProvider
          value={permissionsValue((permission) => permissions.includes(permission))}
        >
          <AdminConfigurationFinder />
          <LocationProbe />
        </StaticPermissionsProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function combobox(name = 'Encontrar uma configuração') {
  return screen.getByRole('combobox', { name });
}

function optionIds(): string[] {
  return screen
    .queryAllByRole('option')
    .map((option) => option.id.replace(/^.*-option-/u, ''))
    .sort();
}

/** Address a result by its destination id rather than by its translated title. */
function optionById(id: string): HTMLElement {
  const option = screen
    .queryAllByRole('option')
    .find((candidate) => candidate.id.endsWith(`-option-${id}`));
  if (!option) throw new Error(`no result for '${id}'; got: ${optionIds().join(', ')}`);
  return option;
}

afterEach(() => {
  cleanup();
  i18nStore.setActiveLocale('pt-PT');
  vi.restoreAllMocks();
});

describe('AdminConfigurationFinder', () => {
  it('filters immediately across accent-insensitive titles and useful configuration keywords', () => {
    renderFinder('backup.manage');
    const input = combobox();

    fireEvent.change(input, { target: { value: 'copias rpo' } });

    const listbox = screen.getByRole('listbox');
    expect(
      within(listbox).getByRole('option', { name: 'Abrir Cópias e recuperação' }),
    ).toBeTruthy();
    expect(within(listbox).getAllByRole('option')).toHaveLength(1);
    expect(input.getAttribute('aria-expanded')).toBe('true');
  });

  it('navigates directly to the matched allowed admin route and clears the finder', () => {
    renderFinder('settings.read');
    const input = combobox();

    fireEvent.change(input, { target: { value: 'smtp.fixture.invalid' } });
    fireEvent.click(screen.getByRole('option', { name: 'Abrir Email' }));

    expect(screen.getByTestId('location').textContent).toBe('/admin/email');
    expect((input as HTMLInputElement).value).toBe('');
    expect(input.getAttribute('aria-expanded')).toBe('false');
  });

  it('exposes the Search configuration only with search.manage and routes to its dedicated page', () => {
    const hidden = renderFinder('settings.read');
    fireEvent.change(combobox(), { target: { value: 'indice memoria' } });
    expect(screen.queryByRole('option', { name: 'Abrir Pesquisa' })).toBeNull();
    hidden.unmount();

    renderFinder('search.manage');
    const input = combobox();
    fireEvent.change(input, { target: { value: 'indice memoria' } });
    fireEvent.click(screen.getByRole('option', { name: 'Abrir Pesquisa' }));

    expect(screen.getByTestId('location').textContent).toBe('/admin/search');
  });

  it('finds the dedicated template preview samples page for settings readers', () => {
    const hidden = renderFinder('settings.manage');
    fireEvent.change(combobox(), { target: { value: 'modelos ficticios pdf' } });
    expect(screen.queryByRole('option', { name: 'Abrir Amostras de pré-visualização' })).toBeNull();
    hidden.unmount();

    renderFinder('settings.read');
    const input = combobox();

    fireEvent.change(input, { target: { value: 'modelos ficticios pdf' } });
    fireEvent.click(screen.getByRole('option', { name: 'Abrir Amostras de pré-visualização' }));

    expect(screen.getByTestId('location').textContent).toBe('/admin/template-preview');
  });

  it('supports active-descendant keyboard selection, navigation, clear and escape', () => {
    renderFinder('signing.configure');
    const input = combobox();

    fireEvent.change(input, { target: { value: 'assinatura' } });
    const listboxId = input.getAttribute('aria-controls');
    expect(listboxId).toBeTruthy();
    expect(screen.getByRole('listbox').id).toBe(listboxId);
    expect(input.getAttribute('aria-activedescendant')).toContain('option-providers');

    fireEvent.keyDown(input, { key: 'ArrowDown' });
    expect(input.getAttribute('aria-activedescendant')).toContain('option-policy');
    fireEvent.keyDown(input, { key: 'End' });
    expect(input.getAttribute('aria-activedescendant')).toContain('option-cmd');
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(screen.getByTestId('location').textContent).toBe('/admin/signing/cmd');

    fireEvent.change(input, { target: { value: 'tsa' } });
    expect(screen.getByRole('button', { name: 'Limpar pesquisa' })).toBeTruthy();
    fireEvent.keyDown(input, { key: 'Escape' });
    expect((input as HTMLInputElement).value).toBe('');
    expect(input.getAttribute('aria-expanded')).toBe('false');
    expect(screen.queryByRole('listbox')).toBeNull();
  });

  it('renders a compact no-results status without inventing a destination', () => {
    renderFinder('settings.read');

    fireEvent.change(combobox(), { target: { value: 'configuracao-que-nao-existe' } });

    expect(screen.getByRole('status').textContent).toBe(
      'Nenhuma configuração corresponde à pesquisa.',
    );
    expect(screen.queryByRole('option')).toBeNull();
  });

  it('never exposes labels, keywords or routes for permission-hidden admin areas', () => {
    renderFinder('settings.read');
    const input = combobox();

    // `settings.providerCredentials.*` is the whole Fornecedores corpus; not one key of it may
    // reach a principal without `signing.configure`.
    fireEvent.change(input, { target: { value: 'credenciais de assinatura fornecedores' } });
    expect(screen.queryByRole('option')).toBeNull();
    expect(screen.getByRole('status')).toBeTruthy();

    fireEvent.change(input, { target: { value: 'smtp.fixture.invalid' } });
    expect(screen.getByRole('option', { name: 'Abrir Email' })).toBeTruthy();
    expect(screen.queryByText('Fornecedores de assinatura')).toBeNull();
    expect(screen.queryByText('Chaves API')).toBeNull();
  });

  it('tells the operator which kind of text matched', () => {
    renderFinder('settings.read');
    const input = combobox();

    // A live value: the reason line leads with the value, not with a label or a keyword.
    fireEvent.change(input, { target: { value: '0.0.0.0:8080' } });
    const env = optionById('env');
    expect(env.getAttribute('data-match-kinds')).toContain('value');
    expect(env.querySelector('[data-match-kind]')?.getAttribute('data-match-kind')).toBe('value');
    // The reason is announced, not merely painted.
    const describedBy = env.getAttribute('aria-describedby');
    expect(describedBy).toBeTruthy();
    expect(document.getElementById(describedBy ?? '')?.textContent).toContain('0.0.0.0:8080');

    // A keyword hit reads differently from a value hit.
    fireEvent.change(input, { target: { value: 'verbosidade' } });
    expect(optionById('logs').getAttribute('data-match-kinds')).toBe('keywords');
  });

  it('finds a destination by a field label no keyword list ever mentioned', () => {
    renderFinder('settings.read');

    fireEvent.change(combobox(), { target: { value: 'anfitrioes permitidos' } });

    expect(optionById('connectors').getAttribute('data-match-kinds')).toContain('label');
  });

  it('never matches a Tier B secret value, however the server sent it', () => {
    renderFinder('settings.read');
    const input = combobox();

    fireEvent.change(input, { target: { value: TIER_B_SECRET } });
    expect(screen.queryByRole('option')).toBeNull();
    expect(screen.getByRole('status')).toBeTruthy();
    expect(document.body.textContent).not.toContain(TIER_B_SECRET);

    // The masked variable's NAME is on-screen copy and stays findable, so the assertion above
    // proves the value filter rather than an empty index.
    fireEvent.change(input, { target: { value: 'CHANCELA_DB_PASSWORD' } });
    expect(optionIds()).toContain('env');
  });

  it('keeps the exported index extensible and resolves only permission-visible definitions', () => {
    const visible: AdminConfigurationAreaDefinition = {
      id: 'future-search',
      path: '/admin/future-search',
      title: { source: 'admin', key: 'admin.title' },
      keywords: 'admin.finder.keywords.services',
      permissions: ['future.search.configure'],
    };
    const hidden: AdminConfigurationAreaDefinition = {
      ...visible,
      id: 'future-hidden',
      path: '/admin/future-hidden',
      permissions: ['future.hidden.configure'],
    };
    const resolveTitle = vi.fn(() => 'Pesquisa futura');
    const resolveKeywords = vi.fn(() => 'índice extensível');

    const entries = buildAdminConfigurationSearchEntries({
      areas: [visible, hidden],
      resolveTitle,
      resolveKeywords,
      canAny: (permission) => permission === 'future.search.configure',
    });

    expect(entries.map((entry) => entry.path)).toEqual(['/admin/future-search']);
    expect(entries[0].searchText).toContain('indice extensivel');
    expect(resolveTitle).toHaveBeenCalledTimes(1);
    expect(resolveKeywords).toHaveBeenCalledTimes(1);
  });

  it('ships the owned English finder fallback alongside pt-PT', () => {
    i18nStore.setActiveLocale('en-US');
    renderFinder('settings.read');

    expect(screen.getByRole('combobox', { name: 'Find a setting' })).toBeTruthy();
    expect(screen.getByPlaceholderText('Search settings…')).toBeTruthy();
  });
});
