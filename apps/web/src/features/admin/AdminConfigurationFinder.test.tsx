import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { i18nStore } from '../../i18n';
import { permissionsValue, StaticPermissionsProvider } from '../session/permissions';
import {
  AdminConfigurationFinder,
  buildAdminConfigurationSearchEntries,
  type AdminConfigurationAreaDefinition,
} from './AdminConfigurationFinder';

function LocationProbe() {
  const location = useLocation();
  return <span data-testid="location">{location.pathname}</span>;
}

function renderFinder(...permissions: string[]) {
  return render(
    <MemoryRouter initialEntries={['/admin']}>
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permissions.includes(permission))}
      >
        <AdminConfigurationFinder />
        <LocationProbe />
      </StaticPermissionsProvider>
    </MemoryRouter>,
  );
}

afterEach(() => {
  cleanup();
  i18nStore.setActiveLocale('pt-PT');
  vi.restoreAllMocks();
});

describe('AdminConfigurationFinder', () => {
  it('filters immediately across accent-insensitive titles and useful configuration keywords', () => {
    renderFinder('backup.manage');
    const input = screen.getByRole('combobox', { name: 'Encontrar uma configuração' });

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
    const input = screen.getByRole('combobox', { name: 'Encontrar uma configuração' });

    fireEvent.change(input, { target: { value: 'smtp' } });
    fireEvent.click(screen.getByRole('option', { name: 'Abrir Email' }));

    expect(screen.getByTestId('location').textContent).toBe('/admin/email');
    expect((input as HTMLInputElement).value).toBe('');
    expect(input.getAttribute('aria-expanded')).toBe('false');
  });

  it('supports active-descendant keyboard selection, navigation, clear and escape', () => {
    renderFinder('signing.configure');
    const input = screen.getByRole('combobox', { name: 'Encontrar uma configuração' });

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
    const input = screen.getByRole('combobox', { name: 'Encontrar uma configuração' });

    fireEvent.change(input, { target: { value: 'configuracao-que-nao-existe' } });

    expect(screen.getByRole('status').textContent).toBe(
      'Nenhuma configuração corresponde à pesquisa.',
    );
    expect(screen.queryByRole('option')).toBeNull();
  });

  it('never exposes labels, keywords or routes for permission-hidden admin areas', () => {
    renderFinder('settings.read');
    const input = screen.getByRole('combobox', { name: 'Encontrar uma configuração' });

    fireEvent.change(input, { target: { value: 'assinatura credenciais' } });
    expect(screen.queryByRole('option')).toBeNull();
    expect(screen.getByRole('status')).toBeTruthy();

    fireEvent.change(input, { target: { value: 'smtp' } });
    expect(screen.getByRole('option', { name: 'Abrir Email' })).toBeTruthy();
    expect(screen.queryByText('Fornecedores de assinatura')).toBeNull();
    expect(screen.queryByText('Chaves API')).toBeNull();
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

    const entries = buildAdminConfigurationSearchEntries(
      [visible, hidden],
      resolveTitle,
      resolveKeywords,
      (permission) => permission === 'future.search.configure',
    );

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
