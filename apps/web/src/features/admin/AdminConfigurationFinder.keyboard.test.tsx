/**
 * AdminConfigurationFinder — the combobox's keyboard and pointer model.
 *
 * The existing spec covers what the finder FINDS. This one covers how it is driven, because the
 * control is an ARIA combobox with `aria-activedescendant`: the visual selection and the announced
 * selection are the same state, and a break in the keyboard model is invisible to a mouse user and
 * total for a keyboard one.
 *
 * Every assertion goes through the destination id carried in the option id (`…-option-cmd`), never
 * through a translated title.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { i18nStore } from '../../i18n';
import { keys } from '../../api/hooks';
import { DEFAULT_SETTINGS } from '../../api/types';
import { permissionsValue, StaticPermissionsProvider } from '../session/permissions';
import { AdminConfigurationFinder } from './AdminConfigurationFinder';

function renderFinder(...permissions: string[]) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(keys.settings, DEFAULT_SETTINGS);
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/admin']}>
        <StaticPermissionsProvider
          value={permissionsValue((permission) => permissions.includes(permission))}
        >
          <AdminConfigurationFinder />
        </StaticPermissionsProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function combobox(): HTMLInputElement {
  return screen.getByRole('combobox') as HTMLInputElement;
}

/** The destination ids currently offered, in the order they are rendered. */
function optionIds(): string[] {
  return screen.queryAllByRole('option').map((option) => option.id.replace(/^.*-option-/u, ''));
}

/** The destination id the input currently points assistive tech at. */
function activeId(): string | null {
  const value = combobox().getAttribute('aria-activedescendant');
  return value ? value.replace(/^.*-option-/u, '') : null;
}

afterEach(() => {
  cleanup();
  i18nStore.setActiveLocale('pt-PT');
  vi.restoreAllMocks();
});

describe('AdminConfigurationFinder keyboard model', () => {
  it('wraps ArrowUp from the first option round to the last', () => {
    renderFinder('signing.configure');
    const input = combobox();
    fireEvent.change(input, { target: { value: 'assinatura' } });

    const ids = optionIds();
    expect(ids.length).toBeGreaterThan(1);
    expect(activeId()).toBe(ids[0]);

    fireEvent.keyDown(input, { key: 'ArrowUp' });
    expect(activeId()).toBe(ids[ids.length - 1]);
  });

  it('ArrowUp steps back through the list one option at a time', () => {
    renderFinder('signing.configure');
    const input = combobox();
    fireEvent.change(input, { target: { value: 'assinatura' } });
    const ids = optionIds();

    fireEvent.keyDown(input, { key: 'ArrowDown' });
    fireEvent.keyDown(input, { key: 'ArrowDown' });
    expect(activeId()).toBe(ids[2]);
    fireEvent.keyDown(input, { key: 'ArrowUp' });
    expect(activeId()).toBe(ids[1]);
  });

  it('Home returns to the first option from anywhere in the list', () => {
    renderFinder('signing.configure');
    const input = combobox();
    fireEvent.change(input, { target: { value: 'assinatura' } });
    const ids = optionIds();

    fireEvent.keyDown(input, { key: 'End' });
    expect(activeId()).toBe(ids[ids.length - 1]);
    fireEvent.keyDown(input, { key: 'Home' });
    expect(activeId()).toBe(ids[0]);
  });

  it('ignores the navigation keys entirely when nothing matched', () => {
    renderFinder('settings.read');
    const input = combobox();
    fireEvent.change(input, { target: { value: 'configuracao-que-nao-existe' } });
    expect(optionIds()).toEqual([]);

    // No option exists to point at, so nothing may be announced as active — and Enter must not
    // navigate anywhere on a guess.
    for (const key of ['ArrowDown', 'ArrowUp', 'Home', 'End', 'Enter']) {
      fireEvent.keyDown(input, { key });
      expect(activeId()).toBeNull();
    }
    expect(screen.queryByRole('option')).toBeNull();
  });

  it('Escape is left to the browser when the box is already empty and closed', () => {
    renderFinder('signing.configure');
    const input = combobox();

    // Nothing to clear: the finder must not swallow the key that closes a surrounding dialog.
    const handled = fireEvent.keyDown(input, { key: 'Escape' });
    expect(handled).toBe(true);
    expect(input.value).toBe('');
  });

  it('reopens on focus only when the box still holds a query', () => {
    renderFinder('signing.configure');
    const input = combobox();

    fireEvent.change(input, { target: { value: 'assinatura' } });
    fireEvent.blur(input);
    expect(screen.queryByRole('listbox')).toBeNull();

    fireEvent.focus(input);
    expect(screen.getByRole('listbox')).toBeTruthy();

    // A whitespace-only query is not a query: refocusing must not open an empty popup.
    fireEvent.change(input, { target: { value: '   ' } });
    fireEvent.blur(input);
    fireEvent.focus(input);
    expect(screen.queryByRole('listbox')).toBeNull();
  });

  it('the clear button empties the query, closes the list and returns focus to the input', () => {
    renderFinder('signing.configure');
    const input = combobox();
    fireEvent.change(input, { target: { value: 'assinatura' } });
    expect(screen.getByRole('listbox')).toBeTruthy();

    const clear = screen
      .getAllByRole('button')
      .find((button) => button.className.includes('admin-config-finder__clear'));
    expect(clear).toBeTruthy();
    fireEvent.click(clear!);

    expect(input.value).toBe('');
    expect(screen.queryByRole('listbox')).toBeNull();
    // Focus must land back on the search box, not be dropped on <body> where the next Tab
    // restarts from the top of the page.
    expect(document.activeElement).toBe(input);
    expect(
      screen
        .queryAllByRole('button')
        .some((b) => b.className.includes('admin-config-finder__clear')),
    ).toBe(false);
  });
});

describe('AdminConfigurationFinder pointer model', () => {
  it('hovering an option makes it the announced selection, so pointer and keyboard agree', () => {
    renderFinder('signing.configure');
    const input = combobox();
    fireEvent.change(input, { target: { value: 'assinatura' } });
    const ids = optionIds();

    const last = screen.queryAllByRole('option')[ids.length - 1];
    fireEvent.mouseEnter(last);
    expect(activeId()).toBe(ids[ids.length - 1]);
    expect(last.getAttribute('aria-selected')).toBe('true');
  });

  it('pressing on an option prevents the default focus shift that would close the list first', () => {
    renderFinder('signing.configure');
    fireEvent.change(combobox(), { target: { value: 'assinatura' } });

    const option = screen.queryAllByRole('option')[0];
    const notCancelled = fireEvent.mouseDown(option);
    // `fireEvent` returns false when a handler called preventDefault — the blur-before-click race
    // is exactly what would make the first click on a result do nothing.
    expect(notCancelled).toBe(false);
  });

  it('closes when focus leaves the whole search region', () => {
    renderFinder('signing.configure');
    const input = combobox();
    fireEvent.change(input, { target: { value: 'assinatura' } });
    expect(screen.getByRole('listbox')).toBeTruthy();

    const region = screen.getByRole('search');
    fireEvent.blur(region, { relatedTarget: document.body });
    expect(screen.queryByRole('listbox')).toBeNull();
    // The query itself survives: closing the popup is not discarding what was typed.
    expect(input.value).toBe('assinatura');
  });
});
