/**
 * The scaffold every RGPD register record page is built on (t55-e1): the four page states and
 * the draft hook that decides whether the unsaved-changes guard is armed.
 *
 * These are the two pieces of genuinely new logic in the scaffold, and both are the kind that
 * fails silently: a mis-ordered state check turns an edit into a create on a stale id, and a
 * re-seeding draft discards what the operator typed the moment the list query refetches.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { useState } from 'react';
import { renderWithProviders } from '../../../test/utils';
import { StaticPermissionsProvider, permissionsValue } from '../../session/permissions';
import { PrivacyRecordPageShell } from './PrivacyRecordPageShell';
import { usePrivacyRecordDraft } from './usePrivacyRecordDraft';
import { hasUnsavedChanges } from '../../../hooks/useUnsavedChanges';

afterEach(() => {
  cleanup();
});

describe('PrivacyRecordPageShell — the four states', () => {
  const base = {
    title: 'Nova AIPD',
    listPath: '/settings/privacy',
    notFoundMessage: 'Não foi encontrada nenhuma AIPD com este identificador.',
    allowed: true,
  };

  it('renders the form and both exits when the record resolved', () => {
    renderWithProviders(
      <PrivacyRecordPageShell {...base} state="ready">
        <p>formulário</p>
      </PrivacyRecordPageShell>,
    );
    expect(screen.getByRole('heading', { level: 1, name: 'Nova AIPD' })).toBeTruthy();
    expect(screen.getByText('formulário')).toBeTruthy();
    // The header exit is a real LINK, not a button: an address the operator can middle-click,
    // and a navigation the unsaved-changes guard can challenge.
    const cancel = screen.getByRole('link', { name: 'Cancelar' });
    expect(cancel.getAttribute('href')).toBe('/settings/privacy');
    // Crumbs lead back to the section and to the tab, in that order.
    const crumbLinks = screen.getAllByRole('link', { name: /Configurações|Privacidade/ });
    expect(crumbLinks.map((a) => a.getAttribute('href'))).toEqual([
      '/settings',
      '/settings/privacy',
    ]);
  });

  it('says so BY NAME on a stale id instead of falling through to a blank create form', () => {
    // 🔒 REGRESSION GUARD. Rendering the form here would silently turn an edit into a create —
    // a NEW record where the operator meant to amend an existing one. Reject, never transform.
    renderWithProviders(
      <PrivacyRecordPageShell {...base} state="notFound">
        <p>formulário</p>
      </PrivacyRecordPageShell>,
    );
    expect(
      screen.getByText('Não foi encontrada nenhuma AIPD com este identificador.'),
    ).toBeTruthy();
    expect(screen.queryByText('formulário')).toBeNull();
    expect(screen.getByRole('link', { name: 'Voltar à privacidade' })).toBeTruthy();
  });

  it('paints the header while the list query is still in flight, and holds the form back', () => {
    renderWithProviders(
      <PrivacyRecordPageShell {...base} state="loading">
        <p>formulário</p>
      </PrivacyRecordPageShell>,
    );
    expect(screen.getByRole('heading', { level: 1, name: 'Nova AIPD' })).toBeTruthy();
    expect(screen.queryByText('formulário')).toBeNull();
  });

  it('surfaces a list-query failure rather than an empty form', () => {
    renderWithProviders(
      <PrivacyRecordPageShell {...base} state="error" error={new Error('lista indisponível')}>
        <p>formulário</p>
      </PrivacyRecordPageShell>,
    );
    expect(screen.getByText(/lista indisponível/)).toBeTruthy();
    expect(screen.queryByText('formulário')).toBeNull();
  });

  it('fails closed on its own verb, because a direct URL bypasses the list affordances', () => {
    render(
      <MemoryRouter>
        <StaticPermissionsProvider value={permissionsValue(() => false)}>
          <PrivacyRecordPageShell {...base} allowed={false} state="ready">
            <p>formulário</p>
          </PrivacyRecordPageShell>
        </StaticPermissionsProvider>
      </MemoryRouter>,
    );
    expect(screen.queryByText('formulário')).toBeNull();
    // No authoring surface at all — not even the cancel action, only the way back.
    expect(screen.queryByRole('link', { name: 'Cancelar' })).toBeNull();
    expect(screen.getByRole('link', { name: 'Voltar à privacidade' })).toBeTruthy();
  });
});

interface Draft {
  name: string;
}

function DraftProbe({ seed }: { seed: Draft | null }) {
  const draft = usePrivacyRecordDraft(seed);
  return (
    <div>
      <span data-testid="value">{draft.form ? draft.form.name : '<none>'}</span>
      <span data-testid="dirty">{String(draft.dirty)}</span>
      <span data-testid="registered">{String(hasUnsavedChanges())}</span>
      <button type="button" onClick={() => draft.setForm({ name: 'editado' })}>
        editar
      </button>
      <button type="button" onClick={() => draft.markSaved()}>
        guardar
      </button>
    </div>
  );
}

describe('usePrivacyRecordDraft', () => {
  const value = () => screen.getByTestId('value').textContent;
  const dirty = () => screen.getByTestId('dirty').textContent;

  it('waits for the record instead of seeding a blank draft', () => {
    render(<DraftProbe seed={null} />);
    expect(value()).toBe('<none>');
    expect(dirty()).toBe('false');
  });

  it('is clean when it first paints, so an edit page does not challenge every exit', () => {
    render(<DraftProbe seed={{ name: 'sedeado' }} />);
    expect(value()).toBe('sedeado');
    expect(dirty()).toBe('false');
  });

  it('does NOT re-seed when the list query refetches and hands back a new object', () => {
    // 🔒 REGRESSION GUARD. The seed is rebuilt on every render (`formFromRecord(record)`), and
    // the list query refetches on its own. Re-seeding would throw away the operator's typing
    // mid-sentence, which is exactly the loss this whole task exists to prevent.
    function Host() {
      const [seed, setSeed] = useState<Draft | null>({ name: 'sedeado' });
      return (
        <>
          <button type="button" onClick={() => setSeed({ name: 'do servidor' })}>
            refetch
          </button>
          <DraftProbe seed={seed} />
        </>
      );
    }
    render(<Host />);
    fireEvent.click(screen.getByRole('button', { name: 'editar' }));
    expect(value()).toBe('editado');
    fireEvent.click(screen.getByRole('button', { name: 'refetch' }));
    expect(value()).toBe('editado');
    expect(dirty()).toBe('true');
  });

  it('registers with the unsaved-changes guard only once there are real edits', () => {
    render(<DraftProbe seed={{ name: 'sedeado' }} />);
    expect(screen.getByTestId('registered').textContent).toBe('false');
    fireEvent.click(screen.getByRole('button', { name: 'editar' }));
    expect(dirty()).toBe('true');
    expect(hasUnsavedChanges()).toBe(true);
  });

  it('clears the registration on unmount, so the app does not prompt forever', () => {
    const view = render(<DraftProbe seed={{ name: 'sedeado' }} />);
    fireEvent.click(screen.getByRole('button', { name: 'editar' }));
    expect(hasUnsavedChanges()).toBe(true);
    view.unmount();
    expect(hasUnsavedChanges()).toBe(false);
  });

  it('takes the one-shot navigation bypass on save, so the happy path is not challenged', async () => {
    const unsaved = await import('../../../hooks/useUnsavedChanges');
    const allow = vi.spyOn(unsaved, 'allowNextNavigation');
    render(<DraftProbe seed={{ name: 'sedeado' }} />);
    fireEvent.click(screen.getByRole('button', { name: 'editar' }));
    fireEvent.click(screen.getByRole('button', { name: 'guardar' }));
    expect(allow).toHaveBeenCalledTimes(1);
    allow.mockRestore();
  });
});
