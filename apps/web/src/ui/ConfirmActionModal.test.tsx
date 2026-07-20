import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { ConfirmActionModal } from './ConfirmActionModal';
import { ApiError } from '../api/client';
import { renderWithProviders } from '../test/utils';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function baseProps() {
  return {
    open: true,
    onClose: vi.fn(),
    title: 'Reposição de fábrica',
    intro: 'Isto apaga tudo.',
    confirmLabel: 'Reposição de fábrica',
    pendingLabel: 'A repor…',
  };
}

describe('ConfirmActionModal', () => {
  it('portals the backdrop to <body> so it overlays the whole content area, not the route box', () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    const { container } = renderWithProviders(
      <ConfirmActionModal {...baseProps()} onConfirm={onConfirm} />,
    );

    // The backdrop is rendered through a portal to document.body — NOT nested inside the
    // rendered component tree (whose transformed route ancestor would otherwise clip a
    // fixed backdrop to the route's box).
    expect(container.querySelector('.modal-backdrop')).toBeNull();
    const backdrop = document.body.querySelector('.modal-backdrop');
    expect(backdrop).toBeTruthy();
    expect(backdrop?.parentElement).toBe(document.body);
    // The dialog is still reachable and labelled.
    expect(screen.getByRole('dialog', { name: 'Reposição de fábrica' })).toBeTruthy();
  });

  it('gates the confirm button on the exact type-to-confirm phrase', async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    renderWithProviders(
      <ConfirmActionModal {...baseProps()} phrase="REPOR FÁBRICA" onConfirm={onConfirm} />,
    );

    const confirm = screen.getByRole('button', { name: 'Reposição de fábrica' });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);

    const phraseInput = screen.getByLabelText('Escreva REPOR FÁBRICA para confirmar');
    fireEvent.change(phraseInput, { target: { value: 'REPOR' } });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText('O texto não corresponde.')).toBeTruthy();

    fireEvent.change(phraseInput, { target: { value: 'REPOR FÁBRICA' } });
    expect((confirm as HTMLButtonElement).disabled).toBe(false);
  });

  it('requires a step-up proof and passes it to onConfirm', async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    renderWithProviders(
      <ConfirmActionModal
        {...baseProps()}
        phrase="REPOR FÁBRICA"
        requireReauth
        onConfirm={onConfirm}
      />,
    );

    const confirm = screen.getByRole('button', { name: 'Reposição de fábrica' });
    fireEvent.change(screen.getByLabelText('Escreva REPOR FÁBRICA para confirmar'), {
      target: { value: 'REPOR FÁBRICA' },
    });
    // Phrase matches but no password yet → still gated.
    expect((confirm as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(screen.getByLabelText('Palavra-passe'), { target: { value: 'hunter2' } });
    expect((confirm as HTMLButtonElement).disabled).toBe(false);

    fireEvent.click(confirm);
    await waitFor(() => expect(onConfirm).toHaveBeenCalledTimes(1));
    expect(onConfirm.mock.calls[0][0].reauth).toEqual({ password: 'hunter2' });
  });

  it('renders the honest step-up error inline on a 403 without leaking which proof failed', async () => {
    const onConfirm = vi.fn().mockRejectedValue(new ApiError(403, { error: 'STEP_UP_REQUIRED' }));
    renderWithProviders(
      <ConfirmActionModal
        {...baseProps()}
        phrase="REPOR FÁBRICA"
        requireReauth
        onConfirm={onConfirm}
      />,
    );

    fireEvent.change(screen.getByLabelText('Escreva REPOR FÁBRICA para confirmar'), {
      target: { value: 'REPOR FÁBRICA' },
    });
    fireEvent.change(screen.getByLabelText('Palavra-passe'), { target: { value: 'wrong' } });
    fireEvent.click(screen.getByRole('button', { name: 'Reposição de fábrica' }));

    expect(
      await screen.findByText(
        'É necessária autenticação reforçada. Verifique a palavra-passe ou a frase de recuperação.',
      ),
    ).toBeTruthy();
  });

  it('only allows skipping export-first behind a second explicit confirmation', () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    renderWithProviders(
      <ConfirmActionModal
        {...baseProps()}
        phrase="REPOR FÁBRICA"
        requireReauth
        exportFirst="skippable"
        onConfirm={onConfirm}
      />,
    );
    const confirm = screen.getByRole('button', { name: 'Reposição de fábrica' });
    fireEvent.change(screen.getByLabelText('Escreva REPOR FÁBRICA para confirmar'), {
      target: { value: 'REPOR FÁBRICA' },
    });
    fireEvent.change(screen.getByLabelText('Palavra-passe'), { target: { value: 'pw' } });
    expect((confirm as HTMLButtonElement).disabled).toBe(false);

    // Unchecking "export before deleting" reveals the guarded opt-out and re-gates the button.
    fireEvent.click(screen.getByText('Exportar antes de apagar (recomendado)'));
    expect((confirm as HTMLButtonElement).disabled).toBe(true);
    // Checking "I have my own backup" re-enables it.
    fireEvent.click(screen.getByText('Tenho a minha própria cópia de segurança — não exportar'));
    expect((confirm as HTMLButtonElement).disabled).toBe(false);
  });
});
