import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { api } from '../../api/client';
import type { TemplateSummary, TemplateVersionHistory as HistoryDto } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { TemplateVersionHistory } from './TemplateVersionHistory';

const HISTORY: HistoryDto = {
  history_limit: 25,
  entries: [
    {
      id: 'version-2',
      template_id: 'user-board/v1',
      name: 'Before final review',
      created_at: '2026-07-23T12:34:56Z',
      created_by: 'mariana',
    },
    {
      id: 'version-1',
      template_id: 'user-board/v1',
      created_at: '2026-07-22T09:00:00Z',
      created_by: 'api',
    },
  ],
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('TemplateVersionHistory', () => {
  it('renders a compact, named history table with actor, timestamp and retention limit', async () => {
    vi.spyOn(api, 'listTemplateVersions').mockResolvedValue(HISTORY);

    const { container } = renderWithProviders(
      <TemplateVersionHistory templateId="user-board/v1" />,
    );

    expect(await screen.findByText('Before final review')).toBeTruthy();
    expect(screen.getByText('Versão sem nome')).toBeTruthy();
    expect(screen.getByText(/25 versões/)).toBeTruthy();
    expect(screen.getByText('mariana')).toBeTruthy();
    expect(container.querySelector('.template-version-history__table .table')).toBeTruthy();
    expect(
      screen.getByRole('table', {
        name: 'Histórico de versões guardadas deste modelo',
      }),
    ).toBeTruthy();
    expect(api.listTemplateVersions).toHaveBeenCalledWith('user-board/v1');
  });

  it('renames and clears a friendly name through an inline, labelled form', async () => {
    vi.spyOn(api, 'listTemplateVersions').mockResolvedValue(HISTORY);
    const rename = vi
      .spyOn(api, 'renameTemplateVersion')
      .mockResolvedValue({ ...HISTORY.entries[0], name: null });

    renderWithProviders(<TemplateVersionHistory templateId="user-board/v1" />);
    const row = (await screen.findByText('Before final review')).closest('tr');
    if (!row) throw new Error('history row missing');

    fireEvent.click(within(row).getByRole('button', { name: 'Alterar nome' }));
    const input = within(row).getByLabelText('Nome da versão');
    fireEvent.change(input, { target: { value: '   ' } });
    fireEvent.click(within(row).getByRole('button', { name: 'Guardar nome' }));

    await waitFor(() =>
      expect(rename).toHaveBeenCalledWith('user-board/v1', 'version-2', { name: null }),
    );
  });

  it('counts astral Unicode characters like the server when validating a friendly name', async () => {
    vi.spyOn(api, 'listTemplateVersions').mockResolvedValue(HISTORY);
    const accepted = '😀'.repeat(200);
    const rename = vi
      .spyOn(api, 'renameTemplateVersion')
      .mockResolvedValue({ ...HISTORY.entries[0], name: accepted });

    renderWithProviders(<TemplateVersionHistory templateId="user-board/v1" />);
    const row = (await screen.findByText('Before final review')).closest('tr');
    if (!row) throw new Error('history row missing');

    fireEvent.click(within(row).getByRole('button', { name: 'Alterar nome' }));
    const input = within(row).getByLabelText('Nome da versão');
    fireEvent.change(input, {
      target: { value: '😀'.repeat(201) },
    });
    fireEvent.click(within(row).getByRole('button', { name: 'Guardar nome' }));

    expect((await screen.findByRole('alert')).textContent).toBe(
      'O nome não pode exceder 200 caracteres.',
    );
    expect(rename).not.toHaveBeenCalled();

    fireEvent.change(input, { target: { value: accepted } });
    fireEvent.click(within(row).getByRole('button', { name: 'Guardar nome' }));
    await waitFor(() =>
      expect(rename).toHaveBeenCalledWith('user-board/v1', 'version-2', {
        name: accepted,
      }),
    );
  });

  it('confirms restore, calls the server, and hands the restored summary to its parent', async () => {
    vi.spyOn(api, 'listTemplateVersions').mockResolvedValue(HISTORY);
    const restored = { id: 'user-board/v1' } as TemplateSummary;
    vi.spyOn(api, 'restoreTemplateVersion').mockResolvedValue(restored);
    const onRestored = vi.fn();

    renderWithProviders(
      <TemplateVersionHistory templateId="user-board/v1" onRestored={onRestored} />,
    );
    const row = (await screen.findByText('Before final review')).closest('tr');
    if (!row) throw new Error('history row missing');

    fireEvent.click(within(row).getByRole('button', { name: 'Repor versão' }));
    const dialog = screen.getByRole('dialog', { name: 'Repor esta versão?' });
    expect(
      within(dialog).getByText(/estado reposto será guardado como uma nova versão/),
    ).toBeTruthy();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Repor versão' }));

    await waitFor(() =>
      expect(api.restoreTemplateVersion).toHaveBeenCalledWith('user-board/v1', 'version-2'),
    );
    expect(onRestored).toHaveBeenCalledWith(restored);
  });

  it('keeps history management usable but blocks restore with an accessible local-work reason', async () => {
    vi.spyOn(api, 'listTemplateVersions').mockResolvedValue(HISTORY);
    const restore = vi.spyOn(api, 'restoreTemplateVersion');
    const reason =
      'Existem alterações locais por guardar. Guarde-as ou descarte-as antes de repor uma versão, para não perder trabalho.';

    renderWithProviders(
      <TemplateVersionHistory templateId="user-board/v1" restoreBlockedReason={reason} />,
    );
    const row = (await screen.findByText('Before final review')).closest('tr');
    if (!row) throw new Error('history row missing');

    expect(screen.getByText('Reposição bloqueada')).toBeTruthy();
    expect(screen.getByText(reason)).toBeTruthy();
    const restoreButton = within(row).getByRole('button', {
      name: 'Repor versão',
    }) as HTMLButtonElement;
    expect(restoreButton.disabled).toBe(true);
    expect(
      document.getElementById(restoreButton.getAttribute('aria-describedby') ?? '')?.textContent,
    ).toContain(reason);
    expect(
      (within(row).getByRole('button', { name: 'Alterar nome' }) as HTMLButtonElement).disabled,
    ).toBe(false);
    expect(
      (within(row).getByRole('button', { name: 'Eliminar versão' }) as HTMLButtonElement).disabled,
    ).toBe(false);

    fireEvent.click(restoreButton);
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(restore).not.toHaveBeenCalled();
  });

  it('requires confirmation before permanently deleting a retained save', async () => {
    vi.spyOn(api, 'listTemplateVersions').mockResolvedValue(HISTORY);
    const remove = vi.spyOn(api, 'deleteTemplateVersion').mockResolvedValue(undefined);

    renderWithProviders(<TemplateVersionHistory templateId="user-board/v1" />);
    const row = (await screen.findByText('Before final review')).closest('tr');
    if (!row) throw new Error('history row missing');

    fireEvent.click(within(row).getByRole('button', { name: 'Eliminar versão' }));
    expect(remove).not.toHaveBeenCalled();
    const dialog = screen.getByRole('dialog', { name: 'Eliminar esta versão guardada?' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Eliminar versão' }));

    await waitFor(() => expect(remove).toHaveBeenCalledWith('user-board/v1', 'version-2'));
  });
});
