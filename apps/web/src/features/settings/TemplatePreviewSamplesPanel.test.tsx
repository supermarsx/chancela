import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import {
  DEFAULT_TEMPLATE_PREVIEW_SAMPLES,
  type TemplatePreviewSampleSettings,
} from '../../api/types';
import { i18nStore } from '../../i18n';
import { renderWithProviders } from '../../test/utils';
import { TemplatePreviewSamplesPanel } from './TemplatePreviewSamplesPanel';

function PanelHarness({
  canEdit = true,
  onChange = vi.fn(),
  onReset = vi.fn(),
  initialValue = DEFAULT_TEMPLATE_PREVIEW_SAMPLES,
}: {
  canEdit?: boolean;
  onChange?: (value: TemplatePreviewSampleSettings) => void;
  onReset?: () => void;
  initialValue?: TemplatePreviewSampleSettings;
}) {
  const [value, setValue] = useState(() => structuredClone(initialValue));
  return (
    <TemplatePreviewSamplesPanel
      value={value}
      canEdit={canEdit}
      onChange={(next) => {
        setValue(next);
        onChange(next);
      }}
      onReset={onReset}
    />
  );
}

afterEach(() => {
  cleanup();
  i18nStore.setActiveLocale('pt-PT');
  vi.restoreAllMocks();
});

describe('TemplatePreviewSamplesPanel', () => {
  it('uses eight left-edge sub-tabs and full-width tables instead of a raw JSON editor', () => {
    const { container } = renderWithProviders(<PanelHarness />);

    expect(
      screen.getByText(/Configure os dados fictícios usados para resolver modelos/),
    ).toBeTruthy();
    expect(
      screen.getByText(/nunca introduza dados pessoais reais, credenciais, tokens/),
    ).toBeTruthy();
    const tabs = within(
      screen.getByRole('group', { name: 'Secções das amostras da pré-visualização' }),
    );
    expect(tabs.getAllByRole('button').map((button) => button.textContent)).toEqual([
      'Geral',
      'Entidade',
      'Reunião',
      'Ordem de trabalhos',
      'Convocatória',
      'Evidência',
      'Livro',
      'Alternativas',
    ]);
    expect(container.querySelector('textarea')).toBeNull();
    expect(container.textContent).not.toContain('law_references');

    fireEvent.click(tabs.getByRole('button', { name: 'Entidade' }));
    const profiles = screen.getByRole('table', { name: 'Perfis por família' });
    expect(within(profiles).getAllByRole('row')).toHaveLength(6);
    expect(within(profiles).getByRole('row', { name: /Sociedade comercial/ })).toBeTruthy();
    expect(profiles.closest('.template-preview-sample-table')).toBeTruthy();
  });

  it('edits family profiles in a portalled modal and applies the typed value', async () => {
    const onChange = vi.fn();
    renderWithProviders(<PanelHarness onChange={onChange} />);
    fireEvent.click(screen.getByRole('button', { name: 'Entidade' }));
    fireEvent.click(
      within(screen.getByRole('table', { name: 'Perfis por família' })).getByRole('button', {
        name: 'Editar linha 1 de Associação',
      }),
    );

    const dialog = screen.getByRole('dialog', { name: 'Editar Associação' });
    expect(dialog.closest('.modal-backdrop')?.parentElement).toBe(document.body);
    fireEvent.change(within(dialog).getByLabelText('Nome'), {
      target: { value: 'Associação Fictícia Renovada' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Aplicar' }));

    await waitFor(() => expect(screen.getByText('Associação Fictícia Renovada')).toBeTruthy());
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({
        family_profiles: expect.objectContaining({
          association: expect.objectContaining({ name: 'Associação Fictícia Renovada' }),
        }),
      }),
    );
  });

  it('adds, reorders and removes repeatable rows through icon-only accessible actions', async () => {
    const onChange = vi.fn();
    renderWithProviders(<PanelHarness onChange={onChange} />);
    fireEvent.click(screen.getByRole('button', { name: 'Reunião' }));
    const attendees = screen.getByRole('table', { name: 'Presenças' });
    expect(within(attendees).getAllByRole('row')).toHaveLength(4);

    const moveSecondUp = within(attendees).getByRole('button', {
      name: 'Mover linha 2 para cima',
    });
    expect(moveSecondUp.textContent).toBe('');
    fireEvent.click(moveSecondUp);
    expect(within(attendees).getAllByRole('row')[1].textContent).toContain('Carlos Ferreira');

    fireEvent.click(
      within(attendees).getByRole('button', { name: 'Remover linha 1 de Presenças' }),
    );
    expect(within(attendees).getAllByRole('row')).toHaveLength(3);

    fireEvent.click(screen.getByRole('button', { name: 'Adicionar a Presenças' }));
    const dialog = screen.getByRole('dialog', { name: 'Adicionar a Presenças' });
    const apply = within(dialog).getByRole('button', { name: 'Aplicar' }) as HTMLButtonElement;
    expect(apply.disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText('Nome'), {
      target: { value: 'Pessoa Exemplo' },
    });
    expect(apply.disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText('Nota da qualidade'), {
      target: { value: 'Sócio fictício' },
    });
    expect(apply.disabled).toBe(false);
    fireEvent.click(apply);

    await waitFor(() => expect(within(attendees).getByText('Pessoa Exemplo')).toBeTruthy());
    expect(onChange).toHaveBeenCalled();
  });

  it('preserves malformed rows for repair and enables Apply only after the format is valid', async () => {
    const invalid = structuredClone(DEFAULT_TEMPLATE_PREVIEW_SAMPLES);
    invalid.evidence.attachments[0].digest = 'A'.repeat(64);
    const onChange = vi.fn();
    renderWithProviders(<PanelHarness initialValue={invalid} onChange={onChange} />);

    fireEvent.click(screen.getByRole('button', { name: 'Evidência' }));
    fireEvent.click(
      within(screen.getByRole('table', { name: 'Anexos' })).getByRole('button', {
        name: 'Editar linha 1 de Anexos',
      }),
    );
    const dialog = screen.getByRole('dialog', { name: 'Editar Anexos' });
    const digest = within(dialog).getByLabelText('Resumo criptográfico') as HTMLInputElement;
    const apply = within(dialog).getByRole('button', { name: 'Aplicar' }) as HTMLButtonElement;
    expect(digest.value).toBe('A'.repeat(64));
    expect(apply.disabled).toBe(true);

    fireEvent.change(digest, { target: { value: 'a'.repeat(64) } });
    expect(apply.disabled).toBe(false);
    fireEvent.click(apply);

    await waitFor(() =>
      expect(onChange).toHaveBeenLastCalledWith(
        expect.objectContaining({
          evidence: expect.objectContaining({
            attachments: expect.arrayContaining([
              expect.objectContaining({ digest: 'a'.repeat(64) }),
            ]),
          }),
        }),
      ),
    );
  });

  it('resets only after the shared confirmation modal is confirmed', async () => {
    const onReset = vi.fn();
    renderWithProviders(<PanelHarness onReset={onReset} />);
    const reset = screen.getByRole('button', { name: 'Repor amostras fictícias' });

    fireEvent.click(reset);
    let dialog = screen.getByRole('dialog', {
      name: 'Repor as amostras da pré-visualização?',
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancelar' }));
    expect(onReset).not.toHaveBeenCalled();

    fireEvent.click(reset);
    dialog = screen.getByRole('dialog', {
      name: 'Repor as amostras da pré-visualização?',
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Repor amostras' }));
    await waitFor(() => expect(onReset).toHaveBeenCalledOnce());
  });

  it('keeps samples readable but disables every mutation without settings.manage', () => {
    const onChange = vi.fn();
    const { container } = renderWithProviders(<PanelHarness canEdit={false} onChange={onChange} />);

    expect(screen.getByText(/a edição requer permissão para gerir configurações/)).toBeTruthy();
    expect((screen.getByLabelText('Título') as HTMLInputElement).disabled).toBe(true);
    expect(
      (screen.getByRole('button', { name: 'Repor amostras fictícias' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Reunião' }));
    expect(
      (screen.getByRole('button', { name: 'Adicionar a Presenças' }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(
      (container.querySelector('[aria-label^="Editar linha"]') as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(onChange).not.toHaveBeenCalled();
  });

  it('shows stale over-limit values and prevents adding more instead of silently hiding rows', () => {
    const invalid = structuredClone(DEFAULT_TEMPLATE_PREVIEW_SAMPLES);
    invalid.act.number = 0;
    invalid.meeting.mesa.secretaries = Array.from({ length: 11 }, (_, index) => `S${index + 1}`);
    invalid.meeting.attendees = Array.from({ length: 51 }, (_, index) => ({
      ...invalid.meeting.attendees[index % invalid.meeting.attendees.length],
      name: `Pessoa fictícia ${index + 1}`,
    }));
    invalid.deliberations.items[0].statements = Array.from({ length: 21 }, (_, index) => ({
      agenda_number: index + 1,
      member: `Membro ${index + 1}`,
      text: `Declaração ${index + 1}`,
    }));
    const onChange = vi.fn();
    renderWithProviders(<PanelHarness initialValue={invalid} onChange={onChange} />);

    expect(screen.getByText('Corrija os valores antes de guardar')).toBeTruthy();
    expect(screen.getByText(/Secretários: existem 11 linhas; use entre 1 e 10/)).toBeTruthy();
    expect(screen.getByText(/Presenças: existem 51 linhas; use entre 1 e 50/)).toBeTruthy();
    expect(screen.getByText(/Declarações: existem 21 linhas; use entre 0 e 20/)).toBeTruthy();
    expect(screen.getByText(/Número: introduza um número inteiro entre 1 e 999/)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Reunião' }));
    expect(
      (screen.getByRole('button', { name: 'Adicionar a Secretários' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    expect(
      (screen.getByRole('button', { name: 'Adicionar a Presenças' }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(
      within(screen.getByRole('table', { name: 'Presenças' })).getAllByRole('row'),
    ).toHaveLength(52);

    fireEvent.change(screen.getByLabelText('Número'), { target: { value: '1' } });
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ act: expect.objectContaining({ number: 1 }) }),
    );
  });

  it('keeps malformed authored values visible and explains every authoritative format boundary', () => {
    const invalid = structuredClone(DEFAULT_TEMPLATE_PREVIEW_SAMPLES);
    invalid.general.title = '   ';
    invalid.general.created_at = '2026-02-30';
    invalid.entity.nipc = '123ABC';
    invalid.entity.address = 'a'.repeat(501);
    invalid.act.meeting_time = '25:00';
    invalid.agenda[1].number = invalid.agenda[0].number;
    invalid.agenda[0].text = 'p'.repeat(2_001);
    invalid.evidence.attachments[0].digest = 'A'.repeat(64);
    renderWithProviders(<PanelHarness initialValue={invalid} />);

    expect((screen.getByLabelText('Título') as HTMLInputElement).value).toBe('   ');
    expect(screen.getByText('Título: introduza um valor.')).toBeTruthy();
    expect(screen.getByText(/Data de criação: use o formato AAAA-MM-DD/)).toBeTruthy();
    expect(
      screen.getByText(/NIPC fictício: use o formato NIPC com exatamente 9 algarismos/),
    ).toBeTruthy();
    expect(screen.getByText(/Morada: tem 501 carateres; o máximo é 500/)).toBeTruthy();
    expect(screen.getByText(/Hora da reunião: use o formato HH:MM/)).toBeTruthy();
    expect(screen.getByText(/Número: o número 1 está repetido/)).toBeTruthy();
    expect(screen.getByText(/Texto: tem 2001 carateres; o máximo é 2000/)).toBeTruthy();
    expect(
      screen.getByText(/Resumo criptográfico: use o formato 64 carateres hexadecimais/),
    ).toBeTruthy();
  });

  it('ships complete English fallback copy for tabs, fields and safeguards', () => {
    i18nStore.setActiveLocale('en-US');
    renderWithProviders(<PanelHarness />);

    expect(screen.getByText(/never enter real personal data, credentials, tokens/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Entity' }));
    expect(screen.getByRole('table', { name: 'Profiles by family' })).toBeTruthy();
    expect(screen.getByText('Commercial company')).toBeTruthy();
    expect(screen.queryByText('Forma jurídica')).toBeNull();
  });
});
