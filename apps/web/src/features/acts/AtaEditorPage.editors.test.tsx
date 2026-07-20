import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import {
  AgendaEditor,
  AttachmentsEditor,
  AttendeesEditor,
  DeliberationItemsEditor,
  MesaEditor,
  ReferencedDocumentsEditor,
  SignatoriesEditor,
  StatementsEditor,
  attendanceWeightKind,
  attendeeQualityOptions,
} from './AtaEditorPage';
import type { ActAttendee } from '../../api/types';

afterEach(cleanup);

describe('AtaEditorPage structured editors', () => {
  it('edits, adds, and removes bureau secretaries', () => {
    const onChange = vi.fn();
    render(
      <MesaEditor
        mesa={{ presidente: 'Ana', secretarios: ['Bruno'] }}
        disabled={false}
        onChange={onChange}
      />,
    );

    fireEvent.change(screen.getByLabelText('Nome do secretário'), { target: { value: 'Carla' } });
    expect(onChange).toHaveBeenLastCalledWith({ presidente: 'Ana', secretarios: ['Carla'] });
    fireEvent.click(screen.getByRole('button', { name: 'Remover' }));
    expect(onChange).toHaveBeenLastCalledWith({ presidente: 'Ana', secretarios: [] });
    fireEvent.click(screen.getByRole('button', { name: 'Adicionar secretário' }));
    expect(onChange).toHaveBeenLastCalledWith({ presidente: 'Ana', secretarios: ['Bruno', ''] });
  });

  it('renumbers agenda reorder, remove, add, and edit operations', () => {
    const onChange = vi.fn();
    const agenda = [
      { number: 1, text: 'Contas' },
      { number: 2, text: 'Orçamento' },
    ];
    render(<AgendaEditor agenda={agenda} disabled={false} onChange={onChange} />);

    fireEvent.change(screen.getAllByLabelText('Ponto da ordem de trabalhos')[0], {
      target: { value: 'Relatório' },
    });
    expect(onChange).toHaveBeenLastCalledWith([{ number: 1, text: 'Relatório' }, agenda[1]]);
    fireEvent.click(screen.getAllByRole('button', { name: 'Descer ponto' })[0]);
    expect(onChange).toHaveBeenLastCalledWith([
      { number: 1, text: 'Orçamento' },
      { number: 2, text: 'Contas' },
    ]);
    fireEvent.click(screen.getAllByRole('button', { name: 'Subir ponto' })[1]);
    fireEvent.click(screen.getAllByRole('button', { name: 'Remover' })[0]);
    expect(onChange).toHaveBeenLastCalledWith([{ number: 1, text: 'Orçamento' }]);
    fireEvent.click(screen.getByRole('button', { name: 'Adicionar ponto' }));
    expect(onChange).toHaveBeenLastCalledWith([...agenda, { number: 3, text: '' }]);
  });

  it('edits and maintains member statements', () => {
    const onChange = vi.fn();
    const statements = [{ member: 'Ana', text: 'A favor' }];
    render(<StatementsEditor statements={statements} disabled={false} onChange={onChange} />);

    fireEvent.change(screen.getByLabelText('Autor da declaração'), {
      target: { value: 'Bruno' },
    });
    expect(onChange).toHaveBeenLastCalledWith([{ member: 'Bruno', text: 'A favor' }]);
    fireEvent.change(screen.getByLabelText('Texto da declaração'), {
      target: { value: 'Contra' },
    });
    expect(onChange).toHaveBeenLastCalledWith([{ member: 'Ana', text: 'Contra' }]);
    fireEvent.click(screen.getByRole('button', { name: 'Remover' }));
    expect(onChange).toHaveBeenLastCalledWith([]);
    fireEvent.click(screen.getByRole('button', { name: 'Adicionar declaração' }));
    expect(onChange).toHaveBeenLastCalledWith([...statements, { member: '', text: '' }]);
  });

  it('edits, removes, and adds structured deliberations', () => {
    const onChange = vi.fn();
    const items = [
      {
        agenda_number: null,
        text: 'Aprovar contas',
        vote: null,
        statements: [],
      },
    ];
    render(
      <DeliberationItemsEditor
        items={items}
        agenda={[{ number: 1, text: 'Contas' }]}
        disabled={false}
        onChange={onChange}
      />,
    );

    fireEvent.change(screen.getByLabelText('Ponto associado'), { target: { value: '1' } });
    expect(onChange).toHaveBeenLastCalledWith([{ ...items[0], agenda_number: 1 }]);
    fireEvent.change(screen.getByLabelText('Texto da deliberação'), {
      target: { value: 'Aprovado' },
    });
    expect(onChange).toHaveBeenLastCalledWith([{ ...items[0], text: 'Aprovado' }]);
    fireEvent.change(screen.getByLabelText('Resultado da votação'), {
      target: { value: 'Unanimous' },
    });
    expect(onChange).toHaveBeenLastCalledWith([{ ...items[0], vote: { type: 'Unanimous' } }]);
    fireEvent.click(screen.getByRole('button', { name: 'Remover' }));
    expect(onChange).toHaveBeenLastCalledWith([]);
    fireEvent.click(screen.getByRole('button', { name: 'Adicionar deliberação' }));
    expect(onChange).toHaveBeenLastCalledWith([
      ...items,
      { agenda_number: null, text: '', vote: null, statements: [] },
    ]);
  });

  it('edits, removes, and adds referenced documents', () => {
    const onChange = vi.fn();
    const documents = [{ label: 'Relatório', reference: 'DOC-1' }];
    render(
      <ReferencedDocumentsEditor documents={documents} disabled={false} onChange={onChange} />,
    );

    fireEvent.change(screen.getByLabelText('Designação do documento'), {
      target: { value: 'Balanço' },
    });
    expect(onChange).toHaveBeenLastCalledWith([{ label: 'Balanço', reference: 'DOC-1' }]);
    fireEvent.change(screen.getByLabelText('Referência do documento'), { target: { value: ' ' } });
    expect(onChange).toHaveBeenLastCalledWith([{ label: 'Relatório', reference: null }]);
    fireEvent.click(screen.getByRole('button', { name: 'Remover' }));
    expect(onChange).toHaveBeenLastCalledWith([]);
    fireEvent.click(screen.getByRole('button', { name: 'Adicionar documento' }));
    expect(onChange).toHaveBeenLastCalledWith([...documents, { label: '', reference: null }]);
  });

  it('edits every signatory field and supports collection maintenance', () => {
    const onChange = vi.fn();
    const signatories = [
      {
        name: 'Ana',
        email: 'ana@example.test',
        capacity: 'CondoOwner' as const,
        permilage: 125,
        signed: false,
      },
    ];
    render(<SignatoriesEditor signatories={signatories} disabled={false} onChange={onChange} />);

    fireEvent.change(screen.getByLabelText('Nome do signatário'), { target: { value: 'Bea' } });
    expect(onChange).toHaveBeenLastCalledWith([{ ...signatories[0], name: 'Bea' }]);
    fireEvent.change(screen.getByLabelText('E-mail (opcional)'), { target: { value: '' } });
    expect(onChange).toHaveBeenLastCalledWith([{ ...signatories[0], email: null }]);
    fireEvent.change(screen.getByLabelText('Qualidade'), { target: { value: 'Chair' } });
    expect(onChange).toHaveBeenLastCalledWith([{ ...signatories[0], capacity: 'Chair' }]);
    fireEvent.change(screen.getByLabelText('Permilagem (‰)'), { target: { value: '333.9' } });
    expect(onChange).toHaveBeenLastCalledWith([{ ...signatories[0], permilage: 333 }]);
    fireEvent.click(screen.getByLabelText('Assinou'));
    expect(onChange).toHaveBeenLastCalledWith([{ ...signatories[0], signed: true }]);
    fireEvent.click(screen.getByRole('button', { name: 'Remover' }));
    expect(onChange).toHaveBeenLastCalledWith([]);
    fireEvent.click(screen.getByRole('button', { name: 'Adicionar signatário' }));
    expect(onChange).toHaveBeenLastCalledWith([
      ...signatories,
      { name: '', capacity: 'Member', signed: false },
    ]);
  });

  it('edits every attachment field and supports collection maintenance', () => {
    const onChange = vi.fn();
    const attachments = [
      {
        label: 'Mapa',
        kind: 'Exhibit' as const,
        digest: 'sha256:0123456789abcdef',
        beginning_of_proof: false,
      },
    ];
    render(<AttachmentsEditor attachments={attachments} disabled={false} onChange={onChange} />);

    fireEvent.change(screen.getByLabelText('Descrição do anexo'), { target: { value: 'Planta' } });
    expect(onChange).toHaveBeenLastCalledWith([{ ...attachments[0], label: 'Planta' }]);
    fireEvent.change(screen.getByLabelText('Tipo de anexo'), { target: { value: 'Report' } });
    expect(onChange).toHaveBeenLastCalledWith([{ ...attachments[0], kind: 'Report' }]);
    fireEvent.click(screen.getByLabelText('Início de prova'));
    expect(onChange).toHaveBeenLastCalledWith([{ ...attachments[0], beginning_of_proof: true }]);
    fireEvent.click(screen.getByRole('button', { name: 'Remover' }));
    expect(onChange).toHaveBeenLastCalledWith([]);
    fireEvent.click(screen.getByRole('button', { name: 'Adicionar anexo' }));
    expect(onChange).toHaveBeenLastCalledWith([
      ...attachments,
      { label: '', kind: 'Exhibit', digest: null, beginning_of_proof: false },
    ]);
  });

  it('edits every attendance field and supports collection maintenance', () => {
    const onChange = vi.fn();
    const attendees: ActAttendee[] = [
      {
        name: 'Ana Rocha',
        quality: 'Member',
        quality_note: null,
        presence: 'InPerson',
        represented_by: null,
        weight: { Capital: 500000 },
      },
    ];
    render(
      <AttendeesEditor
        attendees={attendees}
        family="CommercialCompany"
        qualities={['Member', 'Chair', 'Other']}
        disabled={false}
        onChange={onChange}
      />,
    );

    fireEvent.change(screen.getByLabelText('Nome do participante'), {
      target: { value: 'Bruno Dias' },
    });
    expect(onChange).toHaveBeenLastCalledWith([{ ...attendees[0], name: 'Bruno Dias' }]);
    fireEvent.change(screen.getByLabelText('Qualidade do participante'), {
      target: { value: 'Chair' },
    });
    expect(onChange).toHaveBeenLastCalledWith([
      { ...attendees[0], quality: 'Chair', quality_note: null },
    ]);
    fireEvent.change(screen.getByLabelText('Capital (cêntimos)'), {
      target: { value: '250000.7' },
    });
    expect(onChange).toHaveBeenLastCalledWith([{ ...attendees[0], weight: { Capital: 250000 } }]);
    fireEvent.change(screen.getByLabelText('Capital (cêntimos)'), { target: { value: '' } });
    expect(onChange).toHaveBeenLastCalledWith([{ ...attendees[0], weight: null }]);
    fireEvent.click(screen.getByRole('button', { name: 'Remover' }));
    expect(onChange).toHaveBeenLastCalledWith([]);
    fireEvent.click(screen.getByRole('button', { name: 'Adicionar presença' }));
    expect(onChange).toHaveBeenLastCalledWith([
      ...attendees,
      {
        name: '',
        quality: 'Member',
        quality_note: null,
        presence: 'InPerson',
        represented_by: null,
        weight: null,
      },
    ]);
    expect(screen.getByText('1 presentes · 0 representados · 0 ausentes')).toBeTruthy();
  });

  it('shows the proxy field only while represented, and drops the proxy on the way out', () => {
    const onChange = vi.fn();
    const attendees: ActAttendee[] = [
      {
        name: 'Ana Rocha',
        quality: 'Member',
        quality_note: null,
        presence: 'Represented',
        represented_by: 'Carla Neves',
        weight: null,
      },
    ];
    const { rerender } = render(
      <AttendeesEditor
        attendees={attendees}
        family="CommercialCompany"
        qualities={['Member', 'Chair', 'Other']}
        disabled={false}
        onChange={onChange}
      />,
    );

    fireEvent.change(screen.getByLabelText('Representado por'), { target: { value: 'Diogo' } });
    expect(onChange).toHaveBeenLastCalledWith([{ ...attendees[0], represented_by: 'Diogo' }]);
    fireEvent.change(screen.getByLabelText('Modo de presença'), { target: { value: 'Absent' } });
    expect(onChange).toHaveBeenLastCalledWith([
      { ...attendees[0], presence: 'Absent', represented_by: null },
    ]);

    // A represented row with no proxy named warns rather than silently failing the PATCH.
    rerender(
      <AttendeesEditor
        attendees={[{ ...attendees[0], represented_by: '' }]}
        family="CommercialCompany"
        qualities={['Member', 'Chair', 'Other']}
        disabled={false}
        onChange={onChange}
      />,
    );
    expect(screen.getByText('Indique quem representou este participante.')).toBeTruthy();

    rerender(
      <AttendeesEditor
        attendees={[{ ...attendees[0], presence: 'InPerson', represented_by: null }]}
        family="CommercialCompany"
        qualities={['Member', 'Chair', 'Other']}
        disabled={false}
        onChange={onChange}
      />,
    );
    expect(screen.queryByLabelText('Representado por')).toBeNull();
  });

  it('weights attendance by the family: capital, permilagem, or neither', () => {
    expect(attendanceWeightKind('CommercialCompany')).toBe('Capital');
    expect(attendanceWeightKind('Condominium')).toBe('Permilage');
    expect(attendanceWeightKind('Association')).toBeNull();
    expect(attendanceWeightKind(undefined)).toBe('Capital');

    const onChange = vi.fn();
    const attendees: ActAttendee[] = [
      {
        name: 'Ana Rocha',
        quality: 'CondoOwner',
        quality_note: null,
        presence: 'InPerson',
        represented_by: null,
        weight: { Permilage: 125 },
      },
    ];
    const { rerender } = render(
      <AttendeesEditor
        attendees={attendees}
        family="Condominium"
        qualities={['CondoOwner', 'Chair']}
        disabled={false}
        onChange={onChange}
      />,
    );
    fireEvent.change(screen.getByLabelText('Permilagem (‰)'), { target: { value: '250' } });
    expect(onChange).toHaveBeenLastCalledWith([{ ...attendees[0], weight: { Permilage: 250 } }]);

    rerender(
      <AttendeesEditor
        attendees={[{ ...attendees[0], weight: null }]}
        family="Association"
        qualities={['Associate', 'Chair']}
        disabled={false}
        onChange={onChange}
      />,
    );
    expect(screen.queryByLabelText('Permilagem (‰)')).toBeNull();
    expect(screen.queryByLabelText('Capital (cêntimos)')).toBeNull();
  });

  it('offers the qualidades of the entity legal type, not a fixed sócio/acionista pair', () => {
    // The server derives the list from the legal type; the editor only renders what it is given.
    expect(attendeeQualityOptions(['Member', 'Chair', 'Other'], 'Member')).toEqual([
      'Member',
      'Chair',
      'Other',
    ]);
    // A qualidade the row already carries stays selectable even if the entity stopped offering
    // it, so an existing roll is never silently rewritten by the picker.
    expect(attendeeQualityOptions(['Shareholder', 'Chair'], 'CondoOwner')).toEqual([
      'Shareholder',
      'Chair',
      'CondoOwner',
    ]);
    // While the entity query is in flight, offer everything rather than an empty picker.
    const pending = attendeeQualityOptions(undefined, undefined);
    expect(pending).toContain('Member');
    expect(pending).toContain('Shareholder');

    const onChange = vi.fn();
    const { rerender } = render(
      <AttendeesEditor
        attendees={[
          {
            name: 'Ana Rocha',
            quality: 'Shareholder',
            quality_note: null,
            presence: 'InPerson',
            represented_by: null,
            weight: null,
          },
        ]}
        family="CommercialCompany"
        qualities={['Shareholder', 'Chair', 'Other']}
        disabled={false}
        onChange={onChange}
      />,
    );
    // A sociedade anónima's roll says acionista and never offers sócio.
    const picker = screen.getByLabelText('Qualidade do participante') as HTMLSelectElement;
    const offered = Array.from(picker.options).map((o) => o.textContent);
    expect(offered).toContain('Acionista');
    expect(offered).not.toContain('Sócio');
    // ...and `Member` reads as the concrete membership term where it *is* offered.
    rerender(
      <AttendeesEditor
        attendees={[
          {
            name: 'Ana Rocha',
            quality: 'Member',
            quality_note: null,
            presence: 'InPerson',
            represented_by: null,
            weight: null,
          },
        ]}
        family="CommercialCompany"
        qualities={['Member', 'Chair', 'Other']}
        disabled={false}
        onChange={onChange}
      />,
    );
    const quotas = Array.from(
      (screen.getByLabelText('Qualidade do participante') as HTMLSelectElement).options,
    ).map((o) => o.textContent);
    expect(quotas).toContain('Sócio');
    expect(quotas).not.toContain('Acionista');
    expect(quotas).not.toContain('Membro');
  });

  it('keeps the free-text qualidade paired with Other', () => {
    const onChange = vi.fn();
    const row: ActAttendee = {
      name: 'Ana Rocha',
      quality: 'Other',
      quality_note: '',
      presence: 'InPerson',
      represented_by: null,
      weight: null,
    };
    const { rerender } = render(
      <AttendeesEditor
        attendees={[row]}
        family="CommercialCompany"
        qualities={['Member', 'Other']}
        disabled={false}
        onChange={onChange}
      />,
    );
    // Empty free text warns rather than silently rendering an ata with no qualidade.
    expect(
      screen.getByText(
        'Indique a qualidade, ou escolha uma da lista — sem texto a ata não a menciona.',
      ),
    ).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Qualidade (texto livre)'), {
      target: { value: 'usufrutuário da quota' },
    });
    expect(onChange).toHaveBeenLastCalledWith([{ ...row, quality_note: 'usufrutuário da quota' }]);

    // Moving back to a structured capacity drops the note — the API 422s on the pair.
    fireEvent.change(screen.getByLabelText('Qualidade do participante'), {
      target: { value: 'Member' },
    });
    expect(onChange).toHaveBeenLastCalledWith([{ ...row, quality: 'Member', quality_note: null }]);

    rerender(
      <AttendeesEditor
        attendees={[{ ...row, quality: 'Member', quality_note: null }]}
        family="CommercialCompany"
        qualities={['Member', 'Other']}
        disabled={false}
        onChange={onChange}
      />,
    );
    expect(screen.queryByLabelText('Qualidade (texto livre)')).toBeNull();
  });

  it('renders honest empty read-only states', () => {
    render(
      <>
        <MesaEditor mesa={{ presidente: null, secretarios: [] }} disabled onChange={vi.fn()} />
        <AgendaEditor agenda={[]} disabled onChange={vi.fn()} />
        <StatementsEditor statements={[]} disabled onChange={vi.fn()} />
        <DeliberationItemsEditor items={[]} agenda={[]} disabled onChange={vi.fn()} />
        <ReferencedDocumentsEditor documents={[]} disabled onChange={vi.fn()} />
        <SignatoriesEditor signatories={[]} disabled onChange={vi.fn()} />
        <AttachmentsEditor attachments={[]} disabled onChange={vi.fn()} />
        <AttendeesEditor
          attendees={[]}
          family="CommercialCompany"
          qualities={['Member']}
          disabled
          onChange={vi.fn()}
        />
      </>,
    );

    expect(screen.getByText('Sem secretários.')).toBeTruthy();
    expect(screen.getByText('Sem pontos na ordem de trabalhos.')).toBeTruthy();
    expect(screen.getByText('Sem declarações.')).toBeTruthy();
    expect(screen.getByText('Sem deliberações estruturadas.')).toBeTruthy();
    expect(screen.getByText('Sem documentos referidos.')).toBeTruthy();
    expect(screen.getByText('Sem signatários.')).toBeTruthy();
    expect(screen.getByText('Sem anexos.')).toBeTruthy();
    expect(screen.getByText('Sem presenças preenchidas.')).toBeTruthy();
  });
});
