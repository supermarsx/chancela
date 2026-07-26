import { useState } from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import type { TemplateBlockSpec } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import {
  parseTemplateBlocksText,
  TemplateBlocksEditor,
  withNarrativeBodyPlacement,
} from './TemplateBlocksEditor';

const ALL_BLOCKS: TemplateBlockSpec[] = [
  { kind: 'Heading', level: 2, template: 'Ata n.º {{ ata_number }}' },
  { kind: 'Paragraph', items: 'agenda', template: '{{ number }}. {{ text }}' },
  {
    kind: 'KeyValue',
    items: 'entity',
    rows: [
      { key: 'Nome', value: '{{ name }}' },
      { key: 'NIPC', value: '{{ nipc }}' },
    ],
  },
  {
    kind: 'VoteTable',
    items: 'deliberation_items',
    label: '{{ text }}',
    vote_field: 'vote',
    unanimous_total: '{{ members_present }}',
  },
  {
    kind: 'SignatureBlock',
    source: 'signatories',
    role: '{{ capacity }}',
    name: '{{ name }}',
  },
  { kind: 'PageBreak' },
  { kind: 'Rule' },
  { kind: 'NarrativeBody' },
];

function Harness({
  initial,
  presentation = 'cards',
  disabled = false,
}: {
  initial: TemplateBlockSpec[] | string;
  presentation?: 'cards' | 'document';
  disabled?: boolean;
}) {
  const [value, setValue] = useState(
    typeof initial === 'string' ? initial : JSON.stringify(initial, null, 2),
  );
  return (
    <>
      <TemplateBlocksEditor
        value={value}
        onChange={setValue}
        presentation={presentation}
        disabled={disabled}
        renderNarrativeBody={({ occurrence, primary }) => (
          <textarea
            aria-label={primary ? 'Corpo narrativo em linha' : `Espelho narrativo ${occurrence}`}
            data-narrative-placement={occurrence}
            defaultValue="Prosa da ata"
            readOnly={!primary}
          />
        )}
      />
      <output aria-label="current-json">{value}</output>
    </>
  );
}

function currentBlocks(): TemplateBlockSpec[] {
  return JSON.parse(
    screen.getByLabelText('current-json').textContent ?? '[]',
  ) as TemplateBlockSpec[];
}

afterEach(cleanup);

describe('TemplateBlocksEditor', () => {
  it('round-trips every BlockSpec variant, including NarrativeBody, without normalising data', () => {
    const source = JSON.stringify(ALL_BLOCKS, null, 2);
    expect(parseTemplateBlocksText(source)).toEqual({ blocks: ALL_BLOCKS, error: null });

    renderWithProviders(<Harness initial={ALL_BLOCKS} />);
    for (const label of [
      'Título',
      'Parágrafo',
      'Tabela de propriedades',
      'Tabela de votação',
      'Assinaturas',
      'Quebra de página',
      'Linha horizontal',
      'Corpo narrativo',
    ]) {
      expect(screen.getAllByText(label).length).toBeGreaterThan(0);
    }
    expect(currentBlocks()).toEqual(ALL_BLOCKS);
  });

  it('composes document mode as one continuous surface with an inline page-break marker', () => {
    const { container } = renderWithProviders(
      <Harness initial={ALL_BLOCKS} presentation="document" />,
    );

    const flow = container.querySelector('[data-template-document-flow]');
    expect(flow).toBeTruthy();
    expect(flow?.querySelectorAll('[data-template-document-surface]')).toHaveLength(1);
    expect(flow?.querySelector('[data-template-document-page]')).toBeNull();
    expect(flow?.querySelector('.template-document-page__folio')).toBeNull();
    expect(
      Array.from(flow?.querySelectorAll('[data-template-block-kind]') ?? []).map((element) =>
        element.getAttribute('data-template-block-kind'),
      ),
    ).toEqual(ALL_BLOCKS.map((block) => block.kind));
    expect(
      flow
        ?.querySelector('[data-template-block-kind="PageBreak"]')
        ?.querySelector('.template-document-block__marker'),
    ).toBeTruthy();

    expect(screen.getByRole('group', { name: 'Bloco 1: Título' })).toBeTruthy();
    expect(screen.getByRole('group', { name: 'Controlos dos blocos do documento' })).toBeTruthy();
    expect(screen.getByLabelText('Corpo narrativo em linha')).toBeTruthy();
    expect(container.querySelector('.template-document-block__toolbar')).toBeNull();
    expect(currentBlocks()).toEqual(ALL_BLOCKS);
  });

  it('keeps document blocks compact while inserting and duplicating losslessly with focus recovery', async () => {
    const initial: TemplateBlockSpec[] = [
      { kind: 'Heading', level: 2, template: 'Título {{ ata_number }}' },
      {
        kind: 'KeyValue',
        rows: [{ key: 'NIPC', value: '{{ entity.nipc }}' }],
      },
    ];
    const { container } = renderWithProviders(
      <Harness initial={initial} presentation="document" />,
    );

    const firstBlock = container.querySelector('[data-template-block-index="0"]');
    expect(firstBlock?.querySelector('.template-document-block__kind')?.textContent).toBe('Título');
    expect(firstBlock?.querySelector('.template-document-block__direct-text')).toBeTruthy();
    expect(firstBlock?.querySelector('.template-document-block__inspector')).toBeNull();
    expect(screen.queryByRole('dialog', { name: /Definições do bloco/ })).toBeNull();
    const configure = screen.getByRole('button', { name: 'Configurar bloco 1' });
    expect(configure.textContent?.trim()).toBe('');
    expect(configure.getAttribute('aria-describedby')).toBeTruthy();
    const directText = firstBlock?.querySelector(
      '.template-document-block__direct-text',
    ) as HTMLTextAreaElement;
    Object.defineProperty(directText, 'scrollHeight', { configurable: true, value: 180 });
    fireEvent.input(directText);
    expect(directText.style.height).toBe('180px');

    fireEvent.click(screen.getByRole('button', { name: 'Duplicar bloco 1' }));
    expect(currentBlocks()).toEqual([initial[0], initial[0], initial[1]]);
    await waitFor(() =>
      expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Duplicar bloco 2' })),
    );

    fireEvent.click(screen.getByRole('button', { name: 'Inserir parágrafo depois do bloco 2' }));
    expect(currentBlocks()).toEqual([
      initial[0],
      initial[0],
      { kind: 'Paragraph', template: '' },
      initial[1],
    ]);
    await waitFor(() =>
      expect(document.activeElement).toBe(
        screen.getByRole('button', { name: 'Inserir parágrafo depois do bloco 3' }),
      ),
    );
  });

  it('opens block settings only in an accessible right-side drawer and restores focus on Escape', async () => {
    const original = { kind: 'Heading', level: 2, template: 'Título' } as const;
    const { container } = renderWithProviders(
      <Harness initial={[original]} presentation="document" />,
    );

    expect(screen.queryByLabelText('Nível do título')).toBeNull();
    expect(container.querySelector('.template-document-block__inspector')).toBeNull();

    const configure = screen.getByRole('button', { name: 'Configurar bloco 1' });
    configure.focus();
    fireEvent.click(configure);

    const drawer = screen.getByRole('dialog', {
      name: 'Bloco 1 Definições do bloco · Título',
    });
    expect(drawer.getAttribute('aria-modal')).toBe('true');
    expect(container.hasAttribute('inert')).toBe(true);
    expect(document.body.style.overflow).toBe('hidden');
    expect(within(drawer).getByLabelText('Tipo de bloco')).toBeTruthy();
    expect(within(drawer).getByLabelText('Nível do título')).toBeTruthy();
    expect(within(drawer).getAllByRole('button', { name: 'Fechar definições' })).toHaveLength(2);
    expect(drawer.contains(document.activeElement)).toBe(true);

    fireEvent.change(within(drawer).getByLabelText('Nível do título'), {
      target: { value: '3' },
    });
    expect(currentBlocks()).toEqual([{ ...original, level: 3 }]);

    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() =>
      expect(
        screen.queryByRole('dialog', { name: 'Bloco 1 Definições do bloco · Título' }),
      ).toBeNull(),
    );
    expect(container.hasAttribute('inert')).toBe(false);
    expect(document.body.style.overflow).toBe('');
    expect(document.activeElement).toBe(configure);
  });

  it('preserves the inspector across safe kind changes and destructive confirmation cancellation', async () => {
    renderWithProviders(<Harness initial={[{ kind: 'PageBreak' }]} presentation="document" />);

    fireEvent.click(screen.getByRole('button', { name: 'Configurar bloco 1' }));
    let drawer = screen.getByRole('dialog', {
      name: 'Bloco 1 Definições do bloco · Quebra de página',
    });
    fireEvent.change(within(drawer).getByLabelText('Tipo de bloco'), {
      target: { value: 'Rule' },
    });
    drawer = screen.getByRole('dialog', {
      name: 'Bloco 1 Definições do bloco · Linha horizontal',
    });
    expect(screen.queryByRole('dialog', { name: 'Alterar o tipo deste bloco?' })).toBeNull();

    fireEvent.change(within(drawer).getByLabelText('Tipo de bloco'), {
      target: { value: 'Heading' },
    });
    drawer = screen.getByRole('dialog', {
      name: 'Bloco 1 Definições do bloco · Título',
    });
    fireEvent.change(within(drawer).getByLabelText('Texto do modelo'), {
      target: { value: 'Título preservado' },
    });
    fireEvent.change(within(drawer).getByLabelText('Tipo de bloco'), {
      target: { value: 'Paragraph' },
    });

    const confirmation = screen.getByRole('dialog', { name: 'Alterar o tipo deste bloco?' });
    expect(
      screen.queryByRole('dialog', { name: 'Bloco 1 Definições do bloco · Título' }),
    ).toBeNull();
    fireEvent.click(within(confirmation).getByRole('button', { name: 'Cancelar' }));

    drawer = await screen.findByRole('dialog', {
      name: 'Bloco 1 Definições do bloco · Título',
    });
    expect((within(drawer).getByLabelText('Texto do modelo') as HTMLTextAreaElement).value).toBe(
      'Título preservado',
    );
    expect(drawer.contains(document.activeElement)).toBe(true);

    fireEvent.change(within(drawer).getByLabelText('Tipo de bloco'), {
      target: { value: 'Paragraph' },
    });
    fireEvent.click(
      within(screen.getByRole('dialog', { name: 'Alterar o tipo deste bloco?' })).getByRole(
        'button',
        { name: 'Alterar tipo' },
      ),
    );
    drawer = await screen.findByRole('dialog', {
      name: 'Bloco 1 Definições do bloco · Parágrafo',
    });
    expect(currentBlocks()).toEqual([{ kind: 'Paragraph', template: '' }]);
    expect(drawer.contains(document.activeElement)).toBe(true);
    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    await waitFor(() =>
      expect(document.activeElement).toBe(
        screen.getByRole('button', { name: 'Configurar bloco 1' }),
      ),
    );
  });

  it('pins the drawer to the right edge and collapses it to full width at the mobile breakpoint', async () => {
    const nodeFs = 'node:fs';
    const { readFileSync } = (await import(nodeFs)) as {
      readFileSync(path: string, encoding: 'utf8'): string;
    };
    const css = readFileSync('src/features/templates/templateEditor.css', 'utf8').replace(
      /\r\n/gu,
      '\n',
    );

    expect(css).toMatch(
      /\.template-block-inspector__backdrop \{[\s\S]*?justify-content: flex-end;[\s\S]*?overflow: hidden;[\s\S]*?overscroll-behavior: contain;/u,
    );
    expect(css).toMatch(
      /\.template-block-inspector \{[\s\S]*?width: min\(31rem, calc\(100vw - 2rem\)\);[\s\S]*?height: 100%;/u,
    );
    expect(css).toMatch(
      /@media \(max-width: 720px\) \{[\s\S]*?\.template-block-inspector \{\s*width: 100%;\s*border-left: 0;/u,
    );
  });

  it('offers every block kind in the split Add menu and inserts at the invoked position', async () => {
    renderWithProviders(
      <Harness
        initial={[
          { kind: 'Heading', level: 1, template: 'Primeiro' },
          { kind: 'Paragraph', template: 'Segundo' },
        ]}
        presentation="document"
      />,
    );

    const trigger = screen.getByRole('button', { name: 'Escolher tipo de bloco 1' });
    trigger.focus();
    fireEvent.keyDown(trigger, { key: 'ArrowDown' });
    const menu = screen.getByRole('menu', { name: 'Escolher tipo de bloco 1' });
    expect(within(menu).getAllByRole('menuitem')).toHaveLength(8);
    expect(document.activeElement).toBe(within(menu).getByRole('menuitem', { name: 'Título' }));

    fireEvent.keyDown(menu, { key: 'End' });
    expect(document.activeElement).toBe(
      within(menu).getByRole('menuitem', { name: 'Corpo narrativo' }),
    );
    fireEvent.keyDown(menu, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull());
    expect(document.activeElement).toBe(trigger);

    fireEvent.click(trigger);
    fireEvent.click(
      within(screen.getByRole('menu', { name: 'Escolher tipo de bloco 1' })).getByRole('menuitem', {
        name: 'Linha horizontal',
      }),
    );
    expect(currentBlocks().map((block) => block.kind)).toEqual(['Heading', 'Rule', 'Paragraph']);
    await waitFor(() =>
      expect(document.activeElement).toBe(
        screen.getByRole('button', { name: 'Inserir parágrafo depois do bloco 2' }),
      ),
    );
  });

  it('renders later narrative placements as explicit read-only mirrors of the editable source', () => {
    const { container } = renderWithProviders(
      <Harness
        initial={[
          { kind: 'NarrativeBody' },
          { kind: 'Paragraph', template: 'Intermédio' },
          { kind: 'NarrativeBody' },
        ]}
        presentation="document"
      />,
    );

    const primary = screen.getByLabelText('Corpo narrativo em linha') as HTMLTextAreaElement;
    const mirror = screen.getByLabelText('Espelho narrativo 2') as HTMLTextAreaElement;
    expect(primary.readOnly).toBe(false);
    expect(mirror.readOnly).toBe(true);
    expect(primary.value).toBe(mirror.value);
    expect(container.querySelectorAll('[data-narrative-placement]')).toHaveLength(2);
  });

  it('locks every structured and advanced mutation while disabled', () => {
    renderWithProviders(
      <Harness
        initial={[
          { kind: 'Heading', level: 1, template: 'Título' },
          { kind: 'Paragraph', template: 'Texto' },
        ]}
        presentation="document"
        disabled
      />,
    );

    expect(screen.getAllByLabelText('Texto do modelo')[0].matches(':disabled')).toBe(true);
    expect(screen.getByRole('button', { name: 'Configurar bloco 1' }).matches(':disabled')).toBe(
      true,
    );
    expect(screen.getByRole('button', { name: 'Descer bloco 1' }).matches(':disabled')).toBe(true);
    expect(screen.getByRole('button', { name: 'Adicionar bloco' }).matches(':disabled')).toBe(true);
    expect(
      screen
        .getAllByRole('button', { name: /Escolher tipo de bloco/ })
        .every((button) => button.matches(':disabled')),
    ).toBe(true);
    expect(screen.getByLabelText('JSON avançado').matches(':disabled')).toBe(true);
    expect(currentBlocks()).toEqual([
      { kind: 'Heading', level: 1, template: 'Título' },
      { kind: 'Paragraph', template: 'Texto' },
    ]);
  });

  it('adds one narrative placement without overwriting blocks or invalid advanced JSON', () => {
    const source = JSON.stringify(ALL_BLOCKS.filter((block) => block.kind !== 'NarrativeBody'));
    const next = withNarrativeBodyPlacement(source);
    expect(next).not.toBeNull();
    expect(JSON.parse(next ?? '[]')).toEqual([
      ...ALL_BLOCKS.filter((block) => block.kind !== 'NarrativeBody'),
      { kind: 'NarrativeBody' },
    ]);
    expect(withNarrativeBodyPlacement(next ?? '')).toBe(next);
    expect(withNarrativeBodyPlacement('{')).toBeNull();
  });

  it('edits the fields of all value-carrying block variants through friendly controls', () => {
    const cases: {
      block: TemplateBlockSpec;
      label: string;
      value: string;
      expected: (block: TemplateBlockSpec) => boolean;
    }[] = [
      {
        block: ALL_BLOCKS[0],
        label: 'Texto do modelo',
        value: 'Título alterado',
        expected: (block) => block.kind === 'Heading' && block.template === 'Título alterado',
      },
      {
        block: ALL_BLOCKS[1],
        label: 'Texto do modelo',
        value: 'Parágrafo alterado',
        expected: (block) => block.kind === 'Paragraph' && block.template === 'Parágrafo alterado',
      },
      {
        block: ALL_BLOCKS[2],
        label: 'Rótulo 1',
        value: 'Designação',
        expected: (block) => block.kind === 'KeyValue' && block.rows[0]?.key === 'Designação',
      },
      {
        block: ALL_BLOCKS[3],
        label: 'Rótulo de cada votação',
        value: '{{ title }}',
        expected: (block) => block.kind === 'VoteTable' && block.label === '{{ title }}',
      },
      {
        block: ALL_BLOCKS[4],
        label: 'Lista de signatários',
        value: 'attendees',
        expected: (block) => block.kind === 'SignatureBlock' && block.source === 'attendees',
      },
    ];

    for (const testCase of cases) {
      const view = renderWithProviders(<Harness initial={[testCase.block]} />);
      fireEvent.change(screen.getByLabelText(testCase.label), {
        target: { value: testCase.value },
      });
      expect(testCase.expected(currentBlocks()[0])).toBe(true);
      view.unmount();
      cleanup();
    }
  });

  it('explains each fieldless marker instead of exposing meaningless JSON', () => {
    const markers: {
      block: TemplateBlockSpec;
      explanation: string;
    }[] = [
      {
        block: { kind: 'PageBreak' },
        explanation: 'Força o conteúdo seguinte a começar numa nova página.',
      },
      { block: { kind: 'Rule' }, explanation: 'Insere uma linha horizontal no documento.' },
      {
        block: { kind: 'NarrativeBody' },
        explanation:
          'Insere aqui o corpo narrativo escrito no editor e mostrado na pré-visualização.',
      },
    ];

    for (const marker of markers) {
      const view = renderWithProviders(<Harness initial={[marker.block]} />);
      expect(screen.getByText(marker.explanation)).toBeTruthy();
      view.unmount();
      cleanup();
    }
  });

  it('adds and removes nested key/value rows without disturbing the remaining row', () => {
    renderWithProviders(<Harness initial={[ALL_BLOCKS[2]]} />);

    fireEvent.click(screen.getByRole('button', { name: 'Adicionar linha' }));
    fireEvent.change(screen.getByLabelText('Rótulo 3'), { target: { value: 'Sede' } });
    fireEvent.change(screen.getByLabelText('Valor 3'), { target: { value: '{{ seat }}' } });
    fireEvent.click(screen.getByRole('button', { name: 'Remover linha 1' }));

    const block = currentBlocks()[0];
    expect(block.kind).toBe('KeyValue');
    if (block.kind !== 'KeyValue') throw new Error('expected key/value block');
    expect(block.rows).toEqual([
      { key: 'NIPC', value: '{{ nipc }}' },
      { key: 'Sede', value: '{{ seat }}' },
    ]);
  });

  it('reorders, removes and adds blocks from the structured collection', () => {
    renderWithProviders(
      <Harness
        initial={[
          { kind: 'Heading', level: 1, template: 'Primeiro' },
          { kind: 'Paragraph', template: 'Segundo' },
        ]}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Descer bloco 1' }));
    expect(currentBlocks().map((block) => block.kind)).toEqual(['Paragraph', 'Heading']);
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Subir bloco 2' }));

    fireEvent.click(screen.getByRole('button', { name: 'Remover bloco 2' }));
    const dialog = screen.getByRole('dialog', { name: 'Remover este bloco?' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Remover bloco' }));
    expect(currentBlocks().map((block) => block.kind)).toEqual(['Paragraph']);

    fireEvent.click(screen.getByRole('button', { name: 'Escolher tipo de bloco' }));
    fireEvent.click(
      within(screen.getByRole('menu', { name: 'Escolher tipo de bloco' })).getByRole('menuitem', {
        name: 'Corpo narrativo',
      }),
    );
    expect(currentBlocks()).toEqual([
      { kind: 'Paragraph', template: 'Segundo' },
      { kind: 'NarrativeBody' },
    ]);
  });

  it.each(['cards', 'document'] as const)(
    'keeps focus with the moved block and falls back at a boundary in %s mode',
    async (presentation) => {
      renderWithProviders(
        <Harness
          initial={[
            { kind: 'Heading', level: 1, template: 'Primeiro' },
            { kind: 'Paragraph', template: 'Segundo' },
            { kind: 'Rule' },
          ]}
          presentation={presentation}
        />,
      );

      fireEvent.click(screen.getByRole('button', { name: 'Descer bloco 1' }));
      await waitFor(() => {
        expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Descer bloco 2' }));
      });

      fireEvent.click(screen.getByRole('button', { name: 'Descer bloco 2' }));
      expect(currentBlocks().map((block) => block.kind)).toEqual(['Paragraph', 'Rule', 'Heading']);
      await waitFor(() => {
        expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Subir bloco 3' }));
      });
    },
  );

  it('keeps the required last block in friendly editing instead of producing an invalid empty array', () => {
    renderWithProviders(<Harness initial={[{ kind: 'Paragraph', template: 'Único' }]} />);

    const remove = screen.getByRole('button', { name: 'Remover bloco 1' }) as HTMLButtonElement;
    expect(remove.disabled).toBe(true);
    fireEvent.click(remove);
    expect(currentBlocks()).toEqual([{ kind: 'Paragraph', template: 'Único' }]);

    fireEvent.click(screen.getByRole('button', { name: 'Adicionar bloco' }));
    expect(currentBlocks()).toEqual([
      { kind: 'Paragraph', template: 'Único' },
      { kind: 'Paragraph', template: '' },
    ]);
  });

  it('confirms before a populated block kind change can discard its fields', async () => {
    const original = { kind: 'Heading', level: 1, template: 'Título importante' } as const;
    renderWithProviders(<Harness initial={[original]} />);

    fireEvent.change(screen.getByLabelText('Tipo de bloco'), {
      target: { value: 'Paragraph' },
    });

    const dialog = screen.getByRole('dialog', { name: 'Alterar o tipo deste bloco?' });
    expect(
      within(dialog).getByText(
        'Alterar de Título para Parágrafo remove todos os campos atuais deste bloco. A alteração só será aplicada depois de confirmar.',
      ),
    ).toBeTruthy();
    expect(currentBlocks()).toEqual([original]);

    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancelar' }));
    expect(screen.queryByRole('dialog', { name: 'Alterar o tipo deste bloco?' })).toBeNull();
    expect(currentBlocks()).toEqual([original]);

    fireEvent.change(screen.getByLabelText('Tipo de bloco'), {
      target: { value: 'Paragraph' },
    });
    fireEvent.click(
      within(screen.getByRole('dialog', { name: 'Alterar o tipo deste bloco?' })).getByRole(
        'button',
        { name: 'Alterar tipo' },
      ),
    );

    await waitFor(() => {
      expect(currentBlocks()).toEqual([{ kind: 'Paragraph', template: '' }]);
    });
  });

  it('keeps each block disclosure where the user left it while edits rerender the list', () => {
    renderWithProviders(
      <Harness
        initial={[
          { kind: 'Heading', level: 1, template: 'Primeiro' },
          { kind: 'Paragraph', template: 'Segundo' },
        ]}
      />,
    );

    const first = screen.getByText('Bloco 1').closest('details') as HTMLDetailsElement;
    const second = screen.getByText('Bloco 2').closest('details') as HTMLDetailsElement;
    expect(first.open).toBe(true);
    expect(second.open).toBe(false);

    fireEvent.click(first.querySelector('summary') as HTMLElement);
    fireEvent.click(second.querySelector('summary') as HTMLElement);
    expect(first.open).toBe(false);
    expect(second.open).toBe(true);

    fireEvent.change(within(second).getByLabelText('Texto do modelo'), {
      target: { value: 'Segundo alterado' },
    });
    expect(first.open).toBe(false);
    expect(second.open).toBe(true);
  });

  it('keeps invalid advanced JSON editable, diagnoses it, then restores structured editing', () => {
    renderWithProviders(<Harness initial={[{ kind: 'Paragraph', template: 'Texto' }]} />);

    const rawDisclosure = screen.getByText('JSON avançado').closest('details');
    if (!rawDisclosure) throw new Error('missing advanced JSON disclosure');
    fireEvent.click(within(rawDisclosure).getByText('JSON avançado'));
    fireEvent.change(screen.getByLabelText('JSON avançado'), { target: { value: '{' } });

    expect(screen.getAllByText('O JSON dos blocos não é válido.').length).toBeGreaterThan(0);
    expect(screen.queryByText('Bloco 1')).toBeNull();

    fireEvent.change(screen.getByLabelText('JSON avançado'), {
      target: { value: JSON.stringify([{ kind: 'NarrativeBody' }], null, 2) },
    });
    expect(screen.getByText('Bloco 1')).toBeTruthy();
    expect(currentBlocks()).toEqual([{ kind: 'NarrativeBody' }]);
  });
});
