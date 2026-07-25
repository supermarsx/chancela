import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen } from '@testing-library/react';
import type { TemplateSpec } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { TemplateDocumentEditor } from './TemplateDocumentEditor';

vi.mock('../../api/hooks', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/hooks')>();
  return {
    ...actual,
    useTemplateBodyPreview: () => ({ mutate: vi.fn() }),
  };
});

vi.mock('../acts/MarkdownBodyEditor', () => ({
  MarkdownBodyEditor: ({
    value,
    onChange,
    disabled,
  }: {
    value: string;
    onChange: (next: string) => void;
    disabled?: boolean;
  }) => (
    <textarea
      aria-label={disabled ? 'narrative-mirror' : 'narrative-primary'}
      value={value}
      disabled={disabled}
      onChange={(event) => onChange(event.target.value)}
    />
  ),
}));

vi.mock('./TemplatePdfPreview', () => ({
  TemplatePdfPreview: ({ request }: { request: { spec: { blocks: unknown } } }) => (
    <div data-testid="pdf-proof">{JSON.stringify(request.spec.blocks)}</div>
  ),
}));

vi.mock('./TemplateMarkdownPreview', () => ({
  TemplateMarkdownPreview: () => <div data-testid="markdown-proof">Markdown</div>,
}));

const SPEC: TemplateSpec = {
  id: 'user-duplicate-body/v1',
  family: 'CommercialCompany',
  stage: 'Ata',
  channels: [],
  signature_policy: 'QualifiedPreferred',
  rule_pack_id: 'csc-art63/v2',
  locale: 'pt-PT',
  blocks: [
    { kind: 'NarrativeBody' },
    { kind: 'Paragraph', template: 'Intervalo' },
    { kind: 'NarrativeBody' },
  ],
};

function DocumentHarness({ initialBlocks }: { initialBlocks: TemplateSpec['blocks'] }) {
  const [blocksText, setBlocksText] = useState(JSON.stringify(initialBlocks, null, 2));
  return (
    <TemplateDocumentEditor
      spec={SPEC}
      blocksText={blocksText}
      onBlocksChange={setBlocksText}
      bodyMarkdown="Current narrative"
      onBodyChange={vi.fn()}
      onAddBodyPlacement={vi.fn()}
      disabled={false}
      idPrefix="proof-validity-test"
    />
  );
}

afterEach(cleanup);

describe('TemplateDocumentEditor', () => {
  it('edits the first narrative placement, mirrors later placements, and keeps one keyboardable proof', () => {
    const onBodyChange = vi.fn();
    const { container } = renderWithProviders(
      <TemplateDocumentEditor
        spec={SPEC}
        blocksText={JSON.stringify(SPEC.blocks, null, 2)}
        onBlocksChange={vi.fn()}
        bodyMarkdown="Prosa repetida"
        onBodyChange={onBodyChange}
        onAddBodyPlacement={vi.fn()}
        disabled={false}
        idPrefix="duplicate-test"
      />,
    );

    const primary = screen.getByLabelText('narrative-primary') as HTMLTextAreaElement;
    const mirror = screen.getByLabelText('narrative-mirror') as HTMLTextAreaElement;
    expect(primary.value).toBe('Prosa repetida');
    expect(primary.disabled).toBe(false);
    expect(mirror.value).toBe(primary.value);
    expect(mirror.disabled).toBe(true);
    expect(
      screen.getByRole('region', {
        name: 'Corpo narrativo repetido, apenas de leitura, ocorrência 2, bloco 3',
      }),
    ).toBe(container.querySelector('[data-template-narrative-mirror="2"]'));

    fireEvent.change(primary, { target: { value: 'Prosa alterada' } });
    expect(onBodyChange).toHaveBeenCalledWith('Prosa alterada');

    expect(screen.getAllByTestId('pdf-proof')).toHaveLength(1);
    expect(screen.queryByTestId('markdown-proof')).toBeNull();
    const pdfTab = screen.getByRole('tab', { name: 'PDF' });
    const markdownTab = screen.getByRole('tab', { name: 'Markdown' });
    pdfTab.focus();
    fireEvent.keyDown(pdfTab, { key: 'ArrowRight' });
    expect(markdownTab.getAttribute('aria-selected')).toBe('true');
    expect(document.activeElement).toBe(markdownTab);
    expect(screen.getAllByTestId('markdown-proof')).toHaveLength(1);
    expect(screen.queryByTestId('pdf-proof')).toBeNull();
  });

  it('uses current valid blocks for proof and pauses every proof while Advanced JSON is invalid', () => {
    const currentBlocks = [
      { kind: 'Paragraph' as const, template: 'Current structured prose' },
      { kind: 'NarrativeBody' as const },
    ];
    const repairedBlocks = [
      { kind: 'Heading' as const, level: 2 as const, template: 'Repaired heading' },
      { kind: 'NarrativeBody' as const },
    ];
    const { container } = renderWithProviders(<DocumentHarness initialBlocks={currentBlocks} />);

    expect(screen.getByTestId('pdf-proof').textContent).toBe(JSON.stringify(currentBlocks));
    expect(screen.getByTestId('pdf-proof').textContent).not.toBe(JSON.stringify(SPEC.blocks));
    const semiPreviewNotice = container.querySelector(
      '.template-document-editor > header .template-preview-notice details',
    ) as HTMLDetailsElement;
    expect(semiPreviewNotice.open).toBe(false);
    expect(semiPreviewNotice.querySelector('summary')?.textContent).toContain(
      'Pré-visualização estrutural',
    );

    fireEvent.change(screen.getByLabelText('JSON avançado'), { target: { value: '{' } });

    expect(screen.queryByTestId('pdf-proof')).toBeNull();
    expect(screen.queryByTestId('markdown-proof')).toBeNull();
    expect(
      screen
        .getAllByRole('alert')
        .some((alert) => alert.classList.contains('template-preview-notice')),
    ).toBe(true);
    expect(
      screen.getByText(
        'A pré-visualização PDF e Markdown fica em pausa até que o JSON avançado dos blocos seja válido.',
      ),
    ).toBeTruthy();

    fireEvent.change(screen.getByLabelText('JSON avançado'), {
      target: { value: JSON.stringify(repairedBlocks, null, 2) },
    });

    expect(screen.getByTestId('pdf-proof').textContent).toBe(JSON.stringify(repairedBlocks));
    expect(
      screen.queryByText(
        'A pré-visualização PDF e Markdown fica em pausa até que o JSON avançado dos blocos seja válido.',
      ),
    ).toBeNull();
  });
});
