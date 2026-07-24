/**
 * TemplateCreatePage (t56) — the full-page CREATE and FORK surface that replaced the modal.
 *
 * The load-bearing assertions: a create posts the `chancela.template-bundle` envelope (spec + body),
 * a fork seeds the id/rule-pack/body from the source and posts a NEW user template (never a PUT over
 * a built-in), the "a copy cannot yet seal" limit is stated before any work, the no-anchor hint
 * fires when the template places no narrative body, and the live preview renders the server's blocks.
 *
 * The lazy `MarkdownBodyEditor` is mocked to a plain textarea so the wiring is what the test observes.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { TemplateCreatePage } from './TemplateCreatePage';
import { renderWithProviders } from '../../test/utils';
import type { Block, TemplateBlockSpec, TemplateSummary } from '../../api/types';
import {
  StaticPermissionsProvider,
  permissionsValue,
  type PermissionsContextValue,
} from '../session/permissions';

vi.mock('../acts/MarkdownBodyEditor', () => ({
  MarkdownBodyEditor: ({
    value,
    onChange,
    disabled,
    id,
  }: {
    value: string;
    onChange: (next: string) => void;
    disabled?: boolean;
    id?: string;
  }) => (
    <textarea
      aria-label="corpo-markdown"
      id={id}
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
    />
  ),
}));

// The real PDF component's debounce, stale-response handling and pdf.js canvas are covered in its
// focused test. This page test pins only the editor seam and the exclusive PDF/Markdown mounting.
vi.mock('./TemplatePdfPreview', () => ({
  TemplatePdfPreview: ({
    request,
  }: {
    request: { source: string; spec: { id: string }; body_markdown: string };
  }) => (
    <div
      role="status"
      data-testid="real-template-pdf-preview"
      data-template-id={request.spec.id}
      data-body-markdown={request.body_markdown}
    >
      Pré-visualização PDF/A estrutural
    </div>
  ),
}));

const BUILTIN: TemplateSummary = {
  id: 'csc-ata-ag/v1',
  family: 'CommercialCompany',
  stage: 'Ata',
  channels: ['Physical'],
  signature_policy: 'QualifiedPreferred',
  rule_pack_id: 'csc-art63/v2',
  law_references: [],
  locale: 'pt-PT',
  editable: false,
  source: 'builtin',
};

const CREATED: TemplateSummary = { ...BUILTIN, id: 'user-x/v1', editable: true, source: 'user' };

/** The source export as the real `chancela.template-bundle` envelope, carrying a seed body. */
const SOURCE_BUNDLE = {
  format: 'chancela.template-bundle',
  format_version: 1,
  spec: {
    id: 'csc-ata-ag/v1',
    family: 'CommercialCompany',
    stage: 'Ata',
    channels: ['Physical'],
    signature_policy: 'QualifiedPreferred',
    rule_pack_id: 'csc-art63/v2',
    locale: 'pt-PT',
    blocks: [{ kind: 'Paragraph', template: 'Ata de {{ entity.name }}.' }],
  },
  body_markdown: '## Corpo\n\nTexto do corpo.',
};

interface RecordedRequest {
  url: string;
  method: string;
  body?: BodyInit | null;
}

async function editorCss(): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/features/templates/templateEditor.css', 'utf8');
}

function expectCssRule(css: string, selector: RegExp, declarations: string[]) {
  const body = css.match(selector)?.[1] ?? '';
  expect(body).not.toBe('');
  for (const declaration of declarations) expect(body).toContain(declaration);
}

function stubFetch(
  catalog: TemplateSummary[],
  opts: { exportBody?: unknown; previewBlocks?: Block[] } = {},
) {
  const calls: RecordedRequest[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    calls.push({ url, method, body: init?.body });
    const json = (value: unknown, status = 200) =>
      Promise.resolve(
        new Response(JSON.stringify(value), {
          status,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    if (url.includes('/v1/templates/body/preview')) {
      return json({ compiler_id: 'md-block/v1', blocks: opts.previewBlocks ?? [] });
    }
    if (url.includes('/export')) return json(opts.exportBody ?? SOURCE_BUNDLE);
    if (url.endsWith('/v1/templates') && method === 'POST') return json(CREATED, 201);
    if (url.includes('/v1/templates') && method === 'GET') return json(catalog);
    return Promise.reject(new Error(`no stub for ${method} ${url}`));
  }) as typeof fetch;
  return { fn, calls };
}

/** POSTs that are real writes, not the stateless preview compile. */
function writePosts(calls: RecordedRequest[]): RecordedRequest[] {
  return calls.filter((c) => c.method === 'POST' && !c.url.includes('/body/preview'));
}

function renderCreate(search = '', permissions?: PermissionsContextValue) {
  const routes = (
    <Routes>
      <Route path="/templates/new" element={<TemplateCreatePage />} />
      <Route path="/templates/:id/:sec?" element={<div>detalhe</div>} />
    </Routes>
  );
  return renderWithProviders(
    permissions ? (
      <StaticPermissionsProvider value={permissions}>{routes}</StaticPermissionsProvider>
    ) : (
      routes
    ),
    [`/templates/new${search}`],
  );
}

async function openPropertiesStructure(): Promise<HTMLDetailsElement> {
  const properties = await screen.findByRole('button', { name: 'Propriedades' });
  if (properties.getAttribute('aria-pressed') !== 'true') fireEvent.click(properties);
  const summary = await screen.findByText('Estrutura avançada do documento');
  const details = summary.closest('details') as HTMLDetailsElement | null;
  if (!details) throw new Error('advanced document structure disclosure missing');
  if (!details.open) fireEvent.click(summary);
  return details;
}

function openContent() {
  const content = screen.getByRole('button', { name: 'Editor e pré-visualização' });
  if (content.getAttribute('aria-pressed') !== 'true') fireEvent.click(content);
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('TemplateCreatePage', () => {
  it.each([
    { label: 'new', search: '' },
    { label: 'fork', search: '?fork=csc-ata-ag%2Fv1' },
  ])('fails closed on a direct $label route for an act.read-only reader', async ({ search }) => {
    const { fn, calls } = stubFetch([BUILTIN]);
    vi.stubGlobal('fetch', fn);

    renderCreate(
      search,
      permissionsValue((permission) => permission === 'act.read'),
    );

    expect(await screen.findByText('Sem permissão')).toBeTruthy();
    expect(screen.getByText('Não tem permissão para realizar esta operação.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Guardar' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Editor e pré-visualização' })).toBeNull();
    expect(screen.queryByLabelText('corpo-markdown')).toBeNull();
    expect(calls.some((call) => call.url.includes('/export'))).toBe(false);
    expect(calls.some((call) => call.url.includes('/body/preview'))).toBe(false);
    expect(writePosts(calls)).toHaveLength(0);
    expect(calls).toHaveLength(0);
  });

  it('is a full-width page, not a modal', async () => {
    const { fn } = stubFetch([]);
    vi.stubGlobal('fetch', fn);

    const { container } = renderCreate();

    const contentTab = await screen.findByRole('button', {
      name: 'Editor e pré-visualização',
    });
    expect(contentTab.getAttribute('aria-pressed')).toBe('true');
    expect(screen.queryByLabelText('Identificador')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Histórico de versões' })).toBeNull();
    expect(container.querySelector('.wide-page')).toBeTruthy();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(container.querySelector('.template-editor-tabs')).toBeTruthy();
    expect(container.querySelector('.template-body-composer__editor')).toBeTruthy();
    expect(container.querySelector('.template-preview')).toBeTruthy();
    expect(container.querySelector('.delib')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Propriedades' }));
    await screen.findByLabelText('Identificador');
    expect(container.querySelector('.field-table')).toBeTruthy();
    expect(screen.queryByLabelText('corpo-markdown')).toBeNull();
    const structure = screen
      .getByText('Estrutura avançada do documento')
      .closest('details') as HTMLDetailsElement;
    expect(structure.open).toBe(false);
    fireEvent.click(within(structure).getByText('Estrutura avançada do documento'));
    fireEvent.click(within(structure).getByText('JSON avançado'));
    expect(
      JSON.parse((screen.getByLabelText('JSON avançado') as HTMLTextAreaElement).value),
    ).toEqual([{ kind: 'NarrativeBody' }]);
  });

  it('keeps editor tabs left-aligned and the paper and preview full-width in scoped CSS', async () => {
    const css = await editorCss();

    expectCssRule(
      css,
      /\.template-editor-page \.template-editor-tabs \.subnav-rail\s*\{([^}]*)\}/,
      ['width: 100%;', 'max-width: 100%;', 'margin-inline: 0;'],
    );
    expectCssRule(
      css,
      /\.template-body-composer \.markdown-body-editor__surface\.ProseMirror\s*\{([^}]*)\}/,
      ['width: 100%;', 'min-height: 28rem;', 'font: 1rem/1.72 var(--font-body);'],
    );
    expectCssRule(css, /\.template-preview__heading\s*\{([^}]*)\}/, [
      'display: grid;',
      'justify-items: start;',
    ]);
    expectCssRule(css, /\.template-preview__panel\s*\{([^}]*)\}/, [
      'width: 100%;',
      'min-height: 18rem;',
    ]);
  });

  it('offers only the locale accepted by the template authoring API', async () => {
    const { fn } = stubFetch([]);
    vi.stubGlobal('fetch', fn);

    renderCreate();
    await screen.findByLabelText('corpo-markdown');
    fireEvent.click(screen.getByRole('button', { name: 'Propriedades' }));

    const locale = screen.getByLabelText('Idioma') as HTMLSelectElement;
    expect(Array.from(locale.options, (option) => option.value)).toEqual(['pt-PT']);
  });

  it('creates a user template by posting the bundle envelope with the narrative body', async () => {
    const { fn, calls } = stubFetch([]);
    vi.stubGlobal('fetch', fn);

    renderCreate();

    fireEvent.change(await screen.findByLabelText('corpo-markdown'), {
      target: { value: '## Novo corpo' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Propriedades' }));
    fireEvent.change(await screen.findByLabelText('Identificador'), {
      target: { value: 'user-x/v1' },
    });
    fireEvent.change(screen.getByLabelText('Pacote de regras'), {
      target: { value: 'csc-art63/v2' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => expect(writePosts(calls)).toHaveLength(1));
    const post = writePosts(calls)[0];
    expect(post.url.endsWith('/v1/templates')).toBe(true);
    // The whole bundle: the envelope format, the id AND the narrative body.
    expect(String(post.body)).toContain('chancela.template-bundle');
    expect(String(post.body)).toContain('user-x/v1');
    expect(String(post.body)).toContain('## Novo corpo');
    // Lands on the new template's own page.
    expect(await screen.findByText('detalhe')).toBeTruthy();
  });

  it('forks a built-in: seeds id, rule pack and body from the real envelope, states the limit', async () => {
    const { fn } = stubFetch([BUILTIN]);
    vi.stubGlobal('fetch', fn);

    renderCreate('?fork=csc-ata-ag%2Fv1');

    // The first tab is authoring: body and preview stay together.
    expect(((await screen.findByLabelText('corpo-markdown')) as HTMLTextAreaElement).value).toBe(
      '## Corpo\n\nTexto do corpo.',
    );
    fireEvent.click(screen.getByRole('button', { name: 'Propriedades' }));
    // The spec was unwrapped from `.spec` (t48 crash-fix): rule pack carried through, id derived.
    const id = (await screen.findByLabelText('Identificador')) as HTMLInputElement;
    expect(id.value).toBe('user-csc-ata-ag/v1');
    expect((screen.getByLabelText('Pacote de regras') as HTMLInputElement).value).toBe(
      'csc-art63/v2',
    );
    // The honest limit is stated before any work, not at the seal.
    expect(screen.getByText('Os modelos incluídos não se editam')).toBeTruthy();
    expect(screen.getByText('Uma cópia ainda não produz documentos')).toBeTruthy();
    expect(screen.getByText('Modelo de origem: csc-ata-ag/v1')).toBeTruthy();
  });

  it('saves a fork as a NEW user template carrying the source body — never a PUT', async () => {
    const { fn, calls } = stubFetch([BUILTIN]);
    vi.stubGlobal('fetch', fn);

    renderCreate('?fork=csc-ata-ag%2Fv1');

    await screen.findByLabelText('corpo-markdown');
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => expect(writePosts(calls)).toHaveLength(1));
    const post = writePosts(calls)[0];
    expect(String(post.body)).toContain('user-csc-ata-ag/v1');
    expect(String(post.body)).toContain('Texto do corpo.');
    expect(calls.some((c) => c.method === 'PUT')).toBe(false);
  });

  it('hints when the seeded template places no narrative-body anchor, and not when it does', async () => {
    const { fn } = stubFetch([BUILTIN]);
    vi.stubGlobal('fetch', fn);

    // SOURCE_BUNDLE's spec has no `NarrativeBody` block.
    const withoutAnchor = renderCreate('?fork=csc-ata-ag%2Fv1');
    expect(await screen.findByText('O corpo não será incluído no documento')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Adicionar posição do corpo' }));
    await waitFor(() =>
      expect(screen.queryByText('O corpo não será incluído no documento')).toBeNull(),
    );
    const structure = await openPropertiesStructure();
    fireEvent.click(within(structure).getByText('JSON avançado'));
    expect(
      JSON.parse((screen.getByLabelText('JSON avançado') as HTMLTextAreaElement).value),
    ).toContainEqual({ kind: 'NarrativeBody' });
    withoutAnchor.unmount();
    cleanup();

    const anchored = {
      ...SOURCE_BUNDLE,
      spec: {
        ...SOURCE_BUNDLE.spec,
        blocks: [...SOURCE_BUNDLE.spec.blocks, { kind: 'NarrativeBody' }],
      },
    };
    const { fn: fn2 } = stubFetch([BUILTIN], { exportBody: anchored });
    vi.stubGlobal('fetch', fn2);

    renderCreate('?fork=csc-ata-ag%2Fv1');
    await screen.findByLabelText('corpo-markdown');
    expect(screen.queryByText('O corpo não será incluído no documento')).toBeNull();
  });

  it('mounts one honest preview at a time and exposes the exact markdown source with Copy', async () => {
    const { fn } = stubFetch([], {
      previewBlocks: [{ type: 'Heading', level: 2, text: 'Ata n.º {{ ata_number }}' }],
    });
    vi.stubGlobal('fetch', fn);

    renderCreate();

    expect(await screen.findByText('Pré-visualização do modelo')).toBeTruthy();
    fireEvent.change(await screen.findByLabelText('corpo-markdown'), {
      target: { value: '## Ata\n\nTexto {{ literal }}.' },
    });

    const tabs = screen.getByRole('tablist', { name: 'Formato da pré-visualização' });
    expect(within(tabs).getByRole('tab', { name: 'PDF' }).getAttribute('aria-selected')).toBe(
      'true',
    );
    expect(screen.getAllByRole('tabpanel')).toHaveLength(1);
    const pdf = screen.getByTestId('real-template-pdf-preview');
    expect(pdf.textContent).toBe('Pré-visualização PDF/A estrutural');
    expect(pdf.getAttribute('data-body-markdown')).toBe('## Ata\n\nTexto {{ literal }}.');
    expect(screen.queryByRole('article')).toBeNull();
    expect(screen.queryByText('Ata n.º {{ ata_number }}')).toBeNull();

    fireEvent.click(within(tabs).getByRole('tab', { name: 'Markdown' }));
    expect(screen.getAllByRole('tabpanel')).toHaveLength(1);
    expect(screen.queryByTestId('real-template-pdf-preview')).toBeNull();
    const source = screen.getByLabelText('Origem body_markdown');
    expect(source.textContent).toBe('## Ata\n\nTexto {{ literal }}.');
    expect(screen.getByText(/exatamente a origem body_markdown guardada/)).toBeTruthy();

    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
    fireEvent.click(screen.getByRole('button', { name: 'Copiar Markdown' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('## Ata\n\nTexto {{ literal }}.'));
    expect(screen.getByRole('button', { name: 'Markdown copiado' })).toBeTruthy();
  });

  it('keeps all structured variants under Properties while Content remains body-only', async () => {
    const blocks: TemplateBlockSpec[] = [
      { kind: 'Heading', level: 1, template: 'Título inicial' },
      { kind: 'Paragraph', items: 'agenda_items', template: 'Ponto {{ item.text }}' },
      {
        kind: 'KeyValue',
        items: 'entity',
        rows: [{ key: 'Entidade', value: '{{ entity.name }}' }],
      },
      { kind: 'NarrativeBody' },
      {
        kind: 'VoteTable',
        items: 'deliberation_items',
        label: '{{ item.text }}',
        vote_field: 'vote',
        unanimous_total: '{{ members_present }}',
      },
      { kind: 'Rule' },
      { kind: 'PageBreak' },
      {
        kind: 'SignatureBlock',
        source: 'signatories',
        role: '{{ capacity }}',
        name: '{{ name }}',
      },
    ];
    const { fn } = stubFetch([], {
      previewBlocks: [
        {
          type: 'Heading',
          level: 2,
          text: 'Corpo compilado {{ meeting_date }}',
        },
      ],
    });
    vi.stubGlobal('fetch', fn);

    renderCreate();

    expect(await screen.findByLabelText('corpo-markdown')).toBeTruthy();
    expect(screen.queryByText('Bloco 1')).toBeNull();

    const structure = await openPropertiesStructure();
    const rawDisclosure = within(structure).getByText('JSON avançado').closest('details');
    if (!rawDisclosure) throw new Error('advanced JSON disclosure missing');
    fireEvent.click(within(rawDisclosure).getByText('JSON avançado'));
    fireEvent.change(screen.getByLabelText('JSON avançado'), {
      target: { value: JSON.stringify(blocks, null, 2) },
    });

    const firstBlock = screen.getByText('Bloco 1').closest('details');
    const thirdBlock = screen.getByText('Bloco 3').closest('details');
    if (!firstBlock || !thirdBlock) throw new Error('structured block controls missing');
    fireEvent.change(within(firstBlock).getByLabelText('Texto do modelo'), {
      target: { value: 'Título editado' },
    });
    fireEvent.click(within(thirdBlock).getByText('Bloco 3'));
    fireEvent.change(within(thirdBlock).getByLabelText('Rótulo 1'), {
      target: { value: 'Entidade atualizada' },
    });

    const persisted = JSON.parse(
      (screen.getByLabelText('JSON avançado') as HTMLTextAreaElement).value,
    ) as TemplateBlockSpec[];
    expect(persisted.map((block) => block.kind)).toEqual([
      'Heading',
      'Paragraph',
      'KeyValue',
      'NarrativeBody',
      'VoteTable',
      'Rule',
      'PageBreak',
      'SignatureBlock',
    ]);
    expect(persisted[0]).toMatchObject({ template: 'Título editado' });
    expect(persisted[2]).toMatchObject({
      rows: [{ key: 'Entidade atualizada', value: '{{ entity.name }}' }],
    });

    openContent();
    fireEvent.change(screen.getByLabelText('corpo-markdown'), {
      target: { value: '## Corpo compilado' },
    });
    fireEvent.click(screen.getByRole('tab', { name: 'Markdown' }));
    expect(screen.getByLabelText('Origem body_markdown').textContent).toBe('## Corpo compilado');
    expect(document.querySelector('[data-template-authored-preview]')).toBeNull();
  });
});
