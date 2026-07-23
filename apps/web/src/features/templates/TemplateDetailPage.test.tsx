/**
 * The template detail page, and the two helpers that give it its content.
 *
 * What is worth pinning here is not the layout but the three rulings the page encodes:
 *  - a template id containing a slash still resolves through the encoded route param;
 *  - the legal source, hidden from the catalog table by default, is present IN FULL here —
 *    that is the whole justification for hiding the column;
 *  - a `user-…` template says, on its own page, that it cannot yet produce a sealed
 *    document. The dialog that created it says so too, but an operator returning to the copy
 *    a week later never saw that dialog.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { TemplateDetailPage } from './TemplateDetailPage';
import { forkedTemplateId, templateIdBase, templateIdVersion } from './templateFork';
import { templatePlaceholders } from './templatePlaceholders';
import {
  DEFAULT_TEMPLATE_COLUMNS,
  loadTemplateColumns,
  normalizeTemplateColumns,
  saveTemplateColumns,
} from './templateColumns';
import { renderWithProviders } from '../../test/utils';
import type { TemplateSummary } from '../../api/types';

const BUILTIN: TemplateSummary = {
  id: 'assoc-convocatoria-ga/v1',
  family: 'Association',
  stage: 'Convocatoria',
  channels: ['Physical'],
  signature_policy: 'ManualAttested',
  rule_pack_id: 'assoc-cc/v1',
  law_references: [
    {
      source_id: 'cc',
      source_label: 'Código Civil',
      article: '175',
      citation: 'CC arts. 173.º e 175.º',
      source: 'ThresholdRegistry',
      verification: 'Pending',
      threshold_id: 'assoc.convocatoria_maioria',
    },
  ],
  locale: 'pt-PT',
  editable: false,
  source: 'builtin',
};

const USER: TemplateSummary = { ...BUILTIN, id: 'user-encosto/v1', editable: true, source: 'user' };

const SPEC = {
  id: BUILTIN.id,
  family: BUILTIN.family,
  stage: BUILTIN.stage,
  channels: BUILTIN.channels,
  signature_policy: BUILTIN.signature_policy,
  rule_pack_id: BUILTIN.rule_pack_id,
  locale: BUILTIN.locale,
  blocks: [
    { kind: 'Heading', level: 1, template: 'Convocatória de {{ entity.name }}' },
    {
      kind: 'KeyValue',
      rows: [{ key: 'Data', value: '{{ meeting_date | long_date }}' }],
    },
    {
      kind: 'Paragraph',
      items: 'agenda_items',
      template: '{% for item in agenda_items %}{{ item.text }}{% endfor %}',
    },
    { kind: 'NarrativeBody' },
  ],
};

function stub(catalog: TemplateSummary[]) {
  return ((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.includes('/export')) {
      return Promise.resolve(
        new Response(JSON.stringify(SPEC), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }
    if (url.includes('/v1/templates')) {
      return Promise.resolve(
        new Response(JSON.stringify(catalog), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
}

interface PreviewRequest {
  url: string;
  method: string;
  body?: BodyInit | null;
}

/**
 * Serve a real export bundle and let each test control the stateless body-compiler response.
 * The recorded request proves the detail preview compiles the stored `body_markdown`, not a
 * client-side reconstruction of the authored prose.
 */
function previewStub(bodyMarkdown: string, reply: () => Promise<Response>) {
  const calls: PreviewRequest[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    calls.push({ url, method, body: init?.body });
    if (url.includes('/v1/templates/body/preview')) return reply();
    if (url.includes('/export')) {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            format: 'chancela.template-bundle',
            format_version: 1,
            spec: SPEC,
            body_markdown: bodyMarkdown,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );
    }
    if (url.includes('/v1/templates')) {
      return Promise.resolve(
        new Response(JSON.stringify([BUILTIN]), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }
    return Promise.reject(new Error(`no stub for ${method} ${url}`));
  }) as typeof fetch;
  return { fn, calls };
}

function renderDetail(id: string, section = '') {
  return renderWithProviders(
    <Routes>
      <Route path="/templates/:id/:sec?" element={<TemplateDetailPage />} />
    </Routes>,
    [`/templates/${encodeURIComponent(id)}${section ? `/${section}` : ''}`],
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  window.localStorage.clear();
});

describe('TemplateDetailPage', () => {
  it('resolves a slashed id from the encoded route and shows what the template is', async () => {
    vi.stubGlobal('fetch', stub([BUILTIN]));

    renderDetail(BUILTIN.id);

    expect(await screen.findByText('Convocatória — Assembleia Geral')).toBeTruthy();
    // Identification is the default section and carries no `sec` param.
    const overview = document.querySelector('.panel') as HTMLElement;
    expect(within(overview).getByText('assoc-convocatoria-ga')).toBeTruthy();
    expect(within(overview).getByText('v1')).toBeTruthy();
    expect(within(overview).getByText('Associação')).toBeTruthy();
    expect(within(overview).getByText('assoc-cc/v1')).toBeTruthy();
    expect(within(overview).getByText('Incluído (só leitura)')).toBeTruthy();
  });

  it('carries the legal source in full — the column the catalog hides by default', async () => {
    vi.stubGlobal('fetch', stub([BUILTIN]));

    renderDetail(BUILTIN.id);
    await screen.findByText('Convocatória — Assembleia Geral');

    const source = screen.getByRole('button', { name: 'Fonte legal' });
    source.click();

    expect(await screen.findByText('CC arts. 173.º e 175.º')).toBeTruthy();
    expect(screen.getByText('Por verificar')).toBeTruthy();
    expect(screen.getByText('Fonte pendente; não usar como verificada.')).toBeTruthy();
  });

  it('lists the blocks and the record fields they read', async () => {
    vi.stubGlobal('fetch', stub([BUILTIN]));

    renderDetail(BUILTIN.id);
    await screen.findByText('Convocatória — Assembleia Geral');

    screen.getByRole('button', { name: 'Blocos' }).click();
    expect(await screen.findByText('KeyValue')).toBeTruthy();
    expect(screen.getByText('Convocatória de {{ entity.name }}')).toBeTruthy();

    screen.getByRole('button', { name: 'Campos esperados' }).click();
    expect(await screen.findByText('entity.name')).toBeTruthy();
    expect(screen.getByText('meeting_date')).toBeTruthy();
    expect(screen.getByText('agenda_items')).toBeTruthy();
    // `item` is the loop variable, not an input the operator supplies.
    expect(screen.queryByText('item.text')).toBeNull();
  });

  it('compiles the narrative with a labelled, navigable preview and no duplicate native page h1', async () => {
    const bodyMarkdown =
      '# Corpo de {{ entity.name }}\n\nTexto para **{{ meeting_date | long_date }}**.';
    const { fn, calls } = previewStub(bodyMarkdown, () =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            compiler_id: 'md-block/v1',
            blocks: [
              { type: 'Heading', level: 1, text: 'Corpo de {{ entity.name }}' },
              {
                type: 'Paragraph',
                runs: [
                  { text: 'Texto para ', bold: false, italic: false },
                  {
                    text: '{{ meeting_date | long_date }}',
                    bold: true,
                    italic: false,
                  },
                  { text: '.', bold: false, italic: false },
                ],
              },
            ],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    );
    vi.stubGlobal('fetch', fn);

    renderDetail(BUILTIN.id, 'preview');

    expect(await screen.findByText('Pré-visualização do modelo')).toBeTruthy();
    expect(
      screen.getByText(
        'Esta leitura mostra a estrutura escrita no modelo. Os campos substituíveis permanecem visíveis tal como foram escritos e só recebem dados quando uma ata é gerada.',
      ),
    ).toBeTruthy();
    const previewHeading = await screen.findByText('Convocatória de {{ entity.name }}');
    const preview = previewHeading.closest('.doc-preview') as HTMLElement;
    expect(preview).toBeTruthy();
    expect(previewHeading).toBeTruthy();
    const previewTitle = within(preview).getByRole('heading', {
      name: 'Convocatória — Assembleia Geral',
      level: 2,
    });
    expect(preview.getAttribute('aria-labelledby')).toBe(previewTitle.id);
    expect(
      within(preview).getByRole('heading', {
        name: 'Convocatória de {{ entity.name }}',
        level: 3,
      }),
    ).toBe(previewHeading);
    expect(within(preview).getByText('agenda_items')).toBeTruthy();
    const narrative = preview.querySelector('[data-template-narrative]') as HTMLElement;
    const compiledHeading = await within(narrative).findByText('Corpo de {{ entity.name }}');
    expect(compiledHeading.getAttribute('data-heading-level')).toBe('1');
    expect(
      within(narrative).getByRole('heading', {
        name: 'Corpo de {{ entity.name }}',
        level: 3,
      }),
    ).toBe(compiledHeading);
    expect(within(narrative).getByText('{{ meeting_date | long_date }}')).toBeTruthy();

    const compile = calls.find((call) => call.url.includes('/v1/templates/body/preview'));
    expect(compile?.method).toBe('POST');
    expect(JSON.parse(String(compile?.body))).toEqual({ source: bodyMarkdown });

    // The app page retains one native PageHeader <h1>. The nested document stays visually faithful
    // without native page headings while its ARIA-only level-2/3 hierarchy remains navigable.
    expect(document.querySelectorAll('h1')).toHaveLength(1);
    expect(preview.querySelectorAll('h1, h2, h3, h4, h5, h6')).toHaveLength(0);
    expect(previewHeading.tagName).toBe('P');
    expect(compiledHeading.tagName).toBe('P');
  });

  it('announces narrative compilation while the server preview is pending', async () => {
    const { fn } = previewStub('Texto ainda a compilar.', () => new Promise<Response>(() => {}));
    vi.stubGlobal('fetch', fn);

    renderDetail(BUILTIN.id, 'preview');

    const narrative = await waitFor(() => {
      const node = document.querySelector('[data-template-narrative]');
      expect(node).toBeTruthy();
      return node as HTMLElement;
    });
    const status = within(narrative).getByRole('status');
    expect(status.getAttribute('aria-busy')).toBe('true');
    expect(within(status).getByText('A carregar…')).toBeTruthy();
  });

  it('announces a rejected narrative compile without implying that the template changed', async () => {
    const { fn } = previewStub('> citação não suportada', () =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            code: 'unsupported_markdown',
            message: 'Citação não suportada neste corpo.',
          }),
          { status: 422, headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    );
    vi.stubGlobal('fetch', fn);

    renderDetail(BUILTIN.id, 'preview');

    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('Não foi possível pré-visualizar o corpo')).toBeTruthy();
    expect(
      within(alert).getByText(
        'O compilador recusou o corpo guardado. O modelo não foi alterado; reveja o corpo no editor antes de o utilizar.',
      ),
    ).toBeTruthy();
    expect(within(alert).getByText('Citação não suportada neste corpo.')).toBeTruthy();
  });

  it('reads the blocks out of the t43 bundle envelope the export now returns', async () => {
    // Since t43-e3 `/export` emits `{ format, format_version, spec, body_markdown }` rather than a
    // bare spec; the page must read its blocks from the `spec` half, not from the envelope root.
    const bundleStub = ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/export')) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              format: 'chancela.template-bundle',
              format_version: 1,
              spec: SPEC,
              body_markdown: '## Convocatória\n\nTexto.',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          ),
        );
      }
      return Promise.resolve(
        new Response(JSON.stringify([BUILTIN]), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }) as typeof fetch;
    vi.stubGlobal('fetch', bundleStub);

    renderDetail(BUILTIN.id);
    await screen.findByText('Convocatória — Assembleia Geral');

    screen.getByRole('button', { name: 'Blocos' }).click();
    expect(await screen.findByText('KeyValue')).toBeTruthy();
    expect(screen.getByText('Convocatória de {{ entity.name }}')).toBeTruthy();

    screen.getByRole('button', { name: 'Campos esperados' }).click();
    expect(await screen.findByText('entity.name')).toBeTruthy();
  });

  it('warns on a user template that it cannot yet produce a sealed document', async () => {
    vi.stubGlobal('fetch', stub([USER]));

    renderDetail(USER.id);

    expect(await screen.findByText('Uma cópia ainda não produz documentos')).toBeTruthy();
  });

  it('does not carry that warning on a built-in, which does seal', async () => {
    vi.stubGlobal('fetch', stub([BUILTIN]));

    renderDetail(BUILTIN.id);
    await screen.findByText('Convocatória — Assembleia Geral');

    expect(screen.queryByText('Uma cópia ainda não produz documentos')).toBeNull();
  });

  it('answers an unknown id with a dead end that leads back, not with a blank page', async () => {
    vi.stubGlobal('fetch', stub([BUILTIN]));

    renderDetail('nao-existe/v9');

    expect(await screen.findByText('nao-existe/v9')).toBeTruthy();
    expect(screen.getByText('Modelo não encontrado')).toBeTruthy();
    expect(screen.getAllByRole('link', { name: 'Minutas' })[0].getAttribute('href')).toBe(
      '/templates',
    );
  });
});

describe('templatePlaceholders', () => {
  it('reports the fields a template reads, without filters, literals or loop variables', () => {
    expect(templatePlaceholders(SPEC as never)).toEqual([
      'agenda_items',
      'entity.name',
      'meeting_date',
    ]);
  });

  it('keeps a defaulted value and drops the default itself', () => {
    const spec = {
      blocks: [
        { kind: 'Heading', level: 2, template: '{{ title | default("Ata") }}' },
        { kind: 'Paragraph', template: '{% if convening_waiver %}sem convocatória{% endif %}' },
      ],
    };
    expect(templatePlaceholders(spec as never)).toEqual(['convening_waiver', 'title']);
  });
});

describe('templateFork', () => {
  it('splits an id into its base and version', () => {
    expect(templateIdBase('assoc-ata-direcao/v1')).toBe('assoc-ata-direcao');
    expect(templateIdVersion('assoc-ata-direcao/v1')).toBe('v1');
    expect(templateIdVersion('sem-versao')).toBe('');
  });

  it('derives a free id in the user namespace that the server would accept', () => {
    expect(forkedTemplateId('assoc-ata-direcao/v1')).toBe('user-assoc-ata-direcao/v1');
    // Forking the copy does not stack `user-user-`, and never collides with what exists.
    expect(forkedTemplateId('user-assoc-ata-direcao/v1', ['user-assoc-ata-direcao/v1'])).toBe(
      'user-assoc-ata-direcao-2/v1',
    );
    expect(
      forkedTemplateId('assoc-ata-direcao/v1', [
        'user-assoc-ata-direcao/v1',
        'user-assoc-ata-direcao-2/v1',
      ]),
    ).toBe('user-assoc-ata-direcao-3/v1');
    // Every id it produces matches the server's own rule.
    expect(forkedTemplateId('Condomínio — Ata/v2')).toMatch(/^user-[a-z0-9-]+\/v[0-9]+$/);
  });
});

describe('templateColumns', () => {
  it('hides the legal source by default and keeps every other column', () => {
    expect(DEFAULT_TEMPLATE_COLUMNS).not.toContain('LawSource');
    expect(DEFAULT_TEMPLATE_COLUMNS).toContain('Origin');
  });

  it('drops unknown ids, collapses duplicates and forces the table order', () => {
    expect(normalizeTemplateColumns(['Origin', 'nope', 'Family', 'Family'])).toEqual([
      'Family',
      'Origin',
    ]);
    // An empty selection is a legitimate choice; only a non-array falls back.
    expect(normalizeTemplateColumns([])).toEqual([]);
    expect(normalizeTemplateColumns(null)).toEqual([...DEFAULT_TEMPLATE_COLUMNS]);
  });

  it('round-trips through storage and survives a corrupt value', () => {
    saveTemplateColumns(['LawSource', 'Stage']);
    expect(loadTemplateColumns()).toEqual(['Stage', 'LawSource']);
    window.localStorage.setItem('chancela.minutas.columns', '{not json');
    expect(loadTemplateColumns()).toEqual([...DEFAULT_TEMPLATE_COLUMNS]);
  });
});
