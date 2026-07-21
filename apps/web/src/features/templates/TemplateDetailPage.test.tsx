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
import { cleanup, screen, within } from '@testing-library/react';
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

function renderDetail(id: string) {
  return renderWithProviders(
    <Routes>
      <Route path="/templates/:id/:sec?" element={<TemplateDetailPage />} />
    </Routes>,
    [`/templates/${encodeURIComponent(id)}`],
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
