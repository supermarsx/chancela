import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, within } from '@testing-library/react';
import { TemplatesCatalogPage } from './TemplatesCatalogPage';
import { fetchTable, renderWithProviders } from '../../test/utils';
import type { TemplateSummary } from '../../api/types';

const CATALOG: TemplateSummary[] = [
  {
    id: 'csc-ata-ag/v1',
    family: 'CommercialCompany',
    stage: 'Ata',
    channels: ['Physical', 'Hybrid', 'Telematic', 'WrittenResolution'],
    signature_policy: 'QualifiedPreferred',
    rule_pack_id: 'csc-art63/v2',
    law_references: [],
    locale: 'pt-PT',
  },
  {
    id: 'csc-certidao-ata/v1',
    family: 'CommercialCompany',
    stage: 'Certidao',
    channels: [],
    signature_policy: 'QualifiedPreferred',
    rule_pack_id: 'csc-art63/v2',
    law_references: [],
    locale: 'pt-PT',
  },
  {
    id: 'assoc-convocatoria-ga/v1',
    family: 'Association',
    stage: 'Convocatoria',
    channels: [],
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
  },
  {
    id: 'condominio-lista-presencas/v1',
    family: 'Condominium',
    stage: 'Reuniao',
    channels: ['Physical', 'Hybrid', 'Telematic'],
    signature_policy: 'QualifiedOrHandwritten',
    rule_pack_id: 'condominio-dl268/v1',
    law_references: [],
    locale: 'pt-PT',
  },
];

const EDGE_CATALOG: TemplateSummary[] = [
  {
    id: 'assoc-convocatoria-ga/pt',
    family: 'Association',
    stage: 'Convocatoria',
    channels: ['Physical'],
    signature_policy: 'ManualAttested',
    rule_pack_id: 'assoc-cc/v1',
    law_references: [],
    locale: 'pt-PT',
  },
  {
    id: 'assoc-convocatoria-ga/en',
    family: 'Association',
    stage: 'Convocatoria',
    channels: ['Telematic'],
    signature_policy: 'ManualAttested',
    rule_pack_id: 'assoc-cc/v1',
    law_references: [],
    locale: 'en-US',
  },
  {
    id: 'fundacao-reuniao/v1',
    family: 'Foundation',
    stage: 'Reuniao',
    channels: ['Hybrid'],
    signature_policy: 'ManualAttested',
    rule_pack_id: 'fundacao-cc/v1',
    law_references: [],
    locale: 'pt-PT',
  },
];

async function themeCss(): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8');
}

function expectCssRule(css: string, selector: RegExp, declarations: string[]) {
  const match = css.match(selector);
  expect(match?.[1]).toBeTruthy();
  const body = match?.[1] ?? '';
  for (const declaration of declarations) {
    expect(body).toContain(declaration);
  }
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('TemplatesCatalogPage', () => {
  it('browses the existing template catalog and points generation back to acts', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/templates', body: CATALOG }]));

    const { container } = renderWithProviders(<TemplatesCatalogPage />, ['/minutas']);

    const filters = screen.getByRole('search', { name: 'Pesquisar e filtrar' });
    expect(filters.classList.contains('templates-filters')).toBe(true);
    const primary = filters.querySelector('.templates-filterbar__primary') as HTMLElement;
    expect(primary).toBeTruthy();
    expect(primary.querySelectorAll('.field')).toHaveLength(3);
    expect(within(primary).getByLabelText('Pesquisa')).toBeTruthy();
    expect(within(primary).getByLabelText('Família da entidade')).toBeTruthy();
    expect(within(primary).getByLabelText('Fase da minuta')).toBeTruthy();
    const advanced = container.querySelector(
      'details.templates-advanced-filters.filter-advanced',
    ) as HTMLDetailsElement;
    expect(advanced).toBeTruthy();
    expect(advanced.open).toBe(false);
    const advancedBody = advanced.querySelector(
      '.templates-advanced-filters__body.filter-advanced__body',
    );
    expect(advancedBody).toBeTruthy();
    expect(advancedBody?.querySelectorAll('.field')).toHaveLength(4);
    const clearFilters = within(filters).getByRole('button', {
      name: 'Limpar pesquisa e filtros',
    }) as HTMLButtonElement;
    expect(clearFilters.disabled).toBe(true);
    expect(clearFilters.className).toContain('btn--iconOnly');
    expect(clearFilters.textContent?.trim()).toBe('');
    expect(
      document.getElementById(clearFilters.getAttribute('aria-describedby') ?? '')?.textContent,
    ).toBe('Limpar pesquisa e filtros');

    fireEvent.click(within(advanced).getByText('Filtros avançados'));
    expect(advanced.open).toBe(true);
    expect(within(advanced).getByLabelText('Idioma do modelo')).toBeTruthy();
    expect(within(advanced).getByLabelText('Canal do modelo')).toBeTruthy();
    expect(within(advanced).getByLabelText('Política de assinatura')).toBeTruthy();
    expect(within(advanced).getByLabelText('Pacote de regras')).toBeTruthy();

    const ataId = await screen.findByText('csc-ata-ag/v1');
    const ataCard = ataId.closest('article');
    expect(ataCard).toBeTruthy();
    expect(
      within(ataCard as HTMLElement).getByText('Assinatura qualificada preferencial'),
    ).toBeTruthy();
    expect(within(ataCard as HTMLElement).getByText('csc-art63/v2')).toBeTruthy();
    expect(within(ataCard as HTMLElement).getByText('Deliberação por escrito')).toBeTruthy();
    expect(screen.getByText('4 de 4 modelos')).toBeTruthy();
    expect(screen.getAllByRole('link', { name: 'Escolher ata' })[0].getAttribute('href')).toBe(
      '/livros',
    );
    expect(screen.queryByRole('button', { name: /gerar/i })).toBeNull();

    fireEvent.change(screen.getByLabelText('Pesquisa'), {
      target: { value: ' CERTIDÃO ' },
    });
    expect(clearFilters.disabled).toBe(false);
    expect(await screen.findByText('csc-certidao-ata/v1')).toBeTruthy();
    expect(screen.queryByText('csc-ata-ag/v1')).toBeNull();
    expect(screen.getByText('1 de 4 modelos')).toBeTruthy();
    expect(screen.getByText('Sem canal específico')).toBeTruthy();

    fireEvent.click(clearFilters);
    expect(await screen.findByText('csc-ata-ag/v1')).toBeTruthy();
    expect(clearFilters.disabled).toBe(true);

    fireEvent.change(screen.getByLabelText('Canal do modelo'), {
      target: { value: 'Telematic' },
    });
    expect(screen.getByText('2 de 4 modelos')).toBeTruthy();
    expect(screen.getByText('csc-ata-ag/v1')).toBeTruthy();
    expect(screen.getByText('condominio-lista-presencas/v1')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Política de assinatura'), {
      target: { value: 'QualifiedOrHandwritten' },
    });
    expect(screen.getByText('1 de 4 modelos')).toBeTruthy();
    const condoCard = screen.getByText('condominio-lista-presencas/v1').closest('article');
    expect(condoCard).toBeTruthy();
    expect(within(condoCard as HTMLElement).getByText('Qualificada ou manuscrita')).toBeTruthy();

    fireEvent.click(clearFilters);
    expect(await screen.findByText('csc-ata-ag/v1')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Família da entidade'), {
      target: { value: 'Association' },
    });
    const associationCard = await screen.findByText('assoc-convocatoria-ga/v1');
    expect(associationCard).toBeTruthy();
    expect(screen.queryByText('condominio-lista-presencas/v1')).toBeNull();

    fireEvent.change(screen.getByLabelText('Fase da minuta'), {
      target: { value: 'Convocatoria' },
    });
    const catalog = screen.getByRole('region', { name: 'Catálogo de minutas' });
    expect(within(catalog).getByText('assoc-convocatoria-ga/v1')).toBeTruthy();
    expect(within(catalog).getByText('Convocatória')).toBeTruthy();
  });

  it('combines folded search, locale filters, empty state and clear without stale results', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/templates', body: EDGE_CATALOG }]));

    const { container } = renderWithProviders(<TemplatesCatalogPage />, ['/minutas']);
    const advanced = container.querySelector(
      'details.templates-advanced-filters',
    ) as HTMLDetailsElement;

    expect(await screen.findByText('assoc-convocatoria-ga/pt')).toBeTruthy();
    expect(advanced.open).toBe(false);
    fireEvent.click(within(advanced).getByText('Filtros avançados'));
    expect(advanced.open).toBe(true);

    fireEvent.change(screen.getByLabelText('Pesquisa'), {
      target: { value: 'CONVOCATÓRIA' },
    });
    expect(screen.getByText('2 de 3 modelos')).toBeTruthy();
    expect(screen.getByText('assoc-convocatoria-ga/pt')).toBeTruthy();
    expect(screen.getByText('assoc-convocatoria-ga/en')).toBeTruthy();
    expect(screen.queryByText('fundacao-reuniao/v1')).toBeNull();

    fireEvent.change(screen.getByLabelText('Pacote de regras'), {
      target: { value: 'assoc-cc/v1' },
    });
    expect(screen.getByText('2 de 3 modelos')).toBeTruthy();
    expect(screen.queryByText('fundacao-reuniao/v1')).toBeNull();

    fireEvent.change(screen.getByLabelText('Idioma do modelo'), { target: { value: 'en-US' } });
    expect(screen.getByText('1 de 3 modelos')).toBeTruthy();
    expect(screen.getByText('assoc-convocatoria-ga/en')).toBeTruthy();
    expect(screen.queryByText('assoc-convocatoria-ga/pt')).toBeNull();

    fireEvent.change(screen.getByLabelText('Pesquisa'), {
      target: { value: 'sem resultado' },
    });
    expect(await screen.findByText('Sem modelos encontrados')).toBeTruthy();
    expect(screen.getByText('0 de 3 modelos')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Limpar pesquisa e filtros' }));
    expect(await screen.findByText('fundacao-reuniao/v1')).toBeTruthy();
    expect(screen.getByText('3 de 3 modelos')).toBeTruthy();
  });

  it('keeps templates filters compact, collapsible, and overflow-safe in CSS', async () => {
    const css = await themeCss();

    expectCssRule(css, /\.templates-filters\s*\{([^}]*)\}/, [
      'min-width: 0;',
      'max-width: 100%;',
      'overflow-x: clip;',
    ]);
    expectCssRule(css, /\.templates-filterbar\s*\{([^}]*)\}/, [
      'max-width: 100%;',
      'overflow-x: clip;',
    ]);
    expectCssRule(css, /\.templates-controls__primary\s*\{([^}]*)\}/, [
      'display: flex;',
      'flex-wrap: wrap;',
      'max-width: 100%;',
    ]);
    expectCssRule(css, /\.templates-controls__search\s*\{([^}]*)\}/, [
      'min-width: min(100%, 16rem);',
      'max-width: 100%;',
    ]);
    expectCssRule(css, /\.templates-controls__primary > \.field\s*\{([^}]*)\}/, [
      'min-width: min(100%, 11rem);',
      'max-width: 100%;',
    ]);
    expectCssRule(css, /\.templates-controls__advanced\s*\{([^}]*)\}/, [
      'max-width: 100%;',
      'overflow-x: clip;',
    ]);
    expectCssRule(css, /\.templates-controls__filters\s*\{([^}]*)\}/, [
      'display: grid;',
      'grid-template-columns: repeat(auto-fit, minmax(min(100%, 12rem), 1fr));',
      'min-width: 0;',
      'max-width: 100%;',
    ]);
    expectCssRule(css, /\.templates-controls__actions \.btn\s*\{([^}]*)\}/, [
      'max-width: 100%;',
      'overflow: hidden;',
      'white-space: nowrap;',
    ]);
  });

  it('renders pending law references and searches by citation or article text', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/templates', body: CATALOG }]));

    renderWithProviders(<TemplatesCatalogPage />, ['/minutas']);

    const associationId = await screen.findByText('assoc-convocatoria-ga/v1');
    const associationCard = associationId.closest('article');
    expect(associationCard).toBeTruthy();
    expect(within(associationCard as HTMLElement).getByText('Fonte legal')).toBeTruthy();
    expect(within(associationCard as HTMLElement).getByText('Por verificar')).toBeTruthy();
    expect(within(associationCard as HTMLElement).getByText('CC arts. 173.º e 175.º')).toBeTruthy();
    expect(
      within(associationCard as HTMLElement).getByText('Fonte: Código Civil · art. 175'),
    ).toBeTruthy();
    expect(
      within(associationCard as HTMLElement).getByText('Fonte pendente; não usar como verificada.'),
    ).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Pesquisa'), {
      target: { value: '175' },
    });
    expect(screen.getByText('1 de 4 modelos')).toBeTruthy();
    expect(screen.getByText('assoc-convocatoria-ga/v1')).toBeTruthy();
    expect(screen.queryByText('csc-ata-ag/v1')).toBeNull();

    fireEvent.change(screen.getByLabelText('Pesquisa'), {
      target: { value: 'CC ARTS. 173' },
    });
    expect(screen.getByText('1 de 4 modelos')).toBeTruthy();
    expect(screen.getByText('assoc-convocatoria-ga/v1')).toBeTruthy();
  });
});
