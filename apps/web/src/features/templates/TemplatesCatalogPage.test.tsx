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
    locale: 'pt-PT',
  },
  {
    id: 'csc-certidao-ata/v1',
    family: 'CommercialCompany',
    stage: 'Certidao',
    channels: [],
    signature_policy: 'QualifiedPreferred',
    rule_pack_id: 'csc-art63/v2',
    locale: 'pt-PT',
  },
  {
    id: 'assoc-convocatoria-ga/v1',
    family: 'Association',
    stage: 'Convocatoria',
    channels: [],
    signature_policy: 'ManualAttested',
    rule_pack_id: 'assoc-cc/v1',
    locale: 'pt-PT',
  },
  {
    id: 'condominio-lista-presencas/v1',
    family: 'Condominium',
    stage: 'Reuniao',
    channels: ['Physical', 'Hybrid', 'Telematic'],
    signature_policy: 'QualifiedOrHandwritten',
    rule_pack_id: 'condominio-dl268/v1',
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
    locale: 'pt-PT',
  },
  {
    id: 'assoc-convocatoria-ga/en',
    family: 'Association',
    stage: 'Convocatoria',
    channels: ['Telematic'],
    signature_policy: 'ManualAttested',
    rule_pack_id: 'assoc-cc/v1',
    locale: 'en-US',
  },
  {
    id: 'fundacao-reuniao/v1',
    family: 'Foundation',
    stage: 'Reuniao',
    channels: ['Hybrid'],
    signature_policy: 'ManualAttested',
    rule_pack_id: 'fundacao-cc/v1',
    locale: 'pt-PT',
  },
];

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('TemplatesCatalogPage', () => {
  it('browses the existing template catalog and points generation back to acts', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/templates', body: CATALOG }]));

    renderWithProviders(<TemplatesCatalogPage />, ['/minutas']);

    const filters = screen.getByRole('group', { name: 'Pesquisar e filtrar' });
    const clearFilters = within(filters).getByRole('button', {
      name: 'Limpar pesquisa e filtros',
    }) as HTMLButtonElement;
    expect(within(filters).getByLabelText('Pesquisa')).toBeTruthy();
    expect(clearFilters.disabled).toBe(true);

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

    renderWithProviders(<TemplatesCatalogPage />, ['/minutas']);

    expect(await screen.findByText('assoc-convocatoria-ga/pt')).toBeTruthy();

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
});
