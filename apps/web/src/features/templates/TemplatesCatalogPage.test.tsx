import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, within } from '@testing-library/react';
import { TemplatesCatalogPage } from './TemplatesCatalogPage';
import { fetchTable, renderWithProviders } from '../../test/utils';
import type { TemplateSummary } from '../../api/types';

const CATALOG: TemplateSummary[] = [
  { id: 'csc-ata-ag/v1', family: 'CommercialCompany', stage: 'Ata', locale: 'pt-PT' },
  { id: 'csc-certidao-ata/v1', family: 'CommercialCompany', stage: 'Certidao', locale: 'pt-PT' },
  { id: 'assoc-convocatoria-ga/v1', family: 'Association', stage: 'Convocatoria', locale: 'pt-PT' },
  { id: 'condominio-lista-presencas/v1', family: 'Condominium', stage: 'Reuniao', locale: 'pt-PT' },
];

const EDGE_CATALOG: TemplateSummary[] = [
  {
    id: 'assoc-convocatoria-ga/pt',
    family: 'Association',
    stage: 'Convocatoria',
    locale: 'pt-PT',
  },
  {
    id: 'assoc-convocatoria-ga/en',
    family: 'Association',
    stage: 'Convocatoria',
    locale: 'en-US',
  },
  { id: 'fundacao-reuniao/v1', family: 'Foundation', stage: 'Reuniao', locale: 'pt-PT' },
];

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('TemplatesCatalogPage', () => {
  it('browses the existing template catalog and points generation back to acts', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/templates', body: CATALOG }]));

    renderWithProviders(<TemplatesCatalogPage />, ['/minutas']);

    expect(await screen.findByText('csc-ata-ag/v1')).toBeTruthy();
    expect(screen.getByText('4 de 4 modelos')).toBeTruthy();
    expect(screen.getAllByRole('link', { name: 'Escolher ata' })[0].getAttribute('href')).toBe(
      '/livros',
    );
    expect(screen.queryByRole('button', { name: /gerar/i })).toBeNull();

    fireEvent.change(screen.getByLabelText('Pesquisa'), {
      target: { value: ' CERTIDÃO ' },
    });
    expect(await screen.findByText('csc-certidao-ata/v1')).toBeTruthy();
    expect(screen.queryByText('csc-ata-ag/v1')).toBeNull();
    expect(screen.getByText('1 de 4 modelos')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Limpar pesquisa e filtros' }));
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
