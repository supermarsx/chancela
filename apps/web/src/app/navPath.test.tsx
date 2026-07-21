/**
 * The three parts of the addressing work, guarded together because they only hold as a set:
 * sections live in the PATH (t97), slugs are ENGLISH (t97b), and every pre-existing Portuguese
 * or query-string address still resolves to the current one. A half-converted scheme is worse
 * than either scheme alone, because two addressing systems coexist and neither is trustworthy.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import {
  Outlet,
  RouterProvider,
  createMemoryRouter,
  useLocation,
  useNavigationType,
} from 'react-router-dom';
import { LegacyNavRedirect } from './LegacyNavRedirect';
import { LegacySlugRedirect } from './LegacySlugRedirect';
import { translateLegacyAddress } from './legacySlugs';
import { pageKey, pathSegments, useSectionNav } from './navPath';

afterEach(cleanup);

/** Reports the live address and how we got there, so push-vs-replace is assertable. */
function Probe() {
  const { pathname, search, hash } = useLocation();
  return (
    <>
      <span data-testid="href">{`${pathname}${search}${hash}`}</span>
      <span data-testid="navtype">{useNavigationType()}</span>
      <Outlet />
    </>
  );
}

type Sec = 'register' | 'export';

function Sections({ base }: { base: string }) {
  const { section, select } = useSectionNav<Sec>({
    base,
    parse: (raw) => (raw === 'export' ? 'export' : 'register'),
    fallback: 'register',
  });
  return (
    <>
      <span data-testid="section">{section}</span>
      <button type="button" onClick={() => select('export')}>
        export
      </button>
      <button type="button" onClick={() => select('register')}>
        register
      </button>
    </>
  );
}

/** A record page: the base carries an id, so it is sliced off the RAW pathname. */
function RecordSections() {
  const { section, select } = useSectionNav<'identification' | 'source'>({
    depth: 2,
    parse: (raw) => (raw === 'source' ? 'source' : 'identification'),
    fallback: 'identification',
  });
  return (
    <>
      <span data-testid="section">{section}</span>
      <button type="button" onClick={() => select('source')}>
        source
      </button>
    </>
  );
}

function renderAt(
  entry: string,
  children: React.ReactNode,
  path: string,
  extra: { path: string; element: React.ReactNode }[] = [],
) {
  const router = createMemoryRouter(
    [{ path: '/', element: <Probe />, children: [{ path, element: children }, ...extra] }],
    { initialEntries: [entry] },
  );
  return render(<RouterProvider router={router} />);
}

const href = () => screen.getByTestId('href').textContent;

describe('pathSegments / pageKey', () => {
  it('keeps segments raw so an encoded slash is never split', () => {
    expect(pathSegments('/templates/csc-ata-ag%2Fv1/source')).toEqual([
      'templates',
      'csc-ata-ag%2Fv1',
      'source',
    ]);
  });

  it('disagrees with a raw pathname comparison exactly where the guard used to be wrong', () => {
    // The whole reason the unsaved-changes guard cannot compare pathnames any more: these two
    // addresses are the same PAGE (a sub-tab switch) but not the same string, so a pathname
    // comparison would have prompted an operator to confirm discarding work for clicking a tab.
    const a: string = '/settings/operations';
    const b: string = '/settings/operations/email';
    expect(a).not.toBe(b);
    expect(pageKey(a, 1)).toBe(pageKey(b, 1));
    // …while two records stay distinct, so relaxing the comparison does not disarm the guard.
    expect(pageKey('/entities/e1/registry', 2)).not.toBe(pageKey('/entities/e2/registry', 2));
  });

  it('cuts the section segments off the page key, and leaves unknown routes whole', () => {
    expect(pageKey('/settings/operations/email', 1)).toBe('/settings');
    expect(pageKey('/books/b1/opening', 2)).toBe('/books/b1');
    expect(pageKey('/dashboard/stats', 0)).toBe('/');
    expect(pageKey('/books/b1/new-act', undefined)).toBe('/books/b1/new-act');
  });
});

describe('useSectionNav', () => {
  it('derives the section from the path on first paint, with no switch', () => {
    renderAt('/archive/export', <Sections base="/archive" />, 'archive/:sec?');
    expect(screen.getByTestId('section').textContent).toBe('export');
  });

  it('falls back to the default for an unknown segment rather than blanking the panel', () => {
    renderAt('/archive/nao-existe', <Sections base="/archive" />, 'archive/:sec?');
    expect(screen.getByTestId('section').textContent).toBe('register');
  });

  it('writes the segment on switch and drops it again on the default section', () => {
    renderAt('/archive', <Sections base="/archive" />, 'archive/:sec?');
    fireEvent.click(screen.getByRole('button', { name: 'export' }));
    expect(href()).toBe('/archive/export');
    fireEvent.click(screen.getByRole('button', { name: 'register' }));
    expect(href()).toBe('/archive');
  });

  it('carries the query and fragment through a section switch — filters are not navigation', () => {
    renderAt('/archive?q=selo&chain=book%3Ab1#topo', <Sections base="/archive" />, 'archive/:sec?');
    fireEvent.click(screen.getByRole('button', { name: 'export' }));
    expect(href()).toBe('/archive/export?q=selo&chain=book%3Ab1#topo');
  });

  it('leaves an id containing a slash encoded, and appends the section beside it', () => {
    renderAt(
      `/templates/${encodeURIComponent('csc-ata-ag/v1')}`,
      <RecordSections />,
      'templates/:id/:sec?',
    );
    fireEvent.click(screen.getByRole('button', { name: 'source' }));
    // Still ONE id segment: `%2F` is not a segment boundary, and it is not double-encoded.
    expect(href()).toBe('/templates/csc-ata-ag%2Fv1/source');
  });
});

describe('translateLegacyAddress', () => {
  const at = (pathname: string, search = '') => {
    const out = translateLegacyAddress(pathname, search);
    return out === null ? null : `${out.pathname}${out.search}`;
  };

  it('translates a slug-only address', () => {
    expect(at('/configuracoes')).toBe('/settings');
    expect(at('/entidades/nova')).toBe('/entities/new');
    expect(at('/livros/b1/termo')).toBe('/books/b1/opening');
    expect(at('/arquivo/exportacao')).toBe('/archive/export');
    expect(at('/ferramentas/legislacao/prateleira')).toBe('/tools/legislation/shelf');
    expect(at('/utilizadores/u1/editar')).toBe('/users/u1/edit');
  });

  it('translates the pre-t97 query address and the slugs in ONE hop', () => {
    // Two hops would leave the intermediate address in history as a Back-button stop.
    expect(at('/configuracoes', '?sec=operacoes&sub=email')).toBe('/settings/operations/email');
    expect(at('/ferramentas', '?tool=legislacao&leg=prateleira')).toBe('/tools/legislation/shelf');
    expect(at('/arquivo', '?sec=exportacao')).toBe('/archive/export');
  });

  it('keeps genuine parameters while moving only the navigation state', () => {
    expect(at('/configuracoes', '?sec=utilizadores&q=amelia')).toBe('/settings/users?q=amelia');
  });

  it('forwards a sub-tab that was SPLIT to its real successor, not to the strip default', () => {
    // Plataforma became Serviços + Registos (t101); the old address lands on Serviços, which
    // kept the controls it was mostly about.
    expect(at('/configuracoes/operacoes/plataforma')).toBe('/settings/operations/services');
    expect(at('/configuracoes/operacoes/registos')).toBe('/settings/operations/logs');
  });

  it('resolves the retired settings aliases to their English ids', () => {
    expect(at('/configuracoes/identidade')).toBe('/settings/identity');
    expect(at('/configuracoes/chaves-api')).toBe('/settings/api-keys');
    expect(at('/configuracoes/fornecedores-assinatura')).toBe('/settings/signing-providers');
  });

  it('translates the same word differently per surface, which is why it is positional', () => {
    // `registo` is a company registry under an entity and the ledger REGISTER under Arquivo.
    expect(at('/entidades/e1/registo')).toBe('/entities/e1/registry');
    expect(at('/arquivo/registo')).toBe('/archive/register');
  });

  it('passes an unknown segment through raw, so record ids survive untouched', () => {
    expect(at(`/minutas/${encodeURIComponent('csc-ata-ag/v1')}/fonte`)).toBe(
      '/templates/csc-ata-ag%2Fv1/source',
    );
  });

  it('leaves an address it does not recognise alone', () => {
    expect(at('/settings/data')).toBeNull();
    expect(at('/nao-existe')).toBeNull();
  });
});

describe('LegacySlugRedirect', () => {
  const catchAll = (entry: string) =>
    renderAt(entry, <LegacySlugRedirect>{<span>nao encontrado</span>}</LegacySlugRedirect>, '*', [
      { path: 'settings/:sec?/:sub?', element: <span>definicoes</span> },
    ]);

  it('REPLACES rather than pushes, so an old link is not a Back-button stop', () => {
    catchAll('/configuracoes/dados');
    expect(href()).toBe('/settings/data');
    expect(screen.getByTestId('navtype').textContent).toBe('REPLACE');
  });

  it('carries the query and the fragment across the translation', () => {
    catchAll('/configuracoes?sec=utilizadores&q=amelia#acesso');
    expect(href()).toBe('/settings/users?q=amelia#acesso');
  });

  it('renders Not Found for an address that is genuinely unknown', () => {
    catchAll('/nao-existe-de-todo');
    expect(screen.getByText('nao encontrado')).toBeTruthy();
  });
});

describe('LegacyNavRedirect (the dashboard, whose `/` never reaches the catch-all)', () => {
  it('sends the panels to their own base, keeping `/` for the default', () => {
    renderAt(
      '/?painel=stats',
      <LegacyNavRedirect levels={[['painel']]} depth={0} base="/dashboard">
        <span>painel</span>
      </LegacyNavRedirect>,
      '',
      [{ path: 'dashboard/:tab?', element: <span>painel</span> }],
    );
    expect(href()).toBe('/dashboard/stats');
  });

  it('leaves the address alone when the legacy param is absent', () => {
    renderAt(
      '/?outro=1',
      <LegacyNavRedirect levels={[['painel']]} depth={0} base="/dashboard">
        <span>painel</span>
      </LegacyNavRedirect>,
      '',
    );
    expect(href()).toBe('/?outro=1');
    expect(screen.getByText('painel')).toBeTruthy();
  });
});
