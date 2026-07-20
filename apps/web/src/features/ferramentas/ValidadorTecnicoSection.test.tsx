/**
 * The second navigation level inside Ferramentas → Validador PDF: three sub-tabs on the
 * shared `<SubNav>`, deep-linked through `?sec=`, with a browser Back that stays inside
 * the tool instead of leaving it.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useLocation, useNavigate } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';
import { FerramentasPage } from './FerramentasPage';
import { makeClient, renderWithProviders } from '../../test/utils';
import { ToastProvider } from '../../ui/toast';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Only the reports sub-tab fetches on mount; the PDF and ASiC panels stay idle until a
 * file is submitted, so an empty report shelf is the whole stub surface needed here.
 */
function validatorToolsFetch(): typeof fetch {
  return ((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.includes('/v1/external-validator-reports')) {
      return Promise.resolve(
        jsonResponse({
          storage: 'durable',
          count: 0,
          reports: [],
          notice: 'Apenas metadados técnicos redigidos.',
        }),
      );
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
}

const SUBNAV_LABEL = 'Secção do validador técnico';

function subnav(): HTMLElement {
  return screen.getByRole('group', { name: SUBNAV_LABEL });
}

describe('Ferramentas — validador técnico sub-tabs', () => {
  it('reuses the shared SubNav with the three sections in the requested order', () => {
    vi.stubGlobal('fetch', validatorToolsFetch());
    renderWithProviders(<FerramentasPage />, ['/ferramentas?tool=pdf']);

    expect(
      within(subnav())
        .getAllByRole('button')
        .map((b) => b.textContent),
    ).toEqual(['Assinaturas PDF', 'Contentores ASiC', 'Relatórios técnicos']);
    // The shared primitive, not a fork: SubNav renders `.subnav`, the Ferramentas tool
    // level renders `.ferramentas-subnav`.
    expect(document.querySelector('.subnav-wrap')).toBeTruthy();
  });

  it('lands on the PDF validator with no sec param and marks only that tab pressed', () => {
    vi.stubGlobal('fetch', validatorToolsFetch());
    renderWithProviders(<FerramentasPage />, ['/ferramentas?tool=pdf']);

    expect(screen.getByText('Validador técnico de assinaturas PDF')).toBeTruthy();
    expect(
      within(subnav()).getByRole('button', { name: 'Assinaturas PDF' }).getAttribute('aria-pressed'),
    ).toBe('true');
    expect(
      within(subnav())
        .getByRole('button', { name: 'Contentores ASiC' })
        .getAttribute('aria-pressed'),
    ).toBe('false');
  });

  it('deep-links each section, and an unknown sec falls back to the PDF validator', () => {
    vi.stubGlobal('fetch', validatorToolsFetch());

    renderWithProviders(<FerramentasPage />, ['/ferramentas?tool=pdf&sec=asic']);
    expect(screen.getByText('Inspetor técnico ASiC')).toBeTruthy();
    cleanup();

    vi.stubGlobal('fetch', validatorToolsFetch());
    renderWithProviders(<FerramentasPage />, ['/ferramentas?tool=pdf&sec=relatorios']);
    expect(screen.getByText('Relatórios técnicos de validador externo')).toBeTruthy();
    cleanup();

    vi.stubGlobal('fetch', validatorToolsFetch());
    renderWithProviders(<FerramentasPage />, ['/ferramentas?tool=pdf&sec=nao-existe']);
    expect(screen.getByText('Validador técnico de assinaturas PDF')).toBeTruthy();
  });

  it('re-keys the content on sub-tab switch so the enter animation replays', () => {
    vi.stubGlobal('fetch', validatorToolsFetch());
    const { container } = renderWithProviders(<FerramentasPage />, ['/ferramentas?tool=pdf']);
    const animKey = () =>
      container.querySelector('[data-subanim-key]')?.getAttribute('data-subanim-key');

    expect(animKey()).toBe('pdf');
    fireEvent.click(screen.getByRole('button', { name: 'Contentores ASiC' }));
    expect(animKey()).toBe('asic');
  });
});

describe('Ferramentas — validador técnico deep-link and Back behaviour', () => {
  /** Renders the live query string and a Back control, so history is assertable. */
  function HistoryProbe() {
    const navigate = useNavigate();
    return (
      <>
        <span data-testid="search-probe">{useLocation().search}</span>
        <button type="button" onClick={() => navigate(-1)}>
          probe-back
        </button>
      </>
    );
  }

  function renderWithProbe(entry = '/ferramentas?tool=pdf') {
    return render(
      <QueryClientProvider client={makeClient()}>
        <ToastProvider>
          <MemoryRouter initialEntries={[entry]}>
            <HistoryProbe />
            <FerramentasPage />
          </MemoryRouter>
        </ToastProvider>
      </QueryClientProvider>,
    );
  }

  const search = () => screen.getByTestId('search-probe').textContent;

  it('writes ?sec= on switch and drops it again on the default section', async () => {
    vi.stubGlobal('fetch', validatorToolsFetch());
    renderWithProbe();
    expect(search()).toBe('?tool=pdf');

    fireEvent.click(screen.getByRole('button', { name: 'Contentores ASiC' }));
    await waitFor(() => expect(search()).toBe('?tool=pdf&sec=asic'));

    fireEvent.click(screen.getByRole('button', { name: 'Relatórios técnicos' }));
    await waitFor(() => expect(search()).toBe('?tool=pdf&sec=relatorios'));

    // The default section carries no param, matching the Configurações / livros rule.
    fireEvent.click(screen.getByRole('button', { name: 'Assinaturas PDF' }));
    await waitFor(() => expect(search()).toBe('?tool=pdf'));
  });

  it('keeps browser Back inside the tool instead of leaving it', async () => {
    vi.stubGlobal('fetch', validatorToolsFetch());
    renderWithProbe();

    fireEvent.click(screen.getByRole('button', { name: 'Contentores ASiC' }));
    await waitFor(() => expect(search()).toBe('?tool=pdf&sec=asic'));
    expect(screen.getByText('Inspetor técnico ASiC')).toBeTruthy();

    // The sub-tab switch pushes rather than replaces, so Back returns to the sub-tab we
    // came from and the tool stays mounted — the t34-lawback failure mode, avoided.
    fireEvent.click(screen.getByRole('button', { name: 'probe-back' }));
    await waitFor(() => expect(search()).toBe('?tool=pdf'));
    expect(screen.getByText('Validador técnico de assinaturas PDF')).toBeTruthy();
    expect(screen.queryByText('Inspetor técnico ASiC')).toBeNull();
  });
});
