/**
 * Ferramentas → Certidão de Registo Permanente, the lookup-only tool (t95).
 *
 * The load-bearing assertion here is **the request that is never made**. A test that a result
 * rendered would pass just as happily against a tool that quietly imported what it found, so these
 * assert the absent write from the client side: after a lookup, the only call issued is the lookup
 * itself, and repeating it changes nothing.
 *
 * No test asserts on rendered pt-PT copy. Failure distinctness is checked by comparing the nine
 * codes' rendered output to each other — which is the property that matters (no two failures may
 * read alike) and which stays true when the wording is revised.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import type { RegistryExtractView } from '../../api/types';
import { CertidaoLookupPage } from './CertidaoLookupPage';
import { ToolsPage } from './ToolsPage';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** A certidão with a deliberately absent `sede`, so the "never render a blank" rule is exercised. */
const EXTRACT: RegistryExtractView = {
  matricula: '99999/20200101',
  nipc: '503004642',
  firma: 'Encosto Estratégico, Lda',
  forma_juridica: 'Sociedade por quotas',
  legal_form: 'SociedadePorQuotas',
  sede: null,
  cae: [{ code: '68110', role: 'Principal', designation: null, level: null, revision: null }],
  objeto: null,
  capital: '5.000,00 EUR',
  data_constituicao: '2020-01-01',
  orgaos: [],
  inscricoes: [],
  anotacoes: [],
  provenance: {
    access_code_masked: '****-****-9012',
    retrieved_at: '2026-07-28T10:00:00Z',
    source_url: 'mock://registry/certidao',
    raw_digest: 'a'.repeat(64),
    conservatoria: 'Conservatória do Registo Comercial do Porto',
    oficial: 'Amélia Marques',
    subscribed_on: '2026-05-01',
    valid_until: '2027-05-01',
    expired: false,
  },
};

function codeInput(): HTMLInputElement {
  const el = document.getElementById('certidao-lookup-code');
  if (!(el instanceof HTMLInputElement)) throw new Error('access code input not rendered');
  return el;
}

function submitButton(): HTMLButtonElement {
  const el = document.querySelector('button[type="submit"]');
  if (!(el instanceof HTMLButtonElement)) throw new Error('submit button not rendered');
  return el;
}

async function lookup(code = '1234-5678-9012') {
  fireEvent.change(codeInput(), { target: { value: code } });
  fireEvent.click(submitButton());
}

/**
 * The failure note specifically.
 *
 * Not `getByRole('note')`: the page also renders the standing "lookup only" banner as a note, and
 * that one is always present — matching it would make every failure assertion below pass without
 * any error ever being rendered.
 */
async function errorNote(): Promise<HTMLElement> {
  return await waitFor(() => {
    const el = document.querySelector('.inline-warning--error');
    if (!(el instanceof HTMLElement)) throw new Error('no error note rendered');
    return el;
  });
}

/** Every call the component issued, as `METHOD path`. */
function calls(fetchMock: ReturnType<typeof vi.fn>): string[] {
  return fetchMock.mock.calls.map((call) => {
    const [input, init] = call as [RequestInfo, RequestInit | undefined];
    const url = typeof input === 'string' ? input : String(input);
    return `${(init?.method ?? 'GET').toUpperCase()} ${new URL(url, 'http://localhost').pathname}`;
  });
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('Certidão de Registo Permanente lookup', () => {
  it('issues the lookup and nothing else — no import, no entity write', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(EXTRACT));
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(<CertidaoLookupPage />);
    await lookup();
    await waitFor(() => expect(screen.getAllByRole('table').length).toBeGreaterThan(0));

    expect(calls(fetchMock)).toEqual(['POST /v1/registry/lookup']);
  });

  it('is repeatable: a second lookup issues a second lookup and still no write', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(EXTRACT));
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(<CertidaoLookupPage />);
    await lookup();
    await waitFor(() => expect(screen.getAllByRole('table').length).toBeGreaterThan(0));
    await lookup();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));

    const issued = calls(fetchMock);
    expect(issued).toEqual(['POST /v1/registry/lookup', 'POST /v1/registry/lookup']);
    // Nothing that could mutate: no import route, no entity route of any shape.
    expect(issued.some((c) => c.includes('/import') || c.includes('/v1/entities'))).toBe(false);
  });

  it('offers no affordance that would import the result', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(EXTRACT));
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(<CertidaoLookupPage />);
    await lookup();
    await waitFor(() => expect(screen.getAllByRole('table').length).toBeGreaterThan(0));

    // Only the submit and the clear control. An "import this" button appearing here would be a
    // product decision, not an incidental one — this pins that it has not been added by accident.
    expect(
      screen.getAllByRole('button').filter((b) => b.getAttribute('type') !== 'button').length,
    ).toBe(1);
  });

  it('clears the access code from the input once it has been used', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(EXTRACT));
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(<CertidaoLookupPage />);
    await lookup();
    await waitFor(() => expect(codeInput().value).toBe(''));
  });

  it('never echoes the submitted access code back into the document', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(EXTRACT));
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(<CertidaoLookupPage />);
    await lookup('1234-5678-9012');
    await waitFor(() => expect(screen.getAllByRole('table').length).toBeGreaterThan(0));

    const rendered = document.body.textContent ?? '';
    expect(rendered).not.toContain('1234-5678-9012');
    expect(rendered).not.toContain('123456789012');
    // The masked form the server derived is what is shown instead.
    expect(rendered).toContain('****-****-9012');
  });

  it('states an absent field rather than rendering a blank cell', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(EXTRACT));
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(<CertidaoLookupPage />);
    await lookup();
    await waitFor(() => expect(screen.getAllByRole('table').length).toBeGreaterThan(0));

    // `sede` is null in the fixture. Its cell must carry text — a blank or a bare dash would read
    // as "this company has no seat", a claim the certidão never made.
    const sedeRow = screen
      .getAllByRole('row')
      .find((row) => row.querySelector('th')?.textContent?.trim() === 'Sede');
    expect(sedeRow).toBeDefined();
    const cell = sedeRow?.querySelector('td')?.textContent?.trim() ?? '';
    expect(cell.length).toBeGreaterThan(1);
    expect(cell).not.toBe('—');
    expect(cell).not.toBe('-');
  });

  it('renders a distinct message for every registry failure code', async () => {
    const codes = [
      'registry.invalid_code',
      'registry.code_rejected',
      'registry.certidao_not_found',
      'registry.unreachable',
      'registry.credentials_rejected',
      'registry.quota_exceeded',
      'registry.upstream',
      'registry.unrecognized',
      'registry.config',
    ];
    const rendered: string[] = [];

    for (const code of codes) {
      const fetchMock = vi.fn(async () =>
        jsonResponse({ error: `english detail for ${code}`, code }, 422),
      );
      vi.stubGlobal('fetch', fetchMock);
      renderWithProviders(<CertidaoLookupPage />);
      await lookup();
      const note = await errorNote();
      // The first paragraph is the localised sentence; the technical detail line is deliberately
      // excluded, since it varies by construction and would mask a copy collision.
      rendered.push(note.querySelector('.inline-warning__body p')?.textContent?.trim() ?? '');
      cleanup();
    }

    expect(new Set(rendered).size).toBe(codes.length);
    expect(rendered.every((message) => message.length > 0)).toBe(true);
  });

  it('does not tell the operator the certidão is missing when the registry was unreachable', async () => {
    async function messageFor(code: string): Promise<string> {
      vi.stubGlobal(
        'fetch',
        vi.fn(async () => jsonResponse({ error: 'detail', code }, 502)),
      );
      renderWithProviders(<CertidaoLookupPage />);
      await lookup();
      const note = await errorNote();
      const text = note.querySelector('.inline-warning__body p')?.textContent?.trim() ?? '';
      cleanup();
      return text;
    }

    const unreachable = await messageFor('registry.unreachable');
    const notFound = await messageFor('registry.certidao_not_found');
    expect(unreachable).not.toBe(notFound);
    expect(unreachable.length).toBeGreaterThan(0);
  });

  it('falls back to the server detail for a code this build does not know', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse({ error: 'a brand new upstream condition', code: 'registry.future' }, 502),
      ),
    );
    renderWithProviders(<CertidaoLookupPage />);
    await lookup();
    const note = await errorNote();
    expect(note.textContent).toContain('a brand new upstream condition');
  });
});

describe('Ferramentas sub-navigation', () => {
  it('exposes the certidão lookup as its own tab', () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse({})),
    );
    renderWithProviders(<ToolsPage />, ['/tools/certidao']);
    // Addressed by its own path segment, and it renders the lookup form rather than any other tool.
    expect(document.getElementById('certidao-lookup-code')).not.toBeNull();
  });
});
