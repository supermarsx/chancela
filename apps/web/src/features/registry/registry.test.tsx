import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders } from '../../test/utils';
import { ImportFromRegistryForm } from './ImportFromRegistryForm';
import { RegistryImportPanel } from './RegistryImportPanel';
import { RegistryProvenance } from './RegistryProvenance';
import type { Entity, RegistryExtractView, RegistryImportReport } from '../../api/types';

// The full código de acesso used across these tests. It must NEVER appear in any
// rendered output — provenance is masked, and inputs are cleared after submit.
const FULL_CODE = '1234-5678-9012';
const MASKED_CODE = '****-****-9012';

const ENTITY: Entity = {
  id: 'new-ent-1',
  name: 'Encosto Estratégico, Lda.',
  nipc: '503004642',
  nipc_validated: true,
  seat: 'Rua das Amoreiras 12, Lisboa',
  family: 'CommercialCompany',
  kind: 'SociedadePorQuotas',
  profile: {
    family: 'CommercialCompany',
    rule_pack_id: 'csc-art63/v2',
    allowed_channels: ['Physical', 'Hybrid', 'Telematic', 'WrittenResolution'],
    signature_policy: 'QualifiedPreferred',
    template_family: 'csc-commercial',
    calendar_presets: [],
  },
  statute: null,
};

const EXTRACT: RegistryExtractView = {
  matricula: '12045/20200115',
  nipc: '503004642',
  firma: 'Encosto Estratégico, Lda.',
  forma_juridica: 'Sociedade por quotas',
  legal_form: 'SociedadePorQuotas',
  sede: 'Rua das Amoreiras 12, Lisboa',
  cae: [
    {
      code: '70220',
      role: 'Principal',
      designation: 'Atividades de consultoria para os negócios e a gestão.',
      level: 'Subclasse',
      revision: 'Rev4',
    },
    { code: '82990', role: 'Secundario', designation: null, level: null, revision: null },
  ],
  objeto: 'Consultoria para os negócios e a gestão.',
  capital: '5.000,00 EUR',
  data_constituicao: '2020-01-15',
  orgaos: [
    {
      name: 'Maria Silva',
      role: 'Gerente',
      appointment_date: '2020-01-15',
      cessation_date: null,
      source_event: '1',
    },
    {
      name: 'João Costa',
      role: 'Gerente',
      appointment_date: '2020-01-15',
      cessation_date: '2023-06-20',
      source_event: '3 Av. 1',
    },
  ],
  inscricoes: [
    {
      number: '1',
      kind_hint: 'CONSTITUIÇÃO',
      apresentacao: 'AP. 1/20200115',
      date: '2020-01-15',
      text: 'Constituição da sociedade Encosto Estratégico, Lda.',
      detail: null,
    },
    {
      number: '3 Av. 1',
      kind_hint: 'CESSAÇÃO DE GERENTE',
      apresentacao: 'AP. 5/20230620',
      date: '2023-06-20',
      text: 'Cessação de funções de gerente.',
      detail: null,
    },
  ],
  anotacoes: [],
  provenance: {
    access_code_masked: MASKED_CODE,
    retrieved_at: '2026-07-06T10:00:00Z',
    source_url: 'https://registo.example.pt/consulta',
    raw_digest: 'a'.repeat(64),
    conservatoria: null,
    oficial: null,
    subscribed_on: null,
    valid_until: null,
    expired: null,
  },
};

interface Recorded {
  url: string;
  method: string;
  body: Record<string, unknown> | null;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * A recording fetch stub whose responder is provided per-test. Every call is captured
 * (URL, method, parsed body) so a test can assert exactly what was sent — notably the
 * `overwrite` flag and the transient `code`.
 */
function recordingFetch(responder: (r: Recorded) => Response): {
  fn: typeof fetch;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const body = init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : null;
    const rec = { url, method, body };
    calls.push(rec);
    return Promise.resolve(responder(rec));
  }) as typeof fetch;
  return { fn, calls };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('ImportFromRegistryForm', () => {
  it('imports by code and navigates to the newly created entity', async () => {
    const report: RegistryImportReport = {
      entity: ENTITY,
      extract: EXTRACT,
      applied: ['nipc', 'name', 'seat', 'kind'],
      conflicts: [],
      warnings: [],
    };
    const { fn, calls } = recordingFetch((r) =>
      r.url.includes('/v1/entities/import-from-registry')
        ? jsonResponse(report, 201)
        : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <Routes>
        <Route path="/entidades" element={<ImportFromRegistryForm />} />
        <Route path="/entidades/:id" element={<div>DETALHE DA ENTIDADE</div>} />
      </Routes>,
      ['/entidades'],
    );

    fireEvent.change(screen.getByLabelText('Código da certidão permanente'), {
      target: { value: FULL_CODE },
    });
    fireEvent.click(screen.getByRole('button', { name: /importar do registo/i }));

    // Navigation intent: we land on the new entity's detail route.
    expect(await screen.findByText('DETALHE DA ENTIDADE')).toBeTruthy();

    // The code was sent transiently in the import body.
    const post = calls.find((c) => c.url.includes('import-from-registry'));
    expect(post?.body?.code).toBe(FULL_CODE);
  });

  it('renders a 422 (unusable certidão) distinctly with the API message', async () => {
    const { fn } = recordingFetch(() =>
      jsonResponse(
        { error: 'cannot create an entity from this certidão: it lacked a valid NIPC' },
        422,
      ),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<ImportFromRegistryForm />, ['/entidades']);

    fireEvent.change(screen.getByLabelText('Código da certidão permanente'), {
      target: { value: FULL_CODE },
    });
    fireEvent.click(screen.getByRole('button', { name: /importar do registo/i }));

    expect(await screen.findByText('Não foi possível importar')).toBeTruthy();
    expect(screen.getByText(/lacked a valid NIPC/)).toBeTruthy();
  });

  it('renders a 502 (upstream) distinctly from a 422', async () => {
    const { fn } = recordingFetch(() =>
      jsonResponse({ error: 'registry upstream failure: connection refused' }, 502),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<ImportFromRegistryForm />, ['/entidades']);

    fireEvent.change(screen.getByLabelText('Código da certidão permanente'), {
      target: { value: FULL_CODE },
    });
    fireEvent.click(screen.getByRole('button', { name: /importar do registo/i }));

    expect(await screen.findByText('Registo indisponível')).toBeTruthy();
    expect(screen.getByText(/connection refused/)).toBeTruthy();
    // Not confused with the 422 rendering.
    expect(screen.queryByText('Não foi possível importar')).toBeNull();
  });
});

describe('RegistryImportPanel', () => {
  it('shows the conflict table and re-submits with overwrite:true on confirm', async () => {
    const withConflict: RegistryImportReport = {
      entity: { ...ENTITY, id: 'ent-1', name: 'Nome Original, Lda.' },
      extract: EXTRACT,
      applied: ['seat'],
      conflicts: [
        { field: 'name', current: 'Nome Original, Lda.', incoming: 'Encosto Estratégico, Lda.' },
      ],
      warnings: [],
    };
    const resolved: RegistryImportReport = {
      entity: ENTITY,
      extract: EXTRACT,
      applied: ['seat', 'name'],
      conflicts: [],
      warnings: [],
    };

    const { fn, calls } = recordingFetch((r) => {
      if (r.url.includes('/registry/import')) {
        return r.body?.overwrite === true ? jsonResponse(resolved) : jsonResponse(withConflict);
      }
      return jsonResponse([]);
    });
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<RegistryImportPanel entityId="ent-1" />, ['/entidades/ent-1']);

    fireEvent.change(screen.getByLabelText('Código da certidão permanente'), {
      target: { value: FULL_CODE },
    });
    fireEvent.click(screen.getByRole('button', { name: /consultar e importar/i }));

    // The conflict table renders current vs incoming.
    expect(await screen.findByText('Divergências encontradas')).toBeTruthy();
    expect(screen.getByText('Nome Original, Lda.')).toBeTruthy();
    expect(screen.getByText('Encosto Estratégico, Lda.')).toBeTruthy();
    // The field is shown by its PT-PT label.
    expect(screen.getByText('Denominação')).toBeTruthy();

    // The first import was NOT an overwrite.
    const posts = calls.filter((c) => c.url.includes('/registry/import'));
    expect(posts[0].body?.overwrite).toBe(false);

    fireEvent.click(screen.getByRole('button', { name: /confirmar e substituir/i }));

    await waitFor(() => {
      const p = calls.filter((c) => c.url.includes('/registry/import'));
      expect(p).toHaveLength(2);
    });
    const secondPost = calls.filter((c) => c.url.includes('/registry/import'))[1];
    expect(secondPost.body?.overwrite).toBe(true);
    // The same secret code was re-sent transiently for the overwrite.
    expect(secondPost.body?.code).toBe(FULL_CODE);
  });
});

describe('RegistryProvenance', () => {
  it('shows only the masked access code — the full code never reaches the DOM', async () => {
    const { fn } = recordingFetch((r) =>
      r.url.includes('/registry') ? jsonResponse(EXTRACT) : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    const { container } = renderWithProviders(<RegistryProvenance entityId="ent-1" />, [
      '/entidades/ent-1',
    ]);

    // The masked code and an inscrição both render.
    expect(await screen.findByText(MASKED_CODE)).toBeTruthy();
    expect(screen.getByText('CONSTITUIÇÃO')).toBeTruthy();
    expect(screen.getByText(/Cessou funções/)).toBeTruthy();

    // The enriched CAE renders: a catalogued Principal designation + the honest
    // fallback for the uncatalogued Secundário.
    expect(screen.getByText('Principal')).toBeTruthy();
    expect(screen.getByText('Atividades de consultoria para os negócios e a gestão.')).toBeTruthy();
    expect(screen.getByText('Secundário')).toBeTruthy();
    expect(screen.getByText(/Não catalogado/)).toBeTruthy();

    // The full código de acesso is absent everywhere in the rendered tree.
    expect(container.textContent).not.toContain(FULL_CODE);
    expect(document.body.textContent).not.toContain(FULL_CODE);
  });

  it('shows an empty state (not an error) when nothing has been imported (404)', async () => {
    const { fn } = recordingFetch(() => jsonResponse({ error: 'not found' }, 404));
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<RegistryProvenance entityId="ent-1" />, ['/entidades/ent-1']);

    expect(await screen.findByText('Sem dados do registo')).toBeTruthy();
  });

  it('lays out "Dados do registo" as a two-column pair grid with wide long fields', async () => {
    const { fn } = recordingFetch((r) =>
      r.url.includes('/registry') ? jsonResponse(EXTRACT) : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    const { container } = renderWithProviders(<RegistryProvenance entityId="ent-1" />, [
      '/entidades/ent-1',
    ]);

    // Wait for the card to render.
    await screen.findByText('Dados do registo');

    // The Dados do registo definition list opts into the two-column pair grid.
    const pairs = container.querySelector('.deflist--pairs');
    expect(pairs).toBeTruthy();

    // Long free-text fields (objeto, sede, firma, CAE) span both columns.
    const wide = pairs?.querySelectorAll('.deflist__wide');
    expect(wide && wide.length).toBeGreaterThanOrEqual(3);
  });
});
