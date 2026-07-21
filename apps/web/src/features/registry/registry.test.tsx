import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders } from '../../test/utils';
import { formatDate } from '../../format';
import { ImportFromRegistryForm } from './ImportFromRegistryForm';
import { RegistryImportPanel } from './RegistryImportPanel';
import { RegistryProvenance } from './RegistryProvenance';
import { registryFieldHelp } from './fieldHelp';
import { EntityPrintDocument } from '../entities/EntityPrintDocument';
import type {
  Entity,
  InscriptionDetailView,
  RegistryEventView,
  RegistryExtractView,
  RegistryImportReport,
} from '../../api/types';

// The full código de acesso used across these tests. It must NEVER appear in any
// rendered output — provenance is masked, and inputs are cleared after submit.
const FULL_CODE = '1234-5678-9012';
const MASKED_CODE = '****-****-9012';

const ENTITY: Entity = {
  id: 'new-ent-1',
  tenant_id: 'tenant-1',
  group_id: null,
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
    attendee_qualities: ['Member'],
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

function deferredResponse(): {
  fn: typeof fetch;
  resolve: (response: Response) => void;
} {
  let resolvePending!: (response: Response) => void;
  const pending = new Promise<Response>((r) => {
    resolvePending = r;
  });
  const fn = (() => pending) as typeof fetch;
  return { fn, resolve: (response) => resolvePending(response) };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('ImportFromRegistryForm', () => {
  it('renders a clear initial import form with the expected controls', () => {
    renderWithProviders(<ImportFromRegistryForm />, ['/entidades/importar']);

    expect(screen.getByText('Consulta')).toBeTruthy();
    expect(screen.getByText('Aguardando código')).toBeTruthy();
    expect(screen.getByText(/Crie a entidade a partir da certidão permanente/)).toBeTruthy();

    const codeInput = screen.getByLabelText('Código da certidão permanente') as HTMLInputElement;
    expect(codeInput.type).toBe('password');
    expect(screen.getByRole('button', { name: 'Mostrar código' })).toBeTruthy();
    expect(screen.getByLabelText('E-mail (opcional)')).toBeTruthy();
    expect(document.body.textContent).toContain(registryFieldHelp.accessCode);
    expect(document.body.textContent).toContain(registryFieldHelp.email);

    const submit = screen.getByRole('button', { name: /importar do registo/i });
    expect(submit.hasAttribute('disabled')).toBe(true);

    fireEvent.change(codeInput, { target: { value: FULL_CODE } });

    expect(screen.getByText('Pronto')).toBeTruthy();
    expect(
      screen.getByRole('button', { name: /importar do registo/i }).hasAttribute('disabled'),
    ).toBe(false);
  });

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
    // R6: the success toast survives the navigate-away (t44 retrofit-b).
    expect(await screen.findByText('Entidade importada do registo.')).toBeTruthy();

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
    // The message shows both in the inline RegistryErrorNote and the error toast (R7).
    expect(screen.getAllByText(/lacked a valid NIPC/).length).toBeGreaterThanOrEqual(1);
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
    // Inline note + error toast both carry the server message (R7).
    expect(screen.getAllByText(/connection refused/).length).toBeGreaterThanOrEqual(1);
    // Not confused with the 422 rendering.
    expect(screen.queryByText('Não foi possível importar')).toBeNull();
  });
});

describe('RegistryImportPanel', () => {
  it('shows a provenance summary and next action after a successful enrichment', async () => {
    const report: RegistryImportReport = {
      entity: { ...ENTITY, id: 'ent-1' },
      extract: EXTRACT,
      applied: ['name', 'seat'],
      conflicts: [],
      warnings: [],
    };
    const { fn } = recordingFetch((r) =>
      r.url.includes('/registry/import') ? jsonResponse(report) : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<RegistryImportPanel entityId="ent-1" />, ['/entidades/ent-1/importar']);

    fireEvent.change(screen.getByLabelText('Código da certidão permanente'), {
      target: { value: FULL_CODE },
    });
    fireEvent.click(screen.getByRole('button', { name: /consultar e importar/i }));

    expect(await screen.findByText('Resumo da importação')).toBeTruthy();
    expect(screen.getByText('Proveniência')).toBeTruthy();
    expect(screen.getByText(MASKED_CODE)).toBeTruthy();
    expect(screen.getByText(EXTRACT.provenance.source_url)).toBeTruthy();
    expect(screen.getByText('Campos atualizados')).toBeTruthy();
    expect(screen.getByText('Próximo passo')).toBeTruthy();
    expect(document.body.textContent).toContain(registryFieldHelp.firma);
    expect(document.body.textContent).toContain(registryFieldHelp.accessCodeMasked);
    expect(document.body.textContent).toContain(registryFieldHelp.digest);

    const back = screen.getByRole('link', { name: /voltar à entidade/i }) as HTMLAnchorElement;
    expect(back.getAttribute('href')).toBe('/entidades/ent-1');
  });

  it('shows the conflict table and re-submits with overwrite:true on confirm', async () => {
    const withConflict: RegistryImportReport = {
      entity: { ...ENTITY, id: 'ent-1', name: 'Nome Original, Lda.' },
      extract: EXTRACT,
      applied: ['seat'],
      conflicts: [
        { field: 'name', current: 'Nome Original, Lda.', incoming: 'Encosto Estratégico, Lda.' },
      ],
      warnings: ['certidão expirada em 2025-01-01'],
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
    expect(screen.getByText('Avisos da importação')).toBeTruthy();
    expect(screen.getByText('certidão expirada em 2025-01-01')).toBeTruthy();
    expect(screen.getByText('Requer confirmação')).toBeTruthy();
    expect(screen.getByText('Nome Original, Lda.')).toBeTruthy();
    expect(screen.getAllByText('Encosto Estratégico, Lda.').length).toBeGreaterThanOrEqual(1);
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
    // Each enrich that applied a field fired a success toast (t44 retrofit-b); both the
    // first (seat) and the overwrite (name) applied, so one or more toasts are present.
    expect(
      (await screen.findAllByText('Entidade atualizada a partir da certidão.')).length,
    ).toBeGreaterThanOrEqual(1);
  });

  it('keeps the loading and error state usable', async () => {
    const deferred = deferredResponse();
    vi.stubGlobal('fetch', deferred.fn);

    renderWithProviders(<RegistryImportPanel entityId="ent-1" />, ['/entidades/ent-1/importar']);

    const codeInput = screen.getByLabelText('Código da certidão permanente') as HTMLInputElement;
    fireEvent.change(codeInput, { target: { value: FULL_CODE } });
    fireEvent.click(screen.getByRole('button', { name: /consultar e importar/i }));

    const status = await screen.findByRole('status');
    expect(status.textContent).toContain('A consultar');
    expect(
      screen.getByRole('button', { name: /a consultar o registo/i }).hasAttribute('disabled'),
    ).toBe(true);
    expect(codeInput.value).toBe(FULL_CODE);

    deferred.resolve(jsonResponse({ error: 'registry upstream failure: timeout' }, 502));

    expect(await screen.findByText('Registo indisponível')).toBeTruthy();
    expect(screen.getByText('Ação necessária')).toBeTruthy();
    expect((screen.getByLabelText('Código da certidão permanente') as HTMLInputElement).value).toBe(
      FULL_CODE,
    );

    fireEvent.change(screen.getByLabelText('Código da certidão permanente'), {
      target: { value: '1111-2222-3333' },
    });
    expect((screen.getByLabelText('Código da certidão permanente') as HTMLInputElement).value).toBe(
      '1111-2222-3333',
    );
    expect(
      screen.getByRole('button', { name: /consultar e importar/i }).hasAttribute('disabled'),
    ).toBe(false);
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
    expect(document.body.textContent).toContain(registryFieldHelp.accessCodeMasked);
    expect(document.body.textContent).toContain(registryFieldHelp.legalForm);
    expect(document.body.textContent).toContain(registryFieldHelp.sede);
    expect(document.body.textContent).toContain(registryFieldHelp.cae);

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

// --- Structured inscription layer (t21) -----------------------------------------

/** A full Constitution `detail` mirroring the frozen §2.7-v2 wire (fictional values). */
const CONSTITUTION_DETAIL: InscriptionDetailView = {
  apresentacao: {
    number: '1',
    date: '2020-01-15',
    time: '00:55:25 UTC',
    act_kinds: ['CONSTITUIÇÃO DE SOCIEDADE', 'DESIGNAÇÃO DE MEMBRO(S) DE ÓRGÃO(S) SOCIAL(AIS)'],
  },
  payload: {
    type: 'Constitution',
    firma: 'Encosto Estratégico, Lda.',
    nipc: '503004642',
    natureza_juridica: 'Sociedade por quotas',
    sede: {
      lines: ['Rua do Exemplo, n.º 11, Lugarejo'],
      distrito: 'Porto',
      concelho: 'Porto',
      freguesia: 'Cedofeita',
      postal_code: '4000-100',
      locality: 'PORTO',
    },
    objecto: 'Consultoria para os negócios e a gestão.',
    capital: { amount_text: '100,00', currency: 'Euros' },
    capital_realization_note: 'A entregar nos cofres da sociedade.',
    fiscal_year_end: '31 Dezembro',
    socios: [
      {
        amount: { amount_text: '99,00', currency: 'Euros' },
        titular: {
          name: 'Rui Tavares',
          nif: '999999990',
          estado_civil: 'Casado',
          nacionalidade: 'Portuguesa',
          residencia: {
            lines: ['Rua A, n.º 1'],
            distrito: null,
            concelho: null,
            freguesia: null,
            postal_code: null,
            locality: null,
          },
        },
      },
      {
        amount: { amount_text: '1,00', currency: 'Euros' },
        titular: {
          name: 'Amélia Marques',
          nif: '999999982',
          estado_civil: 'Solteira',
          nacionalidade: 'Portuguesa',
          residencia: null,
        },
      },
    ],
    forma_de_obrigar: 'Obriga-se com a assinatura de um gerente.',
    orgaos: [
      {
        name: 'GERÊNCIA',
        members: [
          {
            name: 'Amélia Marques',
            nif: '999999982',
            cargo: 'Gerente',
            nacionalidade: 'Portuguesa',
            residencia: null,
          },
        ],
      },
    ],
    deliberation_date: '2026-05-11',
  },
  signatures: [
    { conservatoria: 'Conservatória do Registo Comercial Porto', oficial: 'Amélia Marques' },
  ],
};

const RAW_CONSTITUTION_TEXT =
  'CONSTITUIÇÃO DE SOCIEDADE. FIRMA: Encosto Estratégico, Lda. NIPC: 503004642. (texto integral da certidão)';

/** A deferred v1 kind (transmissão de quotas): recognized act, but no structured payload. */
const UNSTRUCTURED_DETAIL: InscriptionDetailView = {
  apresentacao: {
    number: '3',
    date: '2021-03-01',
    time: null,
    act_kinds: ['TRANSMISSÃO DE QUOTA'],
  },
  payload: null,
  signatures: [],
};

const STRUCTURED_INSCRICOES: RegistryEventView[] = [
  {
    number: '1',
    kind_hint: 'CONSTITUIÇÃO',
    apresentacao: 'AP. 1/20200115',
    date: '2020-01-15',
    text: RAW_CONSTITUTION_TEXT,
    detail: CONSTITUTION_DETAIL,
  },
  {
    number: '2',
    kind_hint: 'TRANSMISSÃO DE QUOTA',
    apresentacao: 'AP. 3/20210301',
    date: '2021-03-01',
    text: 'Transmissão de quota de Rui Tavares para Amélia Marques.',
    detail: UNSTRUCTURED_DETAIL,
  },
];

const STRUCTURED_EXTRACT: RegistryExtractView = {
  ...EXTRACT,
  inscricoes: STRUCTURED_INSCRICOES,
  anotacoes: [
    {
      number: '1',
      date: '2020-01-20',
      publication_url: 'http://publicacoes.mj.pt',
      text: 'Publicação da constituição.',
    },
  ],
  provenance: {
    ...EXTRACT.provenance,
    conservatoria: 'Conservatória do Registo Comercial Porto',
    oficial: 'Amélia Marques',
    subscribed_on: '2026-06-01',
    valid_until: '2025-01-01',
    expired: true,
  },
};

describe('RegistryProvenance — structured inscriptions', () => {
  it('renders the full Constitution card: apresentação acts, sócios/quotas, órgãos and sede', async () => {
    const { fn } = recordingFetch((r) =>
      r.url.includes('/registry') ? jsonResponse(STRUCTURED_EXTRACT) : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<RegistryProvenance entityId="ent-1" />, ['/entidades/ent-1']);

    // Multi-act apresentação: one accent badge per act kind.
    expect(await screen.findByText('CONSTITUIÇÃO DE SOCIEDADE')).toBeTruthy();
    expect(screen.getByText('DESIGNAÇÃO DE MEMBRO(S) DE ÓRGÃO(S) SOCIAL(AIS)')).toBeTruthy();

    // Sócios e quotas table: quota amount + titular identity.
    expect(screen.getByText('Sócios e quotas')).toBeTruthy();
    expect(screen.getByText('Rui Tavares')).toBeTruthy();
    expect(screen.getByText('999999990')).toBeTruthy();
    expect(screen.getByText('99,00 Euros')).toBeTruthy();
    expect(screen.getByText('Casado')).toBeTruthy();

    // Órgãos designados: the GERÊNCIA organ with a Gerente member (Amélia appears as
    // sócia and as gerente; "Gerente" also labels the extract-level órgãos roll-up).
    expect(screen.getByText('GERÊNCIA')).toBeTruthy();
    expect(screen.getAllByText('Gerente').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('Amélia Marques').length).toBeGreaterThanOrEqual(2);

    // Sede address with the administrative breakdown.
    expect(screen.getByText('Rua do Exemplo, n.º 11, Lugarejo')).toBeTruthy();
    expect(screen.getByText(/Distrito: Porto/)).toBeTruthy();
    expect(screen.getByText('4000-100 PORTO')).toBeTruthy();

    // Deliberation date + forma de obrigar.
    expect(screen.getByText(formatDate('2026-05-11'))).toBeTruthy();
    expect(screen.getByText('Obriga-se com a assinatura de um gerente.')).toBeTruthy();
    expect(document.body.textContent).toContain(registryFieldHelp.naturezaJuridica);
    expect(document.body.textContent).toContain(registryFieldHelp.fiscalYearEnd);
    expect(document.body.textContent).toContain(registryFieldHelp.formaObrigar);
  });

  it('keeps the raw text one "texto integral" toggle away when structured, and shows it plainly when not', async () => {
    const { fn } = recordingFetch((r) =>
      r.url.includes('/registry') ? jsonResponse(STRUCTURED_EXTRACT) : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    const { container } = renderWithProviders(<RegistryProvenance entityId="ent-1" />, [
      '/entidades/ent-1',
    ]);

    // Structured entry: raw body is present but tucked under a collapsible toggle.
    expect(await screen.findByText('Texto integral')).toBeTruthy();
    expect(container.querySelector('details.registry-detail__raw')).toBeTruthy();
    expect(screen.getByText(RAW_CONSTITUTION_TEXT)).toBeTruthy();

    // Unstructured (deferred) entry: the raw text is shown directly, not hidden.
    expect(
      screen.getByText('Transmissão de quota de Rui Tavares para Amélia Marques.'),
    ).toBeTruthy();
    // Its recognized act kind still surfaces (head kind_hint + apresentação act badge).
    expect(screen.getAllByText('TRANSMISSÃO DE QUOTA').length).toBeGreaterThanOrEqual(2);
  });

  it('renders anotações with a publication link opened externally', async () => {
    const { fn } = recordingFetch((r) =>
      r.url.includes('/registry') ? jsonResponse(STRUCTURED_EXTRACT) : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<RegistryProvenance entityId="ent-1" />, ['/entidades/ent-1']);

    expect(await screen.findByText('Anotações')).toBeTruthy();
    expect(screen.getByText('An. 1')).toBeTruthy();
    expect(screen.getByText('Publicação da constituição.')).toBeTruthy();
    const link = screen.getByRole('link', {
      name: 'http://publicacoes.mj.pt',
    }) as HTMLAnchorElement;
    expect(link.getAttribute('href')).toBe('http://publicacoes.mj.pt');
    expect(link.getAttribute('target')).toBe('_blank');
  });

  it('shows the CERTIDÃO EXPIRADA badge and the certidão validity metadata', async () => {
    const { fn } = recordingFetch((r) =>
      r.url.includes('/registry') ? jsonResponse(STRUCTURED_EXTRACT) : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<RegistryProvenance entityId="ent-1" />, ['/entidades/ent-1']);

    expect(await screen.findByText('Certidão expirada')).toBeTruthy();
    // The validity window + conservatória/oficial surface in the provenance card.
    expect(screen.getByText(formatDate('2025-01-01'))).toBeTruthy();
    expect(screen.getAllByText('Conservatória do Registo Comercial Porto').length).toBeGreaterThan(
      0,
    );
  });
});

describe('RegistryImportPanel — expired warning', () => {
  it('surfaces the import report warnings verbatim', async () => {
    const report: RegistryImportReport = {
      entity: { ...ENTITY, id: 'ent-1' },
      extract: STRUCTURED_EXTRACT,
      applied: [],
      conflicts: [],
      warnings: ['certidão expirada em 2025-01-01'],
    };
    const { fn } = recordingFetch((r) =>
      r.url.includes('/registry/import') ? jsonResponse(report) : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<RegistryImportPanel entityId="ent-1" />, ['/entidades/ent-1']);

    fireEvent.change(screen.getByLabelText('Código da certidão permanente'), {
      target: { value: FULL_CODE },
    });
    fireEvent.click(screen.getByRole('button', { name: /consultar e importar/i }));

    expect(await screen.findByText('Avisos da importação')).toBeTruthy();
    expect(screen.getByText('certidão expirada em 2025-01-01')).toBeTruthy();
  });
});

describe('EntityPrintDocument — structured constitution', () => {
  it('includes the sócios/quotas table and órgãos when a constitution is present', async () => {
    const { fn } = recordingFetch((r) =>
      r.url.includes('/registry') ? jsonResponse(STRUCTURED_EXTRACT) : jsonResponse(ENTITY),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<EntityPrintDocument entityId="ent-1" />, ['/entidades/ent-1']);

    // The print sheet composes the structured constitution, not just the raw feed.
    expect(await screen.findByText('Sócios e quotas')).toBeTruthy();
    expect(screen.getByText('Rui Tavares')).toBeTruthy();
    expect(screen.getByText('99,00 Euros')).toBeTruthy();
    expect(screen.getByText('Órgãos designados')).toBeTruthy();
    // The raw text still prints beneath the structured card.
    expect(screen.getByText(RAW_CONSTITUTION_TEXT)).toBeTruthy();
    // Anotações section is composed too.
    expect(screen.getByText('An. 1')).toBeTruthy();
  });
});
