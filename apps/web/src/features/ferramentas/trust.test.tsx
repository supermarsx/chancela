import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { FerramentasPage } from './FerramentasPage';
import { TrustCatalogPage } from './TrustCatalogPage';
import type {
  TslCatalogView,
  TslProviderDetailView,
  TslRefreshStatusView,
  TslServiceDetailView,
  TslServiceSummaryView,
  TslSummaryView,
  TsaCatalogView,
} from '../../api/types';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const SUMMARY: TslSummaryView = {
  source: { kind: 'Fixture', path: null, note: 'Fixture TSL de teste.' },
  last_refresh: null,
  scheme_operator_name: 'Gabinete Nacional de Segurança',
  scheme_name: 'Lista de Confiança de Portugal',
  scheme_territory: 'PT',
  sequence_number: 42,
  issue_date_time: '2026-07-08T00:00:00Z',
  next_update: '2026-08-08T00:00:00Z',
  stale: false,
  validation: {
    checked_at: '2026-07-09T00:00:00Z',
    signature: 'Valid',
    error: null,
  },
  providers: 2,
  services: 3,
  ca_qc_services: 1,
  qualified_esignature_services: 1,
  trusted_esignature_services: 2,
};

const REFRESH_STATUS: TslRefreshStatusView = {
  attempted_at: '2026-07-09T10:00:00Z',
  source_kind: 'Url',
  source_url: 'https://www.gns.gov.pt/media/TSLPT.xml',
  source_path: null,
  target_path: 'F:\\Projects\\chancela\\chancela-data\\tsl.xml',
  outcome: 'Success',
  validation: {
    checked_at: '2026-07-09T10:00:00Z',
    signature: 'Invalid',
    error: 'fixture signature not trusted',
  },
  providers: 2,
  services: 3,
  ca_qc_services: 1,
  qualified_esignature_services: 1,
  trusted_esignature_services: 0,
  error: null,
};

const QUALIFIED_SERVICE: TslServiceSummaryView = {
  id: 'svc-qualified',
  provider_id: 'p-multicert',
  provider_name: 'MULTICERT S.A.',
  name: 'MULTICERT Qualified CA',
  service_type: 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
  status: { kind: 'Granted', uri: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted' },
  status_starting_time: '2024-01-01T00:00:00Z',
  status_starting_time_raw: '2024-01-01T00:00:00Z',
  ca_qc: true,
  qualified_for_esignatures: true,
  trusted_for_esignatures: true,
  additional_service_info: ['QCForESig'],
  service_supply_points: [],
  history_count: 1,
  identities: {
    certificates: 2,
    subject_names: ['CN=MULTICERT Qualified CA'],
    subject_key_ids: ['A1'],
  },
};

const TSA_SERVICE: TslServiceSummaryView = {
  id: 'svc-tsa',
  provider_id: 'p-multicert',
  provider_name: 'MULTICERT S.A.',
  name: 'MULTICERT Timestamping',
  service_type: 'http://uri.etsi.org/TrstSvc/Svctype/TSA',
  status: { kind: 'Granted', uri: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted' },
  status_starting_time: '2024-02-01T00:00:00Z',
  status_starting_time_raw: '2024-02-01T00:00:00Z',
  ca_qc: false,
  qualified_for_esignatures: false,
  trusted_for_esignatures: true,
  additional_service_info: [],
  service_supply_points: ['http://tsa.multicert.test/tsa'],
  history_count: 0,
  identities: {
    certificates: 1,
    subject_names: ['CN=MULTICERT TSA'],
    subject_key_ids: ['B2'],
  },
};

const WITHDRAWN_SERVICE: TslServiceSummaryView = {
  id: 'svc-withdrawn',
  provider_id: 'p-ama',
  provider_name: 'AMA',
  name: 'AMA Legacy CA',
  service_type: 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
  status: { kind: 'Withdrawn', uri: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn' },
  status_starting_time: null,
  status_starting_time_raw: 'not-a-date',
  ca_qc: true,
  qualified_for_esignatures: false,
  trusted_for_esignatures: false,
  additional_service_info: [],
  service_supply_points: [],
  history_count: 0,
  identities: {
    certificates: 1,
    subject_names: ['CN=AMA Legacy CA'],
    subject_key_ids: ['C3'],
  },
};

const CATALOG: TslCatalogView = {
  summary: SUMMARY,
  providers: [
    {
      id: 'p-multicert',
      name: 'MULTICERT S.A.',
      trade_names: ['MULTICERT'],
      information_uris: ['https://www.multicert.pt'],
      analysis: {
        services: 2,
        granted_services: 2,
        withdrawn_services: 0,
        other_status_services: 0,
        services_with_history: 1,
        services_with_supply_points: 1,
        ca_qc_services: 1,
        qualified_esignature_services: 1,
        trusted_esignature_services: 1,
        duplicate_service_names: ['MULTICERT Qualified CA'],
      },
      services: [QUALIFIED_SERVICE, TSA_SERVICE],
    },
    {
      id: 'p-ama',
      name: 'AMA',
      trade_names: [],
      information_uris: ['https://www.ama.gov.pt'],
      analysis: {
        services: 1,
        granted_services: 0,
        withdrawn_services: 1,
        other_status_services: 0,
        services_with_history: 0,
        services_with_supply_points: 0,
        ca_qc_services: 1,
        qualified_esignature_services: 0,
        trusted_esignature_services: 0,
        duplicate_service_names: [],
      },
      services: [WITHDRAWN_SERVICE],
    },
  ],
};

const TSA_CATALOG: TsaCatalogView = {
  summary: {
    configured_url: 'http://ts.cartaodecidadao.pt/tsa/server',
    status: 'Ready',
    status_message:
      'TSA URL configured; offline RFC 3161 fixture probe passed. No live TSA request was sent.',
    profile: {
      protocol: 'RFC 3161 Time-Stamp Protocol',
      hash_algorithm: 'SHA-256',
      request_content_type: 'application/timestamp-query',
      response_content_type: 'application/timestamp-reply',
      nonce_policy: 'request nonce must be echoed when present',
      cert_req_default: true,
      accepted_policy: 'Any',
    },
    accepted_hash: {
      algorithm: 'SHA-256',
      input: 'abc',
      digest: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    },
    timestamp: {
      gen_time: '2023-06-07T11:26:26Z',
      policy: '1.2.3.4.1',
      serial_number: '04',
      token_sha256: 'd'.repeat(64),
      token_bytes: 2048,
      tsa_certificate_embedded: false,
    },
    last_probe: {
      kind: 'Fixture',
      status: 'Passed',
      checked_at: '2026-07-09T00:00:00Z',
      request_der_sha256: 'a'.repeat(64),
      response_der_sha256: 'b'.repeat(64),
      request_matches_fixture: true,
      error: null,
    },
    tsl: { source: SUMMARY.source, signature: 'Invalid', error: 'fixture signature not trusted' },
    records: 1,
    granted_records: 1,
    trusted_records: 0,
    policy_analysis: {
      accepted_policy: 'Any',
      fixture_policy: '1.2.3.4.1',
      fixture_policy_accepted: true,
      qualified_timestamp_records: 1,
      trusted_qualified_timestamp_records: 0,
      advisory: true,
    },
  },
  records: [
    {
      id: 'svc-tsa',
      provider_id: 'p-tsa',
      provider_name: 'Cartorio Notarial Timestamping',
      name: 'Qualified Timestamping Authority',
      service_type: 'http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST',
      status: { kind: 'Granted', uri: null },
      status_starting_time: '2019-01-01T00:00:00Z',
      status_starting_time_raw: '2019-01-01T00:00:00Z',
      qualified_timestamp_service: true,
      granted: true,
      effective: true,
      trusted: false,
      additional_service_info: [],
      service_supply_points: ['http://tsa.cartorio.example.test/tsa/server'],
      history_count: 0,
      identities: {
        certificates: 1,
        subject_names: ['CN=Qualified Timestamping Authority,O=Cartorio Notarial,C=PT'],
        subject_key_ids: ['91b78a4499dc5fa769175c6b8ba32b9b4d8528a6'],
      },
      analysis: {
        classification: 'QualifiedTimestampService',
        trust_basis: 'AdvisoryOnlyInvalidTslSignature',
        blocking_reasons: ['TSL signature is not valid; record is advisory'],
      },
    },
  ],
};

const PROVIDER_DETAIL: TslProviderDetailView = {
  provider: CATALOG.providers[0],
  summary: SUMMARY,
};

const SERVICE_DETAILS: Record<string, TslServiceDetailView> = {
  'svc-qualified': {
    ...QUALIFIED_SERVICE,
    summary: SUMMARY,
    digital_identities: [
      {
        kind: 'X509Certificate',
        value: 'MIID-qualified-test',
        sha256: 'b'.repeat(64),
        byte_length: 1024,
      },
    ],
    history: [
      {
        name: 'MULTICERT Qualified CA legacy',
        service_type: 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
        status: { kind: 'Withdrawn', uri: null },
        status_starting_time: '2020-01-01T00:00:00Z',
        status_starting_time_raw: '2020-01-01T00:00:00Z',
        additional_service_info: [],
        service_supply_points: [],
        identities: {
          certificates: 0,
          subject_names: [],
          subject_key_ids: ['00'],
        },
      },
    ],
  },
  'svc-tsa': {
    ...TSA_SERVICE,
    summary: SUMMARY,
    digital_identities: [
      { kind: 'X509Certificate', value: 'MIID-tsa-test', sha256: 'c'.repeat(64), byte_length: 512 },
    ],
    history: [],
  },
};

const TRUST_QUERY_KEYS = ['search', 'service_type', 'status', 'history', 'supply_point'];

function foldFixture(value: string): string {
  return value
    .normalize('NFD')
    .replace(/\p{Diacritic}/gu, '')
    .toLowerCase();
}

function fixtureIncludes(values: string[], term: string | null): boolean {
  if (!term?.trim()) return true;
  const folded = foldFixture(term.trim());
  return values.some((value) => foldFixture(value).includes(folded));
}

function hasTrustQuery(params: URLSearchParams): boolean {
  return TRUST_QUERY_KEYS.some((key) => params.has(key));
}

function serviceMatchesFixtureQuery(
  service: TslServiceSummaryView,
  params: URLSearchParams,
): boolean {
  return (
    fixtureIncludes(
      [
        service.name,
        service.provider_name,
        service.service_type,
        service.status.kind,
        service.status.uri ?? '',
        service.status_starting_time_raw ?? '',
        ...service.additional_service_info,
        ...service.service_supply_points,
        ...service.identities.subject_names,
        ...service.identities.subject_key_ids,
      ],
      params.get('search'),
    ) &&
    fixtureIncludes([service.service_type], params.get('service_type')) &&
    fixtureIncludes([service.status.kind, service.status.uri ?? ''], params.get('status')) &&
    (params.get('history') !== 'any' || service.history_count > 0) &&
    (params.get('supply_point') !== 'any' || service.service_supply_points.length > 0)
  );
}

function tsaMatchesFixtureQuery(record: TsaCatalogView['records'][number], params: URLSearchParams) {
  return (
    fixtureIncludes(
      [
        record.name,
        record.provider_name,
        record.service_type,
        record.status.kind,
        record.status.uri ?? '',
        record.status_starting_time_raw ?? '',
        ...record.additional_service_info,
        ...record.service_supply_points,
        ...record.identities.subject_names,
        ...record.identities.subject_key_ids,
        record.analysis.classification,
        record.analysis.trust_basis,
        ...record.analysis.blocking_reasons,
      ],
      params.get('search'),
    ) &&
    fixtureIncludes([record.service_type], params.get('service_type')) &&
    fixtureIncludes([record.status.kind, record.status.uri ?? ''], params.get('status')) &&
    (params.get('history') !== 'any' || record.history_count > 0) &&
    (params.get('supply_point') !== 'any' || record.service_supply_points.length > 0)
  );
}

function requestMatching(
  fetchMock: ReturnType<typeof vi.fn>,
  path: string,
  expected: Record<string, string>,
): boolean {
  return fetchMock.mock.calls.some(([input]) => {
    const url = new URL(String(input), 'http://localhost');
    return (
      url.pathname === path &&
      Object.entries(expected).every(([key, value]) => url.searchParams.get(key) === value)
    );
  });
}

function trustFetch(): typeof fetch {
  let summary = SUMMARY;
  return ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const parsed = new URL(url, 'http://localhost');
    const method = init?.method ?? (input instanceof Request ? input.method : 'GET');
    if (parsed.pathname === '/v1/trust/refresh' && method === 'POST') {
      summary = { ...SUMMARY, source: { ...SUMMARY.source, kind: 'Cache' }, last_refresh: REFRESH_STATUS };
      return Promise.resolve(jsonResponse(REFRESH_STATUS));
    }
    if (parsed.pathname === '/v1/trust/tsa') {
      return Promise.resolve(
        jsonResponse(
          hasTrustQuery(parsed.searchParams)
            ? TSA_CATALOG.records.filter((record) =>
                tsaMatchesFixtureQuery(record, parsed.searchParams),
              )
            : TSA_CATALOG,
        ),
      );
    }
    if (url.includes('/v1/trust/status')) return Promise.resolve(jsonResponse(summary));
    if (url.includes('/v1/trust/providers/p-multicert'))
      return Promise.resolve(jsonResponse(PROVIDER_DETAIL));
    const serviceId = url.match(/\/v1\/trust\/services\/([^?]+)/)?.[1];
    if (serviceId) {
      const detail = SERVICE_DETAILS[decodeURIComponent(serviceId)];
      return Promise.resolve(
        detail ? jsonResponse(detail) : jsonResponse({ error: 'unknown service' }, 404),
      );
    }
    if (parsed.pathname === '/v1/trust/catalog') {
      return Promise.resolve(
        jsonResponse(
          hasTrustQuery(parsed.searchParams)
            ? CATALOG.providers
                .flatMap((provider) => provider.services)
                .filter((service) => serviceMatchesFixtureQuery(service, parsed.searchParams))
            : CATALOG,
        ),
      );
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('Ferramentas — TSL trust catalog', () => {
  it('exposes the trust section and renders scheme/source/signature status', async () => {
    vi.stubGlobal('fetch', trustFetch());
    renderWithProviders(<FerramentasPage />, ['/ferramentas?tool=trust']);

    expect(
      screen.getByRole('button', { name: 'Lista de confiança' }).getAttribute('aria-pressed'),
    ).toBe('true');
    expect(await screen.findByText('Gabinete Nacional de Segurança')).toBeTruthy();
    expect(screen.getByText('Assinatura válida')).toBeTruthy();
    expect(screen.getByText('TSA / RFC 3161')).toBeTruthy();
    expect(screen.getAllByText('Fixture OK').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByRole('group', { name: 'Resumo TSL' })).toBeTruthy();
    expect(screen.getByRole('group', { name: 'Cobertura' })).toBeTruthy();
  });

  it('imports the TSL on operator request and renders the persisted attempt status', async () => {
    const fetchMock = vi.fn(trustFetch());
    vi.stubGlobal('fetch', fetchMock);
    renderWithProviders(<TrustCatalogPage />, ['/ferramentas?tool=trust']);

    await screen.findByRole('group', { name: 'Resumo TSL' });
    fireEvent.click(screen.getByRole('button', { name: 'Atualizar TSL' }));

    await waitFor(() =>
      expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/v1/trust/refresh'))).toBe(
        true,
      ),
    );
    const attempt = await screen.findByRole('group', { name: 'Última tentativa de importação' });
    expect(attempt).toBeTruthy();
    expect(screen.getByText('Importado')).toBeTruthy();
    expect(screen.getByText('https://www.gns.gov.pt/media/TSLPT.xml')).toBeTruthy();
    expect(within(attempt).getByText('2 prestadores · 3 serviços')).toBeTruthy();
    expect(screen.getAllByText('Assinatura inválida').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('fixture signature not trusted')).toBeTruthy();
  });

  it('renders TSA diagnostics and filters timestamp authority records', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const fetchMock = vi.fn(trustFetch());
    vi.stubGlobal('fetch', fetchMock);
    renderWithProviders(<TrustCatalogPage />, ['/ferramentas?tool=trust']);

    const acceptedHash = TSA_CATALOG.summary.accepted_hash.digest;

    const tsaSummary = await screen.findByRole('group', { name: 'Resumo TSA' });
    expect(within(tsaSummary).getByText('http://ts.cartaodecidadao.pt/tsa/server')).toBeTruthy();
    expect(within(tsaSummary).getByText('Pronto')).toBeTruthy();
    expect(within(tsaSummary).getByText('Fixture OK')).toBeTruthy();
    expect(screen.getByRole('group', { name: 'Configuração' })).toBeTruthy();
    expect(screen.getByRole('group', { name: 'Fixture e prova' })).toBeTruthy();
    expect(screen.getByRole('group', { name: 'Token de timestamp' })).toBeTruthy();
    expect(screen.getByRole('group', { name: 'Registos TSL' })).toBeTruthy();
    expect(screen.getByRole('group', { name: 'Filtros TSA' })).toBeTruthy();

    const acceptedHashGroup = screen.getByRole('group', {
      name: `Hash aceite completo: ${acceptedHash}`,
    });
    const acceptedHashValue = within(acceptedHashGroup).getByTitle(acceptedHash);
    expect(acceptedHashValue.textContent).toBe('ba7816bf…f20015ad');
    expect(acceptedHashValue.textContent).not.toBe(acceptedHash);
    expect(acceptedHashGroup.closest('.trust-digest-cell')).toBeTruthy();
    fireEvent.click(within(acceptedHashGroup).getByRole('button', { name: /copiar/i }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(acceptedHash));
    expect(screen.getByText('1.2.3.4.1 / 04')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Procurar registos TSA'), {
      target: { value: 'qtst' },
    });
    fireEvent.change(document.querySelector('#tsa-type-filter') as HTMLSelectElement, {
      target: { value: 'qtst' },
    });
    await waitFor(() =>
      expect(
        requestMatching(fetchMock, '/v1/trust/tsa', {
          search: 'qtst',
          service_type: 'TSA/QTST',
        }),
      ).toBe(true),
    );
    fireEvent.click(
      await screen.findByRole('button', { name: /Qualified Timestamping Authority/i }),
    );

    const subjectName = await screen.findByText(
      'CN=Qualified Timestamping Authority,O=Cartorio Notarial,C=PT',
    );
    expect(subjectName.closest('[aria-live]')).toBeNull();
    expect(screen.getByRole('group', { name: 'Identidades' })).toBeTruthy();
    expect(screen.getByRole('group', { name: 'Pontos de serviço' })).toBeTruthy();
    expect(screen.getByText('http://tsa.cartorio.example.test/tsa/server')).toBeTruthy();
    expect(screen.getByText('TSL signature is not valid; record is advisory')).toBeTruthy();
    expect(screen.getAllByText('Advisório').length).toBeGreaterThanOrEqual(1);
  });

  it('searches services and opens the selected service detail', async () => {
    vi.stubGlobal('fetch', trustFetch());
    renderWithProviders(<TrustCatalogPage />, ['/ferramentas?tool=trust']);

    expect(await screen.findByRole('group', { name: 'Filtros TSL' })).toBeTruthy();
    fireEvent.change(await screen.findByLabelText('Procurar na lista de confiança TSL'), {
      target: { value: 'qualified' },
    });
    fireEvent.click(await screen.findByRole('button', { name: /MULTICERT Qualified CA/i }));

    expect(await screen.findByText('Identidades digitais')).toBeTruthy();
    expect(screen.getByText('MIID-qualified-test')).toBeTruthy();
    const historyEntry = screen.getByText('MULTICERT Qualified CA legacy');
    expect(historyEntry.closest('[role="group"]')?.getAttribute('aria-label')).toBe('Histórico');
    expect(screen.queryByText('AMA Legacy CA')).toBeNull();
  });

  it('filters to providers and drills from provider detail into a service', async () => {
    vi.stubGlobal('fetch', trustFetch());
    renderWithProviders(<TrustCatalogPage />, ['/ferramentas?tool=trust']);

    fireEvent.click(await screen.findByRole('button', { name: 'Prestadores' }));
    fireEvent.click(await screen.findByRole('button', { name: /MULTICERT S\.A\./i }));

    expect(await screen.findByText('Nomes comerciais')).toBeTruthy();
    expect(screen.getByText('MULTICERT')).toBeTruthy();
    expect(screen.getByText('Nomes duplicados')).toBeTruthy();
    expect(screen.getAllByText('MULTICERT Qualified CA').length).toBeGreaterThanOrEqual(1);

    fireEvent.click(screen.getByRole('button', { name: /MULTICERT Timestamping/i }));
    expect(await screen.findByText('MIID-tsa-test')).toBeTruthy();
  });

  it('shows empty states for structured no-match filters', async () => {
    const fetchMock = vi.fn(trustFetch());
    vi.stubGlobal('fetch', fetchMock);
    renderWithProviders(<TrustCatalogPage />, ['/ferramentas?tool=trust']);

    fireEvent.change(await screen.findByLabelText('Procurar na lista de confiança TSL'), {
      target: { value: 'qualified' },
    });
    fireEvent.change(document.querySelector('#trust-type-filter') as HTMLSelectElement, {
      target: { value: 'caqc' },
    });
    const trustStatusFilter = document.querySelector('#trust-status-filter') as HTMLSelectElement;
    fireEvent.change(trustStatusFilter, { target: { value: 'Other' } });

    await waitFor(() =>
      expect(
        requestMatching(fetchMock, '/v1/trust/catalog', {
          search: 'qualified',
          service_type: 'CA/QC',
          status: 'Other',
        }),
      ).toBe(true),
    );
    expect(await screen.findByText('Sem resultados')).toBeTruthy();
    expect(screen.getByText(/Nenhum prestador ou serviço corresponde/)).toBeTruthy();
  });
});
