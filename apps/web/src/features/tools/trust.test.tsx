import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { getByRevealedText, renderWithProviders } from '../../test/utils';
import { ptPT } from '../../i18n/locales/pt-PT';
import { trustSectionsPtPT } from '../../i18n/trustSectionsFallback';
import { ToolsPage } from './ToolsPage';
import { TrustCatalogPage } from './TrustCatalogPage';
import type {
  TslCatalogView,
  TslProviderDetailView,
  TslRefreshStatusView,
  TslServiceDetailView,
  TslServiceSummaryView,
  TslSummaryView,
  TslValidationView,
  TsaCatalogView,
  TrustIdentifierMatchField,
  WeakAlgorithmUse,
} from '../../api/types';
import { TSL_LEGACY_ALGORITHMS } from '../../api/types';

async function themeSource(): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8').replace(/\r\n/g, '\n');
}

/**
 * The banner entry for one concern, once it has rendered.
 *
 * Queried by id rather than by its heading text, because the heading is deliberately also the
 * marker icon's accessible name and its tooltip bubble — three copies of the same sentence, of
 * which exactly one is the entry. Structure disambiguates; a text query cannot.
 */
async function concernEntry(group: string, slug: string): Promise<HTMLElement> {
  const id = `trust-concern-${group}-${slug}`;
  return (await waitFor(() => {
    const found = document.getElementById(id);
    expect(found).not.toBeNull();
    return found;
  })) as HTMLElement;
}

/** The status-line icon for one concern, or `null` when the screen raises none for it. */
function concernMarker(slug: string): HTMLAnchorElement | null {
  return document.querySelector(
    `.trust-statusline__item--concerns a[data-trust-concern="${slug}"]`,
  );
}

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

const TRUST_QUERY_KEYS = [
  'search',
  'identifier',
  'service_type',
  'status',
  'history',
  'supply_point',
];

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

function serviceIdentifierValues(service: TslServiceSummaryView): string[] {
  const detail = SERVICE_DETAILS[service.id];
  return [
    service.name,
    service.provider_name,
    service.service_type,
    ...service.service_supply_points,
    ...service.identities.subject_names,
    ...service.identities.subject_key_ids,
    ...(detail?.digital_identities.flatMap((identity) => [
      identity.kind,
      identity.value,
      identity.sha256 ?? '',
    ]) ?? []),
  ];
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
    fixtureIncludes(serviceIdentifierValues(service), params.get('identifier')) &&
    fixtureIncludes([service.status.kind, service.status.uri ?? ''], params.get('status')) &&
    (params.get('history') !== 'any' || service.history_count > 0) &&
    (params.get('supply_point') !== 'any' || service.service_supply_points.length > 0)
  );
}

function tsaMatchesFixtureQuery(
  record: TsaCatalogView['records'][number],
  params: URLSearchParams,
) {
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
    fixtureIncludes(
      [
        record.name,
        record.provider_name,
        record.service_type,
        ...record.service_supply_points,
        ...record.identities.subject_names,
        ...record.identities.subject_key_ids,
      ],
      params.get('identifier'),
    ) &&
    fixtureIncludes([record.status.kind, record.status.uri ?? ''], params.get('status')) &&
    (params.get('history') !== 'any' || record.history_count > 0) &&
    (params.get('supply_point') !== 'any' || record.service_supply_points.length > 0)
  );
}

function pushIdentifierMatch(
  fields: TrustIdentifierMatchField[],
  field: TrustIdentifierMatchField,
) {
  if (!fields.includes(field)) fields.push(field);
}

function compactHexIdentifier(value: string): string | null {
  const compact = value.replace(/[:\-\s]/g, '').toLowerCase();
  if (!compact) return null;
  return /^[0-9a-f]+$/.test(compact) ? compact : null;
}

function serviceIdentifierMatch(
  service: TslServiceSummaryView,
  identifier: string | null,
): TrustIdentifierMatchField[] | undefined {
  const trimmed = identifier?.trim();
  if (!trimmed) return undefined;
  const compact = compactHexIdentifier(trimmed);
  const detail = SERVICE_DETAILS[service.id];
  if (compact?.length === 64) {
    return detail?.digital_identities.some((identity) => identity.sha256?.toLowerCase() === compact)
      ? ['certificate_sha256']
      : undefined;
  }
  if (compact?.length === 40) {
    return service.identities.subject_key_ids.some((ski) => ski.toLowerCase() === compact)
      ? ['subject_key_id']
      : undefined;
  }
  if (compact) return undefined;

  const fields: TrustIdentifierMatchField[] = [];
  if (fixtureIncludes(service.identities.subject_names, trimmed)) {
    pushIdentifierMatch(fields, 'subject_name');
  }
  if (fixtureIncludes([service.provider_name], trimmed)) pushIdentifierMatch(fields, 'provider');
  if (fixtureIncludes([service.name, service.service_type], trimmed)) {
    pushIdentifierMatch(fields, 'service');
  }
  if (fixtureIncludes(service.service_supply_points, trimmed)) {
    pushIdentifierMatch(fields, 'supply_point');
  }
  return fields.length ? fields : undefined;
}

function withServiceIdentifierMatch(
  service: TslServiceSummaryView,
  params: URLSearchParams,
): TslServiceSummaryView {
  const identifier_match = serviceIdentifierMatch(service, params.get('identifier'));
  return identifier_match ? { ...service, identifier_match } : service;
}

function tsaIdentifierMatch(
  record: TsaCatalogView['records'][number],
  identifier: string | null,
): TrustIdentifierMatchField[] | undefined {
  const trimmed = identifier?.trim();
  if (!trimmed) return undefined;
  const compact = compactHexIdentifier(trimmed);
  if (compact?.length === 40) {
    return record.identities.subject_key_ids.some((ski) => ski.toLowerCase() === compact)
      ? ['subject_key_id']
      : undefined;
  }
  if (compact?.length === 64) return undefined;
  if (compact) return undefined;

  const fields: TrustIdentifierMatchField[] = [];
  if (fixtureIncludes(record.identities.subject_names, trimmed)) {
    pushIdentifierMatch(fields, 'subject_name');
  }
  if (fixtureIncludes([record.provider_name], trimmed)) pushIdentifierMatch(fields, 'provider');
  if (fixtureIncludes([record.name, record.service_type], trimmed)) {
    pushIdentifierMatch(fields, 'service');
  }
  if (fixtureIncludes(record.service_supply_points, trimmed)) {
    pushIdentifierMatch(fields, 'supply_point');
  }
  return fields.length ? fields : undefined;
}

function withTsaIdentifierMatch(
  record: TsaCatalogView['records'][number],
  params: URLSearchParams,
): TsaCatalogView['records'][number] {
  const identifier_match = tsaIdentifierMatch(record, params.get('identifier'));
  return identifier_match ? { ...record, identifier_match } : record;
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

/**
 * The stub, optionally with a weak-algorithm reliance attached to every Trusted List verdict it
 * serves — the TSL status, the import status the refresh returns, and the TSA panel's own list.
 *
 * All three, deliberately. The backend attaches `weak_algorithms` to each independently, and a
 * marker wired to one screen and not the others would leave "validated because SHA-1 was allowed"
 * looking exactly like a clean verdict everywhere it was not wired.
 */
function trustFetch(weak?: readonly WeakAlgorithmUse[]): typeof fetch {
  const withWeak = <T extends { validation: TslValidationView }>(view: T): T =>
    weak ? { ...view, validation: { ...view.validation, weak_algorithms: [...weak] } } : view;
  const refreshStatus = withWeak(REFRESH_STATUS);
  const tsaCatalog: TsaCatalogView = weak
    ? {
        ...TSA_CATALOG,
        summary: {
          ...TSA_CATALOG.summary,
          tsl: { ...TSA_CATALOG.summary.tsl, weak_algorithms: [...weak] },
        },
      }
    : TSA_CATALOG;
  let summary = withWeak(SUMMARY);
  return ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const parsed = new URL(url, 'http://localhost');
    const method = init?.method ?? (input instanceof Request ? input.method : 'GET');
    if (parsed.pathname === '/v1/trust/refresh' && method === 'POST') {
      summary = {
        ...withWeak(SUMMARY),
        source: { ...SUMMARY.source, kind: 'Cache' },
        last_refresh: refreshStatus,
      };
      return Promise.resolve(jsonResponse(refreshStatus));
    }
    if (parsed.pathname === '/v1/trust/tsa') {
      return Promise.resolve(
        jsonResponse(
          hasTrustQuery(parsed.searchParams)
            ? tsaCatalog.records
                .filter((record) => tsaMatchesFixtureQuery(record, parsed.searchParams))
                .map((record) => withTsaIdentifierMatch(record, parsed.searchParams))
            : tsaCatalog,
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
                .map((service) => withServiceIdentifierMatch(service, parsed.searchParams))
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
  /**
   * The at-use-time half of the legacy-algorithm feature.
   *
   * Permitting a broken algorithm is configured once, on a settings screen an operator may never
   * open again. The verdicts it changes are read constantly, and "signature valid" and "signature
   * valid because SHA-1 was allowed" are different facts. These tests pin that the second is
   * visibly the second — and, in the clean case below, that it is NOT, so the marker is a real
   * signal and not decoration that is always on.
   *
   * Both `site` shapes are exercised, because they are structurally different: `signature_method`
   * carries nothing but the algorithm, while `reference` carries a 1-based position and the
   * reference URI. A renderer that narrowed the discriminant wrongly would still compile.
   */
  const WEAK_USES: WeakAlgorithmUse[] = [
    {
      code: 'tsl_weak_signature_method_permitted',
      algorithm: TSL_LEGACY_ALGORITHMS[1],
      site: 'signature_method',
    },
    {
      code: 'tsl_weak_digest_permitted',
      algorithm: TSL_LEGACY_ALGORITHMS[0],
      site: 'reference',
      index: 2,
      total: 2,
      uri: '#signed-props-1',
    },
  ];

  it('marks a Trusted List verdict that leaned on a permitted broken algorithm', async () => {
    vi.stubGlobal('fetch', trustFetch(WEAK_USES));
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);

    const entry = await concernEntry('tsl-status', 'weak-algorithms');
    const banner = entry.closest('.inline-warning') as HTMLElement;
    // A property of the verdict on screen, not an announcement: it must come back next time.
    expect(banner.hasAttribute('data-notice')).toBe(false);

    const list = entry.querySelector('[data-weak-algorithms]') as HTMLElement;
    expect(list.dataset.weakAlgorithms).toBe(String(WEAK_USES.length));
    expect(list.querySelectorAll('li')).toHaveLength(WEAK_USES.length);

    // The two codes word two different facts; both are present, neither collapsed into the other.
    expect(entry.textContent).toContain(ptPT['trust.weakAlgorithms.signatureMethod']);
    expect(entry.textContent).toContain(ptPT['trust.weakAlgorithms.digest']);
    expect(entry.textContent).not.toContain(ptPT['trust.weakAlgorithms.unknown']);

    // The algorithm URI reaches every locale verbatim — it is what the settings document holds
    // and what a 422 names — so it is asserted as the wire value, never as translated copy.
    for (const use of WEAK_USES) expect(entry.textContent).toContain(use.algorithm);
    // …and the `reference` arm's position, which the `signature_method` arm does not have.
    expect(entry.textContent).toContain('#signed-props-1');
    expect(entry.textContent).toContain(
      ptPT['trust.weakAlgorithms.reference']
        .replace('{index}', '2')
        .replace('{total}', '2')
        .replace('{uri}', '#signed-props-1'),
    );

    // The two strings the status-line cell used to carry did not vanish with the cell: they head
    // the entry. Losing them was the obvious way for this restructure to quietly cost information.
    expect(entry.textContent).toContain(ptPT['trust.weakAlgorithms.label']);
    expect(entry.textContent).toContain(ptPT['trust.weakAlgorithms.badge']);

    // The scan line an operator reads first now carries an icon and nothing else, and that icon
    // is a real link to this entry, named for it.
    const marker = concernMarker('weak-algorithms') as HTMLAnchorElement;
    expect(marker.getAttribute('href')).toBe(`#${entry.id}`);
    expect(marker.getAttribute('aria-label')).toBe(ptPT['trust.weakAlgorithms.title']);
  });

  it('shows no weak-algorithm marker when the verdict stood on strong algorithms alone', async () => {
    // The whole design intent: on an untouched install nothing here is permitted, so the marker
    // must be absent. A marker that were always on would carry no information at all.
    vi.stubGlobal('fetch', trustFetch());
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);

    await screen.findByText(ptPT['trust.status.signature']);
    expect(screen.queryByText(ptPT['trust.weakAlgorithms.title'])).toBeNull();
    expect(screen.queryByText(ptPT['trust.weakAlgorithms.badge'])).toBeNull();
    expect(document.querySelector('[data-weak-algorithms]')).toBeNull();
  });

  it('carries the marker onto the TSA panel, whose records come from a list of their own', async () => {
    vi.stubGlobal('fetch', trustFetch(WEAK_USES));
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust/tsa']);

    const entry = await concernEntry('tsa-summary', 'weak-algorithms');
    expect(entry.textContent).toContain(ptPT['trust.weakAlgorithms.title']);
    expect(concernMarker('weak-algorithms')?.getAttribute('href')).toBe(`#${entry.id}`);
  });

  it('words a weak-algorithm code this build does not know rather than falling silent', async () => {
    // A server newer than this bundle can emit a code that did not exist when these translations
    // were written. Falling back to silence would let a newer backend turn the warning off; the
    // fallback still says a broken algorithm was relied upon, and declines only to say which kind.
    const future = [
      {
        code: 'tsl_weak_future_permitted',
        algorithm: 'http://www.w3.org/2001/04/xmldsig-more#hmac-md5',
        site: 'signature_method',
      } as unknown as WeakAlgorithmUse,
    ];
    vi.stubGlobal('fetch', trustFetch(future));
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);

    const entry = await concernEntry('tsl-status', 'weak-algorithms');
    expect(entry.textContent).toContain(ptPT['trust.weakAlgorithms.unknown']);
    expect(entry.textContent).not.toContain(ptPT['trust.weakAlgorithms.signatureMethod']);
    // The URI is still shown verbatim: it is the one thing that identifies what happened.
    expect(entry.textContent).toContain('http://www.w3.org/2001/04/xmldsig-more#hmac-md5');
  });

  it('keeps trust diagnostics and both catalog explorers in one stacked column at every width', async () => {
    const css = await themeSource();
    const diagnosticsRule = css.match(/\.trust-diagnostics-grid\s*\{([^}]*)\}/)?.[1] ?? '';
    const explorerRule = css.match(/\.trust-explorer\s*\{([^}]*)\}/)?.[1] ?? '';

    expect(diagnosticsRule).toMatch(/grid-template-columns:\s*1fr;/);
    expect(diagnosticsRule).not.toContain('auto-fit');
    expect(css.match(/\.trust-diagnostics-grid\s*\{/g)).toHaveLength(1);
    expect(explorerRule).toMatch(/grid-template-columns:\s*1fr;/);
    expect(css.match(/\.trust-explorer\s*\{/g)).toHaveLength(1);
  });

  it('gives TSA fact labels a stable desktop width and releases it in the mobile stack', async () => {
    const css = await themeSource();
    const firstColumn =
      css.match(/\.trust-tsa\s+\.trust-fact-table\s+\.table\s+th:first-child\s*\{([^}]*)\}/)?.[1] ??
      '';
    const mobileCells =
      css.match(
        /\.trust-tsa\s+\.trust-fact-table\s+\.table\s+tbody\s+th,\s*\.trust-tsa\s+\.trust-fact-table\s+\.table\s+tbody\s+td\s*\{([^}]*)\}/,
      )?.[1] ?? '';

    expect(firstColumn).toMatch(/width:\s*12rem;/);
    expect(firstColumn).toMatch(/min-width:\s*12rem;/);
    expect(css).toMatch(
      /\.trust-tsa\s+\.trust-fact-table\s+\.table\s+th,\s*\.trust-tsa\s+\.trust-fact-table\s+\.table\s+td\s*\{[^}]*padding:\s*0\.65rem\s+0\.8rem;/s,
    );
    expect(mobileCells).toMatch(/display:\s*block;/);
    expect(mobileCells).toMatch(/width:\s*auto;/);
    expect(mobileCells).toMatch(/min-width:\s*0;/);
  });

  it('splits the trust surface into TSL and TSA sub-tabs', async () => {
    vi.stubGlobal('fetch', trustFetch());
    renderWithProviders(<ToolsPage />, ['/tools/trust']);

    // The level-1 tool stays "Lista de confiança"; TSL is the default sub-tab, so `/tools/trust`
    // paints the Trusted List and the TSA panel is NOT co-rendered on the same page any more.
    expect(
      screen.getByRole('button', { name: 'Lista de confiança' }).getAttribute('aria-pressed'),
    ).toBe('true');
    expect(await screen.findByText('Gabinete Nacional de Segurança')).toBeTruthy();
    expect(screen.getByText('Assinatura válida')).toBeTruthy();
    expect(screen.getByRole('group', { name: 'Resumo TSL' })).toBeTruthy();
    expect(screen.getByRole('group', { name: 'Cobertura' })).toBeTruthy();
    expect(screen.queryByText('TSA / RFC 3161')).toBeNull();

    // Switching to the TSA sub-tab reveals the timestamp-authority diagnostics and drops the
    // Trusted List panels — the two domains live on their own tabs now.
    fireEvent.click(screen.getByRole('button', { name: 'Selos temporais (TSA)' }));
    expect(await screen.findByText('TSA / RFC 3161')).toBeTruthy();
    expect((await screen.findAllByText('Fixture OK')).length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByRole('group', { name: 'Resumo TSL' })).toBeNull();
  });

  it('imports the TSL on operator request and renders the persisted attempt status', async () => {
    const fetchMock = vi.fn(trustFetch());
    vi.stubGlobal('fetch', fetchMock);
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);

    await screen.findByRole('group', { name: 'Resumo TSL' });
    fireEvent.click(screen.getByRole('button', { name: 'Atualizar TSL' }));

    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(([input]) => String(input).includes('/v1/trust/refresh')),
      ).toBe(true),
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
    // TSA now has its own sub-tab; deep-link straight to it.
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust/tsa']);

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
    const acceptedHashValue = getByRevealedText(acceptedHash, acceptedHashGroup);
    expect(acceptedHashValue.textContent).toBe('ba7816bf…f20015ad');
    expect(acceptedHashValue.textContent).not.toBe(acceptedHash);
    expect(acceptedHashGroup.classList.contains('trust-accepted-hash')).toBe(true);
    expect(acceptedHashValue.classList.contains('digest__value')).toBe(true);
    // t31: the full hash moved off the native `title` onto the described tooltip bubble —
    // which `getByRevealedText` above already matched on, so it is announced, not just present.
    expect(acceptedHashValue.getAttribute('title')).toBeNull();
    expect(acceptedHashGroup.closest('.trust-digest-cell')).toBeTruthy();
    fireEvent.click(within(acceptedHashGroup).getByRole('button', { name: /copiar/i }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(acceptedHash));
    expect(screen.getByText('1.2.3.4.1 / 04')).toBeTruthy();
    const tsaRecordsGroup = screen.getByRole('group', { name: 'Registos TSA' });
    expect(tsaRecordsGroup.classList.contains('trust-result-group')).toBe(true);
    expect(within(tsaRecordsGroup).getByRole('list', { name: 'Registos TSA' })).toBeTruthy();

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
    expect(screen.getAllByText('Consultivo').length).toBeGreaterThanOrEqual(1);
  });

  it('searches services and opens the selected service detail', async () => {
    vi.stubGlobal('fetch', trustFetch());
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);

    expect(await screen.findByRole('group', { name: 'Filtros TSL' })).toBeTruthy();
    const providersGroup = await screen.findByRole('group', { name: 'Prestadores' });
    const servicesGroup = screen.getByRole('group', { name: 'Serviços' });
    expect(providersGroup.classList.contains('trust-result-group')).toBe(true);
    expect(servicesGroup.classList.contains('trust-result-group')).toBe(true);
    expect(within(providersGroup).getByRole('list', { name: 'Prestadores' })).toBeTruthy();
    expect(within(servicesGroup).getByRole('list', { name: 'Serviços' })).toBeTruthy();
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

  it('passes identifier lookups to the TSL catalog endpoint and renders matching services', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const fetchMock = vi.fn(trustFetch());
    vi.stubGlobal('fetch', fetchMock);
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);

    await screen.findByRole('group', { name: 'Filtros TSL' });
    expect(
      screen.getAllByText(
        'Aceita SHA-256 de certificado, SKI, sujeito, prestador, serviço ou ponto de serviço.',
      ).length,
    ).toBeGreaterThanOrEqual(1);

    const certificateSha256 = 'b'.repeat(64);
    fireEvent.change(screen.getByLabelText('Procurar por identificador técnico TSL'), {
      target: { value: certificateSha256 },
    });

    await waitFor(() =>
      expect(
        requestMatching(fetchMock, '/v1/trust/catalog', {
          identifier: certificateSha256,
        }),
      ).toBe(true),
    );
    const matchText = 'Matched by technical catalog identifier only: certificate SHA-256';
    const serviceRow = await screen.findByRole('button', { name: /MULTICERT Qualified CA/i });
    expect(within(serviceRow).getByText(matchText)).toBeTruthy();
    fireEvent.click(serviceRow);

    await screen.findByText('Identidades digitais');
    const identityGroups = await screen.findAllByRole('group', { name: 'Identidades' });
    const identities = identityGroups.find((group) =>
      within(group).queryByText('Identidades digitais'),
    );
    expect(identities).toBeTruthy();
    expect(screen.getAllByText(matchText).length).toBeGreaterThanOrEqual(2);
    const digestValue = getByRevealedText(certificateSha256, identities!);
    expect(digestValue.classList.contains('digest__value')).toBe(true);
    expect(digestValue.textContent).toBe('bbbbbbbb…bbbbbbbb');
    const timeoutSpy = vi.spyOn(window, 'setTimeout').mockReturnValue(0);
    fireEvent.click(within(identities!).getByRole('button', { name: /copiar/i }));
    expect(writeText).toHaveBeenCalledWith(certificateSha256);
    await Promise.resolve();
    timeoutSpy.mockRestore();
    expect(document.body.textContent).not.toMatch(
      /legal validity|external validation|provider approval|qualified-status|validade legal|validação externa|prestador aprovado|aprovação do prestador/i,
    );
    await waitFor(() => expect(screen.queryByText('AMA Legacy CA')).toBeNull());
  });

  it('renders TSA identifier-match explanations and copies full SKI values', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const fetchMock = vi.fn(trustFetch());
    vi.stubGlobal('fetch', fetchMock);
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust/tsa']);

    await screen.findByRole('group', { name: 'Resumo TSA' });
    const ski = TSA_CATALOG.records[0].identities.subject_key_ids[0];
    fireEvent.change(screen.getByLabelText('Procurar registos TSA por identificador técnico'), {
      target: { value: ski },
    });

    await waitFor(() =>
      expect(
        requestMatching(fetchMock, '/v1/trust/tsa', {
          identifier: ski,
        }),
      ).toBe(true),
    );
    const matchText = 'Matched by technical catalog identifier only: subject key ID';
    const recordRow = await screen.findByRole('button', {
      name: /Qualified Timestamping Authority/i,
    });
    expect(within(recordRow).getByText(matchText)).toBeTruthy();
    fireEvent.click(recordRow);

    const identityGroups = await screen.findAllByRole('group', { name: 'Identidades' });
    const identities = identityGroups.find((group) =>
      within(group).queryByText('Identificadores SKI'),
    );
    expect(identities).toBeTruthy();
    expect(screen.getAllByText(matchText).length).toBeGreaterThanOrEqual(2);
    const skiValue = getByRevealedText(ski, identities!);
    expect(skiValue.classList.contains('digest__value')).toBe(true);
    expect(skiValue.textContent).toBe('91b78a44…4d8528a6');
    const timeoutSpy = vi.spyOn(window, 'setTimeout').mockReturnValue(0);
    fireEvent.click(within(identities!).getByRole('button', { name: /copiar/i }));
    expect(writeText).toHaveBeenCalledWith(ski);
    await Promise.resolve();
    timeoutSpy.mockRestore();
    expect(document.body.textContent).not.toMatch(
      /legal validity|external validation|provider approval|qualified-status|validade legal|validação externa|prestador aprovado|aprovação do prestador/i,
    );
  });

  it('passes identifier lookups to TSA search and shows the empty state for no matches', async () => {
    const fetchMock = vi.fn(trustFetch());
    vi.stubGlobal('fetch', fetchMock);
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust/tsa']);

    await screen.findByRole('group', { name: 'Resumo TSA' });
    fireEvent.change(screen.getByLabelText('Procurar registos TSA por identificador técnico'), {
      target: { value: 'no-such-technical-identifier' },
    });

    await waitFor(() =>
      expect(
        requestMatching(fetchMock, '/v1/trust/tsa', {
          identifier: 'no-such-technical-identifier',
        }),
      ).toBe(true),
    );
    expect(await screen.findByText('Sem registos TSA')).toBeTruthy();
    expect(
      screen.getByText(
        /Nenhum serviço de selo temporal corresponde a “no-such-technical-identifier”/,
      ),
    ).toBeTruthy();
  });

  it('filters to providers and drills from provider detail into a service', async () => {
    vi.stubGlobal('fetch', trustFetch());
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);

    fireEvent.click(await screen.findByRole('button', { name: 'Prestadores' }));
    fireEvent.click(await screen.findByRole('button', { name: /MULTICERT S\.A\./i }));

    expect(await screen.findByText('Nomes comerciais')).toBeTruthy();
    expect(screen.getByText('MULTICERT')).toBeTruthy();
    expect(screen.getByText('Nomes duplicados')).toBeTruthy();
    expect(screen.getAllByText('MULTICERT Qualified CA').length).toBeGreaterThanOrEqual(1);

    fireEvent.click(screen.getByRole('button', { name: /MULTICERT Timestamping/i }));
    expect(await screen.findByText('MIID-tsa-test')).toBeTruthy();
  });

  it('renders the catalog as tables: facts as field/value rows, repeated entries as grids', async () => {
    // The user asked for the trust list "table displayed styled so its easier to read". Two
    // different shapes came out of that, and this asserts the distinction rather than just
    // counting tables:
    //
    //  - read-only facts about ONE subject are a two-column field/value table, with the field
    //    as a row header so a screen reader knows the left cell names the right one;
    //  - repeated homogeneous entries are real multi-column grids, and those — and only those —
    //    carry the keyboard-reachable per-column help.
    vi.stubGlobal('fetch', trustFetch());
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);

    fireEvent.click(await screen.findByRole('button', { name: 'Prestadores' }));
    fireEvent.click(await screen.findByRole('button', { name: /MULTICERT S\.A\./i }));

    // Facts: a field/value table. The field name is a ROW header — that is the part carrying the
    // meaning, and it is what tells a screen reader the left cell names the right one.
    const tradeNames = await screen.findByRole('rowheader', { name: 'Nomes comerciais' });
    const factTable = tradeNames.closest('table') as HTMLTableElement;
    expect(factTable.closest('.trust-fact-table')).toBeTruthy();
    expect(within(factTable).getByRole('columnheader', { name: 'Campo' })).toBeTruthy();
    expect(within(factTable).getByRole('columnheader', { name: 'Valor' })).toBeTruthy();
    // The old shape was a definition list; assert the element genuinely changed.
    expect(factTable.closest('[role="group"]')?.querySelector('dl')).toBeFalsy();

    // A field/value header says nothing a tooltip could improve on, so it deliberately has none.
    expect(within(factTable).queryByRole('button', { name: /^Ajuda sobre a coluna/ })).toBeNull();

    // Repeated entries: the provider's services, as a grid with described column help.
    const servicesTable = screen.getByRole('table', { name: 'Serviços deste prestador' });
    for (const column of ['Serviço', 'Tipo', 'Estado e atributos']) {
      const header = within(servicesTable).getByRole('columnheader', { name: column });
      const trigger = within(header).getByRole('button', {
        name: `Ajuda sobre a coluna ${column}`,
      });
      trigger.focus();
      expect(document.activeElement, column).toBe(trigger);
      const bubble = document.getElementById(trigger.getAttribute('aria-describedby') as string);
      expect(bubble?.textContent?.length ?? 0, column).toBeGreaterThan(60);
    }
    // The row's own affordance is still a real button, so the grid stays keyboard-navigable.
    // The qualified CA is the service with published status history, so its record exercises
    // both of the remaining grids.
    fireEvent.click(within(servicesTable).getByRole('button', { name: /MULTICERT Qualified CA/i }));

    // The service record: digital identities and status history are both grids now.
    const identities = await screen.findByRole('table', {
      name: 'Identidades digitais do serviço',
    });
    expect(within(identities).getByRole('columnheader', { name: 'SHA-256' })).toBeTruthy();
    // Identifiers are never truncated away: the value is present in full in the DOM, and the
    // block inherits the wrap + text-selection opt-in rather than being ellipsised.
    expect(within(identities).getByText('MIID-qualified-test')).toBeTruthy();
    expect(identities.closest('.trust-opaque')).toBeTruthy();

    const history = screen.getByRole('table', { name: 'Histórico de estado do serviço' });
    expect(within(history).getByRole('columnheader', { name: 'Nome nessa altura' })).toBeTruthy();
    // The count is a sentence, not a one-row table pretending to be one.
    expect(screen.getByText(/Entradas de histórico: \d+/)).toBeTruthy();
  });

  it('shows empty states for structured no-match filters', async () => {
    const fetchMock = vi.fn(trustFetch());
    vi.stubGlobal('fetch', fetchMock);
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);

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

/**
 * The unverified-transport marker, on all three surfaces the backend attaches it to.
 *
 * Two properties are asserted, and the second is the one that makes the copy defensible.
 *
 * 1. It appears wherever the backend sets it — a marker wired to one screen and not the others
 *    would leave "fetched over an unauthenticated connection" looking exactly like an ordinary
 *    result everywhere it was missed. This is the same argument as the `weak_algorithms` test above.
 * 2. It does **not** contradict the signature verdict beside it. The fixture pairs the marker with
 *    `signature: 'Valid'` on purpose: that pairing is the normal case, because a list's authenticity
 *    comes from its own signature against the configured anchors and not from TLS. Copy that told
 *    the operator the list was untrustworthy here would be false, and false warnings are how true
 *    ones get ignored.
 */
describe('Ferramentas — unverified transport marker', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  const TRANSPORT = {
    code: 'tsl_transport_not_verified',
    source_id: 'pt-gns',
    url: 'https://lists.example.pt/tsl.xml',
  } as const;

  function markedFetch(): typeof fetch {
    const mark = <T extends { validation: TslValidationView }>(view: T): T => ({
      ...view,
      validation: { ...view.validation, unverified_transport: { ...TRANSPORT } },
    });
    const summary = mark(SUMMARY);
    const tsaCatalog: TsaCatalogView = {
      ...TSA_CATALOG,
      summary: {
        ...TSA_CATALOG.summary,
        tsl: { ...TSA_CATALOG.summary.tsl, unverified_transport: { ...TRANSPORT } },
      },
    };
    return ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      const parsed = new URL(url, 'http://localhost');
      if (parsed.pathname === '/v1/trust/status') return Promise.resolve(jsonResponse(summary));
      if (parsed.pathname === '/v1/trust/tsa') return Promise.resolve(jsonResponse(tsaCatalog));
      if (parsed.pathname === '/v1/trust/catalog') return Promise.resolve(jsonResponse(CATALOG));
      return Promise.resolve(jsonResponse({}, 404));
    }) as typeof fetch;
  }

  it('reports an unverified transport on the trust status screen without contradicting the verdict', async () => {
    vi.stubGlobal('fetch', markedFetch());
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);

    const entry = await concernEntry('tsl-status', 'unverified-transport');
    expect(entry.textContent).toContain(ptPT['trust.unverifiedTransport.title']);
    // The reassurance is not optional garnish: it is what stops an operator concluding that the
    // Valid badge beside it cannot be relied on either.
    expect(entry.textContent).toContain(ptPT['trust.unverifiedTransport.stillAuthenticated']);
    // Both risks named, neither overstated.
    expect(entry.textContent).toContain(ptPT['trust.unverifiedTransport.residualRisk']);
    expect(entry.textContent).toContain(ptPT['trust.unverifiedTransport.remedy']);
    // The source and host verbatim, so an operator can find the setting that caused this.
    expect(entry.textContent).toContain(TRANSPORT.url);
    expect(entry.textContent).toContain(TRANSPORT.source_id);
  });

  it('reports it on the TSA screen too, where the records were read off the same list', async () => {
    vi.stubGlobal('fetch', markedFetch());
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust/tsa']);
    const entry = await concernEntry('tsa-summary', 'unverified-transport');
    expect(entry.textContent).toContain(ptPT['trust.unverifiedTransport.title']);
  });

  it('says nothing at all when the transport is verified', async () => {
    // The ordinary state is silent — no green "verified" badge. The marker's mere presence is the
    // signal, so an install that never opted out sees exactly the screen it saw before.
    vi.stubGlobal('fetch', trustFetch());
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);
    await screen.findByText(SUMMARY.scheme_operator_name);
    expect(screen.queryByText(ptPT['trust.unverifiedTransport.title'])).toBeNull();
    expect(screen.queryByText(ptPT['trust.unverifiedTransport.badge'])).toBeNull();
  });
});

/**
 * t88 — "clicking on a provider should show the provider info on a floating right hand popup
 * instead of below all the info, same for ts providers".
 *
 * The detail used to be `.trust-explorer__detail`, a box stacked under the search results, so a
 * long result list pushed the record the operator had just picked off the bottom of the page. It
 * is now a `SidePanel` portaled beside the list.
 *
 * The real risk in a move like this is a field quietly not making the trip, so each of these
 * enumerates the panel's field/value row headers and its section labels as EXACT arrays: drop one
 * (or bolt one on) and the assertion fails. The expected names are read out of the pt-PT catalog
 * and the trust sub-tab fallback module by key rather than typed in as prose, so a copy revision
 * moves the test with the product instead of pinning a rendered substring.
 */
describe('Ferramentas — trust detail side panel', () => {
  /** The names the panel's fact tables give their fields, in render order. */
  function fieldNames(panel: HTMLElement): string[] {
    return within(panel)
      .getAllByRole('rowheader')
      .map((cell) => cell.textContent?.trim() ?? '');
  }

  /** The blocks the panel is divided into, in render order. */
  function sectionNames(panel: HTMLElement): (string | null)[] {
    return within(panel)
      .getAllByRole('group')
      .map((group) => group.getAttribute('aria-label'));
  }

  /** Click a row the way a pointer does: focus lands on the control before the click fires. */
  function pickRow(row: HTMLElement): HTMLElement {
    row.focus();
    fireEvent.click(row);
    return row;
  }

  it('floats the TSL provider detail beside the list instead of stacking it below', async () => {
    vi.stubGlobal('fetch', trustFetch());
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);

    fireEvent.click(await screen.findByRole('button', { name: ptPT['trust.filter.providers'] }));
    // Nothing floats until something is picked.
    expect(screen.queryByRole('complementary')).toBeNull();
    pickRow(await screen.findByRole('button', { name: /MULTICERT S\.A\./i }));

    const panel = await screen.findByRole('complementary', {
      name: trustSectionsPtPT['tools.trust.panel.provider'],
    });
    // The panel opens onto its loading skeleton; wait for the record itself before enumerating.
    const heading = await within(panel).findByRole('heading', { level: 3 });

    // It is genuinely OUT of the explorer column, not merely restyled: the old in-flow detail box
    // is gone and the panel hangs off <body> so no transformed route ancestor can clip it.
    expect(document.querySelector('.trust-explorer__detail')).toBeNull();
    expect(panel.closest('.trust-explorer')).toBeNull();
    expect(panel.closest('.side-panel-layer')?.parentElement).toBe(document.body);
    // The list underneath keeps working — this is a panel beside the list, not a dialog over it.
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.getByRole('list', { name: ptPT['trust.results.providers'] })).toBeTruthy();

    // Every field the stacked detail showed, and only those.
    expect(fieldNames(panel)).toEqual([
      ptPT['trust.provider.tradeNames'],
      ptPT['trust.provider.informationUris'],
      ptPT['trust.status.services'],
      ptPT['trust.provider.analysis'],
    ]);
    expect(sectionNames(panel)).toEqual([
      ptPT['trust.detail.summary'],
      ptPT['trust.provider.duplicateNames'],
      ptPT['trust.provider.services'],
    ]);
    // …with their values, including the provider's own name as the detail heading and the
    // services grid the operator drills through.
    expect(heading.textContent).toBe('MULTICERT S.A.');
    expect(within(panel).getByText('MULTICERT')).toBeTruthy();
    expect(within(panel).getByText('https://www.multicert.pt')).toBeTruthy();
    expect(
      within(panel).getByRole('table', { name: ptPT['trust.table.service.caption'] }),
    ).toBeTruthy();
    expect(within(panel).getByRole('button', { name: /MULTICERT Timestamping/i })).toBeTruthy();
  });

  it('floats the TSL service detail, keeps every field, and hands focus back on Escape', async () => {
    vi.stubGlobal('fetch', trustFetch());
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);

    fireEvent.change(await screen.findByLabelText(ptPT['trust.search.aria']), {
      target: { value: 'qualified' },
    });
    const row = pickRow(await screen.findByRole('button', { name: /MULTICERT Qualified CA/i }));

    const panel = await screen.findByRole('complementary', {
      name: trustSectionsPtPT['tools.trust.panel.service'],
    });
    // Opening a panel puts the keyboard on the thing that just appeared.
    expect(document.activeElement).toBe(panel);
    const heading = await within(panel).findByRole('heading', { level: 3 });

    expect(fieldNames(panel)).toEqual([
      ptPT['trust.service.type'],
      ptPT['trust.service.statusUri'],
      ptPT['trust.service.statusStartingTime'],
      ptPT['trust.service.certificates'],
    ]);
    expect(sectionNames(panel)).toEqual([
      ptPT['trust.detail.summary'],
      ptPT['trust.service.additionalInfo'],
      ptPT['trust.detail.supplyPoints'],
      ptPT['trust.detail.history'],
      ptPT['trust.detail.identities'],
    ]);
    expect(heading.textContent).toBe('MULTICERT Qualified CA');
    expect(within(panel).getByText('QCForESig')).toBeTruthy();
    expect(within(panel).getByText('CN=MULTICERT Qualified CA')).toBeTruthy();
    expect(
      within(panel).getByRole('table', { name: ptPT['trust.table.history.caption'] }),
    ).toBeTruthy();
    expect(
      within(panel).getByRole('table', { name: ptPT['trust.table.identity.caption'] }),
    ).toBeTruthy();
    expect(within(panel).getByText('MIID-qualified-test')).toBeTruthy();

    fireEvent.keyDown(document, { key: 'Escape' });

    await waitFor(() => expect(screen.queryByRole('complementary')).toBeNull());
    expect(document.activeElement).toBe(row);
    // Dismissing drops the selection from the URL, so the list is back to an unpicked state.
    expect(
      screen
        .getByRole('button', { name: /MULTICERT Qualified CA/i })
        .classList.contains('is-current'),
    ).toBe(false);
  });

  it('floats the TSA record detail, opens only on a pick, and still honours a deep link', async () => {
    vi.stubGlobal('fetch', trustFetch());
    const first = renderWithProviders(<TrustCatalogPage />, ['/tools/trust/tsa']);

    await screen.findByRole('group', { name: ptPT['trust.tsa.summary.aria'] });
    // The stacked detail used to fall back to the first record; something that floats over the
    // page must wait to be asked for.
    expect(screen.queryByRole('complementary')).toBeNull();

    const row = pickRow(
      await screen.findByRole('button', { name: /Qualified Timestamping Authority/i }),
    );
    const panel = await screen.findByRole('complementary', {
      name: trustSectionsPtPT['tools.trust.panel.tsaRecord'],
    });
    expect(document.activeElement).toBe(panel);
    expect(panel.closest('.trust-explorer')).toBeNull();

    expect(fieldNames(panel)).toEqual([
      ptPT['trust.service.type'],
      ptPT['trust.service.statusStartingTime'],
      ptPT['trust.tsa.detail.grantedEffective'],
      ptPT['trust.service.certificates'],
      ptPT['trust.detail.historyEntries'],
      ptPT['trust.tsa.detail.classification'],
      ptPT['trust.tsa.detail.trustBasis'],
    ]);
    expect(sectionNames(panel)).toEqual([
      ptPT['trust.detail.summary'],
      ptPT['trust.detail.supplyPoints'],
      ptPT['trust.detail.history'],
      ptPT['trust.tsa.detail.blockingReasons'],
      ptPT['trust.detail.identities'],
    ]);
    expect(within(panel).getByRole('heading', { level: 3 }).textContent).toBe(
      'Qualified Timestamping Authority',
    );
    expect(within(panel).getByText('Cartorio Notarial Timestamping')).toBeTruthy();
    expect(within(panel).getByText('http://tsa.cartorio.example.test/tsa/server')).toBeTruthy();
    // The blocking reason and the classification stay verbatim — these are the record's own
    // evidentiary wording, not product copy to be tidied.
    expect(within(panel).getByText('TSL signature is not valid; record is advisory')).toBeTruthy();
    expect(within(panel).getByText('QualifiedTimestampService')).toBeTruthy();
    expect(within(panel).getByText('AdvisoryOnlyInvalidTslSignature')).toBeTruthy();

    // Closing from the panel's own control returns the keyboard to the row.
    fireEvent.click(
      within(panel).getByRole('button', { name: trustSectionsPtPT['tools.trust.panel.close'] }),
    );
    await waitFor(() => expect(screen.queryByRole('complementary')).toBeNull());
    expect(document.activeElement).toBe(row);

    // The selection is still addressable: a URL naming a record paints its panel on arrival.
    first.unmount();
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust/tsa?tsaRecord=svc-tsa']);
    const deepLinked = await screen.findByRole('complementary', {
      name: trustSectionsPtPT['tools.trust.panel.tsaRecord'],
    });
    expect(within(deepLinked).getByRole('heading', { level: 3 }).textContent).toBe(
      'Qualified Timestamping Authority',
    );
  });
});
