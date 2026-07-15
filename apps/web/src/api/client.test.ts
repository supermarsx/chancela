import { describe, it, expect, vi, afterEach } from 'vitest';
import { ApiError, api, parseResponse } from './client';
import type { LedgerArchiveDocumentParams } from './types';

interface TestRuntimeWindow {
  __CHANCELA_CONFIG__?: {
    apiBaseUrl?: string;
  };
  __CHANCELA_MOBILE_SHELL__?: unknown;
}

function runtimeWindow(): TestRuntimeWindow {
  return window as unknown as TestRuntimeWindow;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
  delete runtimeWindow().__CHANCELA_CONFIG__;
  delete runtimeWindow().__CHANCELA_MOBILE_SHELL__;
  vi.restoreAllMocks();
});

describe('parseResponse', () => {
  it('parses a 2xx JSON body into the typed value', async () => {
    const entity = { id: 'e1', name: 'Encosto Estratégico', nipc: '500000000', seat: 'Lisboa' };
    await expect(parseResponse(jsonResponse(entity))).resolves.toEqual(entity);
  });

  it('resolves an empty body to undefined', async () => {
    const res = new Response(null, { status: 204 });
    await expect(parseResponse(res)).resolves.toBeUndefined();
  });

  const catchError = async (p: Promise<unknown>): Promise<ApiError> =>
    (await p.catch((e: unknown) => e)) as ApiError;

  it('throws ApiError carrying status and message on non-2xx', async () => {
    const err = await catchError(parseResponse(jsonResponse({ error: 'NIPC inválido' }, 422)));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(422);
    expect(err.message).toBe('NIPC inválido');
  });

  it('surfaces the issues array on a compliance-blocked seal', async () => {
    const body = {
      error: 'compliance blocked',
      issues: [{ rule_id: 'csc-art63', severity: 'Error', message: 'faltam deliberações' }],
    };
    const err = await catchError(parseResponse(jsonResponse(body, 422)));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.issues).toHaveLength(1);
    expect(err.issues?.[0].rule_id).toBe('csc-art63');
  });

  it('surfaces the warnings array on a warnings-not-acknowledged seal', async () => {
    const body = {
      error: 'warnings not acknowledged',
      warnings: [{ rule_id: 'sig-03', severity: 'Warning', message: 'assinatura manual' }],
    };
    const err = await catchError(parseResponse(jsonResponse(body, 409)));
    expect(err.status).toBe(409);
    expect(err.warnings?.[0].rule_id).toBe('sig-03');
  });

  it('throws a clear typed error when the server returns HTML instead of JSON', async () => {
    // A stale server serves the SPA shell for a route it does not know: a 200 text/html body
    // where the client expects JSON. This must not surface as a raw JSON.parse SyntaxError.
    const htmlShell = new Response('<!doctype html><title>Chancela</title>', {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
    const err = await catchError(parseResponse(htmlShell, '/v1/users'));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(200);
    expect(err.message).toContain('HTML em vez de JSON');
    expect(err.message).toContain('/v1/users');
    expect(err.message).toContain('desatualizada');
  });

  it('flags a non-JSON, non-HTML body by its content type', async () => {
    const textBody = new Response('server on fire', {
      status: 502,
      headers: { 'Content-Type': 'text/plain' },
    });
    const err = await catchError(parseResponse(textBody));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.message).toContain('text/plain');
  });

  it('reports a JSON content-type whose body is not valid JSON', async () => {
    const broken = new Response('{ not json', {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
    const err = await catchError(parseResponse(broken, '/v1/entities'));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.message).toContain('não é JSON válido');
    expect(err.message).toContain('/v1/entities');
  });
});

describe('api client', () => {
  it('requests relative /v1 paths and JSON-encodes POST bodies', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ id: 'e1' }, 201));
    vi.stubGlobal('fetch', fetchMock);

    await api.createEntity({
      name: 'X',
      nipc: '500000000',
      seat: 'Porto',
      kind: 'SociedadePorQuotas',
    });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/v1/entities');
    expect(init.method).toBe('POST');
    expect(init.headers['Content-Type']).toBe('application/json');
    expect(JSON.parse(init.body)).toMatchObject({ nipc: '500000000', kind: 'SociedadePorQuotas' });
  });

  it('uses a configured API base URL for client requests', async () => {
    runtimeWindow().__CHANCELA_CONFIG__ = {
      apiBaseUrl: 'https://api.example.test/chancela/',
    };
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ id: 'e1' }, 201));
    vi.stubGlobal('fetch', fetchMock);

    await api.createEntity({
      name: 'X',
      nipc: '500000000',
      seat: 'Porto',
      kind: 'SociedadePorQuotas',
    });

    expect(fetchMock.mock.calls[0][0]).toBe('https://api.example.test/chancela/v1/entities');
  });

  it('initiates remote signing sessions with the batch endpoint and exact request body', async () => {
    const response = {
      provider_id: 'multi/cert prod',
      family: 'QualifiedCertificate',
      evidentiary_level: 'Qualified',
      auth_mode: 'per_document_activation',
      requested: 2,
      pending: 1,
      failed: 1,
      initiate_events: 1,
      results: [
        {
          act_id: 'act-1',
          status: 'pending',
          session_id: 'sess-1',
          provider_id: 'multi/cert prod',
          family: 'QualifiedCertificate',
          pending_status: 'activation_pending',
          activation_hint: 'activation sent',
          expires_at: '2026-07-14T10:05:00Z',
        },
        { act_id: 'act-2', status: 'error', error: 'document already signed' },
      ],
    };
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(response));
    vi.stubGlobal('fetch', fetchMock);

    const result = await api.remoteBatchInitiateSignature('multi/cert prod', {
      act_ids: ['act-1', 'act-2'],
      user_ref: 'amelia.marques',
      credential: 'transient-secret',
      capacity: 'Presidente da Mesa',
      actor: 'operator-1',
      seal: {
        invisible: false,
        page: 0,
        x: 10,
        y: 20,
        w: 120,
        h: 48,
        template: { kind: 'name_date', name: 'Amélia Marques', date: '2026-07-14' },
      },
    });

    expect(fetchMock.mock.calls[0][0]).toBe(
      '/v1/signature/remote/multi%2Fcert%20prod/batch-initiate',
    );
    expect(fetchMock.mock.calls[0][1].method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      act_ids: ['act-1', 'act-2'],
      user_ref: 'amelia.marques',
      credential: 'transient-secret',
      capacity: 'Presidente da Mesa',
      actor: 'operator-1',
      seal: {
        invisible: false,
        page: 0,
        x: 10,
        y: 20,
        w: 120,
        h: 48,
        template: { kind: 'name_date', name: 'Amélia Marques', date: '2026-07-14' },
      },
    });
    expect(JSON.stringify(result)).not.toContain('transient-secret');
    expect(result.auth_mode).toBe('per_document_activation');
  });

  it('builds a query string only from defined params', async () => {
    // Fresh Response per call: a body may only be read once.
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(jsonResponse([])));
    vi.stubGlobal('fetch', fetchMock);

    await api.listBooks('ent-1');
    expect(fetchMock.mock.calls[0][0]).toBe('/v1/books?entity_id=ent-1');

    await api.listBooks();
    expect(fetchMock.mock.calls[1][0]).toBe('/v1/books');
  });

  it('records AI human-review decisions on the act-scoped endpoint', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ id: 'act-1' }));
    vi.stubGlobal('fetch', fetchMock);

    await api.verifyActHumanReview('act-1', { decision: 'accept', note: 'reviewed by operator' });

    expect(fetchMock.mock.calls[0][0]).toBe('/v1/acts/act-1/human-verification');
    expect(fetchMock.mock.calls[0][1].method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      decision: 'accept',
      note: 'reviewed by operator',
    });
  });

  it('uses the API-key lifecycle endpoints and JSON body shape', async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(jsonResponse([])));
    vi.stubGlobal('fetch', fetchMock);

    await api.listApiKeys();
    expect(fetchMock.mock.calls[0][0]).toBe('/v1/api-keys');

    await api.createApiKey({
      name: 'Ledger export',
      grant: {
        kind: 'permissions',
        permissions: ['ledger.read'],
        scope: { kind: 'global' },
      },
      rate_limit: { rpm: 120, burst: 10 },
    });
    expect(fetchMock.mock.calls[1][0]).toBe('/v1/api-keys');
    expect(fetchMock.mock.calls[1][1].method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toMatchObject({
      grant: { kind: 'permissions', permissions: ['ledger.read'], scope: { kind: 'global' } },
      rate_limit: { rpm: 120, burst: 10 },
    });

    await api.rotateApiKey('key-1');
    expect(fetchMock.mock.calls[2][0]).toBe('/v1/api-keys/key-1/rotate');
    expect(fetchMock.mock.calls[2][1].method).toBe('POST');

    await api.revokeApiKey('key-1');
    expect(fetchMock.mock.calls[3][0]).toBe('/v1/api-keys/key-1');
    expect(fetchMock.mock.calls[3][1].method).toBe('DELETE');
  });

  it('uses the data key rotation execution endpoint and sends only the replacement key', async () => {
    const fetchMock = vi.fn().mockImplementation(() =>
      Promise.resolve(
        jsonResponse({
          status: 'rekey_applied',
          rekey_executed: true,
          ledger_integrity_verified: true,
          ledger_length: 1,
          evidence: {
            operation: 'sqlcipher_rekey',
            requested_key_config: 'configured',
            sqlcipher_available: true,
            checkpointed_before_rekey: true,
            checkpointed_after_rekey: true,
            post_rekey_integrity_checked: true,
          },
        }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    await api.executeDataKeyRotation({ new_key: 'replacement-secret' });

    expect(fetchMock.mock.calls[0][0]).toBe('/v1/data/key-rotation');
    expect(fetchMock.mock.calls[0][1].method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      new_key: 'replacement-secret',
    });
  });

  it('uses the privacy register endpoints', async () => {
    const fetchMock = vi.fn().mockImplementation(() =>
      Promise.resolve(
        jsonResponse({
          id: 'record-1',
          name: 'Cloud Processor',
          title: 'High-risk assessment',
          purpose: 'Hosting',
          legal_basis: 'Contrato',
          data_categories: ['Identificação'],
          subprocessors: [],
          risk_level: 'medium',
          status: 'draft',
          evidence_receipts: [],
          created_at: '2026-07-09T10:00:00Z',
          created_by: 'amelia.marques',
          updated_at: '2026-07-09T10:00:00Z',
          updated_by: 'amelia.marques',
        }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    await api.listProcessorRecords();
    expect(fetchMock.mock.calls[0][0]).toBe('/v1/privacy/processors');

    await api.createProcessorRecord({
      name: 'Cloud Processor',
      purpose: 'Hosting',
      legal_basis: 'Contrato',
      data_categories: ['Identificação'],
      subprocessors: [],
      risk_level: 'medium',
      status: 'draft',
    });
    expect(fetchMock.mock.calls[1][0]).toBe('/v1/privacy/processors');
    expect(fetchMock.mock.calls[1][1].method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toMatchObject({
      name: 'Cloud Processor',
      risk_level: 'medium',
      status: 'draft',
    });

    await api.patchProcessorRecord('processor-1', { status: 'active' });
    expect(fetchMock.mock.calls[2][0]).toBe('/v1/privacy/processors/processor-1');
    expect(fetchMock.mock.calls[2][1].method).toBe('PATCH');
    expect(JSON.parse(fetchMock.mock.calls[2][1].body)).toEqual({ status: 'active' });

    await api.listDpiaRecords();
    expect(fetchMock.mock.calls[3][0]).toBe('/v1/privacy/dpias');

    await api.createDpiaRecord({
      title: 'High-risk assessment',
      purpose: 'Profiling',
      legal_basis: 'Interesse legítimo',
      data_categories: ['Comportamento'],
      subprocessors: ['Analytics Processor SA'],
      risk_level: 'high',
      status: 'under_review',
    });
    expect(fetchMock.mock.calls[4][0]).toBe('/v1/privacy/dpias');
    expect(fetchMock.mock.calls[4][1].method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[4][1].body)).toMatchObject({
      title: 'High-risk assessment',
      risk_level: 'high',
      status: 'under_review',
    });

    await api.patchDpiaRecord('dpia-1', { risk_level: 'critical' });
    expect(fetchMock.mock.calls[5][0]).toBe('/v1/privacy/dpias/dpia-1');
    expect(fetchMock.mock.calls[5][1].method).toBe('PATCH');
    expect(JSON.parse(fetchMock.mock.calls[5][1].body)).toEqual({ risk_level: 'critical' });

    await api.listBreachPlaybooks();
    expect(fetchMock.mock.calls[6][0]).toBe('/v1/privacy/breach-playbooks');

    await api.createBreachPlaybook({
      title: 'Suspected compromise',
      scope: 'account-access',
      detection_channels: ['SIEM alert'],
      containment_steps: ['Disable sessions'],
      notification_roles: ['DPO'],
      risk_level: 'high',
      status: 'active',
      evidence_receipt: {
        evidence_type: 'drill',
        notes: 'Tabletop drill reviewed escalation paths.',
        authority_notified: false,
        subjects_notified: false,
      },
    });
    expect(fetchMock.mock.calls[7][0]).toBe('/v1/privacy/breach-playbooks');
    expect(fetchMock.mock.calls[7][1].method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[7][1].body)).toMatchObject({
      title: 'Suspected compromise',
      detection_channels: ['SIEM alert'],
      risk_level: 'high',
      evidence_receipt: {
        evidence_type: 'drill',
        notes: 'Tabletop drill reviewed escalation paths.',
        authority_notified: false,
        subjects_notified: false,
      },
    });

    await api.patchBreachPlaybook('breach-1', {
      status: 'under_review',
      evidence_receipt: {
        evidence_type: 'review',
        notes: 'Operator review only.',
        authority_notified: false,
        subjects_notified: false,
      },
    });
    expect(fetchMock.mock.calls[8][0]).toBe('/v1/privacy/breach-playbooks/breach-1');
    expect(fetchMock.mock.calls[8][1].method).toBe('PATCH');
    expect(JSON.parse(fetchMock.mock.calls[8][1].body)).toEqual({
      status: 'under_review',
      evidence_receipt: {
        evidence_type: 'review',
        notes: 'Operator review only.',
        authority_notified: false,
        subjects_notified: false,
      },
    });

    await api.listTransferControls();
    expect(fetchMock.mock.calls[9][0]).toBe('/v1/privacy/transfer-controls');

    await api.createTransferControl({
      name: 'EU to UK support access',
      purpose: 'Support',
      legal_basis: 'Contract',
      data_categories: ['Support messages'],
      recipient: 'UK Support Ltd',
      destination_country: 'United Kingdom',
      transfer_mechanism: 'UK adequacy regulation',
      safeguards: ['Ticket-scoped access'],
      risk_level: 'medium',
      status: 'draft',
      evidence_receipt: {
        notes: 'Quarterly review only.',
        transfer_approved: false,
        data_transfer_executed: false,
      },
    });
    expect(fetchMock.mock.calls[10][0]).toBe('/v1/privacy/transfer-controls');
    expect(fetchMock.mock.calls[10][1].method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[10][1].body)).toMatchObject({
      name: 'EU to UK support access',
      recipient: 'UK Support Ltd',
      safeguards: ['Ticket-scoped access'],
      evidence_receipt: {
        notes: 'Quarterly review only.',
        transfer_approved: false,
        data_transfer_executed: false,
      },
    });

    await api.patchTransferControl('transfer-1', {
      risk_level: 'high',
      evidence_receipt: {
        notes: 'Follow-up control review.',
        transfer_approved: false,
        data_transfer_executed: false,
      },
    });
    expect(fetchMock.mock.calls[11][0]).toBe('/v1/privacy/transfer-controls/transfer-1');
    expect(fetchMock.mock.calls[11][1].method).toBe('PATCH');
    expect(JSON.parse(fetchMock.mock.calls[11][1].body)).toEqual({
      risk_level: 'high',
      evidence_receipt: {
        notes: 'Follow-up control review.',
        transfer_approved: false,
        data_transfer_executed: false,
      },
    });

    await api.listRetentionExecutions('blocked');
    expect(fetchMock.mock.calls[12][0]).toBe('/v1/privacy/retention-executions?status=blocked');

    await api.closeRetentionExecutionReview('retention-exec-blocked', {
      review_closure_decision: 'blocked_evidence_acknowledged',
      review_closure_note: 'Blocked evidence acknowledged for governance review.',
      review_closure_evidence: [
        {
          label: 'checklist',
          value: 'operator reviewed retained bounded evidence',
        },
      ],
      destructive_disposal_completed: false,
      full_erasure_completed: false,
      legal_hold_mutated: false,
      retention_policy_mutated: false,
    });
    expect(fetchMock.mock.calls[13][0]).toBe(
      '/v1/privacy/retention-executions/retention-exec-blocked/review-closure',
    );
    expect(fetchMock.mock.calls[13][1].method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[13][1].body)).toEqual({
      review_closure_decision: 'blocked_evidence_acknowledged',
      review_closure_note: 'Blocked evidence acknowledged for governance review.',
      review_closure_evidence: [
        {
          label: 'checklist',
          value: 'operator reviewed retained bounded evidence',
        },
      ],
      destructive_disposal_completed: false,
      full_erasure_completed: false,
      legal_hold_mutated: false,
      retention_policy_mutated: false,
    });
  });

  it('downloads the read-only book preservation package from the archive endpoint', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response('zipbytes', {
        status: 200,
        headers: { 'Content-Type': 'application/zip' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const blob = await api.fetchBookArchivePackage('book-1');

    expect(fetchMock.mock.calls[0][0]).toBe('/v1/books/book-1/archive/package');
    expect(fetchMock.mock.calls[0][1]?.method).toBeUndefined();
    expect(blob).toBeInstanceOf(Blob);
    expect(blob.size).toBeGreaterThan(0);
    expect(blob.type).toBe('application/zip');
  });

  it('serializes paged ledger filters for newest-first lazy loading', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        events: [],
        next_cursor: 41,
        has_more: true,
        limit: 100,
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await api.listLedgerPage({
      q: 'approved digest',
      chain: 'book:book-1',
      scope: 'act:7',
      kind: 'act.sealed',
      actor: 'amelia.marques',
      from: '2026-07-01',
      to: '2026-07-31',
      before_seq: 42,
      limit: 100,
      order: 'desc',
    });

    expect(fetchMock.mock.calls[0][0]).toBe(
      '/v1/ledger/events/page?q=approved+digest&chain=book%3Abook-1&scope=act%3A7&kind=act.sealed&actor=amelia.marques&from=2026-07-01&to=2026-07-31&before_seq=42&limit=100&order=desc',
    );
  });

  it('downloads ledger archive formats through the bounded format query', async () => {
    for (const [format, contentType, body] of [
      ['pdfa', 'application/pdf', '%PDF-archive'],
      ['txt', 'text/plain; charset=utf-8', 'AUDIT EXPORT'],
      ['json', 'application/json', '{"events":[]}'],
      ['csv', 'text/csv; charset=utf-8', 'seq,kind\n1,act.sealed\n'],
      ['html', 'text/html; charset=utf-8', '<!doctype html><h1>Audit export</h1>'],
    ] as const) {
      const fetchMock = vi.fn().mockResolvedValue(
        new Response(body, {
          status: 200,
          headers: { 'Content-Type': contentType },
        }),
      );
      vi.stubGlobal('fetch', fetchMock);

      const blob = await api.fetchLedgerArchiveDocument({
        format,
        q: 'approved digest',
        chain: 'book:book-1',
        scope: 'act:7',
        kind: 'act.sealed',
        actor: 'amelia.marques',
        from: '2026-07-01',
        to: '2026-07-31',
        before_seq: 42,
        limit: 100,
        order: 'desc',
      } as unknown as LedgerArchiveDocumentParams);

      expect(fetchMock.mock.calls[0][0]).toBe(
        `/v1/ledger/archive/document?format=${format}&q=approved+digest&chain=book%3Abook-1&scope=act%3A7&kind=act.sealed&actor=amelia.marques&from=2026-07-01&to=2026-07-31&limit=100&order=desc`,
      );
      expect(blob).toBeInstanceOf(Blob);
      expect(blob.type).toBe(contentType.replace('; ', ';'));
    }
  });

  it('passes the all-filtered archive scope without a cursor parameter', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response('{"events":[]}', {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await api.fetchLedgerArchiveDocument({
      format: 'json',
      export_scope: 'all_filtered',
      q: 'approved digest',
      limit: 100,
      order: 'desc',
    });

    expect(fetchMock.mock.calls[0][0]).toBe(
      '/v1/ledger/archive/document?format=json&export_scope=all_filtered&q=approved+digest&limit=100&order=desc',
    );
  });

  it('downloads an act working-copy export as Markdown text plus a typed blob', async () => {
    const markdown = '# WORKING COPY - NON-EVIDENTIARY\n\nAta da AG anual\n';
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(markdown, {
        status: 200,
        headers: {
          'Content-Type': 'text/markdown; charset=utf-8',
          'Content-Disposition': 'attachment; filename="act-act-1-working-copy.md"',
        },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const download = await api.fetchActDocumentWorkingCopy('act-1');

    expect(fetchMock.mock.calls[0][0]).toBe('/v1/acts/act-1/document/working-copy');
    expect(fetchMock.mock.calls[0][1]?.method).toBeUndefined();
    expect(download.text).toBe(markdown);
    expect(download.contentType).toBe('text/markdown; charset=utf-8');
    expect(download.blob).toBeInstanceOf(Blob);
    expect(download.blob.type).toBe('text/markdown;charset=utf-8');
    expect(download.blob.type).not.toBe('application/pdf');
    expect(download.headers.get('Content-Disposition')).toContain('working-copy.md');
  });

  it('downloads TXT, HTML, and RTF act working-copy exports through the bounded format query', async () => {
    for (const [format, contentType, extension, body] of [
      ['txt', 'text/plain; charset=utf-8', 'txt', 'WORKING COPY - NON-EVIDENTIARY\n'],
      ['html', 'text/html; charset=utf-8', 'html', '<!doctype html><h1>WORKING COPY</h1>'],
      ['rtf', 'application/rtf', 'rtf', '{\\rtf1 WORKING COPY - NON-EVIDENTIARY}'],
    ] as const) {
      const fetchMock = vi.fn().mockResolvedValue(
        new Response(body, {
          status: 200,
          headers: {
            'Content-Type': contentType,
            'Content-Disposition': `attachment; filename="act-act-1-working-copy.${extension}"`,
          },
        }),
      );
      vi.stubGlobal('fetch', fetchMock);

      const download = await api.fetchActDocumentWorkingCopy('act-1', format);

      expect(fetchMock.mock.calls[0][0]).toBe(
        `/v1/acts/act-1/document/working-copy?format=${format}`,
      );
      expect(fetchMock.mock.calls[0][1]?.method).toBeUndefined();
      expect(download.text).toBe(body);
      expect(download.contentType).toBe(contentType);
      expect(download.blob).toBeInstanceOf(Blob);
      expect(download.blob.type).toBe(contentType.replace('; ', ';'));
      expect(download.blob.type).not.toBe('application/pdf');
      expect(download.headers.get('Content-Disposition')).toContain(`working-copy.${extension}`);
    }
  });

  it('downloads an ODT act working-copy export through the bounded format query', async () => {
    const odt = new Blob(['PK\u0003\u0004odt'], {
      type: 'application/vnd.oasis.opendocument.text',
    });
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(odt, {
        status: 200,
        headers: {
          'Content-Type': 'application/vnd.oasis.opendocument.text',
          'Content-Disposition': 'attachment; filename="act-act-1-working-copy.odt"',
        },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const download = await api.fetchActDocumentWorkingCopy('act-1', 'odt');

    expect(fetchMock.mock.calls[0][0]).toBe('/v1/acts/act-1/document/working-copy?format=odt');
    expect(fetchMock.mock.calls[0][1]?.method).toBeUndefined();
    expect(download.blob).toBeInstanceOf(Blob);
    expect(download.blob.type).toBe('application/vnd.oasis.opendocument.text');
    expect(download.blob.type).not.toBe('application/pdf');
    expect(download.headers.get('Content-Disposition')).toContain('working-copy.odt');
  });

  it('downloads an act office working-copy export as DOCX bytes', async () => {
    const docx = new Blob(['PK\u0003\u0004docx'], {
      type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    });
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(docx, {
        status: 200,
        headers: {
          'Content-Type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
          'Content-Disposition': 'attachment; filename="act-act-1-office-working-copy.docx"',
        },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const download = await api.fetchActDocumentOffice('act-1');

    expect(fetchMock.mock.calls[0][0]).toBe('/v1/acts/act-1/document/office');
    expect(fetchMock.mock.calls[0][1]?.method).toBeUndefined();
    expect(download).toBeInstanceOf(Blob);
    expect(download.type).toBe(
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    );
  });

  it('routes generated-document discovery, generation, PDF download, and dispatch evidence bodies', async () => {
    const generated = [
      {
        id: 'generated doc',
        act_id: 'act 1',
        template_id: 'condominio-comunicacao-ausentes/v1',
        pdf_digest: 'a'.repeat(64),
        profile: 'application/pdf; profile=PDF/A-2u',
        created_at: '2026-07-11T10:00:00Z',
        download: '/v1/documents/generated/generated%20doc',
        dispatch_evidence_status: {
          status: 'required_pending',
          required: true,
          evidence_attached: false,
          dispatch_completed: false,
          completion_basis: 'none',
          required_recipients: ['Fração B'],
          recorded_recipients: [],
          missing_recipients: ['Fração B'],
          note: 'operator-recorded evidence only',
        },
      },
    ];
    const generatedCertidao = {
      id: 'generated/certidão',
      act_id: 'act 1/2',
      template_id: 'condominio-certidao-deliberacoes/v1',
      pdf_digest: 'b'.repeat(64),
      profile: 'application/pdf; profile=PDF/A-2u',
      created_at: '2026-07-12T10:00:00Z',
      download: '/v1/documents/generated/generated%2Fcertid%C3%A3o',
      dispatch_evidence_status: null,
    };
    const evidence = {
      document_id: 'generated doc',
      act_id: 'act 1',
      template_id: 'condominio-comunicacao-ausentes/v1',
      dispatch_evidence_status: generated[0].dispatch_evidence_status,
      evidence: [],
    };
    const recorded = {
      evidence: {
        document_id: 'generated doc',
        idempotency_key: 'idem-1',
        act_id: 'act 1',
        template_id: 'condominio-comunicacao-ausentes/v1',
        actor: 'web-operator',
        dispatched_at: '2026-07-11T10:30:00Z',
        channel: 'RegisteredLetter',
        reference: 'RL-1',
        evidence_reference: null,
        imported_document_id: null,
        recipients: ['Fração B'],
        operator_note: null,
        recorded_at: '2026-07-11T10:31:00Z',
        sending_performed_by_chancela: false,
        delivery_confirmed: false,
        legal_sufficiency_claimed: false,
        legal_notice_completion_claimed: false,
        bytes_in_payload: false,
      },
      dispatch_evidence_status: {
        ...generated[0].dispatch_evidence_status,
        status: 'operator_evidence_covered',
        evidence_attached: true,
        recorded_recipients: ['Fração B'],
        missing_recipients: [],
      },
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(generated))
      .mockResolvedValueOnce(jsonResponse(generatedCertidao, 201))
      .mockResolvedValueOnce(
        new Response(new Blob(['%PDF-generated'], { type: 'application/pdf' }), {
          status: 200,
          headers: { 'Content-Type': 'application/pdf' },
        }),
      )
      .mockResolvedValueOnce(jsonResponse(evidence))
      .mockResolvedValueOnce(jsonResponse(recorded, 201));
    vi.stubGlobal('fetch', fetchMock);

    await api.listGeneratedDocuments('act 1');
    await api.generateActDocument('act 1/2', 'condominio-certidão deliberações/v1');
    await api.fetchGeneratedDocumentPdf('generated doc');
    await api.getGeneratedDocumentDispatchEvidence('generated doc');
    await api.recordGeneratedDocumentDispatchEvidence('generated doc', {
      actor: 'web-operator',
      dispatched_at: '2026-07-11T10:30:00Z',
      channel: 'RegisteredLetter',
      reference: 'RL-1',
      recipients: ['Fração B'],
      evidence_reference: null,
      imported_document_id: null,
      operator_note: null,
    });

    expect(fetchMock.mock.calls[0][0]).toBe('/v1/acts/act%201/documents/generated');
    expect(fetchMock.mock.calls[1][0]).toBe(
      '/v1/acts/act%201%2F2/document/generate?template_id=condominio-certid%C3%A3o+delibera%C3%A7%C3%B5es%2Fv1',
    );
    expect(fetchMock.mock.calls[1][1].method).toBe('POST');
    expect(fetchMock.mock.calls[1][1].body).toBeUndefined();
    expect(fetchMock.mock.calls[2][0]).toBe('/v1/documents/generated/generated%20doc');
    expect(fetchMock.mock.calls[3][0]).toBe(
      '/v1/documents/generated/generated%20doc/dispatch-evidence',
    );
    expect(fetchMock.mock.calls[4][0]).toBe(
      '/v1/documents/generated/generated%20doc/dispatch-evidence',
    );
    expect(fetchMock.mock.calls[4][1].method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[4][1].body)).toEqual({
      actor: 'web-operator',
      dispatched_at: '2026-07-11T10:30:00Z',
      channel: 'RegisteredLetter',
      reference: 'RL-1',
      recipients: ['Fração B'],
      evidence_reference: null,
      imported_document_id: null,
      operator_note: null,
    });
  });

  it('records act convening dispatch evidence through the act endpoint', async () => {
    const act = {
      id: 'act-1',
      book_id: 'book-1',
      title: 'Ata com convocatória',
      state: 'Signing',
    };
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse(act));
    vi.stubGlobal('fetch', fetchMock);

    await api.dispatchActConvening('act-1', {
      dispatched_at: '2026-06-01',
      channel: 'Email',
      reference: 'doc:convocatoria-2026-06-01',
      recipients: ['Ana', 'Bruno'],
    });

    expect(fetchMock.mock.calls[0][0]).toBe('/v1/acts/act-1/convening/dispatch');
    expect(fetchMock.mock.calls[0][1].method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      dispatched_at: '2026-06-01',
      channel: 'Email',
      reference: 'doc:convocatoria-2026-06-01',
      recipients: ['Ana', 'Bruno'],
    });
  });

  it('creates, lists, and revokes external signer invites with redacted list data', async () => {
    const invite = {
      id: 'invite-1',
      act_id: 'act-1',
      recipient_name: 'Bruno Dias',
      recipient_email: 'bruno@example.test',
      purpose: 'Assinar a ata',
      status: 'pending',
      workflow: 'tracking_only',
      token_hint: 'cxi_abcd...123456',
      created_at: '2026-07-06T10:00:00Z',
      created_by: 'amelia.marques',
      expires_at: '2026-07-08T10:00:00Z',
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ invite, token: 'cxi_fulltoken' }), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify([invite]), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ ...invite, status: 'revoked' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    vi.stubGlobal('fetch', fetchMock);

    const created = await api.createExternalSignerInvite('act-1', {
      recipient_name: 'Bruno Dias',
      recipient_email: 'bruno@example.test',
      expires_at: '2026-07-08T10:00:00Z',
      purpose: 'Assinar a ata',
    });
    const listed = await api.listExternalSignerInvites('act-1');
    const revoked = await api.revokeExternalSignerInvite('act-1', 'invite-1');

    expect(fetchMock.mock.calls[0][0]).toBe('/v1/acts/act-1/signature/external-invites');
    expect(fetchMock.mock.calls[0][1]?.method).toBe('POST');
    expect(fetchMock.mock.calls[1][0]).toBe('/v1/acts/act-1/signature/external-invites');
    expect(fetchMock.mock.calls[1][1]?.method).toBeUndefined();
    expect(fetchMock.mock.calls[2][0]).toBe(
      '/v1/acts/act-1/signature/external-invites/invite-1/revoke',
    );
    expect(fetchMock.mock.calls[2][1]?.method).toBe('POST');
    expect(created.token).toBe('cxi_fulltoken');
    expect(listed[0]).not.toHaveProperty('token');
    expect(revoked.status).toBe('revoked');
  });

  it('creates and lists external signing envelopes and sends linked invite fields', async () => {
    const envelope = {
      id: 'env-1',
      act_id: 'act-1',
      order_policy: 'sequential',
      slots: [
        {
          id: 'slot-1',
          signer_label: 'Bruno Dias',
          contact_hint: 'bruno@example.test',
          identity_requirements: ['contact_control'],
          required: true,
          status: 'pending',
          evidence: [],
        },
      ],
      completed: false,
      completion: {
        completed: false,
        required_slot_count: 1,
        signed_required_slot_count: 0,
        blocking_required_slot_ids: ['slot-1'],
      },
      notice:
        'External signing envelope workflow only; no legal, qualified-signature, or certificate-level claim is made.',
    };
    const invite = {
      id: 'invite-1',
      act_id: 'act-1',
      recipient_name: 'Bruno Dias',
      recipient_email: 'bruno@example.test',
      purpose: 'Assinar a ata',
      status: 'pending',
      workflow: 'external_envelope',
      external_envelope: {
        id: 'env-1',
        slot_id: 'slot-1',
        order_policy: 'sequential',
        slot_status: 'initiated',
      },
      token_hint: 'cxi_abcd...123456',
      created_at: '2026-07-06T10:00:00Z',
      created_by: 'amelia.marques',
      expires_at: '2026-07-08T10:00:00Z',
    };
    const updatedEnvelope = {
      ...envelope,
      slots: [
        {
          ...envelope.slots[0],
          status: 'signed',
          evidence: [
            {
              label: 'Operator technical evidence',
              reference: 'operator-log:slot-1',
              digest: 'a'.repeat(64),
            },
          ],
        },
      ],
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse([envelope]))
      .mockResolvedValueOnce(jsonResponse(envelope, 201))
      .mockResolvedValueOnce(jsonResponse(updatedEnvelope))
      .mockResolvedValueOnce(jsonResponse({ invite, token: 'cxi_fulltoken' }, 201));
    vi.stubGlobal('fetch', fetchMock);

    const listed = await api.listExternalSigningEnvelopes('act-1');
    const created = await api.createExternalSigningEnvelope('act-1', {
      order_policy: 'sequential',
      slots: [
        {
          signer_label: 'Bruno Dias',
          contact_hint: 'bruno@example.test',
          identity_requirements: ['contact_control'],
          required: true,
        },
      ],
    });
    const updated = await api.updateExternalSigningEnvelope('env-1', {
      slots: [
        {
          id: 'slot-1',
          status: 'signed',
          evidence: [
            {
              label: 'Operator technical evidence',
              reference: 'operator-log:slot-1',
              digest: 'a'.repeat(64),
            },
          ],
        },
      ],
    });
    const linkedInvite = await api.createExternalSignerInvite('act-1', {
      recipient_name: 'Bruno Dias',
      recipient_email: 'bruno@example.test',
      external_envelope_id: 'env-1',
      external_slot_id: 'slot-1',
      expires_at: '2026-07-08T10:00:00Z',
      purpose: 'Assinar a ata',
    });

    expect(fetchMock.mock.calls[0][0]).toBe('/v1/acts/act-1/external-signing/envelopes');
    expect(fetchMock.mock.calls[0][1]?.method).toBeUndefined();
    expect(fetchMock.mock.calls[1][0]).toBe('/v1/acts/act-1/external-signing/envelopes');
    expect(fetchMock.mock.calls[1][1]?.method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[1][1]?.body as string)).toEqual({
      order_policy: 'sequential',
      slots: [
        {
          signer_label: 'Bruno Dias',
          contact_hint: 'bruno@example.test',
          identity_requirements: ['contact_control'],
          required: true,
        },
      ],
    });
    expect(fetchMock.mock.calls[2][0]).toBe('/v1/external-signing/envelopes/env-1');
    expect(fetchMock.mock.calls[2][1]?.method).toBe('PATCH');
    expect(JSON.parse(fetchMock.mock.calls[2][1]?.body as string)).toEqual({
      slots: [
        {
          id: 'slot-1',
          status: 'signed',
          evidence: [
            {
              label: 'Operator technical evidence',
              reference: 'operator-log:slot-1',
              digest: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            },
          ],
        },
      ],
    });
    expect(fetchMock.mock.calls[3][0]).toBe('/v1/acts/act-1/signature/external-invites');
    expect(JSON.parse(fetchMock.mock.calls[3][1]?.body as string)).toMatchObject({
      external_envelope_id: 'env-1',
      external_slot_id: 'slot-1',
    });
    expect(listed[0].slots[0].status).toBe('pending');
    expect(created.order_policy).toBe('sequential');
    expect(updated.slots[0].status).toBe('signed');
    expect(linkedInvite.invite.external_envelope?.slot_status).toBe('initiated');
  });

  it('looks up and responds to an external signer invite with the token in JSON only', async () => {
    const envelope = {
      invite_id: 'invite-1',
      act: {
        id: 'act-1',
        title: 'Ata da AG anual',
        state: 'Sealed',
        ata_number: 1,
        entity_name: 'Encosto Estrategico, S.A.',
        book_kind: 'AssembleiaGeral',
      },
      recipient_name: 'Bruno Dias',
      purpose: 'Assinar a ata',
      status: 'pending',
      workflow: 'tracking_only',
      created_at: '2026-07-06T10:00:00Z',
      expires_at: '2026-07-08T10:00:00Z',
      notice: 'tracking only',
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(envelope))
      .mockResolvedValueOnce(jsonResponse({ ...envelope, status: 'accepted' }))
      .mockResolvedValueOnce(
        new Response('# working copy', {
          headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
        }),
      );
    vi.stubGlobal('fetch', fetchMock);

    const lookedUp = await api.lookupExternalSignerInvite('cxi_fulltoken');
    const accepted = await api.respondExternalSignerInvite('cxi_fulltoken', 'accept', {
      signed_pdf_base64: 'JVBERi0xLjQKc2lnbmVk',
      filename: 'signed.pdf',
    });
    const workingCopy = await api.fetchExternalSignerInviteWorkingCopy('cxi_fulltoken');

    expect(fetchMock.mock.calls[0][0]).toBe('/v1/signature/external-invites/lookup');
    expect(fetchMock.mock.calls[0][1]?.method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[0][1]?.body as string)).toEqual({
      token: 'cxi_fulltoken',
    });
    expect(fetchMock.mock.calls[1][0]).toBe('/v1/signature/external-invites/respond');
    expect(fetchMock.mock.calls[1][1]?.method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[1][1]?.body as string)).toEqual({
      token: 'cxi_fulltoken',
      decision: 'accept',
      signed_pdf_base64: 'JVBERi0xLjQKc2lnbmVk',
      filename: 'signed.pdf',
    });
    expect(fetchMock.mock.calls[2][0]).toBe('/v1/signature/external-invites/document/working-copy');
    expect(fetchMock.mock.calls[2][1]?.method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[2][1]?.body as string)).toEqual({
      token: 'cxi_fulltoken',
    });
    expect(lookedUp).not.toHaveProperty('token');
    expect(accepted.status).toBe('accepted');
    expect(JSON.stringify(fetchMock.mock.calls[1][1])).not.toContain('/cxi_fulltoken');
    expect(workingCopy.text).toBe('# working copy');
  });

  it('lists external-validator report metadata without raw report bytes', async () => {
    const report = {
      case_id: 'CASE-001',
      validator_family: 'AMA DSS',
      path: 'evidence/external-validators/CASE-001-ama-dss.json',
      content_type: 'application/json',
      sha256: 'a'.repeat(64),
    };
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        storage: 'durable',
        status: 'ok',
        count: 1,
        malformed_count: 0,
        duplicate_suggested_path_count: 0,
        reports: [report],
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const listed = await api.listExternalValidatorReports();

    expect(fetchMock.mock.calls[0][0]).toBe('/v1/external-validator-reports');
    expect(fetchMock.mock.calls[0][1]?.method).toBeUndefined();
    expect(listed.reports).toEqual([report]);
    expect(listed.reports[0]).not.toHaveProperty('raw');
    expect(listed.reports[0]).not.toHaveProperty('bytes');
  });

  it('uploads external-validator report JSON as raw selected text', async () => {
    const raw = '{\n  "case_id": "CASE-001",\n  "validator_family": "AMA DSS"\n}\n';
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(
        {
          storage: 'durable',
          status: 'stored',
          report: {
            case_id: 'CASE-001',
            validator_family: 'AMA DSS',
            path: 'evidence/external-validators/CASE-001-ama-dss.json',
            content_type: 'application/json',
            sha256: 'b'.repeat(64),
          },
        },
        201,
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const uploaded = await api.uploadExternalValidatorReport(raw);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/v1/external-validator-reports');
    expect(init.method).toBe('POST');
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json');
    expect(init.body).toBe(raw);
    expect(init.body).not.toBe(JSON.stringify(raw));
    expect(uploaded.report.case_id).toBe('CASE-001');
  });
});
