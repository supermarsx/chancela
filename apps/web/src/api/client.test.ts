import { describe, it, expect, vi, afterEach } from 'vitest';
import { ApiError, api, parseResponse } from './client';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
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

  it('builds a query string only from defined params', async () => {
    // Fresh Response per call: a body may only be read once.
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(jsonResponse([])));
    vi.stubGlobal('fetch', fetchMock);

    await api.listBooks('ent-1');
    expect(fetchMock.mock.calls[0][0]).toBe('/v1/books?entity_id=ent-1');

    await api.listBooks();
    expect(fetchMock.mock.calls[1][0]).toBe('/v1/books');
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

  it('uses the privacy processor and DPIA register endpoints', async () => {
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
    const accepted = await api.respondExternalSignerInvite('cxi_fulltoken', 'accept');
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
    });
    expect(fetchMock.mock.calls[2][0]).toBe('/v1/signature/external-invites/document/working-copy');
    expect(fetchMock.mock.calls[2][1]?.method).toBe('POST');
    expect(JSON.parse(fetchMock.mock.calls[2][1]?.body as string)).toEqual({
      token: 'cxi_fulltoken',
    });
    expect(lookedUp).not.toHaveProperty('token');
    expect(accepted.status).toBe('accepted');
    expect(workingCopy.text).toBe('# working copy');
  });
});
