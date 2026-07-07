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
});
