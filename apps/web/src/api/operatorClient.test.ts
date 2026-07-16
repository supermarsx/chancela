import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './client';
import { clearSessionToken, setSessionToken } from './session';
import { connectorConfigTemplate } from '../features/operations/operatorModels';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
  clearSessionToken();
  vi.restoreAllMocks();
});

describe('tenant operator API client', () => {
  it('builds encoded company-group and template-library routes with exact HTTP verbs', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json([]))
      .mockResolvedValueOnce(json({ revision: 2 }, 201));

    await api.listCompanyGroups('tenant/one');
    await api.appendGroupTemplateLibraryRevision('tenant/one', 'group?one', 'library one', {
      template_ids: ['tpl-a', 'tpl-b'],
    });

    expect(fetchMock.mock.calls[0]?.[0]).toBe('/v1/tenants/tenant%2Fone/groups');
    expect(fetchMock.mock.calls[0]?.[1]?.method).toBeUndefined();
    expect(fetchMock.mock.calls[1]?.[0]).toBe(
      '/v1/tenants/tenant%2Fone/groups/group%3Fone/template-libraries/library%20one/revisions',
    );
    expect(fetchMock.mock.calls[1]?.[1]).toEqual(
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ template_ids: ['tpl-a', 'tpl-b'] }),
      }),
    );
  });

  it('submits connector credential references and durable job pagination without secret query data', async () => {
    const target = {
      schema_version: 1,
      id: 'target-1',
      repository_id: 'repository-1',
      tenant_id: 'tenant-1',
      name: 'WebDAV',
      enabled: true,
      purposes: ['sync'],
      kind: 'web_dav',
      config: connectorConfigTemplate('web_dav'),
      credential_storage: 'environment_or_confined_file_reference',
      created_at: '2026-07-16T00:00:00Z',
      updated_at: '2026-07-16T00:00:00Z',
      archived_at: null,
    } as const;
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(target, 201))
      .mockResolvedValueOnce(json({ jobs: [], next_before_created_unix_millis: null }));

    await api.createConnectorTarget('tenant-1', {
      name: 'WebDAV',
      enabled: true,
      purposes: ['sync'],
      config: connectorConfigTemplate('web_dav'),
    });
    await api.listConnectorJobs('tenant-1', {
      limit: 25,
      before_created_unix_millis: 1234,
    });

    const createBody = String(fetchMock.mock.calls[0]?.[1]?.body);
    expect(createBody).toContain('CHANCELA_CONNECTOR_SECRET_WEBDAV_PASSWORD');
    expect(createBody).not.toContain('actual-secret');
    expect(fetchMock.mock.calls[1]?.[0]).toBe(
      '/v1/tenants/tenant-1/connector-jobs?limit=25&before_created_unix_millis=1234',
    );
  });

  it('preserves opaque byte and readability attachment boundaries with session authentication', async () => {
    setSessionToken('session-token');
    const committed = {
      archive_id: 'archive-1',
      tenant_id: 'tenant-1',
      manifest: {},
      ciphertext_url: '/ciphertext',
      committed_at: '2026-07-16T00:00:00Z',
    };
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(committed, 201))
      .mockResolvedValueOnce(
        new Response(new Uint8Array([80, 75, 3, 4]), {
          status: 200,
          headers: { 'Content-Type': 'application/zip' },
        }),
      );
    const ciphertext = Uint8Array.from([1, 2, 3]).buffer;
    await api.commitZkObjectCiphertext('/v1/uploads/u1/ciphertext', ciphertext);
    const attachment = await api.createZkReadabilityPackage(
      'tenant-1',
      'repository-1',
      'object-1',
      3,
      {
        mode: 'encrypted_archive_with_portable_key_package',
        book_id: 'book-1',
        portable_key_package_jwe: 'encrypted-jwe',
        recipient_instructions: 'Exchange the private material out of band.',
        reauth: { password: 'transient-proof' },
      },
    );

    expect(fetchMock.mock.calls[0]?.[1]).toEqual(
      expect.objectContaining({
        method: 'PUT',
        body: ciphertext,
        headers: expect.objectContaining({
          'Content-Type': 'application/octet-stream',
          'X-Chancela-Session': 'session-token',
        }),
      }),
    );
    expect(fetchMock.mock.calls[1]?.[0]).toBe(
      '/v1/tenants/tenant-1/repositories/repository-1/objects/object-1/versions/3/readability-package',
    );
    expect(String(fetchMock.mock.calls[1]?.[1]?.body)).toContain('encrypted-jwe');
    expect(attachment.blob.type).toBe('application/zip');
  });
});
