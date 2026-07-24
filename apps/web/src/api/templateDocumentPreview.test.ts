import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './client';
import type { TemplateSpec } from './types';

const SPEC: TemplateSpec = {
  id: 'user-board/v1',
  family: 'CommercialCompany',
  stage: 'Ata',
  channels: ['Physical'],
  signature_policy: 'QualifiedPreferred',
  rule_pack_id: 'csc-art63/v2',
  locale: 'pt-PT',
  blocks: [{ kind: 'Heading', level: 1, template: 'Ata {{ ata_number }}' }],
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('template document PDF preview API', () => {
  it('posts an unsaved draft and preserves PDF bytes plus proof metadata', async () => {
    const bytes = new TextEncoder().encode('%PDF-1.7 structural');
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(bytes, {
        headers: {
          'Content-Type': 'application/pdf; profile=PDF/A-2u',
          'X-Chancela-Template-Preview': 'structural-unresolved',
        },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const result = await api.previewTemplateDocumentPdf({
      source: 'draft',
      spec: SPEC,
      body_markdown: '# Corpo {{ ata_number }}',
    });

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/templates/document/preview',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          source: 'draft',
          spec: SPEC,
          body_markdown: '# Corpo {{ ata_number }}',
        }),
      }),
    );
    expect(new TextDecoder().decode(result.data)).toBe('%PDF-1.7 structural');
    expect(result.content_type).toBe('application/pdf; profile=PDF/A-2u');
    expect(result.preview_kind).toBe('structural-unresolved');
  });

  it('posts a catalog source and preserves structured validation failures', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(new TextEncoder().encode('%PDF-1.7 catalog'), {
          headers: { 'Content-Type': 'application/pdf' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            code: 'unsupported_locale',
            field: 'locale',
            message: 'unsupported template locale',
          }),
          {
            status: 422,
            headers: { 'Content-Type': 'application/json' },
          },
        ),
      );
    vi.stubGlobal('fetch', fetchMock);

    await api.previewTemplateDocumentPdf({
      source: 'catalog',
      template_id: 'csc-ata-ag/v1',
    });
    await expect(
      api.previewTemplateDocumentPdf({
        source: 'draft',
        spec: { ...SPEC, locale: 'en-GB' },
        body_markdown: '',
      }),
    ).rejects.toMatchObject({
      status: 422,
      code: 'unsupported_locale',
      field: 'locale',
    });

    expect(JSON.parse(fetchMock.mock.calls[0]?.[1]?.body as string)).toEqual({
      source: 'catalog',
      template_id: 'csc-ata-ag/v1',
    });
  });
});
