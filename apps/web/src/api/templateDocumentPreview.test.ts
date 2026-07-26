import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './client';
import { templateSpecFromExport } from './hooks';
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
  it('posts an unsaved draft and preserves PDF bytes plus preview metadata', async () => {
    const bytes = new TextEncoder().encode('%PDF-1.7 sample');
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(bytes, {
        headers: {
          'Content-Type': 'application/pdf; profile=PDF/A-2u',
          'X-Chancela-Template-Preview': 'sample-resolved',
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
    expect(new TextDecoder().decode(result.data)).toBe('%PDF-1.7 sample');
    expect(result.content_type).toBe('application/pdf; profile=PDF/A-2u');
    expect(result.preview_kind).toBe('sample-resolved');
  });

  it('returns complete server Markdown with the same sample classification', async () => {
    const markdown = '# Ata n.º {{ ata_number }}\n\n## Ordem de trabalhos\n';
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(markdown, {
        headers: {
          'Content-Type': 'text/markdown; charset=utf-8',
          'X-Chancela-Template-Preview': 'sample-resolved',
        },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const result = await api.previewTemplateDocumentMarkdown({
      source: 'catalog',
      template_id: 'csc-ata-ag/v1',
    });

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/templates/document/preview/markdown',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          source: 'catalog',
          template_id: 'csc-ata-ag/v1',
        }),
      }),
    );
    expect(result).toEqual({
      markdown,
      content_type: 'text/markdown; charset=utf-8',
      preview_kind: 'sample-resolved',
    });
  });

  it('strips runtime-only fields from an older built-in export before draft preview', async () => {
    const exported = {
      format: 'chancela.template-bundle',
      format_version: 1,
      spec: {
        ...SPEC,
        id: 'csc-ata-ag/v1',
        law_references: [
          {
            source_id: 'csc',
            source: 'Código das Sociedades Comerciais',
            article: '63',
            citation: 'Código das Sociedades Comerciais, Artigo 63.º',
          },
        ],
        default_body: [{ heading: 'Abertura', text: 'Texto derivado.' }],
      },
      body_markdown: '## Abertura\n\nTexto derivado.',
    };
    const normalized = templateSpecFromExport(exported);
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(new TextEncoder().encode('%PDF-1.7 normalized'), {
        headers: { 'Content-Type': 'application/pdf' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await api.previewTemplateDocumentPdf({
      source: 'draft',
      spec: normalized,
      body_markdown: exported.body_markdown,
    });

    expect(normalized).toEqual({ ...SPEC, id: 'csc-ata-ag/v1' });
    expect(normalized).not.toHaveProperty('law_references');
    expect(normalized).not.toHaveProperty('default_body');
    const request = JSON.parse(fetchMock.mock.calls[0]?.[1]?.body as string) as {
      spec: Record<string, unknown>;
    };
    expect(request.spec).not.toHaveProperty('law_references');
    expect(request.spec).not.toHaveProperty('default_body');
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
