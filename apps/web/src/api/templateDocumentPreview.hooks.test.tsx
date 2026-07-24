import type { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './client';
import { useTemplateDocumentPdfPreview } from './hooks';
import type { TemplateDocumentPreviewRequest } from './types';

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('useTemplateDocumentPdfPreview', () => {
  it('forwards the tagged source through a read-only mutation', async () => {
    const result = {
      data: new ArrayBuffer(4),
      content_type: 'application/pdf; profile=PDF/A-2u',
      preview_kind: 'structural-unresolved',
    };
    const preview = vi.spyOn(api, 'previewTemplateDocumentPdf').mockResolvedValue(result);
    const request: TemplateDocumentPreviewRequest = {
      source: 'catalog',
      template_id: 'csc-ata-ag/v1',
    };
    const hook = renderHook(() => useTemplateDocumentPdfPreview(), { wrapper });

    await act(async () => {
      await hook.result.current.mutateAsync(request);
    });

    expect(preview).toHaveBeenCalledWith(request);
    await waitFor(() => expect(hook.result.current.data).toBe(result));
  });
});
