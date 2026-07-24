import { act, cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  TemplateDocumentPreviewRequest,
  TemplateDocumentPreviewResult,
} from '../../api/types';
import { renderWithProviders, Wrapper } from '../../test/utils';
import { TemplatePdfPreview } from './TemplatePdfPreview';

const mocks = vi.hoisted(() => ({
  mutateAsync: vi.fn(),
  usePdfPage: vi.fn(),
}));

vi.mock('../../api/hooks', () => ({
  useTemplateDocumentPdfPreview: () => ({ mutateAsync: mocks.mutateAsync }),
}));

vi.mock('../signing/seal-designer/usePdfPage', () => ({
  usePdfPage: (options: unknown) => mocks.usePdfPage(options),
}));

const REQUEST_A: TemplateDocumentPreviewRequest = {
  source: 'catalog',
  template_id: 'csc-ata-ag/v1',
};
const REQUEST_B: TemplateDocumentPreviewRequest = {
  source: 'catalog',
  template_id: 'condominio-ata-assembleia/v1',
};

function result(label: string): TemplateDocumentPreviewResult {
  return {
    data: new TextEncoder().encode(label).buffer,
    content_type: 'application/pdf; profile=PDF/A-2u',
    preview_kind: 'structural-unresolved',
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

beforeEach(() => {
  mocks.mutateAsync.mockReset();
  mocks.usePdfPage.mockReset();
  mocks.usePdfPage.mockImplementation(
    (options: { data: ArrayBuffer | null; pageIndex: number }) => ({
      status: options.data ? 'ready' : 'idle',
      pageCount: options.data ? 3 : 0,
      geometry: null,
      error: null,
    }),
  );
  let url = 0;
  vi.stubGlobal('URL', {
    ...URL,
    createObjectURL: vi.fn(() => `blob:template-proof-${++url}`),
    revokeObjectURL: vi.fn(),
  });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('TemplatePdfPreview', () => {
  it('debounces generation, renders one accessible PDF canvas, pages it, and exposes fallbacks', async () => {
    mocks.mutateAsync.mockResolvedValue(result('proof-a'));
    const view = renderWithProviders(
      <TemplatePdfPreview request={REQUEST_A} debounceMs={10} downloadFilename="board-proof" />,
    );

    expect(mocks.mutateAsync).not.toHaveBeenCalled();
    await waitFor(() => expect(mocks.mutateAsync).toHaveBeenCalledWith(REQUEST_A));
    const canvas = screen.getByRole('img', {
      name: /Página 1 de 3 da pré-visualização PDF\/A estrutural/,
    });
    expect(canvas).toBeTruthy();
    const open = await screen.findByRole('link', { name: 'Abrir PDF' });
    const download = screen.getByRole('link', { name: 'Descarregar PDF' });
    expect(open.getAttribute('href')).toBe('blob:template-proof-1');
    expect(open.getAttribute('target')).toBe('_blank');
    expect(download.getAttribute('download')).toBe('board-proof.pdf');

    fireEvent.click(screen.getByRole('button', { name: 'Página seguinte' }));
    expect(
      screen.getByRole('img', {
        name: /Página 2 de 3 da pré-visualização PDF\/A estrutural/,
      }),
    ).toBeTruthy();
    expect(mocks.usePdfPage.mock.calls.at(-1)?.[0]).toEqual(
      expect.objectContaining({ pageIndex: 1 }),
    );

    view.unmount();
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:template-proof-1');
  });

  it('suppresses an older slow response after a newer draft has already won', async () => {
    const first = deferred<TemplateDocumentPreviewResult>();
    const second = deferred<TemplateDocumentPreviewResult>();
    mocks.mutateAsync.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const view = renderWithProviders(<TemplatePdfPreview request={REQUEST_A} debounceMs={0} />);

    await waitFor(() => expect(mocks.mutateAsync).toHaveBeenCalledTimes(1));
    view.rerender(
      <Wrapper>
        <TemplatePdfPreview request={REQUEST_B} debounceMs={0} />
      </Wrapper>,
    );
    await waitFor(() => expect(mocks.mutateAsync).toHaveBeenCalledTimes(2));

    await act(async () => {
      second.resolve(result('newer-proof'));
      await second.promise;
    });
    await waitFor(() =>
      expect(screen.getByRole('link', { name: 'Abrir PDF' }).getAttribute('href')).toBe(
        'blob:template-proof-1',
      ),
    );

    await act(async () => {
      first.resolve(result('older-proof'));
      await first.promise;
    });
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
    const latestOptions = mocks.usePdfPage.mock.calls.at(-1)?.[0] as {
      data: ArrayBuffer;
    };
    expect(new TextDecoder().decode(latestOptions.data)).toBe('newer-proof');
  });

  it('keeps the last good PDF on failure and retries the current request', async () => {
    mocks.mutateAsync.mockResolvedValueOnce(result('valid-proof'));
    const view = renderWithProviders(<TemplatePdfPreview request={REQUEST_A} debounceMs={0} />);
    await waitFor(() => expect(screen.getByRole('link', { name: 'Abrir PDF' })).toBeTruthy());

    mocks.mutateAsync.mockRejectedValueOnce(new Error('preview unavailable'));
    view.rerender(
      <Wrapper>
        <TemplatePdfPreview request={REQUEST_B} debounceMs={0} />
      </Wrapper>,
    );

    expect((await screen.findByRole('alert')).textContent).toContain('preview unavailable');
    expect(screen.getByRole('img')).toBeTruthy();
    expect(screen.getByRole('status').textContent).toContain('última pré-visualização válida');

    mocks.mutateAsync.mockResolvedValueOnce(result('retried-proof'));
    fireEvent.click(screen.getByRole('button', { name: 'Tentar novamente' }));
    await waitFor(() => expect(mocks.mutateAsync).toHaveBeenCalledTimes(3));
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
  });
});
