import { act, cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  TemplateDocumentMarkdownPreviewResult,
  TemplateDocumentPreviewRequest,
} from '../../api/types';
import { renderWithProviders, Wrapper } from '../../test/utils';
import { TemplateMarkdownPreview } from './TemplateMarkdownPreview';

const mocks = vi.hoisted(() => ({
  mutateAsync: vi.fn(),
}));

vi.mock('../../api/hooks', () => ({
  useTemplateDocumentMarkdownPreview: () => ({ mutateAsync: mocks.mutateAsync }),
}));

const REQUEST_A: TemplateDocumentPreviewRequest = {
  source: 'catalog',
  template_id: 'csc-ata-ag/v1',
};
const REQUEST_B: TemplateDocumentPreviewRequest = {
  source: 'catalog',
  template_id: 'condominio-ata-assembleia/v1',
};

function result(markdown: string): TemplateDocumentMarkdownPreviewResult {
  return {
    markdown,
    content_type: 'text/markdown; charset=utf-8',
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
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
    configurable: true,
  });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('TemplateMarkdownPreview', () => {
  it('renders and copies the complete server-generated document, including block-authored prose', async () => {
    const markdown = '# Ata n.º {{ ata_number }}\n\n## Ordem de trabalhos\n\n## Signature slots\n';
    mocks.mutateAsync.mockResolvedValue(result(markdown));

    renderWithProviders(<TemplateMarkdownPreview request={REQUEST_A} debounceMs={0} />);

    expect(
      (await screen.findByLabelText('Pré-visualização Markdown estrutural completa')).textContent,
    ).toContain('Ordem de trabalhos');
    expect(mocks.mutateAsync).toHaveBeenCalledWith(REQUEST_A);

    fireEvent.click(screen.getByRole('button', { name: 'Copiar Markdown' }));
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith(markdown));
    expect(screen.getByRole('button', { name: 'Markdown copiado' })).toBeTruthy();
  });

  it('suppresses an older slow response after the newer draft wins', async () => {
    const first = deferred<TemplateDocumentMarkdownPreviewResult>();
    const second = deferred<TemplateDocumentMarkdownPreviewResult>();
    mocks.mutateAsync.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const view = renderWithProviders(
      <TemplateMarkdownPreview request={REQUEST_A} debounceMs={0} />,
    );

    await waitFor(() => expect(mocks.mutateAsync).toHaveBeenCalledTimes(1));
    view.rerender(
      <Wrapper>
        <TemplateMarkdownPreview request={REQUEST_B} debounceMs={0} />
      </Wrapper>,
    );
    await waitFor(() => expect(mocks.mutateAsync).toHaveBeenCalledTimes(2));

    await act(async () => {
      second.resolve(result('# Documento novo'));
      await second.promise;
    });
    expect(
      (await screen.findByLabelText('Pré-visualização Markdown estrutural completa')).textContent,
    ).toContain('Documento novo');

    await act(async () => {
      first.resolve(result('# Documento antigo'));
      await first.promise;
    });
    expect(
      screen.getByLabelText('Pré-visualização Markdown estrutural completa').textContent,
    ).not.toContain('Documento antigo');
  });

  it('keeps the last good document after failure and retries the current request', async () => {
    mocks.mutateAsync.mockResolvedValueOnce(result('# Documento válido'));
    const view = renderWithProviders(
      <TemplateMarkdownPreview request={REQUEST_A} debounceMs={0} />,
    );
    await screen.findByText('# Documento válido', { exact: false });

    mocks.mutateAsync.mockRejectedValueOnce(new Error('preview unavailable'));
    view.rerender(
      <Wrapper>
        <TemplateMarkdownPreview request={REQUEST_B} debounceMs={0} />
      </Wrapper>,
    );

    expect((await screen.findByRole('alert')).textContent).toContain('preview unavailable');
    expect(
      screen.getByLabelText('Pré-visualização Markdown estrutural completa').textContent,
    ).toContain('Documento válido');
    expect(screen.getByRole('status').textContent).toContain('última pré-visualização válida');

    mocks.mutateAsync.mockResolvedValueOnce(result('# Documento repetido'));
    fireEvent.click(screen.getByRole('button', { name: 'Tentar novamente' }));
    await waitFor(() => expect(mocks.mutateAsync).toHaveBeenCalledTimes(3));
    expect(
      (await screen.findByLabelText('Pré-visualização Markdown estrutural completa')).textContent,
    ).toContain('Documento repetido');
  });
});
