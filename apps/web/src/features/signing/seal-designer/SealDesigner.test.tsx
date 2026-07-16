/**
 * SealDesigner component test (t67-e12).
 *
 * The acceptance-critical case: a seal box drawn at KNOWN canvas coordinates over a rendered page
 * must map to the exact backend seal DTO `{page, x, y, w, h}` in unrotated PDF user space (the
 * §0.3 binding spec, incl. the y-flip). `usePdfPage` is mocked so the assertion runs on the real
 * component wiring without a live pdf.js render, and the page geometry is fixed and known.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ToastProvider } from '../../../ui/toast';
import type { SealAppearanceBody } from '../../../api/types';
import type { PageGeometry } from './coordinates';

// A known, non-square US-Letter page at scale 1 (render surface = 612x792 CSS px, no rotation).
const GEOMETRY: PageGeometry = { widthPt: 612, heightPt: 792, rotation: 0, scale: 1 };

type PdfPageMockResult = {
  status: 'idle' | 'loading' | 'ready' | 'error';
  pageCount: number;
  geometry: PageGeometry | null;
  error: unknown;
};

const pdfPageMock = vi.hoisted(() => ({
  result: {
    status: 'ready',
    pageCount: 1,
    geometry: { widthPt: 612, heightPt: 792, rotation: 0, scale: 1 },
    error: null,
  } as PdfPageMockResult,
  calls: [] as Array<{ pageIndex: number }>,
}));

vi.mock('./usePdfPage', () => ({
  usePdfPage: (args: { pageIndex: number }) => {
    pdfPageMock.calls.push(args);
    return pdfPageMock.result;
  },
}));

// Import AFTER the mock is registered.
import { SealDesigner } from './SealDesigner';

function renderDesigner(
  onApply: (seal: unknown) => void,
  initialSeal: SealAppearanceBody | null = null,
  onCancel: () => void = () => {},
  loadPdf: () => Promise<ArrayBuffer> = () => Promise.resolve(new ArrayBuffer(8)),
) {
  return render(
    <ToastProvider>
      <SealDesigner
        loadPdf={loadPdf}
        initialSeal={initialSeal}
        defaultName="Amélia Marques"
        defaultDate="2026-07-12"
        onApply={onApply}
        onCancel={onCancel}
      />
    </ToastProvider>,
  );
}

/** Stub the render surface's client rect so canvas coordinates are deterministic (origin 0,0). */
function stubSurfaceRect() {
  const surface = screen.getByRole('application');
  surface.getBoundingClientRect = () =>
    ({
      left: 0,
      top: 0,
      right: GEOMETRY.widthPt,
      bottom: GEOMETRY.heightPt,
      width: GEOMETRY.widthPt,
      height: GEOMETRY.heightPt,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    }) as DOMRect;
  return surface;
}

beforeEach(() => {
  pdfPageMock.result = { status: 'ready', pageCount: 1, geometry: GEOMETRY, error: null };
  pdfPageMock.calls = [];
});

afterEach(cleanup);

describe('SealDesigner coordinate mapping', () => {
  it('maps a box drawn near the canvas top to the y-flipped PDF rect and emits the seal DTO', () => {
    const onApply = vi.fn();
    renderDesigner(onApply);
    const surface = stubSurfaceRect();

    // Draw a 200x80 box, 100px from the left and 50px from the TOP of the 612x792 render.
    fireEvent.mouseDown(surface, { clientX: 100, clientY: 50 });
    fireEvent.mouseMove(window, { clientX: 300, clientY: 130 });
    fireEvent.mouseUp(window);

    // The live overlay renders at the drawn box.
    expect(screen.getByTestId('seal-box')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Aplicar selo' }));

    expect(onApply).toHaveBeenCalledTimes(1);
    // Binding spec: x = left; y = page_height - top - h = 792 - 50 - 80 = 662; template content.
    expect(onApply).toHaveBeenCalledWith({
      invisible: false,
      page: 0,
      x: 100,
      y: 662,
      w: 200,
      h: 80,
      template: { kind: 'name_date', name: 'Amélia Marques', date: '2026-07-12' },
    });
  });

  it('lets precise numeric fields drive the exact PDF rect', () => {
    const onApply = vi.fn();
    renderDesigner(onApply);
    stubSurfaceRect();

    // Type an exact placement (points) instead of drawing.
    fireEvent.change(screen.getByLabelText('X (pontos)'), { target: { value: '72' } });
    fireEvent.change(screen.getByLabelText('Y (pontos)'), { target: { value: '144' } });
    fireEvent.change(screen.getByLabelText('Largura (pontos)'), { target: { value: '150' } });
    fireEvent.change(screen.getByLabelText('Altura (pontos)'), { target: { value: '60' } });

    fireEvent.click(screen.getByRole('button', { name: 'Aplicar selo' }));

    expect(onApply).toHaveBeenCalledWith(
      expect.objectContaining({ invisible: false, page: 0, x: 72, y: 144, w: 150, h: 60 }),
    );
  });

  it('disables apply until a seal box is placed', () => {
    const onApply = vi.fn();
    renderDesigner(onApply);
    const apply = screen.getByRole('button', { name: 'Aplicar selo' }) as HTMLButtonElement;
    expect(apply.disabled).toBe(true);
  });

  it('keeps a stable fallback page surface while the PDF geometry is loading', () => {
    pdfPageMock.result = { status: 'loading', pageCount: 0, geometry: null, error: null };
    renderDesigner(vi.fn());

    const surface = screen.getByRole('application');
    expect(surface.style.width).toBe('560px');
    expect(surface.style.height).toBe('725px');
    expect(surface.style.minHeight).toBe('725px');
    expect(surface.style.aspectRatio).toBe('560 / 725');
    expect(screen.getByText('A carregar a pré-visualização…')).toBeTruthy();
  });

  it('moves the seal with arrow keys from the focusable placement control', () => {
    const onApply = vi.fn();
    renderDesigner(onApply, {
      invisible: false,
      page: 0,
      x: 72,
      y: 144,
      w: 150,
      h: 60,
    });
    stubSurfaceRect();

    const moveControl = screen.getByTestId('seal-move-control') as HTMLButtonElement;
    expect(moveControl.tagName).toBe('BUTTON');
    expect(moveControl.getAttribute('aria-keyshortcuts')).toContain('Shift+ArrowUp');

    fireEvent.keyDown(moveControl, { key: 'ArrowRight' });
    fireEvent.keyDown(moveControl, { key: 'ArrowUp', shiftKey: true });
    fireEvent.click(screen.getByRole('button', { name: 'Aplicar selo' }));

    expect(onApply).toHaveBeenCalledWith(
      expect.objectContaining({ invisible: false, page: 0, x: 73, y: 154, w: 150, h: 60 }),
    );
  });

  it('resizes the seal with arrow keys from the focusable handle', () => {
    const onApply = vi.fn();
    renderDesigner(onApply, {
      invisible: false,
      page: 0,
      x: 72,
      y: 144,
      w: 150,
      h: 60,
    });
    stubSurfaceRect();

    const handle = screen.getByTestId('seal-resize-handle') as HTMLButtonElement;
    expect(handle.tagName).toBe('BUTTON');
    expect(handle.getAttribute('aria-label')).toContain('Largura (pontos)');

    fireEvent.keyDown(handle, { key: 'ArrowRight' });
    fireEvent.keyDown(handle, { key: 'ArrowDown', shiftKey: true });
    fireEvent.click(screen.getByRole('button', { name: 'Aplicar selo' }));

    expect(onApply).toHaveBeenCalledWith(
      expect.objectContaining({ invisible: false, page: 0, x: 72, y: 134, w: 151, h: 70 }),
    );
  });

  it('previews and re-applies an existing image seal without the original File', () => {
    const onApply = vi.fn();
    const { container } = renderDesigner(onApply, {
      invisible: false,
      page: 0,
      x: 72,
      y: 144,
      w: 150,
      h: 60,
      image_base64: 'QUJDRA==',
      image_format: 'png',
    });
    stubSurfaceRect();

    const image = container.querySelector('.seal-designer__box-image') as HTMLImageElement | null;
    expect(image?.getAttribute('src')).toBe('data:image/png;base64,QUJDRA==');

    fireEvent.click(screen.getByRole('button', { name: 'Aplicar selo' }));

    expect(onApply).toHaveBeenCalledWith({
      invisible: false,
      page: 0,
      x: 72,
      y: 144,
      w: 150,
      h: 60,
      image_base64: 'QUJDRA==',
      image_format: 'png',
    });
  });

  it('navigates every rendered PDF page without moving outside the page range', async () => {
    pdfPageMock.result = { status: 'ready', pageCount: 3, geometry: GEOMETRY, error: null };
    renderDesigner(vi.fn(), {
      invisible: false,
      page: 1,
      x: 72,
      y: 144,
      w: 150,
      h: 60,
    });

    expect(pdfPageMock.calls.at(-1)?.pageIndex).toBe(1);
    fireEvent.click(screen.getByText('›'));
    await waitFor(() => expect(pdfPageMock.calls.at(-1)?.pageIndex).toBe(2));

    const next = screen.getByText('›').closest('button') as HTMLButtonElement;
    expect(next.disabled).toBe(true);

    fireEvent.click(screen.getByText('‹'));
    await waitFor(() => expect(pdfPageMock.calls.at(-1)?.pageIndex).toBe(1));
  });

  it('builds the signed-by template and exposes cancel as a non-mutating exit', () => {
    const onApply = vi.fn();
    const onCancel = vi.fn();
    const { container } = renderDesigner(
      onApply,
      { invisible: false, page: 0, x: 72, y: 144, w: 150, h: 60 },
      onCancel,
    );

    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'signed_by' } });
    fireEvent.change(container.querySelector('#seal-heading') as HTMLInputElement, {
      target: { value: 'Assinado digitalmente por' },
    });
    fireEvent.change(container.querySelector('#seal-name') as HTMLInputElement, {
      target: { value: 'Beatriz Silva' },
    });
    fireEvent.change(container.querySelector('#seal-date') as HTMLInputElement, {
      target: { value: '2026-07-16' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Aplicar selo' }));

    expect(onApply).toHaveBeenCalledWith(
      expect.objectContaining({
        template: {
          kind: 'signed_by',
          heading: 'Assinado digitalmente por',
          name: 'Beatriz Silva',
          date: '2026-07-16',
        },
      }),
    );

    fireEvent.click(screen.getByRole('button', { name: 'Cancelar' }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('moves and resizes an existing seal through pointer gestures', () => {
    const onApply = vi.fn();
    renderDesigner(onApply, {
      invisible: false,
      page: 0,
      x: 72,
      y: 144,
      w: 150,
      h: 60,
    });
    stubSurfaceRect();

    fireEvent.mouseDown(screen.getByTestId('seal-move-control'), {
      clientX: 80,
      clientY: 600,
    });
    fireEvent.mouseMove(window, { clientX: 100, clientY: 620 });
    fireEvent.mouseUp(window);

    fireEvent.mouseDown(screen.getByTestId('seal-resize-handle'), {
      clientX: 242,
      clientY: 668,
    });
    fireEvent.mouseMove(window, { clientX: 272, clientY: 683 });
    fireEvent.mouseUp(window);
    fireEvent.click(screen.getByRole('button', { name: 'Aplicar selo' }));

    expect(onApply).toHaveBeenCalledWith(expect.objectContaining({ x: 92, y: 109, w: 180, h: 75 }));
  });

  it('covers every keyboard direction and ignores unrelated keys', () => {
    const onApply = vi.fn();
    renderDesigner(onApply, {
      invisible: false,
      page: 0,
      x: 72,
      y: 144,
      w: 150,
      h: 60,
    });
    stubSurfaceRect();

    const move = screen.getByTestId('seal-move-control');
    fireEvent.keyDown(move, { key: 'ArrowLeft' });
    fireEvent.keyDown(move, { key: 'ArrowDown' });
    fireEvent.keyDown(move, { key: 'Enter' });

    const resize = screen.getByTestId('seal-resize-handle');
    fireEvent.keyDown(resize, { key: 'ArrowLeft' });
    fireEvent.keyDown(resize, { key: 'ArrowUp' });
    fireEvent.keyDown(resize, { key: 'Escape' });
    fireEvent.click(screen.getByRole('button', { name: 'Aplicar selo' }));

    expect(onApply).toHaveBeenCalledWith(expect.objectContaining({ x: 71, y: 144, w: 149, h: 59 }));
  });

  it('validates image selections, applies a valid image, and revokes object URLs', async () => {
    const onApply = vi.fn();
    const createObjectURL = vi
      .fn()
      .mockReturnValueOnce('blob:first')
      .mockReturnValueOnce('blob:next');
    const revokeObjectURL = vi.fn();
    URL.createObjectURL = createObjectURL;
    URL.revokeObjectURL = revokeObjectURL;

    const { container, unmount } = renderDesigner(onApply, {
      invisible: false,
      page: 0,
      x: 72,
      y: 144,
      w: 150,
      h: 60,
    });
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'image' } });
    const input = container.querySelector('#seal-image') as HTMLInputElement;
    const file = (bytes: Uint8Array, type: string) =>
      ({
        type,
        arrayBuffer: () =>
          Promise.resolve(
            bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
          ),
      }) as unknown as File;

    fireEvent.change(input, { target: { files: [file(new Uint8Array([1]), 'image/gif')] } });
    expect((await screen.findByRole('alert')).textContent).toContain('não suportado');

    fireEvent.change(input, { target: { files: [file(new Uint8Array(), 'image/png')] } });
    expect((await screen.findByRole('alert')).textContent).toContain('está vazia');

    fireEvent.change(input, {
      target: { files: [file(new Uint8Array(2 * 1024 * 1024 + 1), 'image/png')] },
    });
    expect((await screen.findByRole('alert')).textContent).toContain('2 MiB');

    fireEvent.change(input, {
      target: { files: [file(new Uint8Array([137, 80, 78, 71]), 'image/png')] },
    });
    await waitFor(() => expect(container.querySelector('.seal-designer__box-image')).toBeTruthy());
    fireEvent.click(screen.getByRole('button', { name: 'Aplicar selo' }));
    expect(onApply).toHaveBeenCalledWith(
      expect.objectContaining({ image_base64: 'iVBORw==', image_format: 'png' }),
    );

    fireEvent.change(input, {
      target: { files: [file(new Uint8Array([255, 216, 255]), 'image/jpeg')] },
    });
    await waitFor(() => expect(revokeObjectURL).toHaveBeenCalledWith('blob:first'));
    unmount();
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:next');
  });

  it('surfaces both PDF loading and rendering failures', async () => {
    pdfPageMock.result = {
      status: 'error',
      pageCount: 0,
      geometry: null,
      error: new Error('pdf.js render failed'),
    };
    renderDesigner(vi.fn(), null, undefined, () => Promise.reject(new Error('load failed')));

    expect((await screen.findByRole('alert')).textContent).toContain('pré-visualização');
    expect(screen.getByText('Error: pdf.js render failed')).toBeTruthy();
  });
});
