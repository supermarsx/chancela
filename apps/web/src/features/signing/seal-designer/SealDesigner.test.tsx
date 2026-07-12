/**
 * SealDesigner component test (t67-e12).
 *
 * The acceptance-critical case: a seal box drawn at KNOWN canvas coordinates over a rendered page
 * must map to the exact backend seal DTO `{page, x, y, w, h}` in unrotated PDF user space (the
 * §0.3 binding spec, incl. the y-flip). `usePdfPage` is mocked so the assertion runs on the real
 * component wiring without a live pdf.js render, and the page geometry is fixed and known.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
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
}));

vi.mock('./usePdfPage', () => ({
  usePdfPage: () => pdfPageMock.result,
}));

// Import AFTER the mock is registered.
import { SealDesigner } from './SealDesigner';

function renderDesigner(
  onApply: (seal: unknown) => void,
  initialSeal: SealAppearanceBody | null = null,
) {
  return render(
    <ToastProvider>
      <SealDesigner
        loadPdf={() => Promise.resolve(new ArrayBuffer(8))}
        initialSeal={initialSeal}
        defaultName="Amélia Marques"
        defaultDate="2026-07-12"
        onApply={onApply}
        onCancel={() => {}}
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
});
