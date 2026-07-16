import { act, renderHook, waitFor } from '@testing-library/react';
import type { RefObject } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const pdfjsMock = vi.hoisted(() => ({
  GlobalWorkerOptions: { workerSrc: '' },
  getDocument: vi.fn(),
}));

vi.mock('pdfjs-dist', () => pdfjsMock);
vi.mock('pdfjs-dist/build/pdf.worker.min.mjs?url', () => ({ default: '/pdf.worker.mjs' }));

import { usePdfPage } from './usePdfPage';

type Deferred<T> = {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
};

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function canvasRef(context: CanvasRenderingContext2D | null = {} as CanvasRenderingContext2D) {
  const canvas = document.createElement('canvas');
  vi.spyOn(canvas, 'getContext').mockReturnValue(context);
  return { canvas, ref: { current: canvas } as RefObject<HTMLCanvasElement | null> };
}

function pdfFixture(
  options: {
    numPages?: number;
    rotation?: number;
    renderPromise?: Promise<void>;
  } = {},
) {
  const renderTask = {
    promise: options.renderPromise ?? Promise.resolve(),
    cancel: vi.fn(),
  };
  const page = {
    view: [10, 20, 622, 812] as [number, number, number, number],
    rotate: options.rotation ?? 90,
    getViewport: vi.fn(({ scale }: { scale: number }) => ({
      width: 792 * scale,
      height: 612 * scale,
    })),
    render: vi.fn((_options: { transform?: unknown }) => renderTask),
  };
  const doc = {
    numPages: options.numPages ?? 2,
    getPage: vi.fn().mockResolvedValue(page),
  };
  const task = {
    promise: Promise.resolve(doc),
    destroy: vi.fn().mockResolvedValue(undefined),
  };
  pdfjsMock.getDocument.mockReturnValue(task);
  return { doc, page, renderTask, task };
}

beforeEach(() => {
  pdfjsMock.getDocument.mockReset();
  pdfjsMock.GlobalWorkerOptions.workerSrc = '';
  vi.stubGlobal('devicePixelRatio', 2);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('usePdfPage', () => {
  it('stays idle without bytes and does not start pdf.js', () => {
    const { ref } = canvasRef();
    const { result } = renderHook(() =>
      usePdfPage({ data: null, pageIndex: 0, targetWidth: 560, canvasRef: ref }),
    );

    expect(result.current).toEqual({ status: 'idle', pageCount: 0, geometry: null, error: null });
    expect(pdfjsMock.getDocument).not.toHaveBeenCalled();
  });

  it('loads copied bytes, clamps the page, renders at device scale, and exposes geometry', async () => {
    const fixture = pdfFixture();
    const { canvas, ref } = canvasRef();
    const source = new Uint8Array([1, 2, 3, 4]).buffer;
    const { result, unmount } = renderHook(() =>
      usePdfPage({ data: source, pageIndex: 99, targetWidth: 396, canvasRef: ref }),
    );

    await waitFor(() => expect(result.current.geometry).not.toBeNull());

    expect(pdfjsMock.GlobalWorkerOptions.workerSrc).toBe('/pdf.worker.mjs');
    const loadedBytes = pdfjsMock.getDocument.mock.calls[0][0].data as Uint8Array;
    expect([...loadedBytes]).toEqual([1, 2, 3, 4]);
    expect(loadedBytes.buffer).not.toBe(source);
    expect(fixture.doc.getPage).toHaveBeenCalledWith(2);
    expect(fixture.page.getViewport).toHaveBeenNthCalledWith(1, { scale: 1 });
    expect(fixture.page.getViewport).toHaveBeenNthCalledWith(2, { scale: 0.5 });
    expect(fixture.page.render).toHaveBeenCalledWith(
      expect.objectContaining({
        canvas,
        transform: [2, 0, 0, 2, 0, 0],
      }),
    );
    expect(canvas.width).toBe(792);
    expect(canvas.height).toBe(612);
    expect(canvas.style.width).toBe('396px');
    expect(canvas.style.height).toBe('306px');
    expect(result.current).toEqual({
      status: 'ready',
      pageCount: 2,
      geometry: { widthPt: 612, heightPt: 792, rotation: 90, scale: 0.5 },
      error: null,
    });

    unmount();
    expect(fixture.task.destroy).toHaveBeenCalledTimes(1);
    expect(fixture.renderTask.cancel).toHaveBeenCalledTimes(1);
  });

  it('uses a one-to-one render transform when devicePixelRatio is unavailable', async () => {
    vi.stubGlobal('devicePixelRatio', 0);
    const fixture = pdfFixture({ numPages: 1, rotation: -90 });
    const { ref } = canvasRef();
    const data = new ArrayBuffer(2);
    const { result } = renderHook(() =>
      usePdfPage({ data, pageIndex: -4, targetWidth: 792, canvasRef: ref }),
    );

    await waitFor(() => expect(result.current.status).toBe('ready'));
    await waitFor(() => expect(result.current.geometry).not.toBeNull());
    expect(result.current.error).toBeNull();
    expect(result.current.geometry).not.toBeNull();
    expect(fixture.doc.getPage).toHaveBeenCalledWith(1);
    expect(fixture.page.render.mock.calls[0]?.[0].transform).toBeUndefined();
    expect(result.current.geometry?.rotation).toBe(270);
  });

  it('reports document-load failures without rendering', async () => {
    const failure = new Error('invalid PDF');
    pdfjsMock.getDocument.mockReturnValue({
      promise: Promise.reject(failure),
      destroy: vi.fn().mockResolvedValue(undefined),
    });
    const { ref } = canvasRef();
    const data = new ArrayBuffer(1);
    const { result } = renderHook(() =>
      usePdfPage({ data, pageIndex: 0, targetWidth: 300, canvasRef: ref }),
    );

    await waitFor(() => expect(result.current.status).toBe('error'));
    expect(result.current.error).toBe(failure);
  });

  it('reports a missing 2d context as a render failure', async () => {
    pdfFixture();
    const { ref } = canvasRef(null);
    const data = new ArrayBuffer(1);
    const { result } = renderHook(() =>
      usePdfPage({ data, pageIndex: 0, targetWidth: 300, canvasRef: ref }),
    );

    await waitFor(() => expect(result.current.status).toBe('error'));
    expect(result.current.error).toEqual(new Error('canvas 2d context unavailable'));
  });

  it('does not surface pdf.js cancellation and cancels an in-flight render on unmount', async () => {
    const pendingRender = deferred<void>();
    const fixture = pdfFixture({ renderPromise: pendingRender.promise });
    const { ref } = canvasRef();
    const data = new ArrayBuffer(1);
    const { result, unmount } = renderHook(() =>
      usePdfPage({ data, pageIndex: 0, targetWidth: 300, canvasRef: ref }),
    );

    await waitFor(() => expect(fixture.page.render).toHaveBeenCalled());
    unmount();
    await act(async () => {
      pendingRender.reject({ name: 'RenderingCancelledException' });
      await Promise.resolve();
    });

    expect(fixture.renderTask.cancel).toHaveBeenCalledTimes(1);
    expect(result.current.status).toBe('ready');
    expect(result.current.error).toBeNull();
  });
});
