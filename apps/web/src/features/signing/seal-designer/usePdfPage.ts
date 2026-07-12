/**
 * pdf.js page loader/renderer for the visual seal designer (t67-e12).
 *
 * Introduces the app's first PDF-page renderer (§0.3: the web tier had no PDF viewer). pdf.js
 * is imported LAZILY inside an effect — never at module load — so (a) the ~1 MB engine and its
 * worker stay out of the initial bundle and off the jsdom test path, and (b) the component that
 * mounts this hook can be unit-tested by mocking the hook without pulling pdf.js into jsdom.
 *
 * The worker is wired with Vite's `?url` asset import (`GlobalWorkerOptions.workerSrc`), the
 * documented pattern that makes the pdf.js worker bundle cleanly under `vite build`.
 *
 * The hook renders the selected page into the caller's `<canvas>` at a scale chosen to fit a
 * target CSS width, and reports the {@link PageGeometry} (unrotated MediaBox dimensions, display
 * rotation, and the CSS-px-per-point scale) the coordinate mapping needs.
 */
import { useEffect, useRef, useState } from 'react';
import type { PDFDocumentProxy, PDFPageProxy, RenderTask } from 'pdfjs-dist';
import { normalizeRotation, type PageGeometry } from './coordinates';

type PdfjsLib = typeof import('pdfjs-dist');

/** Module-level singletons: load the engine + wire the worker exactly once per session. */
let pdfjsPromise: Promise<PdfjsLib> | null = null;

async function loadPdfjs(): Promise<PdfjsLib> {
  if (!pdfjsPromise) {
    pdfjsPromise = (async () => {
      const pdfjs = await import('pdfjs-dist');
      const workerUrl = (await import('pdfjs-dist/build/pdf.worker.min.mjs?url')).default;
      pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;
      return pdfjs;
    })();
  }
  return pdfjsPromise;
}

export type PdfPageStatus = 'idle' | 'loading' | 'ready' | 'error';

export interface UsePdfPageResult {
  status: PdfPageStatus;
  /** Total page count of the loaded document (0 until loaded). */
  pageCount: number;
  /** Geometry of the currently rendered page — the coordinate-mapping input. */
  geometry: PageGeometry | null;
  /** A non-secret error (load/render failure) for an honest inline message. */
  error: unknown;
}

export interface UsePdfPageOptions {
  /** The PDF bytes to render, or `null` while they are still loading. */
  data: ArrayBuffer | null;
  /** 0-based page to render. */
  pageIndex: number;
  /** Target CSS width (px) to fit the rendered page into; the scale is derived from it. */
  targetWidth: number;
  /** The canvas to render into. */
  canvasRef: React.RefObject<HTMLCanvasElement | null>;
}

/**
 * Load a PDF and render one page into a canvas, exposing the geometry needed to map an overlay
 * box to PDF user space. Re-renders when the page, target width, or document changes.
 */
export function usePdfPage(options: UsePdfPageOptions): UsePdfPageResult {
  const { data, pageIndex, targetWidth, canvasRef } = options;
  const [status, setStatus] = useState<PdfPageStatus>('idle');
  const [pageCount, setPageCount] = useState(0);
  const [geometry, setGeometry] = useState<PageGeometry | null>(null);
  const [error, setError] = useState<unknown>(null);
  const docRef = useRef<PDFDocumentProxy | null>(null);

  // Load (or reload) the document whenever the source bytes change.
  useEffect(() => {
    if (!data) {
      return;
    }
    let cancelled = false;
    setStatus('loading');
    setError(null);
    // pdf.js takes ownership of (and detaches) the buffer it is handed, so give it a copy and
    // keep the caller's `data` intact for a later reload (e.g. a page change re-render).
    const bytes = new Uint8Array(data.slice(0));
    let localDoc: PDFDocumentProxy | null = null;
    (async () => {
      try {
        const pdfjs = await loadPdfjs();
        const doc = await pdfjs.getDocument({ data: bytes }).promise;
        if (cancelled) {
          await doc.destroy();
          return;
        }
        localDoc = doc;
        docRef.current = doc;
        setPageCount(doc.numPages);
        setStatus('ready');
      } catch (err) {
        if (!cancelled) {
          setError(err);
          setStatus('error');
        }
      }
    })();
    return () => {
      cancelled = true;
      if (localDoc) {
        void localDoc.destroy();
      }
      docRef.current = null;
    };
  }, [data]);

  // Render the selected page whenever it, the fit width, or the loaded document changes.
  useEffect(() => {
    const doc = docRef.current;
    const canvas = canvasRef.current;
    if (status !== 'ready' || !doc || !canvas || targetWidth <= 0) {
      return;
    }
    let cancelled = false;
    let renderTask: RenderTask | null = null;
    (async () => {
      try {
        const clampedIndex = Math.min(Math.max(0, pageIndex), doc.numPages - 1);
        const page: PDFPageProxy = await doc.getPage(clampedIndex + 1);
        if (cancelled) {
          return;
        }
        // Unrotated MediaBox dimensions (page.view = [x0, y0, x1, y1]) and display rotation.
        const [x0, y0, x1, y1] = page.view;
        const widthPt = x1 - x0;
        const heightPt = y1 - y0;
        const rotation = normalizeRotation(page.rotate);
        // Scale to fit the target width against the ROTATED display width (rotation-1 viewport).
        const displayWidthAt1 = page.getViewport({ scale: 1 }).width;
        const scale = targetWidth / displayWidthAt1;
        const viewport = page.getViewport({ scale });
        const dpr = typeof window !== 'undefined' ? window.devicePixelRatio || 1 : 1;
        const ctx = canvas.getContext('2d');
        if (!ctx) {
          throw new Error('canvas 2d context unavailable');
        }
        canvas.width = Math.floor(viewport.width * dpr);
        canvas.height = Math.floor(viewport.height * dpr);
        canvas.style.width = `${viewport.width}px`;
        canvas.style.height = `${viewport.height}px`;
        renderTask = page.render({
          canvasContext: ctx,
          viewport,
          transform: dpr !== 1 ? [dpr, 0, 0, dpr, 0, 0] : undefined,
        });
        await renderTask.promise;
        if (!cancelled) {
          setGeometry({ widthPt, heightPt, rotation, scale });
        }
      } catch (err) {
        // A cancelled render throws a RenderingCancelledException — not an error worth surfacing.
        if (!cancelled && !isRenderCancellation(err)) {
          setError(err);
          setStatus('error');
        }
      }
    })();
    return () => {
      cancelled = true;
      if (renderTask) {
        renderTask.cancel();
      }
    };
  }, [status, pageIndex, targetWidth, canvasRef]);

  return { status, pageCount, geometry, error };
}

/** Whether an error is pdf.js's benign "render was cancelled" signal. */
function isRenderCancellation(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'name' in err &&
    (err as { name?: unknown }).name === 'RenderingCancelledException'
  );
}
