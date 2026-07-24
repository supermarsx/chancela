/**
 * A real, stateless PDF/A proof for an authored template.
 *
 * The server receives either the current unsaved authored halves or a catalog id and writes the
 * result through the production PDF/A writer. It deliberately does not invent an act context:
 * placeholders, collection paths and signatory bindings stay unresolved and the UI says so.
 *
 * Requests are debounced and sequence-gated. A slow response for an older draft can therefore
 * never replace a newer proof, while the last successful PDF remains usable during an update or
 * after a transient failure. pdf.js is reached through the existing lazy `usePdfPage` boundary,
 * keeping the heavy engine out of the eager template-editor bundle.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import type {
  TemplateDocumentPreviewRequest,
  TemplateDocumentPreviewResult,
} from '../../api/types';
import { useTemplateDocumentPdfPreview } from '../../api/hooks';
import { useTemplatesPdfPreviewT } from '../../i18n/templatesPdfPreviewFallback';
import { Button, Icon, InlineWarning, Skeleton, SkeletonRegion } from '../../ui';
import { usePdfPage } from '../signing/seal-designer/usePdfPage';
import './templatePdfPreview.css';

type PreviewPhase = 'idle' | 'loading' | 'updating' | 'ready' | 'error';

export interface TemplatePdfPreviewProps {
  /** Unsaved draft or catalog source. `null` pauses generation and keeps the last valid proof. */
  request: TemplateDocumentPreviewRequest | null;
  /** Lets a parent keep the component mounted behind a preview-mode switch without issuing work. */
  enabled?: boolean;
  /** Debounce applied after the authored request content changes. */
  debounceMs?: number;
  /** Safe browser download name; the server response itself also carries an inline fallback name. */
  downloadFilename?: string;
  idPrefix?: string;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function safePdfFilename(value: string): string {
  const cleaned = Array.from(value.trim(), (character) =>
    character.charCodeAt(0) < 32 || '<>:"/\\|?*'.includes(character) ? '-' : character,
  )
    .join('')
    .replace(/\s+/g, ' ');
  if (!cleaned) return 'template-structural-preview.pdf';
  return cleaned.toLowerCase().endsWith('.pdf') ? cleaned : `${cleaned}.pdf`;
}

export function TemplatePdfPreview({
  request,
  enabled = true,
  debounceMs = 500,
  downloadFilename = 'template-structural-preview.pdf',
  idPrefix = 'template-pdf-preview',
}: TemplatePdfPreviewProps) {
  const pt = useTemplatesPdfPreviewT();
  const requestPdf = useTemplateDocumentPdfPreview();
  const mutateAsync = requestPdf.mutateAsync;
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const requestRef = useRef(request);
  const sequenceRef = useRef(0);
  const lastGoodRef = useRef<TemplateDocumentPreviewResult | null>(null);
  const [lastGood, setLastGood] = useState<TemplateDocumentPreviewResult | null>(null);
  const [phase, setPhase] = useState<PreviewPhase>('idle');
  const [requestError, setRequestError] = useState<unknown>(null);
  const [retryVersion, setRetryVersion] = useState(0);
  const [pageIndex, setPageIndex] = useState(0);
  const [blobUrl, setBlobUrl] = useState<string | null>(null);

  requestRef.current = request;
  const requestKey = useMemo(() => (request ? JSON.stringify(request) : ''), [request]);

  useEffect(() => {
    const sequence = ++sequenceRef.current;
    const currentRequest = requestRef.current;
    setRequestError(null);
    if (!enabled || !currentRequest) {
      setPhase(lastGoodRef.current ? 'ready' : 'idle');
      return;
    }

    setPhase(lastGoodRef.current ? 'updating' : 'loading');
    const handle = window.setTimeout(
      () => {
        void mutateAsync(currentRequest).then(
          (result) => {
            if (sequenceRef.current !== sequence) return;
            lastGoodRef.current = result;
            setLastGood(result);
            setRequestError(null);
            setPhase('ready');
          },
          (error) => {
            if (sequenceRef.current !== sequence) return;
            setRequestError(error);
            setPhase('error');
          },
        );
      },
      Math.max(0, debounceMs),
    );

    return () => {
      window.clearTimeout(handle);
      if (sequenceRef.current === sequence) sequenceRef.current += 1;
    };
  }, [debounceMs, enabled, mutateAsync, requestKey, retryVersion]);

  // pdf.js takes a defensive copy, so these original bytes can also back one shared Blob URL for
  // the open/download fallbacks. Revoke on every replacement and on unmount.
  useEffect(() => {
    setBlobUrl(null);
    if (!lastGood || typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function') {
      return;
    }
    const url = URL.createObjectURL(
      new Blob([lastGood.data.slice(0)], {
        type: lastGood.content_type || 'application/pdf',
      }),
    );
    setBlobUrl(url);
    return () => {
      URL.revokeObjectURL(url);
    };
  }, [lastGood]);

  useEffect(() => {
    setPageIndex(0);
  }, [lastGood?.data]);

  const pdf = usePdfPage({
    data: lastGood?.data ?? null,
    pageIndex,
    targetWidth: 700,
    canvasRef,
  });
  const pageCount = Math.max(1, pdf.pageCount);

  useEffect(() => {
    if (pdf.pageCount > 0) {
      setPageIndex((current) => Math.min(current, pdf.pageCount - 1));
    }
  }, [pdf.pageCount]);

  const isWorking = phase === 'loading' || phase === 'updating';
  const pageParams = {
    current: String(pageIndex + 1),
    total: String(pageCount),
  };
  const canvasDescriptionId = `${idPrefix}-canvas-description`;
  const filename = safePdfFilename(downloadFilename);

  return (
    <section
      className="template-pdf-preview stack--tight"
      aria-labelledby={`${idPrefix}-title`}
      aria-busy={isWorking || pdf.status === 'loading'}
    >
      <header className="template-pdf-preview__head">
        <p className="card__label" id={`${idPrefix}-title`}>
          {pt('templates.pdfPreview.title')}
        </p>
        <p className="field__hint" id={canvasDescriptionId}>
          {pt('templates.pdfPreview.description')}
        </p>
      </header>

      <div className="template-pdf-preview__status" role="status" aria-live="polite">
        {phase === 'loading'
          ? pt('templates.pdfPreview.loading')
          : phase === 'updating'
            ? pt('templates.pdfPreview.updating')
            : null}
        {(phase === 'updating' || phase === 'error') && lastGood
          ? ` ${pt('templates.pdfPreview.lastGood')}`
          : null}
      </div>

      {requestError ? (
        <div role="alert">
          <InlineWarning tone="error" title={pt('templates.pdfPreview.error.title')}>
            <p>{errorMessage(requestError)}</p>
            <Button type="button" variant="secondary" onClick={() => setRetryVersion((n) => n + 1)}>
              {pt('templates.pdfPreview.retry')}
            </Button>
          </InlineWarning>
        </div>
      ) : null}

      {!lastGood && phase === 'loading' ? (
        <SkeletonRegion label={pt('templates.pdfPreview.loading')}>
          <Skeleton height="32rem" />
        </SkeletonRegion>
      ) : null}

      {!lastGood && phase === 'idle' ? (
        <p className="muted">{pt('templates.pdfPreview.empty')}</p>
      ) : null}

      {lastGood ? (
        <>
          <div className="row-wrap template-pdf-preview__actions">
            {blobUrl ? (
              <>
                <a
                  className="btn btn--secondary btn--icon"
                  href={blobUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <span className="btn__icon" aria-hidden="true">
                    <Icon.ExternalLink />
                  </span>
                  {pt('templates.pdfPreview.open')}
                </a>
                <a className="btn btn--ghost btn--icon" href={blobUrl} download={filename}>
                  <span className="btn__icon" aria-hidden="true">
                    <Icon.Save />
                  </span>
                  {pt('templates.pdfPreview.download')}
                </a>
              </>
            ) : null}
          </div>

          {pdf.pageCount > 1 ? (
            <div className="template-pdf-preview__pager">
              <Button
                type="button"
                variant="ghost"
                aria-label={pt('templates.pdfPreview.previous')}
                disabled={pageIndex <= 0}
                onClick={() => setPageIndex((current) => Math.max(0, current - 1))}
              >
                ‹
              </Button>
              <span>{pt('templates.pdfPreview.page', pageParams)}</span>
              <Button
                type="button"
                variant="ghost"
                aria-label={pt('templates.pdfPreview.next')}
                disabled={pageIndex >= pdf.pageCount - 1}
                onClick={() => setPageIndex((current) => Math.min(pdf.pageCount - 1, current + 1))}
              >
                ›
              </Button>
            </div>
          ) : null}

          <div className="template-pdf-preview__viewport">
            <canvas
              ref={canvasRef}
              className="template-pdf-preview__canvas"
              role="img"
              aria-describedby={canvasDescriptionId}
              aria-label={pt('templates.pdfPreview.canvas', pageParams)}
            />
            {pdf.status === 'loading' ? (
              <SkeletonRegion
                className="template-pdf-preview__canvas-loading"
                label={pt('templates.pdfPreview.loading')}
              >
                <Skeleton height="32rem" />
              </SkeletonRegion>
            ) : null}
          </div>

          {pdf.status === 'error' ? (
            <div role="alert">
              <InlineWarning tone="error" title={pt('templates.pdfPreview.error.title')}>
                <p>{errorMessage(pdf.error)}</p>
              </InlineWarning>
            </div>
          ) : null}
        </>
      ) : null}
    </section>
  );
}
