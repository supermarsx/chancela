/**
 * Complete, stateless Markdown representation of an authored template.
 *
 * This deliberately asks the server for the same unresolved `DocumentModel` used by the PDF/A
 * proof. Shipped ATA templates frequently keep their prose in `spec.blocks` and have an empty
 * `body_markdown`; showing that source alone therefore produced a blank and misleading preview.
 *
 * Requests are debounced and sequence-gated like the PDF preview. The last successful document
 * remains visible while a newer draft is rendered or after a transient failure.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { useTemplateDocumentMarkdownPreview } from '../../api/hooks';
import type {
  TemplateDocumentMarkdownPreviewResult,
  TemplateDocumentPreviewRequest,
} from '../../api/types';
import { useTemplatesEditorT } from '../../i18n/templatesEditorFallback';
import { Button, Icon, InlineWarning, Skeleton, SkeletonRegion } from '../../ui';

type PreviewPhase = 'idle' | 'loading' | 'updating' | 'ready' | 'error';
type CopyState = 'idle' | 'copied' | 'failed';

export interface TemplateMarkdownPreviewProps {
  /** Unsaved draft or catalog source. `null` pauses generation and keeps the last valid proof. */
  request: TemplateDocumentPreviewRequest | null;
  /** Lets a parent keep the component mounted behind a format switch without issuing work. */
  enabled?: boolean;
  debounceMs?: number;
  idPrefix?: string;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function TemplateMarkdownPreview({
  request,
  enabled = true,
  debounceMs = 500,
  idPrefix = 'template-markdown-preview',
}: TemplateMarkdownPreviewProps) {
  const bt = useTemplatesEditorT();
  const requestMarkdown = useTemplateDocumentMarkdownPreview();
  const mutateAsync = requestMarkdown.mutateAsync;
  const requestRef = useRef(request);
  const sequenceRef = useRef(0);
  const lastGoodRef = useRef<TemplateDocumentMarkdownPreviewResult | null>(null);
  const [lastGood, setLastGood] = useState<TemplateDocumentMarkdownPreviewResult | null>(null);
  const [phase, setPhase] = useState<PreviewPhase>('idle');
  const [requestError, setRequestError] = useState<unknown>(null);
  const [retryVersion, setRetryVersion] = useState(0);
  const [copyState, setCopyState] = useState<CopyState>('idle');

  requestRef.current = request;
  const requestKey = useMemo(() => (request ? JSON.stringify(request) : ''), [request]);

  useEffect(() => {
    const sequence = ++sequenceRef.current;
    const currentRequest = requestRef.current;
    setRequestError(null);
    setCopyState('idle');
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

  async function copyMarkdown() {
    if (!lastGood) return;
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard API unavailable');
      await navigator.clipboard.writeText(lastGood.markdown);
      setCopyState('copied');
    } catch {
      setCopyState('failed');
    }
  }

  const isWorking = phase === 'loading' || phase === 'updating';

  return (
    <section className="stack--tight" aria-labelledby={`${idPrefix}-title`} aria-busy={isWorking}>
      <div className="template-preview__markdown-head">
        <div>
          <p className="field__hint" id={`${idPrefix}-title`}>
            {bt('templates.editor.preview.markdown.note')}
          </p>
          <div role="status" aria-live="polite">
            {phase === 'loading'
              ? bt('templates.editor.preview.markdown.loading')
              : phase === 'updating'
                ? bt('templates.editor.preview.markdown.updating')
                : null}
            {(phase === 'updating' || phase === 'error') && lastGood
              ? ` ${bt('templates.editor.preview.markdown.lastGood')}`
              : null}
          </div>
        </div>
        {lastGood ? (
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.Copy />}
            onClick={() => void copyMarkdown()}
          >
            {bt(
              copyState === 'copied'
                ? 'templates.editor.preview.markdown.copied'
                : copyState === 'failed'
                  ? 'templates.editor.preview.markdown.copyFailed'
                  : 'templates.editor.preview.markdown.copy',
            )}
          </Button>
        ) : null}
      </div>

      {requestError ? (
        <div role="alert">
          <InlineWarning tone="error" title={bt('templates.editor.preview.markdown.error.title')}>
            <p>{errorMessage(requestError)}</p>
            <Button type="button" variant="secondary" onClick={() => setRetryVersion((n) => n + 1)}>
              {bt('templates.editor.preview.markdown.retry')}
            </Button>
          </InlineWarning>
        </div>
      ) : null}

      {!lastGood && phase === 'loading' ? (
        <SkeletonRegion label={bt('templates.editor.preview.markdown.loading')}>
          <Skeleton height="14rem" />
        </SkeletonRegion>
      ) : null}

      {!lastGood && phase === 'idle' ? (
        <p className="muted">{bt('templates.editor.preview.empty')}</p>
      ) : null}

      {lastGood ? (
        <pre
          className="template-preview__markdown-source"
          aria-label={bt('templates.editor.preview.markdown.sourceLabel')}
          tabIndex={0}
        >
          <code>{lastGood.markdown}</code>
        </pre>
      ) : null}
    </section>
  );
}
