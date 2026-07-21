/**
 * MarkdownBodyEditor — the ata's narrative body (t74-e6). Public entry point.
 *
 * This file is deliberately thin: it exists to be the **chunk boundary**. ProseMirror and its
 * markdown packages are reached only through the `React.lazy` import below, so they land in their
 * own async chunk (`vendor-prosemirror`, see `vite.config.ts`) and never in the eager vendor bundle
 * that every page pays for on first paint. `vendor-pdfjs` is the established precedent.
 *
 * The editing surface, the schema and the markdown round-trip all live in
 * `MarkdownBodyEditorInner.tsx`. See that file's header for the design: a WYSIWYG whose **schema is
 * the frozen block set**, so unsupported constructs are unrepresentable rather than rejected after
 * the fact — and for why markdown, not ProseMirror JSON, remains the stored source of truth.
 */
import { Suspense, lazy } from 'react';
import { useT } from '../../i18n';
import type { MarkdownBodyEditorProps } from './markdownBodyTypes';

export type { MarkdownBodyEditorProps, MarkdownDiagnostic, PasteReport } from './markdownBodyTypes';
export { byteLength, charIndexForByteOffset, locateIndex } from './markdownBodyTypes';

const Inner = lazy(() => import('./MarkdownBodyEditorInner'));

export function MarkdownBodyEditor(props: MarkdownBodyEditorProps) {
  const t = useT();
  return (
    <Suspense fallback={<p className="field__hint">{t('acts.body.editor.loading')}</p>}>
      <Inner {...props} />
    </Suspense>
  );
}
