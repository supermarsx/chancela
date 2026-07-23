/**
 * The single read-only renderer for an authored template specification.
 *
 * Create, edit and detail all pass their current `TemplateBlockSpec[]` through this component so
 * every block kind and property has one visual contract. Narrative Markdown is deliberately not
 * compiled here: callers supply the result of the authoritative server compiler as a small state
 * union, allowing editors to keep their debounced diagnostic flow while the detail page keeps its
 * immediate read-only flow. The compiled blocks are inserted exactly where each `NarrativeBody`
 * marker appears.
 *
 * Document headings remain styled paragraphs with explicit ARIA heading levels. This preserves a
 * labelled, navigable document hierarchy beneath the application page without introducing another
 * native `<h1>`.
 */
import { useId } from 'react';
import type { Block, TemplateBlockSpec } from '../../api/types';
import { useT } from '../../i18n';
import { useTemplatesCatalogT } from '../../i18n/templatesCatalogFallback';
import { InlineWarning, SkeletonRegion, SkeletonText } from '../../ui';
import { previewHeadingAriaLevel, TemplateBodyPreview } from './TemplateBodyPreview';
import '../documents/documents.css';

export type TemplateNarrativePreviewState =
  | { status: 'empty' }
  | { status: 'loading' }
  | { status: 'ready'; blocks: Block[] }
  | { status: 'error'; diagnostic: string };

export interface TemplateAuthoredPreviewProps {
  title: string;
  templateId: string;
  locale?: string;
  blocks: TemplateBlockSpec[];
  narrative: TemplateNarrativePreviewState;
}

/** Clamp an authored heading level before deriving its visual document class. */
function authoredHeadingLevel(level: number): 1 | 2 | 3 | 4 | 5 | 6 {
  if (!Number.isFinite(level)) return 2;
  return Math.min(6, Math.max(1, Math.round(level))) as 1 | 2 | 3 | 4 | 5 | 6;
}

function NarrativeBodyPreview({ state }: { state: TemplateNarrativePreviewState }) {
  const ct = useTemplatesCatalogT();

  switch (state.status) {
    case 'empty':
      return <p className="doc-paragraph muted">{ct('templates.catalog.preview.narrative')}</p>;
    case 'loading':
      return (
        <SkeletonRegion className="stack--tight">
          <SkeletonText lines={3} />
        </SkeletonRegion>
      );
    case 'error':
      return (
        <div role="alert">
          <InlineWarning tone="error" title={ct('templates.catalog.preview.error.title')}>
            <p>{ct('templates.catalog.preview.error.body')}</p>
            <p className="muted">{state.diagnostic}</p>
          </InlineWarning>
        </div>
      );
    case 'ready':
      return (
        <TemplateBodyPreview
          blocks={state.blocks}
          emptyLabel={ct('templates.catalog.preview.narrative')}
        />
      );
  }
}

/**
 * One authored block, with merge expressions and collection paths kept literal.
 *
 * `data-template-block-kind` is both a useful inspection seam and an explicit statement that the
 * rendered DOM order is the authored block order.
 */
function AuthoredTemplateBlock({
  block,
  narrative,
}: {
  block: TemplateBlockSpec;
  narrative: TemplateNarrativePreviewState;
}) {
  const t = useT();

  switch (block.kind) {
    case 'Heading': {
      const level = authoredHeadingLevel(block.level);
      return (
        <p
          className={`doc-block doc-heading doc-heading--${level}`}
          data-template-block-kind={block.kind}
          data-heading-level={level}
          role="heading"
          aria-level={previewHeadingAriaLevel(level)}
        >
          {block.template}
        </p>
      );
    }
    case 'Paragraph':
      return (
        <div className="doc-block" data-template-block-kind={block.kind}>
          {block.items ? (
            <p className="field__hint">
              <code>{block.items}</code>
            </p>
          ) : null}
          <p className="doc-paragraph">{block.template}</p>
        </div>
      );
    case 'KeyValue':
      return (
        <div className="doc-block" data-template-block-kind={block.kind}>
          {block.items ? (
            <p className="field__hint">
              <code>{block.items}</code>
            </p>
          ) : null}
          <dl className="doc-kv">
            {block.rows.map((row, index) => (
              <div
                key={`${row.key}:${index}`}
                className="doc-kv__row"
                style={{ display: 'contents' }}
              >
                <dt className="doc-kv__key">{row.key}</dt>
                <dd className="doc-kv__value">{row.value}</dd>
              </div>
            ))}
          </dl>
        </div>
      );
    case 'VoteTable':
      return (
        <div className="doc-block" data-template-block-kind={block.kind}>
          <p className="field__hint">
            <code>{block.items}</code> · <code>{block.vote_field ?? 'vote'}</code>
            {block.unanimous_total ? (
              <>
                {' · '}
                <code>{block.unanimous_total}</code>
              </>
            ) : null}
          </p>
          <table className="doc-votetable">
            <thead>
              <tr>
                <th scope="col">{t('documents.vote.label')}</th>
                <th scope="col" className="doc-votetable__num">
                  {t('documents.vote.favor')}
                </th>
                <th scope="col" className="doc-votetable__num">
                  {t('documents.vote.against')}
                </th>
                <th scope="col" className="doc-votetable__num">
                  {t('documents.vote.abstain')}
                </th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>{block.label}</td>
                <td className="doc-votetable__num muted">…</td>
                <td className="doc-votetable__num muted">…</td>
                <td className="doc-votetable__num muted">…</td>
              </tr>
            </tbody>
          </table>
        </div>
      );
    case 'SignatureBlock':
      return (
        <div className="doc-block" data-template-block-kind={block.kind}>
          <p className="field__hint">
            <code>{block.source}</code>
          </p>
          <div className="doc-signatures">
            <div className="doc-signature">
              <p className="doc-signature__role">{block.role}</p>
              <div className="doc-signature__line">
                <span className="doc-signature__name">{block.name}</span>
              </div>
            </div>
          </div>
        </div>
      );
    case 'Rule':
      return <hr className="doc-block doc-rule" data-template-block-kind={block.kind} />;
    case 'PageBreak':
      return (
        <div
          className="doc-block doc-pagebreak"
          data-template-block-kind={block.kind}
          aria-hidden="true"
        >
          {t('documents.pageBreak')}
        </div>
      );
    case 'NarrativeBody':
      return (
        <div className="doc-block" data-template-block-kind={block.kind} data-template-narrative>
          <NarrativeBodyPreview state={narrative} />
        </div>
      );
  }
}

export function TemplateAuthoredPreview({
  title,
  templateId,
  locale,
  blocks,
  narrative,
}: TemplateAuthoredPreviewProps) {
  const previewTitleId = useId();

  return (
    <article
      className="doc-preview"
      lang={locale || undefined}
      aria-labelledby={previewTitleId}
      data-template-authored-preview
    >
      <header className="doc-preview__head">
        <p className="doc-preview__title" id={previewTitleId} role="heading" aria-level={2}>
          {title}
        </p>
        {templateId ? (
          <p className="doc-preview__entity">
            <code>{templateId}</code>
          </p>
        ) : null}
      </header>
      <div className="doc-preview__body">
        {blocks.map((block, index) => (
          <AuthoredTemplateBlock
            key={`${block.kind}:${index}`}
            block={block}
            narrative={narrative}
          />
        ))}
      </div>
    </article>
  );
}
