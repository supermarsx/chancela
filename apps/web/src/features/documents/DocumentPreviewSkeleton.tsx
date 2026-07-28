/**
 * The loading shape of {@link DocumentPreview}.
 *
 * The preview used to load behind one flat 12rem bar, so the document arrived as a jolt: a
 * plain rectangle in UI chrome was replaced by a bordered paper column in a serif idiom. This
 * reserves the real shape instead — the same `.doc-preview` box (A4-ish column, gilt top rule,
 * centred head over a rule) holding placeholders in the order `DocumentPreview` renders:
 * title/entity/NIPC head, then a heading, a key/value grid, paragraph lines, and the ruled
 * signature slots.
 *
 * It reuses the document's own layout classes rather than restating them, exactly as
 * `SkeletonCards` reuses `.cards`, so the box model is identical before and after the swap.
 * The blocks themselves are the shared `Skeleton` primitive — one pulsing system, not two —
 * and they are `aria-hidden`, so `SkeletonRegion` carries the announcement.
 */
import { Skeleton, SkeletonRegion } from '../../ui';
import './documents.css';

/** Widths of the placeholder paragraph lines; the last is short like a real paragraph end. */
const PARAGRAPH_LINES = ['100%', '100%', '96%', '62%'];
const SHORT_PARAGRAPH_LINES = ['100%', '92%', '48%'];

function SkeletonParagraph({ widths }: { widths: readonly string[] }) {
  return (
    <span className="doc-block doc-skeleton__paragraph">
      {widths.map((width, i) => (
        <Skeleton key={i} height="0.85rem" width={width} />
      ))}
    </span>
  );
}

export function DocumentPreviewSkeleton() {
  return (
    <SkeletonRegion>
      <div className="doc-preview doc-preview--loading" aria-hidden="true">
        <div className="doc-preview__head doc-skeleton__head">
          <Skeleton height="1.4rem" width="58%" />
          <Skeleton height="1rem" width="42%" />
          <Skeleton height="0.85rem" width="24%" />
        </div>
        <div className="doc-preview__body doc-skeleton__body">
          <Skeleton className="doc-block" height="1.1rem" width="34%" />
          <div className="doc-block doc-kv">
            {Array.from({ length: 4 }, (_, i) => (
              <div key={i} style={{ display: 'contents' }}>
                <Skeleton height="0.85rem" width="70%" />
                <Skeleton height="0.85rem" width={i % 2 === 0 ? '80%' : '55%'} />
              </div>
            ))}
          </div>
          <SkeletonParagraph widths={PARAGRAPH_LINES} />
          <Skeleton className="doc-block" height="1.1rem" width="28%" />
          <SkeletonParagraph widths={SHORT_PARAGRAPH_LINES} />
          <div className="doc-block doc-signatures doc-skeleton__signatures">
            {Array.from({ length: 2 }, (_, i) => (
              <div className="doc-skeleton__signature" key={i}>
                <Skeleton height="0.75rem" width="7rem" />
                <Skeleton height="0.85rem" width="11rem" />
              </div>
            ))}
          </div>
        </div>
      </div>
    </SkeletonRegion>
  );
}
