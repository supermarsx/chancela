/**
 * Skeleton loaders (t19-e2 item c). Editorial shimmer placeholders that mirror the real
 * layout of each surface, so a page reserves its final shape while data loads and the
 * content swaps in without any jank. The shimmer is a single gilt sweep over a muted
 * block; it is fully disabled under `prefers-reduced-motion` (the blocks then rest as
 * static tints), and every block is `aria-hidden` — a screen reader hears the busy
 * region's status text, not the decorative bars.
 *
 * The composites (`SkeletonTable`, `SkeletonCards`, `SkeletonDeflist`) match the shapes
 * of the corresponding `ui` primitives (Table, dashboard cards, deflist) so swapping a
 * `<Loading/>` for one of these keeps the box model identical before and after load.
 */
import type { CSSProperties } from 'react';

interface SkeletonProps {
  /** CSS width (e.g. '8rem', '60%'). Defaults to full width. */
  width?: string;
  /** CSS height. Defaults to a text-line height. */
  height?: string;
  /** Extra class (e.g. a radius modifier). */
  className?: string;
  style?: CSSProperties;
}

/** One shimmer block. */
export function Skeleton({ width, height, className, style }: SkeletonProps) {
  return (
    <span
      className={`skeleton ${className ?? ''}`.trim()}
      aria-hidden="true"
      style={{ width, height, ...style }}
    />
  );
}

/** A stack of text lines; the last line is shortened like a real paragraph. */
export function SkeletonText({ lines = 3, className }: { lines?: number; className?: string }) {
  return (
    <span className={`skeleton-text ${className ?? ''}`.trim()} aria-hidden="true">
      {Array.from({ length: lines }, (_, i) => (
        <Skeleton key={i} height="0.85em" width={i === lines - 1 ? '55%' : '100%'} />
      ))}
    </span>
  );
}

/** A table skeleton: a header rule plus shimmering rows/cols matching `<Table>`. */
export function SkeletonTable({ rows = 4, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <div className="skeleton-table" aria-hidden="true">
      <div className="skeleton-table__row skeleton-table__row--head">
        {Array.from({ length: cols }, (_, c) => (
          <Skeleton key={c} height="0.7rem" width="60%" />
        ))}
      </div>
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="skeleton-table__row">
          {Array.from({ length: cols }, (_, c) => (
            <Skeleton key={c} height="0.95rem" width={c === 0 ? '80%' : '55%'} />
          ))}
        </div>
      ))}
    </div>
  );
}

/** A grid of metric-card skeletons matching the dashboard `.cards`. */
export function SkeletonCards({ count = 6 }: { count?: number }) {
  return (
    <div className="cards" aria-hidden="true">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="card">
          <Skeleton height="0.7rem" width="45%" />
          <Skeleton height="2.2rem" width="3.5rem" style={{ marginTop: '0.7rem' }} />
          <Skeleton height="0.8rem" width="70%" style={{ marginTop: '0.7rem' }} />
        </div>
      ))}
    </div>
  );
}

/** A definition-list skeleton (label + value pairs) matching `.deflist`. */
export function SkeletonDeflist({ rows = 4 }: { rows?: number }) {
  return (
    <div className="deflist" aria-hidden="true">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i}>
          <Skeleton height="0.7rem" width="40%" />
          <Skeleton height="1rem" width="75%" style={{ marginTop: '0.35rem' }} />
        </div>
      ))}
    </div>
  );
}
