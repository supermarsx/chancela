/**
 * Skeleton loaders (t19-e2 item c). Editorial shimmer placeholders that mirror the real
 * layout of each surface, so a page reserves its final shape while data loads and the
 * content swaps in without any jank. The shimmer is a single gilt sweep over a muted
 * block; it is fully disabled under `prefers-reduced-motion` (the blocks then rest as
 * static tints), and every block is `aria-hidden` — a screen reader hears the busy
 * region's status text, not the decorative bars. That busy region is `SkeletonRegion`
 * below: because the blocks are all `aria-hidden`, a loading branch that omits it is
 * silent to assistive tech, so wrap skeleton branches in it.
 *
 * The composites (`SkeletonTable`, `SkeletonCards`, `SkeletonDeflist`) match the shapes
 * of the corresponding `ui` primitives (Table, dashboard cards, deflist) so swapping a
 * `<Loading/>` for one of these keeps the box model identical before and after load.
 */
import type { CSSProperties, ReactNode } from 'react';
import { useT } from '../i18n';

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

/**
 * The busy region the blocks above are silent in favour of. Every skeleton block is
 * `aria-hidden`, so without a wrapper like this one a screen reader hears *nothing* while
 * a surface loads — the placeholder bars are decorative by design. Wrap a loading branch
 * in this to restore the announcement that `<Loading>` used to carry as visible text.
 *
 * `role="status"` is a polite live region, so the label is announced without interrupting;
 * `aria-busy` marks the subtree as in-flux for assistive tech that reports it.
 */
export function SkeletonRegion({
  label,
  children,
  className,
}: {
  /** Announced text. Defaults to the shared "A carregar…" string. */
  label?: string;
  children: ReactNode;
  className?: string;
}) {
  const t = useT();
  return (
    <div className={className} role="status" aria-busy="true">
      <span className="sr-only">{label ?? t('common.loading')}</span>
      {children}
    </div>
  );
}

/**
 * A stacked-list skeleton matching `.dashboard-list__item` (a badge + title head row over
 * a muted meta row), for feed-shaped surfaces such as the dashboard "Atividade recente"
 * panel. Sized from the real item's own box so the list does not jump on swap.
 */
export function SkeletonList({ items = 4 }: { items?: number }) {
  return (
    <div className="dashboard-list" aria-hidden="true">
      {Array.from({ length: items }, (_, i) => (
        <div className="dashboard-list__item" key={i}>
          <div className="dashboard-list__head">
            <Skeleton height="1.05rem" width="5.5rem" />
            <Skeleton height="1.05rem" width="45%" />
          </div>
          <div className="dashboard-list__meta">
            <Skeleton height="0.76rem" width="7rem" />
            <Skeleton height="0.76rem" width="6rem" />
            <Skeleton height="0.76rem" width="5rem" />
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * A definition-list skeleton (label + value pairs) matching `.deflist`.
 *
 * `className` swaps in a different label/value grid class so the skeleton inherits that
 * grid's own columns and gaps — the operations metric strips (`.operations-metrics`) and
 * detail grids (`.operations-detail-grid`) are the same dt/dd shape under another name,
 * and a `.deflist` placeholder in front of them would lay out at the wrong width.
 */
export function SkeletonDeflist({
  rows = 4,
  className = 'deflist',
}: {
  rows?: number;
  className?: string;
}) {
  return (
    <div className={className} aria-hidden="true">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i}>
          <Skeleton height="0.7rem" width="40%" />
          <Skeleton height="1rem" width="75%" style={{ marginTop: '0.35rem' }} />
        </div>
      ))}
    </div>
  );
}

/**
 * A form skeleton: label + control pairs on the real `.form` / `.field` boxes, so a form
 * that is waiting on the data it will be seeded with reserves the height of the fields
 * rather than collapsing to one line and then shoving the page down.
 */
export function SkeletonForm({ fields = 3, className }: { fields?: number; className?: string }) {
  return (
    <div className={`form ${className ?? ''}`.trim()} aria-hidden="true">
      {Array.from({ length: fields }, (_, i) => (
        <div className="field" key={i}>
          <Skeleton height="0.7rem" width="30%" />
          <Skeleton height="2.4rem" style={{ marginTop: '0.4rem' }} />
        </div>
      ))}
    </div>
  );
}

/**
 * A row of pill-shaped placeholders matching a `.operations-selector-list` / chip row —
 * a horizontal band of buttons whose count is unknown but whose height is not.
 */
export function SkeletonChips({ count = 4 }: { count?: number }) {
  const widths = ['9rem', '7.5rem', '11rem', '8rem', '10rem', '6.5rem'];
  return (
    <div className="skeleton-chips" aria-hidden="true">
      {Array.from({ length: count }, (_, i) => (
        <Skeleton key={i} height="2.1rem" width={widths[i % widths.length]} />
      ))}
    </div>
  );
}
