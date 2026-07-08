/**
 * A segmented sub-navigation pill shared by surfaces that split into sub-tabs. It mirrors
 * the Ferramentas sub-nav visually (same `.subnav*` styling, aliased to `.ferramentas-subnav*`
 * in theme.css) — a gliding gilt indicator that slides under the active button, measured
 * from the live button box so it tracks label widths. Pair it with the app's
 * `.route-transition` (keyed on the active id) to fade the content in on switch.
 *
 * IMPORTANT — the indicator effect is written to avoid the "Maximum update depth exceeded"
 * loop that the first cut of the Ferramentas pill hit: it depends ONLY on stable values
 * (`active` + the `locale` tag, never the per-render `t` function) and guards `setIndicator`
 * by geometry (returns the same ref when unchanged), so a re-render never re-triggers it.
 * `SubNav.test.tsx` is the regression guard.
 */
import { useCallback, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { useActiveLocale } from '../i18n';

export interface SubNavItem<T extends string> {
  id: T;
  label: ReactNode;
  /**
   * An optional leading glyph (one of the shared `Icon.*` set) rendered before the label
   * in a decorative `aria-hidden` span. Backward-compatible: items without an `icon` render
   * exactly as before, so existing call-sites are unchanged.
   */
  icon?: ReactNode;
}

interface SubNavProps<T extends string> {
  items: SubNavItem<T>[];
  active: T;
  onSelect: (id: T) => void;
  ariaLabel: string;
}

interface Rect {
  left: number;
  top: number;
  width: number;
  height: number;
}

export function SubNav<T extends string>({ items, active, onSelect, ariaLabel }: SubNavProps<T>) {
  // A stable tag (not the `t` function) so the measure effect re-runs on a locale-driven
  // label-width change without running every render.
  const locale = useActiveLocale();
  const btnRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const scrollRef = useRef<HTMLDivElement>(null);
  const [indicator, setIndicator] = useState<Rect | null>(null);
  // Whether the sub-tab strip is scrolled away from either edge — drives the fade shadows
  // that hint at more sub-tabs off-screen. Only shown when content actually overflows in
  // that direction (a standard scroll-shadow cue).
  const [overflow, setOverflow] = useState({ start: false, end: false });

  const updateShadows = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    const start = el.scrollLeft > 1;
    const end = el.scrollLeft + el.clientWidth < el.scrollWidth - 1;
    // Guard by value so a scroll that doesn't cross an edge threshold never re-renders.
    setOverflow((prev) => (prev.start === start && prev.end === end ? prev : { start, end }));
  }, []);

  useLayoutEffect(() => {
    const measure = () => {
      const btn = btnRefs.current[active];
      if (btn) {
        const next: Rect = {
          left: btn.offsetLeft,
          top: btn.offsetTop,
          width: btn.offsetWidth,
          height: btn.offsetHeight,
        };
        // Same-ref-when-unchanged guard: only a real geometry change re-renders, so the
        // effect (which re-runs on active/locale/resize, not on the state it sets) can't loop.
        setIndicator((prev) =>
          prev &&
          prev.left === next.left &&
          prev.top === next.top &&
          prev.width === next.width &&
          prev.height === next.height
            ? prev
            : next,
        );
      }
      updateShadows();
    };
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, [active, locale, updateShadows]);

  return (
    <div
      className="subnav-wrap"
      data-overflow-start={overflow.start ? 'true' : undefined}
      data-overflow-end={overflow.end ? 'true' : undefined}
    >
      <div
        className="subnav"
        role="group"
        aria-label={ariaLabel}
        ref={scrollRef}
        onScroll={updateShadows}
      >
        <span
          className="subnav__indicator"
          aria-hidden="true"
          style={
            indicator
              ? {
                  transform: `translateX(${indicator.left}px)`,
                  top: `${indicator.top}px`,
                  width: `${indicator.width}px`,
                  height: `${indicator.height}px`,
                }
              : { opacity: 0 }
          }
        />
        {items.map((item) => (
          <button
            key={item.id}
            ref={(el) => {
              btnRefs.current[item.id] = el;
            }}
            type="button"
            className={item.id === active ? 'subnav__btn is-active' : 'subnav__btn'}
            aria-pressed={item.id === active}
            onClick={() => onSelect(item.id)}
          >
            {item.icon ? (
              <span className="subnav__icon" aria-hidden="true">
                {item.icon}
              </span>
            ) : null}
            {item.label}
          </button>
        ))}
      </div>
    </div>
  );
}
