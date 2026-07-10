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
import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { useActiveLocale } from '../i18n';
import { ArrowRight } from './icons';
import { Tooltip } from './Tooltip';

interface SubNavItemBase<T extends string> {
  id: T;
  label: ReactNode;
  /**
   * An optional leading glyph (one of the shared `Icon.*` set) rendered before the label
   * in a decorative `aria-hidden` span. Backward-compatible: items without an `icon` render
   * exactly as before, so existing call-sites are unchanged.
   */
  icon?: ReactNode;
}

export type SubNavItem<T extends string> =
  | (SubNavItemBase<T> & {
      iconOnly?: false;
      tooltipLabel?: string;
    })
  | (SubNavItemBase<T> & {
      /**
       * Render only the glyph in the button. The text label is kept out of the visible
       * button content and exposed through `aria-label` + `Tooltip`.
       */
      iconOnly: true;
      icon: ReactNode;
      tooltipLabel: string;
    });

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

type ScrollEdge = 'start' | 'end';
type ScrollSource = 'hover' | 'focus' | 'press';
type ScrollDirection = -1 | 1;

const AUTO_SCROLL_PX_PER_MS = 0.42;

const emptyScrollSources = (): Record<ScrollSource, boolean> => ({
  hover: false,
  focus: false,
  press: false,
});

const edgeDirection = (edge: ScrollEdge): ScrollDirection => (edge === 'start' ? -1 : 1);

const directionEdge = (direction: ScrollDirection | null): ScrollEdge | null =>
  direction === -1 ? 'start' : direction === 1 ? 'end' : null;

export function SubNav<T extends string>({ items, active, onSelect, ariaLabel }: SubNavProps<T>) {
  // A stable tag (not the `t` function) so the measure effect re-runs on a locale-driven
  // label-width change without running every render.
  const locale = useActiveLocale();
  const btnRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const scrollRef = useRef<HTMLDivElement>(null);
  const autoScrollRef = useRef<{
    direction: ScrollDirection | null;
    frame: number | null;
    lastTimestamp: number | null;
  }>({ direction: null, frame: null, lastTimestamp: null });
  const scrollSourcesRef = useRef<Record<ScrollEdge, Record<ScrollSource, boolean>>>({
    start: emptyScrollSources(),
    end: emptyScrollSources(),
  });
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

  const stopAutoScroll = useCallback(() => {
    const state = autoScrollRef.current;
    if (state.frame !== null) window.cancelAnimationFrame(state.frame);
    state.direction = null;
    state.frame = null;
    state.lastTimestamp = null;
  }, []);

  const stepAutoScroll = useCallback(
    (timestamp: number) => {
      const state = autoScrollRef.current;
      const direction = state.direction;
      const el = scrollRef.current;
      if (!direction || !el) {
        state.frame = null;
        state.lastTimestamp = null;
        return;
      }

      const maxLeft = Math.max(0, el.scrollWidth - el.clientWidth);
      const current = Math.min(maxLeft, Math.max(0, el.scrollLeft));
      const elapsed =
        state.lastTimestamp === null
          ? 16
          : Math.min(Math.max(timestamp - state.lastTimestamp, 0), 32);
      const next = Math.min(
        maxLeft,
        Math.max(0, current + direction * elapsed * AUTO_SCROLL_PX_PER_MS),
      );
      el.scrollLeft = next;
      state.lastTimestamp = timestamp;
      updateShadows();

      if (next <= 0 || next >= maxLeft) {
        state.direction = null;
        state.frame = null;
        state.lastTimestamp = null;
        return;
      }

      state.frame = window.requestAnimationFrame(stepAutoScroll);
    },
    [updateShadows],
  );

  const startAutoScroll = useCallback(
    (direction: ScrollDirection) => {
      const state = autoScrollRef.current;
      state.direction = direction;
      state.lastTimestamp = null;
      if (state.frame === null) state.frame = window.requestAnimationFrame(stepAutoScroll);
    },
    [stepAutoScroll],
  );

  const hasActiveSource = useCallback((edge: ScrollEdge) => {
    const sources = scrollSourcesRef.current[edge];
    return sources.hover || sources.focus || sources.press;
  }, []);

  const setScrollSource = useCallback(
    (edge: ScrollEdge, source: ScrollSource, activeSource: boolean) => {
      scrollSourcesRef.current[edge][source] = activeSource;

      if (activeSource) {
        startAutoScroll(edgeDirection(edge));
        return;
      }

      const currentEdge = directionEdge(autoScrollRef.current.direction);
      if (currentEdge && hasActiveSource(currentEdge)) return;

      const otherEdge: ScrollEdge = edge === 'start' ? 'end' : 'start';
      if (hasActiveSource(edge)) startAutoScroll(edgeDirection(edge));
      else if (hasActiveSource(otherEdge)) startAutoScroll(edgeDirection(otherEdge));
      else stopAutoScroll();
    },
    [hasActiveSource, startAutoScroll, stopAutoScroll],
  );

  useEffect(() => stopAutoScroll, [stopAutoScroll]);

  useEffect(() => {
    if (!overflow.start) scrollSourcesRef.current.start = emptyScrollSources();
    if (!overflow.end) scrollSourcesRef.current.end = emptyScrollSources();

    const currentEdge = directionEdge(autoScrollRef.current.direction);
    if ((currentEdge === 'start' && !overflow.start) || (currentEdge === 'end' && !overflow.end)) {
      stopAutoScroll();
    }
  }, [overflow.start, overflow.end, stopAutoScroll]);

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

  const renderScrollButton = (edge: ScrollEdge) => {
    const label = `${ariaLabel}: scroll ${edge === 'start' ? 'left' : 'right'}`;
    return (
      <button
        type="button"
        className={`subnav__scroll subnav__scroll--${edge}`}
        aria-label={label}
        onMouseEnter={() => setScrollSource(edge, 'hover', true)}
        onMouseLeave={() => setScrollSource(edge, 'hover', false)}
        onFocus={() => setScrollSource(edge, 'focus', true)}
        onBlur={() => setScrollSource(edge, 'focus', false)}
        onPointerDown={() => setScrollSource(edge, 'press', true)}
        onPointerUp={() => setScrollSource(edge, 'press', false)}
        onPointerLeave={() => setScrollSource(edge, 'press', false)}
        onPointerCancel={() => setScrollSource(edge, 'press', false)}
      >
        <ArrowRight />
      </button>
    );
  };
  const isScrollable = overflow.start || overflow.end;

  return (
    <div
      className="subnav-wrap"
      data-scrollable={isScrollable ? 'true' : undefined}
      data-overflow-start={overflow.start ? 'true' : undefined}
      data-overflow-end={overflow.end ? 'true' : undefined}
    >
      {overflow.start ? renderScrollButton('start') : null}
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
        {items.map((item) => {
          const button = (
            <button
              key={item.iconOnly ? undefined : item.id}
              ref={(el) => {
                btnRefs.current[item.id] = el;
              }}
              type="button"
              className={`${item.id === active ? 'subnav__btn is-active' : 'subnav__btn'}${
                item.iconOnly ? ' subnav__btn--iconOnly' : ''
              }`}
              aria-label={item.iconOnly ? item.tooltipLabel : undefined}
              aria-pressed={item.id === active}
              onClick={() => onSelect(item.id)}
            >
              {item.icon ? (
                <span className="subnav__icon" aria-hidden="true">
                  {item.icon}
                </span>
              ) : null}
              {item.iconOnly ? null : item.label}
            </button>
          );

          return item.iconOnly ? (
            <Tooltip key={item.id} label={item.tooltipLabel} placement="bottom">
              {button}
            </Tooltip>
          ) : (
            button
          );
        })}
      </div>
      {overflow.end ? renderScrollButton('end') : null}
    </div>
  );
}
