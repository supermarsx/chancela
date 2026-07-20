/**
 * Accessible, gilt-styled tooltip + the icon-only action button that consumes it (t50 W1).
 *
 * `Tooltip` wraps exactly ONE focusable child (a button / link). It shows on hover AND
 * keyboard focus, hides on blur / Escape / pointer-leave, and links the trigger to the
 * bubble via a generated `aria-describedby` id. The bubble stays mounted (visibility is
 * toggled by CSS) so the description is always reachable by assistive tech and so the
 * `aria-describedby` target never dangles; it is `pointer-events: none`, so it never traps
 * focus nor intercepts clicks. The entrance fade/rise lives entirely in the `.tooltip*`
 * theme block, which collapses to nothing under BOTH `@media (prefers-reduced-motion:
 * reduce)` and `:root[data-safe-mode='on']` (each zeroes animation/transition on `*`), so
 * no motion escapes the two global kill-switches.
 *
 * ## Rendering ABOVE everything (t71 z-index/portal fix)
 * The bubble is **portaled to `document.body`** and positioned `fixed` against the trigger's
 * `getBoundingClientRect()`, so it escapes every `overflow: hidden` / transform / `will-change`
 * ancestor that would otherwise clip or trap it (notably the `.route-transition` container and
 * the confirm-modal body). Its z-index sits at the TOP of the app scale (`2200`, above the
 * titlebar 2100, safe-banner 1700, modal 1500, degraded 1450, toast 1400), so a tooltip — even
 * one inside `ConfirmActionModal` — always floats on top. While open it re-pins to the trigger
 * on scroll (capture, so nested scrollers count) and resize. Public API is unchanged.
 *
 * `IconButton` is the ergonomic icon-only action: a real `<button>` carrying `aria-label`
 * (its accessible name) wrapped in a `Tooltip` that surfaces the same string visually. The
 * glyph stays decorative (`aria-hidden`, as the shared icon set already is). It forwards
 * every native button prop (`onClick`, `disabled`, `type`, …) and reuses the `.btn` gilt
 * chrome plus a compact `.btn--iconOnly` modifier.
 */
import {
  cloneElement,
  useCallback,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type CSSProperties,
  type KeyboardEvent,
  type ReactElement,
  type ReactNode,
  type RefObject,
} from 'react';
import { createPortal } from 'react-dom';

export type TooltipPlacement = 'top' | 'bottom' | 'left' | 'right';

/** Chain the child's own handler (if any) before ours, preserving native behaviour. */
function mergeHandler<E>(original: unknown, next: (event: E) => void): (event: E) => void {
  return (event: E) => {
    if (typeof original === 'function') (original as (e: E) => void)(event);
    next(event);
  };
}

/** The viewport-fixed anchor point the bubble hangs off, per placement (the bubble's own
 *  transform — set in the `.tooltip__bubble--*` theme rules — centres/offsets it from here). */
function anchorPoint(rect: DOMRect, placement: TooltipPlacement): { left: number; top: number } {
  switch (placement) {
    case 'bottom':
      return { left: rect.left + rect.width / 2, top: rect.bottom };
    case 'left':
      return { left: rect.left, top: rect.top + rect.height / 2 };
    case 'right':
      return { left: rect.right, top: rect.top + rect.height / 2 };
    case 'top':
    default:
      return { left: rect.left + rect.width / 2, top: rect.top };
  }
}

/** The side directly opposite `placement`. */
const OPPOSITE: Record<TooltipPlacement, TooltipPlacement> = {
  top: 'bottom',
  bottom: 'top',
  left: 'right',
  right: 'left',
};

/**
 * Keep the bubble on screen by flipping to the opposite side when the requested one has no
 * room (WCAG 1.4.13 wants hover/focus content to stay perceivable, and a bubble hanging off
 * the viewport edge is not). Falls back to the requested side when NEITHER fits, so a bubble
 * taller than the viewport degrades predictably rather than oscillating.
 */
function flipPlacement(
  rect: DOMRect,
  bubble: DOMRect | null,
  placement: TooltipPlacement,
): TooltipPlacement {
  if (!bubble) return placement;
  const gap = 8; // the 0.5rem the placement transforms add between trigger and bubble
  const room: Record<TooltipPlacement, number> = {
    top: rect.top,
    bottom: window.innerHeight - rect.bottom,
    left: rect.left,
    right: window.innerWidth - rect.right,
  };
  const needed = placement === 'top' || placement === 'bottom' ? bubble.height : bubble.width;
  const wanted = needed + gap;
  if (room[placement] >= wanted) return placement;
  const opposite = OPPOSITE[placement];
  return room[opposite] >= wanted ? opposite : placement;
}

interface TooltipProps {
  label: string;
  /** Where the bubble sits relative to the trigger. Default `top`. */
  placement?: TooltipPlacement;
  /**
   * Bubble content style. `'label'` (default) is the compact nowrap gilt chip used for short
   * action labels; `'prose'` relaxes it to a wrapping sentence (used by {@link FieldHelp}).
   * The public trigger contract is unchanged — this is an internal styling hook for the
   * primitives that consume Tooltip; it travels ON the bubble so it survives the portal.
   */
  variant?: 'label' | 'prose';
  /**
   * Measure and anchor against THIS element instead of wrapping the trigger in a
   * `.tooltip` span (t31). The default wrapper is an `inline-flex` box, which silently
   * changes layout when the trigger is a block-level or flex-sized element — notably the
   * `display: block` ellipsised `.truncate`, and any span sized as a flex/grid child. When
   * a caller already holds a ref to the trigger's own DOM node (as {@link TooltipText}
   * does, since it renders that node itself), passing it here makes the tooltip add ZERO
   * boxes to the layout: nothing is wrapped, so nothing can be resized.
   */
  anchorRef?: RefObject<HTMLElement | null>;
  /**
   * Expose the bubble to assistive tech via `aria-describedby` (default `true`).
   *
   * Set `false` ONLY when the bubble repeats text that is already complete in the DOM —
   * the CSS-clipped case, where `text-overflow: ellipsis` hides characters visually but
   * removes nothing from the accessibility tree. There the bubble is a sighted-mouse
   * convenience; describing it would make a screen reader read the same string twice. The
   * bubble is then also `aria-hidden`, so it contributes nothing to the tree at all.
   */
  describe?: boolean;
  /** The trigger — a single focusable element; it receives `aria-describedby`. */
  children: ReactElement;
}

export function Tooltip({
  label,
  placement = 'top',
  variant = 'label',
  anchorRef: externalAnchorRef,
  describe = true,
  children,
}: TooltipProps) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const ownAnchorRef = useRef<HTMLSpanElement>(null);
  const anchorRef = externalAnchorRef ?? ownAnchorRef;
  const bubbleRef = useRef<HTMLSpanElement>(null);
  const [coords, setCoords] = useState<{ left: number; top: number } | null>(null);
  // The placement actually used this frame. Starts as the requested one and flips to the
  // opposite side when that side has no room (see `reposition`).
  const [effective, setEffective] = useState<TooltipPlacement>(placement);

  const show = () => setOpen(true);
  const hide = () => setOpen(false);

  // Pin the fixed bubble to the trigger's current viewport box, then clamp its CENTRED axis
  // so a wide/tall wrapped bubble near a screen edge stays fully in view. The CSS transform
  // centres the bubble on this anchor point (translate(-50%) on the placement's cross axis),
  // so we measure the bubble's REAL post-wrap box — width capped by the `max-width` set in
  // `.tooltip__bubble` — and slide the anchor in by any overflow. Only the centred axis is
  // clamped; the leading axis carries the trigger gap and must not move onto the trigger.
  const reposition = useCallback(() => {
    const el = anchorRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const bubbleBox = bubbleRef.current?.getBoundingClientRect() ?? null;

    // FLIP first, then shift. The clamp below can only slide the bubble along its centred
    // axis; it cannot rescue a bubble pushed off the LEADING edge (a `top` tooltip on a
    // trigger near the top of the viewport). So if the requested side lacks room and the
    // opposite side has it, use the opposite side — the standard flip. Measured against the
    // real bubble box, including the 0.5rem gap the CSS transform adds.
    const placed = flipPlacement(rect, bubbleBox, placement);
    const next = anchorPoint(rect, placed);
    setEffective((prev) => (prev === placed ? prev : placed));

    const bubble = bubbleRef.current;
    if (bubble) {
      const box = bubble.getBoundingClientRect();
      const margin = 8;
      if (placed === 'top' || placed === 'bottom') {
        const half = box.width / 2;
        const min = margin + half;
        const max = window.innerWidth - margin - half;
        if (min <= max) next.left = Math.min(Math.max(next.left, min), max);
      } else {
        const half = box.height / 2;
        const min = margin + half;
        const max = window.innerHeight - margin - half;
        if (min <= max) next.top = Math.min(Math.max(next.top, min), max);
      }
    }
    setCoords((prev) => (prev && prev.left === next.left && prev.top === next.top ? prev : next));
  }, [anchorRef, placement]);

  // A changed request resets the flip, so the next open re-decides from the caller's choice
  // rather than inheriting a flip made for a position the trigger has since left.
  useLayoutEffect(() => setEffective(placement), [placement]);

  // While open, position once (synchronously before paint, so there is no first-frame flash)
  // and keep it pinned as the page scrolls (capture phase → nested scrollers count) or resizes.
  useLayoutEffect(() => {
    if (!open) return;
    reposition();
    window.addEventListener('scroll', reposition, true);
    window.addEventListener('resize', reposition);
    return () => {
      window.removeEventListener('scroll', reposition, true);
      window.removeEventListener('resize', reposition);
    };
  }, [open, reposition]);

  const child = children as ReactElement<Record<string, unknown>>;
  const childProps = child.props;
  // Preserve any describedby the child already carries, then append ours.
  const existing = childProps['aria-describedby'];
  const describedBy = [typeof existing === 'string' ? existing : null, id]
    .filter(Boolean)
    .join(' ');

  const trigger = cloneElement(child, {
    'aria-describedby': describe ? describedBy : (existing ?? undefined),
    onMouseEnter: mergeHandler(childProps.onMouseEnter, show),
    onMouseLeave: mergeHandler(childProps.onMouseLeave, hide),
    onFocus: mergeHandler(childProps.onFocus, show),
    onBlur: mergeHandler(childProps.onBlur, hide),
    onKeyDown: mergeHandler(childProps.onKeyDown, (event: KeyboardEvent) => {
      if (event.key === 'Escape') hide();
    }),
  });

  // A benign fixed origin while closed (coords is only computed on open): keeps the always-
  // mounted, invisible bubbles parked at (0,0) rather than at their auto static position at
  // the end of <body>, so a page full of tooltips never stacks hidden boxes into overflow.
  const bubbleStyle: CSSProperties = { left: coords?.left ?? 0, top: coords?.top ?? 0 };

  // Always mounted (so `aria-describedby` never dangles), portaled to <body> so no ancestor
  // can clip or under-stack it. IDs are document-global, so the association holds across the
  // portal boundary.
  const bubble = (
    <span
      id={id}
      ref={bubbleRef}
      // Undescribed bubbles are decorative duplicates of on-screen text, so they are kept
      // out of the accessibility tree entirely rather than exposed as an orphan `tooltip`.
      role={describe ? 'tooltip' : undefined}
      aria-hidden={describe ? undefined : true}
      style={bubbleStyle}
      className={`tooltip__bubble tooltip__bubble--${effective}${
        variant === 'prose' ? ' tooltip__bubble--prose' : ''
      }${open ? ' is-open' : ''}`}
    >
      {label}
    </span>
  );

  const portaled = typeof document !== 'undefined' ? createPortal(bubble, document.body) : bubble;

  // Layout-transparent mode: the caller owns the trigger node and gave us its ref, so we add
  // no wrapper at all (see `anchorRef`). The portal is a sibling but renders into <body>, so
  // it contributes nothing to the local box tree either.
  if (externalAnchorRef) {
    return (
      <>
        {trigger}
        {portaled}
      </>
    );
  }

  return (
    <span className="tooltip" ref={ownAnchorRef}>
      {trigger}
      {portaled}
    </span>
  );
}

/**
 * Is this element's text currently ellipsised by CSS? `scrollWidth > clientWidth` is the
 * standard probe; the 1px slack absorbs sub-pixel layout rounding, which would otherwise
 * flag a perfectly-fitting cell as clipped. Re-measures via `ResizeObserver`, so the answer
 * tracks column resizes and window reflows rather than going stale after first paint.
 *
 * `enabled: false` short-circuits the observer entirely for callers that always want the
 * bubble (deliberately abbreviated values, where nothing is CSS-clipped to begin with).
 */
export function useIsClipped(ref: RefObject<HTMLElement | null>, enabled = true): boolean {
  const [clipped, setClipped] = useState(false);
  useLayoutEffect(() => {
    if (!enabled) return;
    const el = ref.current;
    if (!el) return;
    const measure = () => setClipped(el.scrollWidth > el.clientWidth + 1);
    measure();
    if (typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [ref, enabled]);
  return clipped;
}

interface TooltipTextProps {
  /** The full value revealed in the bubble. */
  label: string;
  /**
   * Reveal only when the element is actually clipped by CSS (`text-overflow: ellipsis`).
   * An unclipped cell then renders bare, with no bubble and no redundant `aria-describedby`
   * repeating text the user can already read.
   *
   * Defaults to AUTO-DETECT, which is what makes this safe to drop onto an old `title=`:
   * if the label is exactly the rendered string, there is nothing extra to say and the
   * bubble can only be a visual de-truncation; if it differs, the label carries information
   * the cell does not show (a full type behind an abbreviation, a raw id behind a friendly
   * label) and MUST be announced and keyboard reachable. Getting this backwards silently
   * drops content, so it is inferred rather than left to each call site to remember.
   */
  onlyWhenClipped?: boolean;
  /**
   * Make the trigger a tab stop. Defaults to `!onlyWhenClipped`, which encodes the rule:
   *
   * - **Abbreviated** content (`Digest`'s `a1b2…c3d4`, a shortened chain hash, a raw event
   *   kind behind a friendly label) keeps the full value ONLY in the bubble, so it must be
   *   keyboard reachable — otherwise a non-mouse user can never obtain it.
   * - **CSS-clipped** content is still complete in the DOM, so a screen reader already
   *   announces all of it. The bubble is a sighted-mouse convenience, and adding a tab stop
   *   to every clipped table cell would bury the page's real controls in noise.
   */
  focusable?: boolean;
  /** Render as `<code>` (identifiers/hashes) instead of `<span>`. */
  as?: 'span' | 'code';
  className?: string;
  placement?: TooltipPlacement;
  children: ReactNode;
}

/**
 * The themed replacement for a native `title=` on non-interactive text (t31).
 *
 * A raw `title` attribute is drawn by the browser, cannot be styled at all, ignores the
 * app's theme, and appears only after a ~1s hover delay — so every one of them was a hole
 * in the design system. This renders the same information through the shared {@link Tooltip}
 * bubble instead, and adds the two things `title` never had: an `aria-describedby`
 * association and Escape-to-dismiss.
 *
 * See {@link TooltipTextProps.focusable} for the keyboard-reachability rule.
 */
export function TooltipText({
  label,
  onlyWhenClipped,
  focusable,
  as: Tag = 'span',
  className,
  placement,
  children,
}: TooltipTextProps) {
  const ref = useRef<HTMLElement>(null);
  // Auto-detect (see `onlyWhenClipped`): a label that merely repeats the rendered string can
  // only be de-truncating it; a label that differs is carrying extra content.
  const clippedMode =
    onlyWhenClipped ?? (typeof children === 'string' && children.trim() === label.trim());
  const clipped = useIsClipped(ref, clippedMode);

  const active = clippedMode ? clipped : true;
  const isFocusable = focusable ?? !clippedMode;

  const content = (
    <Tag ref={ref as never} className={className} tabIndex={active && isFocusable ? 0 : undefined}>
      {children}
    </Tag>
  );

  // Not revealing anything the user cannot already read → render bare, so we neither mount a
  // bubble nor point `aria-describedby` at a duplicate of the visible text.
  if (!active) return content;
  return (
    <Tooltip
      label={label}
      placement={placement}
      variant="prose"
      anchorRef={ref}
      // Clipped text is complete in the accessibility tree already; only an ABBREVIATED
      // value genuinely needs describing (see the `focusable` note above).
      describe={!clippedMode}
    >
      {content}
    </Tooltip>
  );
}

interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  icon: ReactNode;
  /** The accessible name AND the tooltip text (the same string). */
  label: string;
  variant?: 'primary' | 'secondary' | 'ghost';
  placement?: TooltipPlacement;
}

export function IconButton({
  icon,
  label,
  variant = 'ghost',
  placement,
  className,
  type = 'button',
  ...props
}: IconButtonProps) {
  return (
    <Tooltip label={label} placement={placement}>
      <button
        type={type}
        className={`btn btn--${variant} btn--icon btn--iconOnly${className ? ` ${className}` : ''}`}
        aria-label={label}
        {...props}
      >
        <span className="btn__icon">{icon}</span>
      </button>
    </Tooltip>
  );
}
