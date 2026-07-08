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
  /** The trigger — a single focusable element; it receives `aria-describedby`. */
  children: ReactElement;
}

export function Tooltip({ label, placement = 'top', variant = 'label', children }: TooltipProps) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const anchorRef = useRef<HTMLSpanElement>(null);
  const bubbleRef = useRef<HTMLSpanElement>(null);
  const [coords, setCoords] = useState<{ left: number; top: number } | null>(null);

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
    const next = anchorPoint(el.getBoundingClientRect(), placement);
    const bubble = bubbleRef.current;
    if (bubble) {
      const box = bubble.getBoundingClientRect();
      const margin = 8;
      if (placement === 'top' || placement === 'bottom') {
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
  }, [placement]);

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
    'aria-describedby': describedBy,
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
      role="tooltip"
      style={bubbleStyle}
      className={`tooltip__bubble tooltip__bubble--${placement}${
        variant === 'prose' ? ' tooltip__bubble--prose' : ''
      }${open ? ' is-open' : ''}`}
    >
      {label}
    </span>
  );

  return (
    <span className="tooltip" ref={anchorRef}>
      {trigger}
      {typeof document !== 'undefined' ? createPortal(bubble, document.body) : bubble}
    </span>
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
