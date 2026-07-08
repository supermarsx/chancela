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
 * `IconButton` is the ergonomic icon-only action: a real `<button>` carrying `aria-label`
 * (its accessible name) wrapped in a `Tooltip` that surfaces the same string visually. The
 * glyph stays decorative (`aria-hidden`, as the shared icon set already is). It forwards
 * every native button prop (`onClick`, `disabled`, `type`, …) and reuses the `.btn` gilt
 * chrome plus a compact `.btn--iconOnly` modifier.
 */
import {
  cloneElement,
  useId,
  useState,
  type ButtonHTMLAttributes,
  type KeyboardEvent,
  type ReactElement,
  type ReactNode,
} from 'react';

export type TooltipPlacement = 'top' | 'bottom' | 'left' | 'right';

/** Chain the child's own handler (if any) before ours, preserving native behaviour. */
function mergeHandler<E>(original: unknown, next: (event: E) => void): (event: E) => void {
  return (event: E) => {
    if (typeof original === 'function') (original as (e: E) => void)(event);
    next(event);
  };
}

interface TooltipProps {
  label: string;
  /** Where the bubble sits relative to the trigger. Default `top`. */
  placement?: TooltipPlacement;
  /** The trigger — a single focusable element; it receives `aria-describedby`. */
  children: ReactElement;
}

export function Tooltip({ label, placement = 'top', children }: TooltipProps) {
  const id = useId();
  const [open, setOpen] = useState(false);

  const show = () => setOpen(true);
  const hide = () => setOpen(false);

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

  return (
    <span className="tooltip">
      {trigger}
      <span
        id={id}
        role="tooltip"
        className={`tooltip__bubble tooltip__bubble--${placement}${open ? ' is-open' : ''}`}
      >
        {label}
      </span>
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
