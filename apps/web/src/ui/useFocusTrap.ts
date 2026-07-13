/**
 * `useFocusTrap` — a small, reusable focus-trap controller for modal dialogs (#4 modal focus).
 *
 * While `active`, it keeps keyboard focus inside a container so a dialog behaves like a real
 * modal for keyboard and screen-reader users:
 *
 *  - **Initial focus / autofocus** — on activation it captures whatever was focused (so it can be
 *    restored later) and, if focus is not already inside the container, moves focus to the first
 *    focusable descendant (or a caller-provided `initialFocus` ref). A dialog that manages its own
 *    field focus therefore keeps that focus (the container already holds it), so this never fights
 *    an existing autofocus.
 *  - **Tab wrapping** — Tab from the last focusable descendant cycles to the first, and Shift+Tab
 *    from the first cycles to the last, so focus never escapes the dialog.
 *  - **Restore on close/unmount** — when `active` flips to false (or the component unmounts) focus
 *    is returned to the element that was focused before activation.
 *
 * It is intentionally UI-agnostic and side-effect-safe: no store, i18n, animation, or timers, so it
 * is reduced-motion / safe-mode neutral by construction and trivially testable. It is SSR/jsdom-safe
 * — all DOM access happens inside effects (never during render) and tolerates a missing
 * `document.activeElement`.
 *
 * Usage: attach the returned ref to the dialog container, and — per the rules of hooks — call it
 * unconditionally, BEFORE any `if (!open) return null` early return.
 */
import { useEffect, useRef, type RefObject } from 'react';

/** CSS selector for the elements considered focusable within the trap. */
const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

function focusableElements(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
    // Skip anything hidden or aria-hidden — it can't take focus and would break the wrap. Uses
    // attribute checks (not `offsetParent`, which jsdom always reports as null) so it is layout-
    // agnostic and works identically in the browser and under test.
    (el) => !el.hasAttribute('aria-hidden') && el.closest('[hidden]') === null,
  );
}

export interface UseFocusTrapOptions {
  /** An element inside the container to focus first, instead of the first focusable descendant. */
  initialFocus?: RefObject<HTMLElement | null>;
}

/**
 * Trap focus inside the returned container ref while `active` is true.
 *
 * @typeParam T - the container element type (attach the ref to the dialog `<div>`).
 * @param active - whether the trap (and Tab wrapping) is engaged; usually the dialog's `open`.
 * @param options - optional `initialFocus` ref to seed focus on activation.
 * @returns a ref to attach to the dialog container.
 */
export function useFocusTrap<T extends HTMLElement = HTMLElement>(
  active: boolean,
  options: UseFocusTrapOptions = {},
): RefObject<T | null> {
  const containerRef = useRef<T | null>(null);
  // Keep the latest initialFocus ref in a ref so the effect isn't re-run (and focus re-seeded)
  // just because the options object identity changed between renders.
  const initialFocusRef = useRef(options.initialFocus);
  initialFocusRef.current = options.initialFocus;

  useEffect(() => {
    if (!active) return;
    const container = containerRef.current;
    if (!container) return;

    // Remember what was focused before we take over, so we can restore it on close/unmount.
    const previouslyFocused =
      typeof document !== 'undefined' ? (document.activeElement as HTMLElement | null) : null;

    // Move focus into the dialog only if it isn't already there — this supplies autofocus for a
    // dialog that has none, without stealing focus a dialog placed on one of its own fields.
    if (!container.contains(document.activeElement)) {
      const initial = initialFocusRef.current?.current;
      const target = initial ?? focusableElements(container)[0];
      // Fall back to the container itself so a dialog with no focusable content still moves
      // focus off the background (a no-op if the container isn't focusable).
      (target ?? container).focus?.();
    }

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;
      const focusable = focusableElements(container);
      if (focusable.length === 0) {
        // Nothing to move to — keep focus on the container and swallow the Tab.
        e.preventDefault();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const activeEl = document.activeElement as HTMLElement | null;

      if (e.shiftKey) {
        // Shift+Tab off the first element (or from outside) wraps to the last.
        if (activeEl === first || !container.contains(activeEl)) {
          e.preventDefault();
          last.focus();
        }
      } else {
        // Tab off the last element (or from outside) wraps to the first.
        if (activeEl === last || !container.contains(activeEl)) {
          e.preventDefault();
          first.focus();
        }
      }
    };

    container.addEventListener('keydown', onKeyDown);

    return () => {
      container.removeEventListener('keydown', onKeyDown);
      // Restore focus to whatever held it before, if that element is still connected.
      if (previouslyFocused && previouslyFocused.isConnected) {
        previouslyFocused.focus?.();
      }
    };
  }, [active]);

  return containerRef;
}
