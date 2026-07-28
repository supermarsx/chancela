/**
 * `SidePanel` — a floating right-hand detail pane for list/detail surfaces (t88).
 *
 * The user asked that picking a provider in the trust list "show the provider info on a floating
 * right hand popup instead of below all the info". That is a recurring shape, not a trust-list
 * quirk — the TSA record list wanted the same treatment on day one — so it lives here as a shared
 * primitive rather than inside the feature.
 *
 * **It is deliberately NOT a dialog.** `ConfirmActionModal` / `GuardedActionModal` are modal: they
 * set `aria-modal`, trap Tab, and cover the page with a blocking backdrop. That is exactly wrong
 * for a detail pane — the operator is meant to keep walking the list while the detail is up, and
 * a trapped panel would make every row click require a close first. So this renders as a
 * `complementary` landmark, leaves Tab alone, and lets pointer events through the layer on
 * desktop. What it DOES take from the modal family:
 *
 *  - **Portal to `document.body`.** `.route-transition` establishes a containing block (animation /
 *    transform), which would otherwise clip a `position: fixed` descendant to the route's box.
 *  - **Focus in on open.** Opening moves focus to the panel container so a keyboard user lands on
 *    the thing they just opened instead of staying stranded in the list.
 *  - **Escape closes, focus goes back.** The key listener is on `document`, not the panel, so
 *    Escape works whether focus is inside the panel or back on the list row.
 *
 * **Which element focus returns to.** The opener is captured when the panel opens AND re-captured
 * whenever focus lands outside the panel while it is open. That is what makes selecting a second
 * row behave: the panel stays open, focus stays on the newly clicked row, and Escape returns there
 * rather than to whichever row happened to open the panel first.
 *
 * Responsive behaviour lives in `SidePanel.css`: a fixed right-hand column above 60rem, a
 * full-width bottom sheet over a dismissing scrim below it.
 */
import { useEffect, useId, useRef, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import * as Icon from './icons';
import './SidePanel.css';

export interface SidePanelProps {
  /** Whether the panel is showing. Closed renders nothing at all (no portal, no children). */
  open: boolean;
  /**
   * The panel's visible heading and accessible name — what KIND of record is on show
   * ("Detalhe do prestador"), not the record's own name, which the detail body already carries.
   */
  label: string;
  /** Accessible name for the close control. */
  closeLabel: string;
  onClose: () => void;
  children: ReactNode;
}

export function SidePanel({ open, label, closeLabel, onClose, children }: SidePanelProps) {
  const panelRef = useRef<HTMLElement | null>(null);
  const openerRef = useRef<HTMLElement | null>(null);
  const titleId = useId();

  // Close on Escape from anywhere on the page — the operator may well have tabbed back to the
  // list. Unlike the confirm modal there is nothing in flight to abandon, so it is unconditional.
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [open, onClose]);

  // Focus in on open; remember (and keep re-remembering) the outside element to hand focus back to.
  useEffect(() => {
    if (!open) return;
    const active = typeof document !== 'undefined' ? document.activeElement : null;
    openerRef.current = active instanceof HTMLElement && active !== document.body ? active : null;
    panelRef.current?.focus();

    const onFocusIn = (e: FocusEvent) => {
      const target = e.target;
      if (!(target instanceof HTMLElement) || target === document.body) return;
      // Focus moving WITHIN the panel is not a new opener; focus landing on the list is.
      if (panelRef.current?.contains(target)) return;
      openerRef.current = target;
    };
    document.addEventListener('focusin', onFocusIn);

    return () => {
      document.removeEventListener('focusin', onFocusIn);
      const opener = openerRef.current;
      openerRef.current = null;
      // Guarded: on a route change the row that opened the panel is already gone.
      if (opener?.isConnected) opener.focus();
    };
  }, [open]);

  if (!open) return null;

  return createPortal(
    <div className="side-panel-layer">
      {/* Inert on desktop (`display: none`); on narrow viewports the sheet covers the list, so the
          scrim appears and dismissing by tapping beside the sheet is the expected gesture. */}
      <div className="side-panel__scrim" onClick={onClose} />
      <aside
        ref={panelRef}
        className="side-panel"
        aria-labelledby={titleId}
        // Focusable as a container so opening lands focus on the panel itself rather than on
        // whichever control the detail happens to render first.
        tabIndex={-1}
      >
        <header className="side-panel__head">
          <h2 className="side-panel__title" id={titleId}>
            {label}
          </h2>
          <button
            type="button"
            className="side-panel__close"
            aria-label={closeLabel}
            onClick={onClose}
          >
            <Icon.Close />
          </button>
        </header>
        <div className="side-panel__body">{children}</div>
      </aside>
    </div>,
    document.body,
  );
}
