/**
 * A thin, non-destructive modal shell for the privacy registers' create/edit form (t15).
 *
 * The privacy registers used to render their edit form inline as a `<Card>` pushed above the
 * table; the user asked for editing to happen in its own window. There is no generic modal
 * primitive in `ui/` — the only modal is `ConfirmActionModal`, which is over-specialised for
 * destructive ops (type-to-confirm phrase, step-up re-auth, export-first rail). Rather than
 * bend that gate into a plain editor, this reuses its *proven mechanics* — a portal to
 * `document.body`, the shared `useFocusTrap` hook, Escape-to-close, and the existing
 * `.modal-backdrop` / `.modal` / `.modal__head|body` CSS — with none of the safety rails.
 *
 * It is deliberately local to the settings feature (not promoted to `ui/`) so this change
 * touches no shared primitive and no `theme.css`. The caller supplies the already-built form as
 * `children`; that form keeps its own submit/cancel footer, so this shell only provides the
 * window chrome. It is non-destructive by design — backdrop click and Escape close freely unless
 * a save is in flight (`busy`), which matches the form's own cancel button being disabled while
 * saving.
 */
import { useEffect, useRef, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { useFocusTrap } from '../../ui/useFocusTrap';

export function RegisterEditModal({
  open,
  onClose,
  title,
  busy = false,
  children,
}: {
  open: boolean;
  onClose: () => void;
  /** Accessible dialog title, wired to `aria-labelledby`. */
  title: string;
  /** A save is in flight: suppress Escape / backdrop dismissal so the edit isn't abandoned mid-write. */
  busy?: boolean;
  children: ReactNode;
}) {
  // Stable id for aria-labelledby; generated once so it survives re-renders while open.
  const titleId = useRef(`register-modal-${Math.random().toString(36).slice(2)}`).current;
  // Trap Tab focus inside the dialog and restore it to the opener on close. Called before the
  // `if (!open) return null` early return (rules of hooks). The form manages its own field focus.
  const trapRef = useFocusTrap<HTMLDivElement>(open);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, busy, onClose]);

  if (!open) return null;

  // Rendered through a portal to `document.body` for the same reason `ConfirmActionModal` is: the
  // fixed backdrop must escape the routed content's transformed ancestor (`.route-transition`
  // establishes a containing block that would otherwise clip a `position: fixed` descendant).
  return createPortal(
    <div
      className="modal-backdrop"
      onClick={() => {
        if (!busy) onClose();
      }}
    >
      <div
        ref={trapRef}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="modal__head">
          <h2 className="modal__title" id={titleId}>
            {title}
          </h2>
        </header>
        <div className="modal__body">{children}</div>
      </div>
    </div>,
    document.body,
  );
}
