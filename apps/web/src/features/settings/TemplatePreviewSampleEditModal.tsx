import { useEffect, useRef, type FormEvent, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { Button } from '../../ui';
import { useFocusTrap } from '../../ui/useFocusTrap';
import { useTemplatePreviewSamplesT } from '../../i18n/templatePreviewSamplesFallback';

export function TemplatePreviewSampleEditModal({
  open,
  title,
  valid = true,
  onClose,
  onSave,
  children,
}: {
  open: boolean;
  title: string;
  valid?: boolean;
  onClose: () => void;
  onSave: () => void;
  children: ReactNode;
}) {
  const tt = useTemplatePreviewSamplesT();
  const titleId = useRef(`template-preview-sample-${Math.random().toString(36).slice(2)}`).current;
  const trapRef = useFocusTrap<HTMLDivElement>(open);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (valid) onSave();
  };

  return createPortal(
    <div className="modal-backdrop" onClick={onClose}>
      <div
        ref={trapRef}
        className="modal template-preview-sample-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onClick={(event) => event.stopPropagation()}
      >
        <header className="modal__head">
          <h2 className="modal__title" id={titleId}>
            {title}
          </h2>
        </header>
        {/* No `stack` here: `.modal__body` is a flex column with its own `gap`, so a rhythm class
            on the same element ADDS to that gap instead of replacing it — measured 37.6px against
            every other dialog's 13.6px. The body owns the rhythm; see docs/ui-spacing.md. */}
        <form className="modal__body" onSubmit={submit}>
          <div className="template-preview-sample-modal__fields">{children}</div>
          <div className="form__actions">
            <Button type="button" variant="ghost" onClick={onClose}>
              {tt('templatePreview.action.cancel')}
            </Button>
            <Button type="submit" variant="primary" disabled={!valid}>
              {tt('templatePreview.action.save')}
            </Button>
          </div>
        </form>
      </div>
    </div>,
    document.body,
  );
}
