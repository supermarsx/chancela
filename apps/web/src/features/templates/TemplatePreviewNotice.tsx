import type { ReactNode } from 'react';
import './templateEditor.css';

/**
 * Compact, preview-scoped disclosure.
 *
 * Preview qualifications and failures remain prominent through the coloured document edge, while
 * their explanatory prose stays available on demand instead of consuming the preview canvas.
 */
export function TemplatePreviewNotice({
  label,
  details,
  detailsLabel,
  tone = 'info',
  role,
  live,
  actions,
  id,
}: {
  label: string;
  details?: ReactNode;
  detailsLabel: string;
  tone?: 'info' | 'warn' | 'error';
  role?: 'status' | 'alert' | 'note';
  live?: 'polite' | 'assertive';
  actions?: ReactNode;
  id?: string;
}) {
  return (
    <aside
      className={`template-preview-notice template-preview-notice--${tone}`}
      role={role}
      aria-live={live}
      id={id}
    >
      {details || actions ? (
        <details>
          <summary>
            <strong>{label}</strong>
            <span>{detailsLabel}</span>
          </summary>
          <div className="template-preview-notice__details">
            {details}
            {actions ? <div className="template-preview-notice__actions">{actions}</div> : null}
          </div>
        </details>
      ) : (
        <strong>{label}</strong>
      )}
    </aside>
  );
}
