/**
 * The app-level toast system (plan t44 §3.1, R6/R8).
 *
 * `ToastProvider` owns the live-toast list and exposes a stable {@link ToastHandle} via
 * context. It MUST be mounted ABOVE the router (see `app/providers.tsx`) so a toast fired
 * as a handler navigates away — an entity/book/act create, a registry import — still
 * renders on the destination route rather than unmounting with the source page.
 *
 * Accessibility: the viewport is a persistent labelled region; each toast is its own live
 * region — `role="status"` / `aria-live="polite"` for success & info, `role="alert"` /
 * `aria-live="assertive"` for errors — so a screen reader announces a failure immediately
 * but does not interrupt for routine confirmations. Auto-dismiss pauses while a toast is
 * hovered or focused, so a reader has time to act on it. All motion lives in the
 * `.toast*` theme block, which collapses under `prefers-reduced-motion` and safe mode.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useT } from '../../i18n';
import { Close } from '../icons';
import { ToastContext } from './context';
import { ErrorGlyph, InfoGlyph, SuccessGlyph } from './icons';
import { toastMessage } from './message';
import type { ToastHandle, ToastItem, ToastOptions, ToastVariant } from './types';

/** Default auto-dismiss per variant (ms). Errors linger longer to be read (§3.1). */
const DEFAULT_DURATION = 5000;
const ERROR_DURATION = 8000;
/** Cap on simultaneously-visible toasts; older ones drop off as new ones arrive. */
const MAX_VISIBLE = 4;

/** Monotonic id source — deterministic (no randomness) so tests can reason about ids. */
let nextId = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
  const t = useT();
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((toast) => toast.id !== id));
  }, []);

  // The handle is stable for the provider's lifetime: consumers reading `useToast()` never
  // re-render just because the toast list changed. `setToasts`/`dismiss` are stable, and
  // the generic-error fallback is resolved lazily inside `error` from the live `t`.
  const tRef = useRef(t);
  tRef.current = t;

  const handle = useMemo<ToastHandle>(() => {
    const show = (variant: ToastVariant, message: string, opts?: ToastOptions): string => {
      const id = `toast-${(nextId += 1)}`;
      const duration = opts?.duration ?? (variant === 'error' ? ERROR_DURATION : DEFAULT_DURATION);
      const item: ToastItem = { id, variant, message, title: opts?.title, duration };
      // Newest first in the DOM (read first by a screen reader); the viewport uses
      // column-reverse so it also sits nearest the corner. Cap to the newest MAX_VISIBLE.
      setToasts((prev) => [item, ...prev].slice(0, MAX_VISIBLE));
      return id;
    };
    return {
      show,
      success: (message, opts) => show('success', message, opts),
      info: (message, opts) => show('info', message, opts),
      error: (message, opts) =>
        show('error', toastMessage(message, tRef.current('toast.genericError')), opts),
      dismiss,
    };
  }, [dismiss]);

  return (
    <ToastContext.Provider value={handle}>
      {children}
      <div className="toast-viewport" role="region" aria-label={t('toast.regionLabel')}>
        {toasts.map((toast) => (
          <ToastRow
            key={toast.id}
            toast={toast}
            onDismiss={dismiss}
            dismissLabel={t('toast.dismiss')}
          />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

const VARIANT_ICON: Record<ToastVariant, ReactNode> = {
  success: <SuccessGlyph />,
  error: <ErrorGlyph />,
  info: <InfoGlyph />,
};

function ToastRow({
  toast,
  onDismiss,
  dismissLabel,
}: {
  toast: ToastItem;
  onDismiss: (id: string) => void;
  dismissLabel: string;
}) {
  const [paused, setPaused] = useState(false);

  // Auto-dismiss timer. A `0` duration is sticky (never auto-dismisses). Hover/focus
  // pauses it; leaving restarts the countdown so the toast is not whisked away mid-read.
  useEffect(() => {
    if (toast.duration <= 0 || paused) return;
    const timer = window.setTimeout(() => onDismiss(toast.id), toast.duration);
    return () => window.clearTimeout(timer);
  }, [toast.id, toast.duration, paused, onDismiss]);

  const isError = toast.variant === 'error';
  return (
    <div
      className={`toast toast--${toast.variant}`}
      role={isError ? 'alert' : 'status'}
      aria-live={isError ? 'assertive' : 'polite'}
      aria-atomic="true"
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      onFocus={() => setPaused(true)}
      onBlur={() => setPaused(false)}
    >
      <span className="toast__icon" aria-hidden="true">
        {VARIANT_ICON[toast.variant]}
      </span>
      <div className="toast__content">
        {toast.title ? <p className="toast__title">{toast.title}</p> : null}
        <p className="toast__message">{toast.message}</p>
      </div>
      <button
        type="button"
        className="toast__dismiss"
        aria-label={dismissLabel}
        onClick={() => onDismiss(toast.id)}
      >
        <Close />
      </button>
    </div>
  );
}
