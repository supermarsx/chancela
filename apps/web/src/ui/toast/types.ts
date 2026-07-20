/**
 * The frozen Toast API contract (plan t44 §3.1). These types are consumed by the
 * autosave wiring (t44-w2) and every mutation-flow retrofit (t44-w3/w4) — they are the
 * stable surface, so grow them only additively.
 */

/** The three notification tones the viewport renders. */
export type ToastVariant = 'success' | 'error' | 'info';

export interface ToastOptions {
  /** Optional short heading rendered above the message. */
  title?: string;
  /**
   * Auto-dismiss after `ms`; `0` = sticky (stays until dismissed). Default 5000;
   * error default 8000 (errors linger a little longer to be read).
   */
  duration?: number;
}

export interface ToastHandle {
  /** Generic push; returns the new toast id. */
  show: (variant: ToastVariant, message: string, opts?: ToastOptions) => string;
  success: (message: string, opts?: ToastOptions) => string;
  /**
   * Accepts a plain string OR an unknown error value (ApiError/Error/other) and
   * renders its extracted message — so a caller can pass a caught error straight
   * through: `catch (e) { toast.error(e); }`.
   */
  error: (message: string | unknown, opts?: ToastOptions) => string;
  info: (message: string, opts?: ToastOptions) => string;
  /** Dismiss a toast early by the id returned from a push. */
  dismiss: (id: string) => void;
}

/** One live toast held in the provider's state. `duration` is the resolved value. */
export interface ToastItem {
  id: string;
  variant: ToastVariant;
  message: string;
  title?: string;
  duration: number;
}
