/**
 * `useAutosave` — a small, reusable debounced-autosave controller (t49).
 *
 * Given a `value` and an async `onSave`, it debounces changes (~700ms) and persists the
 * latest value, coalescing so that (a) rapid edits collapse into a single trailing save,
 * and (b) edits made *while a save is in flight* never overlap it — the newest value is
 * saved once the current round-trip settles. It exposes a "dirty → saving → saved/error"
 * status the UI can render inline, plus a {@link AutosaveController.flush} to save/retry
 * immediately (e.g. an explicit "Guardar agora" button or an error retry).
 *
 * It is intentionally UI-agnostic: it never touches toasts or i18n, so it stays trivially
 * testable and reusable. Callers wire feedback via `onSuccess`/`onError` (fired once per
 * settled round-trip) and by rendering `status`.
 */
import { useCallback, useEffect, useRef, useState } from 'react';

export type AutosaveStatus = 'idle' | 'dirty' | 'saving' | 'saved' | 'error';

/** The default debounce window: long enough to collapse a burst of keystrokes, short
 *  enough to feel immediate. */
export const AUTOSAVE_DELAY_MS = 700;

export interface UseAutosaveOptions<T> {
  /** The current (possibly-dirty) value to persist. */
  value: T;
  /** Persist `value`. Rejects on failure (its rejection drives the `error` status). */
  onSave: (value: T) => Promise<unknown>;
  /** Debounce window in ms. Defaults to {@link AUTOSAVE_DELAY_MS}. */
  delay?: number;
  /** While `false`, no baseline is captured and nothing is scheduled (e.g. still loading). */
  enabled?: boolean;
  /** Serialize `value` for change detection. Defaults to `JSON.stringify`. */
  serialize?: (value: T) => string;
  /** Called once after each successful save round-trip. */
  onSuccess?: () => void;
  /** Called once after each failed save round-trip (with the rejection reason). */
  onError?: (error: unknown) => void;
}

export interface AutosaveController {
  status: AutosaveStatus;
  /** True while a save round-trip is in flight. */
  isSaving: boolean;
  /** True when there are edits not yet persisted (pending debounce, saving, or errored). */
  isDirty: boolean;
  /** The last save rejection, or `null`. Cleared when a fresh save starts. */
  error: unknown;
  /** Cancel any pending debounce and save the latest value immediately (also used to retry). */
  flush: () => void;
}

const defaultSerialize = (value: unknown): string => JSON.stringify(value);

export function useAutosave<T>({
  value,
  onSave,
  delay = AUTOSAVE_DELAY_MS,
  enabled = true,
  serialize = defaultSerialize,
  onSuccess,
  onError,
}: UseAutosaveOptions<T>): AutosaveController {
  const [status, setStatus] = useState<AutosaveStatus>('idle');
  const [error, setError] = useState<unknown>(null);

  // Latest inputs kept in refs so the stable, debounced closures always act on the newest
  // value/callbacks without being recreated (which would restart the debounce every render).
  const valueRef = useRef(value);
  valueRef.current = value;
  const onSaveRef = useRef(onSave);
  onSaveRef.current = onSave;
  const serializeRef = useRef(serialize);
  serializeRef.current = serialize;
  const onSuccessRef = useRef(onSuccess);
  onSuccessRef.current = onSuccess;
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;

  // The serialization of the last value we successfully persisted. `null` until the first
  // value is observed, so the initial (unchanged) mount never fires a spurious save.
  const savedKeyRef = useRef<string | null>(null);
  const inFlightRef = useRef(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearTimer = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  // Perform a save if the current value differs from the last-saved one and none is in
  // flight. On settle it re-checks the (possibly newer) value and chains another save,
  // so edits made mid-flight are never dropped and never overlap the request.
  const run = useCallback(() => {
    clearTimer();
    if (inFlightRef.current) return;
    const snapshotKey = serializeRef.current(valueRef.current);
    if (snapshotKey === savedKeyRef.current) return;

    inFlightRef.current = true;
    setError(null);
    setStatus('saving');
    Promise.resolve(onSaveRef.current(valueRef.current))
      .then(() => {
        savedKeyRef.current = snapshotKey;
        inFlightRef.current = false;
        onSuccessRef.current?.();
        if (serializeRef.current(valueRef.current) !== savedKeyRef.current) {
          // The value moved on while saving — persist the newest, once.
          run();
        } else {
          setStatus('saved');
        }
      })
      .catch((e: unknown) => {
        inFlightRef.current = false;
        setError(e);
        setStatus('error');
        onErrorRef.current?.(e);
      });
  }, [clearTimer]);

  const flush = useCallback(() => run(), [run]);

  const key = serialize(value);

  useEffect(() => {
    if (!enabled) return;
    // First observed value seeds the baseline; never a save on mount.
    if (savedKeyRef.current === null) {
      savedKeyRef.current = key;
      return;
    }
    // Not dirty (unchanged, reverted, or just-saved): nothing to schedule.
    if (key === savedKeyRef.current) return;
    // Dirty: (re)arm the debounce. Keep 'saving' visible if a round-trip is already running.
    setStatus((s) => (s === 'saving' ? s : 'dirty'));
    clearTimer();
    timerRef.current = setTimeout(run, delay);
    return clearTimer;
  }, [key, enabled, delay, run, clearTimer]);

  // Cancel a pending debounce if the consumer unmounts.
  useEffect(() => clearTimer, [clearTimer]);

  return {
    status,
    isSaving: status === 'saving',
    isDirty: status === 'dirty' || status === 'saving' || status === 'error',
    error,
    flush,
  };
}
