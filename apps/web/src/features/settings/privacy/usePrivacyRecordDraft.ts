/**
 * The working copy behind every RGPD register record page (t55): seed once, measure real edits,
 * and stop the unsaved-changes guard from challenging the app's own post-save navigation.
 *
 * ## Why a hook and not five copies
 *
 * All five pages need exactly the same three things, and getting any of them subtly wrong is how
 * the five surfaces drift apart:
 *
 *  - **Seed once.** An edit page resolves its record from the already-cached list query, so the
 *    seed arrives asynchronously and then keeps arriving on every refetch. Re-seeding would
 *    silently discard what the operator has typed. The draft is therefore installed exactly once,
 *    on the first non-null seed.
 *  - **`baselineRef` captured at seed time**, so `dirty` measures the operator's edits rather than
 *    the pre-filled record. Without it an edit page is dirty the instant it paints, and the guard
 *    fires on every exit — which trains people to click through it.
 *  - **`markSaved()` before `navigate()`.** It sets the local saved flag AND takes the shared
 *    one-shot navigation bypass, so a successful save leaves without a prompt while a genuine
 *    dirty exit still gets one.
 *
 * ## What this deliberately does NOT do
 *
 * It writes nothing to `localStorage`, `sessionStorage` or IndexedDB. These forms carry categories
 * of personal data, named subcontratantes, legal bases and breach-response detail; mirroring a
 * half-filled DPIA into unencrypted browser storage would create a second copy of compliance
 * content outside the ledger, on a possibly shared workstation, invisible to the very retention
 * policies this screen configures. The product's own resumability primitive is `status: 'draft'`
 * plus the stable address t55 adds: save the rascunho, leave, come back to its deep link.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { allowNextNavigation, useUnsavedChanges } from '../../../hooks/useUnsavedChanges';

export interface PrivacyRecordDraft<T> {
  /** The working copy, or `null` while the seed is still being resolved. */
  form: T | null;
  setForm: (next: T) => void;
  /** True when the working copy differs from what it was seeded with. */
  dirty: boolean;
  /** Call immediately before the post-save `navigate()`. */
  markSaved: () => void;
}

/**
 * @param seed the initial form state — an `EMPTY_*` constant for create, or the record-derived
 *   state for edit, and `null` until the record resolves. Only the first non-null value is used.
 */
export function usePrivacyRecordDraft<T>(seed: T | null): PrivacyRecordDraft<T> {
  const [form, setForm] = useState<T | null>(null);
  const baselineRef = useRef<string | null>(null);
  const savedRef = useRef(false);

  // `seed` is a fresh object on every render, so the guard is the baseline ref rather than the
  // dependency list: once a baseline exists the draft is installed and a later seed is ignored.
  useEffect(() => {
    if (seed === null || baselineRef.current !== null) return;
    baselineRef.current = JSON.stringify(seed);
    setForm(seed);
  }, [seed]);

  const dirty = useMemo(() => {
    if (form === null || baselineRef.current === null) return false;
    return JSON.stringify(form) !== baselineRef.current;
  }, [form]);

  useUnsavedChanges(dirty && !savedRef.current);

  return useMemo(
    () => ({
      form,
      setForm,
      dirty,
      markSaved: () => {
        savedRef.current = true;
        allowNextNavigation();
      },
    }),
    [form, dirty],
  );
}
