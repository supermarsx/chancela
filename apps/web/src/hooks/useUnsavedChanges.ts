/**
 * `useUnsavedChanges` — the registry a surface uses to declare "I am holding work that
 * would be lost right now" (t52).
 *
 * The app must warn before losing typed work, but an UNCONDITIONAL warning is worse than
 * none: browsers make `beforeunload` deliberately hostile (the message cannot be
 * customised, it only fires after a real user interaction), and a site that always
 * prompts trains operators to click through it. So the prompt is driven by a registry of
 * *actually dirty* surfaces rather than by "the editor is open".
 *
 * The contract is deliberately tiny and imperative:
 *
 *  - A surface calls {@link useUnsavedChanges} with its own dirty flag. The hook owns one
 *    registration keyed by a per-instance symbol, keeps it in sync with the flag, and —
 *    the important half — **removes it on unmount**. A stale registration is the failure
 *    mode that makes the whole app prompt forever, so unregistration is not optional and
 *    is covered by tests.
 *  - Consumers ({@link ../app/UnsavedChangesGuard}) read {@link hasUnsavedChanges} at
 *    event time and subscribe with {@link subscribeUnsavedChanges} only so the
 *    `beforeunload` listener can be attached/detached — a permanently-attached
 *    `beforeunload` listener makes the page ineligible for the back/forward cache, so a
 *    clean app keeps none.
 *
 * No React context: the guard needs the answer synchronously inside a DOM event handler
 * and inside a React Router blocker function, both of which run outside render. A module
 * registry answers both without plumbing a provider through the shell.
 */
import { useEffect, useState } from 'react';

/** The identity of one surface's registration. */
type RegistrationId = symbol;

const dirtySurfaces = new Set<RegistrationId>();
const listeners = new Set<() => void>();

/**
 * A one-shot "this next navigation is ours, do not prompt" token. The app itself
 * navigates after a successful save (create → detail page), and prompting on that happy
 * path is the fastest way to make operators hate the feature. The token is consumed by
 * the blocker only when it would otherwise have blocked, and the guard drops it on every
 * completed location change so it can never leak into an unrelated navigation.
 */
let navigationBypass = false;

function notify(): void {
  // Copy first: a listener may unsubscribe itself while being notified.
  for (const listener of [...listeners]) listener();
}

/** Add/remove one surface's registration, notifying only on a real transition. */
export function setUnsavedChanges(id: RegistrationId, isDirty: boolean): void {
  const wasDirty = dirtySurfaces.has(id);
  if (isDirty === wasDirty) return;
  if (isDirty) dirtySurfaces.add(id);
  else dirtySurfaces.delete(id);
  notify();
}

/** Drop a surface's registration entirely (unmount). */
export function clearUnsavedChanges(id: RegistrationId): void {
  if (dirtySurfaces.delete(id)) notify();
}

/** True when at least one mounted surface is holding unsaved work. */
export function hasUnsavedChanges(): boolean {
  return dirtySurfaces.size > 0;
}

/** Subscribe to dirty/clean transitions. Returns the unsubscribe function. */
export function subscribeUnsavedChanges(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * Exempt the very next in-app navigation from the guard. Call this immediately before a
 * `navigate()` the app performs after a successful save, where the local state has not
 * yet caught up with the server.
 */
export function allowNextNavigation(): void {
  navigationBypass = true;
}

/** Read-and-clear the bypass token. */
export function consumeNavigationBypass(): boolean {
  const bypass = navigationBypass;
  navigationBypass = false;
  return bypass;
}

/** Drop an unconsumed bypass token (the guard calls this on every completed navigation). */
export function resetNavigationBypass(): void {
  navigationBypass = false;
}

/**
 * Declare whether this surface is currently holding unsaved work.
 *
 * `isDirty` should be derived by comparing the working copy against what is persisted —
 * not set by hand on every keystroke — so that saving, reverting an edit, or the server
 * echoing the saved value all clear the flag without extra bookkeeping.
 */
export function useUnsavedChanges(isDirty: boolean): void {
  // `useState`'s lazy initialiser gives a stable per-instance identity (and, unlike
  // `useMemo`, is guaranteed not to be recomputed).
  const [id] = useState<RegistrationId>(() => Symbol('unsaved-changes'));

  useEffect(() => {
    setUnsavedChanges(id, isDirty);
  }, [id, isDirty]);

  // Separate effect so unregistration happens ONLY on unmount, never on a flag change.
  useEffect(() => () => clearUnsavedChanges(id), [id]);
}
