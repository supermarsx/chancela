/**
 * `UnsavedChangesGuard` — the single place that turns "a surface has unsaved work"
 * (see {@link ../hooks/useUnsavedChanges}) into a warning before that work is lost (t52).
 *
 * Three ways to leave, three genuinely different mechanisms — the guard is honest about
 * what it can and cannot control in each:
 *
 *  1. **Closing/reloading the browser tab** — `beforeunload`. The browser shows its OWN
 *     generic string; **the message cannot be customised** (every major engine ignores
 *     `returnValue`), so nothing here pretends to translate it. All we control is
 *     *whether* it appears. The listener is attached only while something is dirty: a
 *     permanently-registered `beforeunload` handler disqualifies the page from the
 *     back/forward cache, and a clean app should cost nothing.
 *  2. **In-app route changes** — React Router's `useBlocker` (a data router, so it is the
 *     stable API). Here we CAN show a real dialog: translated, focus-trapped, Escape to
 *     cancel — so this path gets the good experience. Only a change of PAGE is blocked; the
 *     app's own in-page navigation — hash anchors, filter query params, and (since t97) the
 *     sub-tab path segments — is not leaving the page and must never prompt.
 *  3. **Closing the desktop window** — a Tauri `close-requested` event, which is not an
 *     unload at all. The web layer CAN veto it, so the same translated dialog is shown
 *     and the window is destroyed only once the operator confirms. Registering the
 *     listener is what makes Tauri hand us the veto, so this component also owns the
 *     actual close (`destroy()`); the title bar's close button routes through here too.
 *
 * Mounted once, in the shell, above the auth gate. Routes rendered OUTSIDE `Layout`
 * (sign-in, onboarding, the external-signer invite) are deliberately not covered: with
 * the guard unmounted the Tauri listener is removed, so the window closes normally
 * instead of being held hostage by a screen that never registered anything.
 */
import { useCallback, useContext, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { createPortal } from 'react-dom';
import { UNSAFE_DataRouterContext, useBlocker, useLocation } from 'react-router-dom';
import { pageKeyForLocation } from './navPath';
import { isTauri } from '../desktop/tauri';
import { useT } from '../i18n';
import { Button } from '../ui';
import { useFocusTrap } from '../ui/useFocusTrap';
import {
  consumeNavigationBypass,
  hasUnsavedChanges,
  resetNavigationBypass,
  subscribeUnsavedChanges,
} from '../hooks/useUnsavedChanges';

/** The dirty flag as a React value (the guard only needs it to (de)register the listener). */
function useIsDirty(): boolean {
  return useSyncExternalStore(subscribeUnsavedChanges, hasUnsavedChanges, () => false);
}

export function UnsavedChangesGuard() {
  const t = useT();
  const dirty = useIsDirty();
  const [closeRequested, setCloseRequested] = useState(false);
  // `useBlocker` throws outside a DATA router (the app uses `createBrowserRouter`, but the
  // shared test harness and any future plain `<MemoryRouter>` do not). Reading the context
  // lets the route blocker be mounted conditionally instead of taking the whole shell down
  // — the unload and desktop guards, which need no router at all, keep working either way.
  const hasDataRouter = useContext(UNSAFE_DataRouterContext) !== null;
  // Set by the Tauri effect; called to actually close once the operator confirms.
  const destroyWindowRef = useRef<(() => Promise<void>) | null>(null);

  // --- 1. Tab close / reload -------------------------------------------------------
  useEffect(() => {
    if (!dirty) return;
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      // `preventDefault()` is the modern trigger; `returnValue` keeps older engines
      // prompting. Neither can set the text — the browser's own wording is shown.
      event.preventDefault();
      event.returnValue = '';
    };
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => window.removeEventListener('beforeunload', onBeforeUnload);
  }, [dirty]);

  // --- 3. Desktop window close -----------------------------------------------------
  useEffect(() => {
    if (!isTauri()) return;
    let unlisten: (() => void) | undefined;
    let active = true;

    void (async () => {
      const { getCurrentWindow } = await import('@tauri-apps/api/window');
      const win = getCurrentWindow();
      // Closing for real. `destroy()` is used (not `close()`) because `close()` would
      // re-emit close-requested straight back into this handler. If the ACL ever refuses
      // `destroy`, drop our listener and fall back to `close()` so the window can never
      // become unclosable.
      const destroy = async () => {
        try {
          await win.destroy();
        } catch (err) {
          console.error('UnsavedChangesGuard: window destroy failed', err);
          unlisten?.();
          unlisten = undefined;
          await win.close();
        }
      };
      destroyWindowRef.current = destroy;

      const registered = await win.onCloseRequested((event) => {
        // Always veto first and decide ourselves: the JS shim would otherwise destroy the
        // window as soon as this handler returns, which races the dialog.
        event.preventDefault();
        if (hasUnsavedChanges()) {
          setCloseRequested(true);
          return;
        }
        void destroy();
      });

      if (!active) {
        registered();
        return;
      }
      unlisten = registered;
    })();

    return () => {
      active = false;
      unlisten?.();
      destroyWindowRef.current = null;
    };
  }, []);

  return (
    <>
      {/* The desktop close is the more consequential of the two, so it suppresses the
          route dialog rather than stacking a second `role="dialog"` on top of it. */}
      {hasDataRouter ? <RouteChangeBlocker suppressed={closeRequested} /> : null}
      {closeRequested ? (
        <UnsavedChangesDialog
          title={t('unsaved.close.title')}
          body={t('unsaved.close.body')}
          confirmLabel={t('unsaved.close.confirm')}
          cancelLabel={t('unsaved.stay')}
          onCancel={() => setCloseRequested(false)}
          onConfirm={() => {
            setCloseRequested(false);
            void destroyWindowRef.current?.();
          }}
        />
      ) : null}
    </>
  );
}

/**
 * The in-app navigation half. Split out because `useBlocker` is only legal under a data
 * router, and because this is the one exit where we get to show a real dialog rather than
 * the browser's generic string.
 */
function RouteChangeBlocker({ suppressed }: { suppressed: boolean }) {
  const t = useT();
  const location = useLocation();
  // The route table, so "same page" can be decided the way the shell decides it. Since t97 a
  // sub-tab is a PATH segment, so comparing raw pathnames would prompt the operator to confirm
  // discarding their work merely for moving between two tabs of the surface they are editing —
  // Configurações, whose working copy spans every one of its sub-tabs, is exactly that case.
  const routes = useContext(UNSAFE_DataRouterContext)?.router.routes ?? [];
  const blocker = useBlocker(
    useCallback(
      ({ currentLocation, nextLocation }) => {
        // Staying on the same page (sub-tabs, hash anchors, filter query params) is not leaving.
        if (
          pageKeyForLocation(routes, currentLocation.pathname) ===
          pageKeyForLocation(routes, nextLocation.pathname)
        ) {
          return false;
        }
        if (!hasUnsavedChanges()) return false;
        // Only consume the one-shot token when it would actually have blocked, so a
        // post-save `navigate()` spends it on the navigation it was meant for.
        if (consumeNavigationBypass()) return false;
        return true;
      },
      [routes],
    ),
  );

  // A token that was never spent must not leak into some later, unrelated navigation.
  useEffect(() => {
    resetNavigationBypass();
  }, [location.pathname]);

  if (blocker.state !== 'blocked' || suppressed) return null;

  return (
    <UnsavedChangesDialog
      title={t('unsaved.title')}
      body={t('unsaved.body')}
      confirmLabel={t('unsaved.leave')}
      cancelLabel={t('unsaved.stay')}
      onCancel={() => blocker.reset?.()}
      onConfirm={() => blocker.proceed?.()}
    />
  );
}

interface UnsavedChangesDialogProps {
  title: string;
  body: string;
  confirmLabel: string;
  cancelLabel: string;
  onCancel: () => void;
  onConfirm: () => void;
}

/**
 * The confirm dialog for every path we control. Deliberately NOT
 * {@link ../ui/ConfirmActionModal}: that one is the server-side destructive-op gate
 * (type-to-confirm phrase, step-up re-auth, export-first) and none of those rails apply
 * to discarding a local draft. It reuses the same `.modal` chrome and the same
 * {@link useFocusTrap}, so the two dialogs look and behave identically.
 *
 * Cancel is the safe answer, so it is the primary button AND takes initial focus: an
 * operator who dismisses the dialog by reflex keeps their work.
 */
function UnsavedChangesDialog({
  title,
  body,
  confirmLabel,
  cancelLabel,
  onCancel,
  onConfirm,
}: UnsavedChangesDialogProps) {
  // The trap seeds focus on the first focusable descendant, which is the cancel button
  // (first in DOM order) — no explicit `initialFocus` needed.
  const trapRef = useFocusTrap<HTMLDivElement>(true);
  const titleId = useRef(`unsaved-${Math.random().toString(36).slice(2)}`).current;
  const bodyId = `${titleId}-body`;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCancel();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onCancel]);

  return createPortal(
    <div className="modal-backdrop" onClick={onCancel}>
      <div
        ref={trapRef}
        className="modal modal--danger"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={bodyId}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="modal__head">
          <h2 className="modal__title" id={titleId}>
            {title}
          </h2>
        </header>
        <div className="modal__body">
          <p className="modal__intro" id={bodyId}>
            {body}
          </p>
          <div className="modal__foot">
            <Button type="button" variant="primary" onClick={onCancel}>
              {cancelLabel}
            </Button>
            <Button type="button" variant="secondary" className="btn--danger" onClick={onConfirm}>
              {confirmLabel}
            </Button>
          </div>
        </div>
      </div>
    </div>,
    document.body,
  );
}
