/**
 * The minimize / maximize-restore / close window controls for the custom (decorationless)
 * Tauri title bar.
 *
 * Extracted from {@link TitleBar} so the SAME working controls can be rendered by BOTH
 * the normal title bar and the crash-screen shell fallback (t26): if the title bar itself
 * throws, the outer error boundary swaps in a minimal strip that still lets the user drag
 * (via the strip's own drag region) and, crucially, minimize/maximize/close the window —
 * never a "no dice" locked window.
 *
 * The buttons call the JS window API, so `@tauri-apps/api/window` is imported lazily
 * (preloaded into a ref on mount); the browser bundle and vitest never resolve it. The
 * buttons carry no `data-tauri-drag-region`, so Tauri auto-excludes them from the drag
 * region of whatever bar hosts them.
 */
import { useEffect, useRef, useState } from 'react';
import { isTauri } from './tauri';
import { useT } from '../i18n';
import { Tooltip } from '../ui';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type { Window as TauriWindow } from '@tauri-apps/api/window';

async function loadWindow(): Promise<TauriWindow> {
  const { getCurrentWindow } = await import('@tauri-apps/api/window');
  return getCurrentWindow();
}

export function WindowControls() {
  const t = useT();
  const [maximized, setMaximized] = useState(false);
  // Always-on-top has no getter in the Tauri window API, so we own the truth: it starts
  // off (matching the window's default) and flips on each toggle.
  const [alwaysOnTop, setAlwaysOnTop] = useState(false);
  const winRef = useRef<TauriWindow | null>(null);

  // Preload the window handle and keep the maximize/restore icon in sync with the real
  // window state (incl. OS-driven changes: snap, drag-region double-click, keyboard).
  // Only runs inside Tauri.
  useEffect(() => {
    if (!isTauri()) return;

    let unlisten: UnlistenFn | undefined;
    let active = true;

    void (async () => {
      const win = await loadWindow();
      if (!active) return;
      winRef.current = win;
      setMaximized(await win.isMaximized());
      unlisten = await win.onResized(async () => {
        setMaximized(await win.isMaximized());
      });
      if (!active) unlisten?.();
    })();

    return () => {
      active = false;
      unlisten?.();
    };
  }, []);

  const win = () => (winRef.current ? Promise.resolve(winRef.current) : loadWindow());

  const minimize = () => void win().then((w) => w.minimize());
  const toggleMaximize = () => void win().then((w) => w.toggleMaximize());
  const close = () => void win().then((w) => w.close());
  const toggleAlwaysOnTop = () => {
    const next = !alwaysOnTop;
    setAlwaysOnTop(next);
    void win().then((w) => w.setAlwaysOnTop(next));
  };

  const alwaysOnTopLabel = alwaysOnTop ? t('window.alwaysOnTop.active') : t('window.alwaysOnTop');

  return (
    <div className="titlebar__controls">
      <Tooltip label={alwaysOnTopLabel} placement="bottom">
        <button
          type="button"
          className="titlebar__btn"
          onClick={toggleAlwaysOnTop}
          aria-label={alwaysOnTopLabel}
          aria-pressed={alwaysOnTop}
        >
          {/* An arrow rising to a fixed rail — "keep this window above the rest". */}
          <svg viewBox="0 0 12 12" aria-hidden="true">
            <line x1="2.5" y1="2.5" x2="9.5" y2="2.5" />
            <line x1="6" y1="9.5" x2="6" y2="4.5" />
            <path d="M3.75 6.5 L6 4.25 L8.25 6.5" fill="none" />
          </svg>
        </button>
      </Tooltip>

      <button
        type="button"
        className="titlebar__btn"
        onClick={minimize}
        aria-label={t('window.minimize')}
        title={t('window.minimize')}
      >
        <svg viewBox="0 0 12 12" aria-hidden="true">
          <line x1="2.5" y1="6" x2="9.5" y2="6" />
        </svg>
      </button>

      <button
        type="button"
        className="titlebar__btn"
        onClick={toggleMaximize}
        aria-label={maximized ? t('window.restore') : t('window.maximize')}
        title={maximized ? t('window.restore') : t('window.maximize')}
      >
        {maximized ? (
          <svg viewBox="0 0 12 12" aria-hidden="true">
            <rect x="2.5" y="3.5" width="6" height="6" rx="0.5" />
            <path d="M4.5 3.5 V2.5 H9.5 V7.5 H8.5" fill="none" />
          </svg>
        ) : (
          <svg viewBox="0 0 12 12" aria-hidden="true">
            <rect x="2.5" y="2.5" width="7" height="7" rx="0.5" />
          </svg>
        )}
      </button>

      <button
        type="button"
        className="titlebar__btn titlebar__btn--close"
        onClick={close}
        aria-label={t('window.close')}
        title={t('window.close')}
      >
        <svg viewBox="0 0 12 12" aria-hidden="true">
          <line x1="3" y1="3" x2="9" y2="9" />
          <line x1="9" y1="3" x2="3" y2="9" />
        </svg>
      </button>
    </div>
  );
}
