/**
 * Custom themed window title bar for the Tauri desktop shell.
 *
 * The native window chrome is off (`decorations: false`), so this bar IS the
 * window frame: the Chancela seal + wordmark, a draggable region, and minimize /
 * maximize-restore / close controls ({@link WindowControls}). It renders ONLY inside
 * Tauri ({@link isTauri}); in a browser it returns `null` (no DOM, no layout shift).
 *
 * Dragging uses Tauri's native `data-tauri-drag-region="deep"` on the bar root.
 * On Windows/WebView2 `start_dragging` runs `ReleaseCapture()` +
 * `SendMessage(WM_NCLBUTTONDOWN, HTCAPTION)`, which must be issued synchronously
 * inside the live mousedown gesture — Tauri's injected `mousedown` listener does
 * exactly that (a bare `invoke`, no microtask/import hop), so the OS drag loop
 * starts while the button is held. A previous JS `mousedown → startDragging()`
 * handler went through a `Promise.then`/dynamic-`import()` hop and the gesture
 * was already dead by the time the IPC landed — that is why drag silently
 * no-op'd while the buttons (one-shot clicks) still worked. The `"deep"` value
 * makes clicks anywhere in the subtree drag the window while Tauri auto-excludes
 * clickable elements (the min/max/close `<button>`s), and double-click on the
 * bar maximizes — all handled natively, so we do NOT add our own drag handler
 * (a second one would double-invoke and cancel the double-click maximize).
 *
 * The window buttons live in {@link WindowControls} (shared with the crash-screen
 * fallback so window control survives even a title-bar crash — t26).
 */
import { isTauri } from './tauri';
import { useT } from '../i18n';
import { WindowControls } from './WindowControls';

export function TitleBar() {
  const t = useT();
  if (!isTauri()) return null;

  // `data-tauri-drag-region="deep"` makes the whole bar draggable via Tauri's
  // native synchronous mousedown handler (double-click → maximize included); the
  // buttons below are auto-excluded because Tauri treats clickable elements
  // without the attribute as drag-blockers.
  return (
    <div className="titlebar" data-tauri-drag-region="deep">
      <div className="titlebar__brand">
        <Seal />
        <span className="titlebar__wordmark">{t('common.brand')}</span>
      </div>

      <WindowControls />
    </div>
  );
}

/** Small wax-seal mark, echoing the "Chancela" (seal) wordmark. */
function Seal() {
  return (
    <svg className="titlebar__seal" viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="9.25" />
      <circle cx="12" cy="12" r="6.5" />
      <text x="12" y="15.5" textAnchor="middle">
        C
      </text>
    </svg>
  );
}
