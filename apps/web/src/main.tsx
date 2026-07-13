import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider } from 'react-router-dom';
import { Providers } from './app/providers';
import { BootSplash } from './app/BootSplash';
import { router } from './app/router';
import { ShellErrorBoundary } from './app/ErrorBoundary';
import { recordCrash } from './app/safeMode';
import { checkServerVersion } from './api/versionCheck';
import { isTauri } from './desktop/tauri';
import './theme.css';

// Flag the document when running inside the Tauri shell so the CSS can reserve
// space for the custom title bar (`--titlebar-h`). In a browser this is never
// set, so the app renders edge-to-edge with zero layout shift.
if (isTauri()) {
  document.documentElement.dataset.tauri = 'true';
}

// Global last-resort handlers for failures that never reach a React boundary: rejected
// promises with no `.catch` and errors thrown outside the render cycle (event handlers,
// timers, async callbacks). Both handlers log without rendering React; unhandled
// rejections also feed the crash-loop counter so a storm of async failures can trip
// safe mode on the next boot, matching the React boundary's behaviour.
window.addEventListener('unhandledrejection', (event) => {
  console.error('unhandledrejection', event.reason);
  recordCrash();
});
window.addEventListener('error', (event) => {
  console.error('window error', event.error ?? event.message);
});

const rootEl = document.getElementById('root');
if (!rootEl) {
  throw new Error('Root element #root not found in index.html');
}

createRoot(rootEl).render(
  <StrictMode>
    <Providers>
      {/* Defence-in-depth for NON-route render errors (BootSplash, the RouterProvider
          itself, anything above React Router's own per-route `errorElement`). Route render
          and lazy chunk-load failures are caught inside the router by `errorElement`
          (see router.tsx); this boundary catches the rest so they never blank the window.
          It sits INSIDE `<Providers>` so its CrashScreen fallback keeps the i18n store and
          window controls. */}
      <ShellErrorBoundary>
        {/* A brief, decorative boot overlay ABOVE the router. It is never a gate: the router
            (and the AuthGate / safe-mode banner within it) render and become interactive
            underneath, and the splash fades + unmounts on its own short timer. It is skipped
            entirely under reduced-motion / safe-mode (renders nothing). */}
        <BootSplash />
        <RouterProvider router={router} />
      </ShellErrorBoundary>
    </Providers>
  </StrictMode>,
);

// Non-blocking: warn in the console if the running server is a different version than this
// UI build (a common cause of stale-route "Unexpected token '<'" failures).
void checkServerVersion();
