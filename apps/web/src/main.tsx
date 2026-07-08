import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider } from 'react-router-dom';
import { Providers } from './app/providers';
import { BootSplash } from './app/BootSplash';
import { router } from './app/router';
import { checkServerVersion } from './api/versionCheck';
import { isTauri } from './desktop/tauri';
import './theme.css';

// Flag the document when running inside the Tauri shell so the CSS can reserve
// space for the custom title bar (`--titlebar-h`). In a browser this is never
// set, so the app renders edge-to-edge with zero layout shift.
if (isTauri()) {
  document.documentElement.dataset.tauri = 'true';
}

const rootEl = document.getElementById('root');
if (!rootEl) {
  throw new Error('Root element #root not found in index.html');
}

createRoot(rootEl).render(
  <StrictMode>
    <Providers>
      {/* A brief, decorative boot overlay ABOVE the router. It is never a gate: the router
          (and the AuthGate / safe-mode banner within it) render and become interactive
          underneath, and the splash fades + unmounts on its own short timer. It is skipped
          entirely under reduced-motion / safe-mode (renders nothing). */}
      <BootSplash />
      <RouterProvider router={router} />
    </Providers>
  </StrictMode>,
);

// Non-blocking: warn in the console if the running server is a different version than this
// UI build (a common cause of stale-route "Unexpected token '<'" failures).
void checkServerVersion();
