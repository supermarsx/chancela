/**
 * App shell: leather background, custom titlebar (Tauri), a slim fixed secondary
 * tab bar (centered tabs), and the routed outlet inside the single inner scroll
 * container. Nav labels are the pinned PT-PT set (Painel, Entidades, Livros,
 * Arquivo); `NavLink` marks the active route. Route changes fade/slide the routed
 * content in (keyed on the pathname); the fixed background + chrome never
 * re-animate. All motion is disabled under `prefers-reduced-motion`.
 *
 * Crash resilience (t26): two nested error boundaries. The OUTER
 * {@link ShellErrorBoundary} wraps the whole shell — including the title bar — so a
 * title-bar crash still leaves working window controls. The INNER
 * {@link PageErrorBoundary} wraps only the routed outlet inside the main landmark, BELOW
 * the title bar, so a page crash leaves both the title bar (drag/min/max/close) and the
 * skip-link target fully functional. In safe mode the appearance layers are bypassed
 * entirely and a persistent banner is shown.
 */
import { useEffect, useRef } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { LeatherBackground } from '../theme/LeatherBackground';
import { AppearanceEffects } from '../theme/AppearanceEffects';
import { TitleBar } from '../desktop/TitleBar';
import { NotificationBell } from '../features/notifications/NotificationBell';
import { CurrentUserPicker } from '../features/session/CurrentUserPicker';
import { AuthGate } from '../features/session/AuthGate';
import { PageErrorBoundary, ShellErrorBoundary } from './ErrorBoundary';
import { SafeModeBanner } from './SafeModeBanner';
import { DegradedBanner } from './DegradedBanner';
import { isSafeMode } from './safeMode';
import { useT } from '../i18n';
import type { MessageKey } from '../i18n';

const NAV: { to: string; label: MessageKey; end?: boolean }[] = [
  { to: '/', label: 'nav.dashboard', end: true },
  { to: '/entidades', label: 'nav.entities' },
  { to: '/livros', label: 'nav.books' },
  { to: '/minutas', label: 'nav.templates' },
  { to: '/arquivo', label: 'nav.archive' },
  { to: '/ferramentas', label: 'nav.tools' },
  { to: '/configuracoes', label: 'nav.settings' },
];

export function Layout() {
  // The pathname keys the routed content so it remounts and replays the enter
  // animation on every navigation. It ALSO keys the page error boundary, so navigating
  // away from a crashed page remounts a fresh boundary (clearing the error state).
  const t = useT();
  const { pathname } = useLocation();
  const safe = isSafeMode();

  // On navigation, move keyboard focus to the routed <main id="main-content"> (it already
  // remounts keyed on pathname) so screen-reader/keyboard users land on the new page
  // content instead of being stranded at the top of the tab bar. Guarded against the very
  // first mount so it doesn't steal focus from the boot/autofocus flow; the `tabIndex={-1}`
  // main is focusable without a visible outline (via `:focus:not(:focus-visible)`).
  const mainRef = useRef<HTMLElement>(null);
  const firstRender = useRef(true);
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    mainRef.current?.focus();
  }, [pathname]);

  return (
    <ShellErrorBoundary>
      {/* Safe mode bypasses the appearance layers so a crashing settings/appearance
          configuration cannot take the shell down; the banner explains it and offers exit. */}
      {safe ? <SafeModeBanner /> : <AppearanceEffects />}
      {safe ? null : <LeatherBackground />}
      <TitleBar />

      {/* The auth gate blocks the app chrome until a session exists: a fresh install is
          redirected to the onboarding wizard, a signed-out visitor sees the sign-in
          surface, and only a signed-in operator reaches the tab bar + routed content. The
          safe banner / leather layer above stay independent of it (guard × safe-mode). */}
      <AuthGate>
        {/* First focusable element inside the shell: lets keyboard/screen-reader users
            jump the tab bar and land on the routed page content. Off-screen until focused
            (see `.skip-link` in theme.css), then it surfaces above the topbar. */}
        <a className="skip-link" href="#main-content">
          {t('nav.skipToContent')}
        </a>

        {/* Fixed secondary tab bar: topmost in the browser, under the custom titlebar
            in the desktop shell. The brand mark stays left; the tab group is centered
            in the full bar width; the current-user picker sits at the right. The brand
            is hidden on desktop (the titlebar already carries the wordmark). */}
        <nav className="topbar" aria-label={t('nav.aria')}>
          <span className="topbar__brand">{t('common.brand')}</span>
          <div className="topbar__nav" data-testid="tab-bar">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) => (isActive ? 'nav__link is-active' : 'nav__link')}
              >
                {t(item.label)}
              </NavLink>
            ))}
          </div>
          <div className="topbar__session">
            <NotificationBell />
            <CurrentUserPicker />
          </div>
        </nav>

        {/* Server-driven read-only banner: shown whenever the server reports a broken
            integrity chain (distinct from the client-boot safe-mode banner above). */}
        <DegradedBanner />

        {/* The single inner scroll container — the window itself never scrolls. */}
        <div className="app-scroll">
          <div className="app">
            {/* Keyed on the pathname so the routed content remounts and replays the
                `.route-transition` enter on every navigation. The key is set here on the
                wrapper itself (not left implicit in the boundary's remount) so the
                re-trigger is explicit; `data-route-key` exposes it for tests. The page
                error boundary sits INSIDE the landmark so the skip-link target survives
                route crashes. */}
            <main
              ref={mainRef}
              id="main-content"
              tabIndex={-1}
              className="route-transition"
              key={pathname}
              data-route-key={pathname}
            >
              <PageErrorBoundary key={pathname}>
                <Outlet />
              </PageErrorBoundary>
            </main>

            <footer className="footer">{t('common.footer')}</footer>
          </div>
        </div>
      </AuthGate>
    </ShellErrorBoundary>
  );
}
