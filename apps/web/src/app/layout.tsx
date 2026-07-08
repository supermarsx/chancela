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
 * {@link PageErrorBoundary} wraps only the routed content, BELOW the title bar, so a
 * page crash leaves the title bar (drag/min/max/close) fully functional. In safe mode
 * the appearance layers are bypassed entirely and a persistent banner is shown.
 */
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { LeatherBackground } from '../theme/LeatherBackground';
import { AppearanceEffects } from '../theme/AppearanceEffects';
import { TitleBar } from '../desktop/TitleBar';
import { CurrentUserPicker } from '../features/session/CurrentUserPicker';
import { AuthGate } from '../features/session/AuthGate';
import { PageErrorBoundary, ShellErrorBoundary } from './ErrorBoundary';
import { SafeModeBanner } from './SafeModeBanner';
import { isSafeMode } from './safeMode';
import { useT } from '../i18n';
import type { MessageKey } from '../i18n';

const NAV: { to: string; label: MessageKey; end?: boolean }[] = [
  { to: '/', label: 'nav.dashboard', end: true },
  { to: '/entidades', label: 'nav.entities' },
  { to: '/livros', label: 'nav.books' },
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
            <CurrentUserPicker />
          </div>
        </nav>

        {/* The single inner scroll container — the window itself never scrolls. */}
        <div className="app-scroll">
          <div className="app">
            <PageErrorBoundary key={pathname}>
              <main className="route-transition">
                <Outlet />
              </main>
            </PageErrorBoundary>

            <footer className="footer">{t('common.footer')}</footer>
          </div>
        </div>
      </AuthGate>
    </ShellErrorBoundary>
  );
}
