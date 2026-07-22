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
import { useEffect, useRef, type ReactNode } from 'react';
import { NavLink, Outlet, useLocation, useMatches } from 'react-router-dom';
import { Icon, Tooltip } from '../ui';
import { pageKey } from './navPath';
import { LeatherBackground } from '../theme/LeatherBackground';
import { AppearanceEffects } from '../theme/AppearanceEffects';
import { TitleBar } from '../desktop/TitleBar';
import { NotificationBell } from '../features/notifications/NotificationBell';
import { CurrentUserPicker } from '../features/session/CurrentUserPicker';
import { AuthGate } from '../features/session/AuthGate';
import { PageErrorBoundary, ShellErrorBoundary } from './ErrorBoundary';
import { UnsavedChangesGuard } from './UnsavedChangesGuard';
import { SafeModeBanner } from './SafeModeBanner';
import { DegradedBanner } from './DegradedBanner';
import { isSafeMode } from './safeMode';
import { useTopbarTier } from './useTopbarTier';
import { TopbarMenu, type TopbarMenuItem } from './TopbarMenu';
import { useT } from '../i18n';
import { useTopbarExtraT } from '../i18n/topbarFallback';
import type { MessageKey } from '../i18n';
import { displayVersion, UI_VERSION } from '../api/versionCheck';

const NAV: { to: string; label: MessageKey; end?: boolean }[] = [
  { to: '/', label: 'nav.dashboard', end: true },
  { to: '/entities', label: 'nav.entities' },
  { to: '/books', label: 'nav.books' },
  { to: '/templates', label: 'nav.templates' },
  { to: '/operations', label: 'nav.operations' },
];

/**
 * Arquivo, Ferramentas and Configurações, as icons at the right-hand end of the bar (t103, t31).
 *
 * They left the text tab group deliberately. The remaining text tabs are *places you work*;
 * these are the utility surfaces you reach for, which is why they read better beside the
 * alerts bell and the user picker than as the tail of a row of nouns. Arquivo joined them
 * (t31): the ledger archive is a reference surface you consult, not a workspace, so it belongs
 * with the other utility glyphs rather than in the row of nouns. Order is archive → tools → cog
 * → divider → alerts, so the navigational glyphs group together and the divider separates them
 * from the notification affordance rather than sitting between two unrelated things.
 *
 * Each is icon-only, so each carries a real `aria-label` **as well as** a `Tooltip`. A tooltip
 * is not an accessible name — it is a hover/focus affordance — and a screen-reader user given
 * only a glyph gets nothing. Both come from the same `MessageKey` the text tab used, so the
 * name an assistive technology reads is the name a sighted operator sees, in every locale.
 *
 * **Responsive overflow (t42).** This array is the single source for BOTH the inline glyphs and the
 * narrow-tier "more" overflow menu (see `iconNavItems` + the `TopbarMenu` in the session cluster).
 * A task adding a control to this bar — e.g. t36's forthcoming "Administração" glyph — appends ONE
 * entry here (`{ to, label, icon }`) and it flows into the inline row on wide/medium AND into the
 * overflow menu on narrow automatically, with no change to the collapse logic, the CSS, or
 * `TopbarMenu`. (The label must be a real catalog `MessageKey`, as the others are.)
 */
const ICON_NAV: { to: string; label: MessageKey; icon: ReactNode }[] = [
  { to: '/archive', label: 'nav.archive', icon: <Icon.Archive /> },
  { to: '/tools', label: 'nav.tools', icon: <Icon.Wrench /> },
  { to: '/settings', label: 'nav.settings', icon: <Icon.Cog /> },
];

/**
 * The address of the current PAGE, with its sub-tab segments cut off (t97). Sections live in
 * the path now, so keying the routed content on the raw pathname would remount the page on
 * every sub-tab switch — discarding Configurações' unsaved working copy and re-running the
 * focus move. Each section route declares `handle.navDepth` (how many leading segments name
 * the page); routes without one key on the full pathname, exactly as before.
 */
function useRouteKey(pathname: string): string {
  const matches = useMatches();
  const handle = matches[matches.length - 1]?.handle as { navDepth?: number } | undefined;
  return pageKey(pathname, handle?.navDepth);
}

export function Layout() {
  // The route key (the pathname minus any sub-tab segments) keys the routed content so it
  // remounts and replays the enter animation on every navigation. It ALSO keys the page error
  // boundary, so navigating away from a crashed page remounts a fresh boundary.
  const t = useT();
  const tt = useTopbarExtraT();
  const { pathname } = useLocation();
  const routeKey = useRouteKey(pathname);
  const safe = isSafeMode();

  // Which reflow tier the header is in. `wide` lays every control out inline; `medium` folds the
  // primary tabs into a burger; `narrow` also folds the utility glyphs into a "more" menu and drops
  // the brand. A single representation is rendered per tier, so no hidden duplicate of a control
  // sits in the DOM (which would double every tab in the accessibility tree and the tests). See
  // useTopbarTier — it fails open to `wide` where `matchMedia` is absent (jsdom/tests).
  const tier = useTopbarTier();
  const tabsCollapsed = tier !== 'wide';
  const utilitiesCollapsed = tier === 'narrow';
  const showBrand = tier !== 'narrow';

  // Active is decided against the ROUTE key (the pathname minus sub-tab segments) rather than left
  // to `NavLink`'s own match: the dashboard's non-default panels live at `/dashboard/:tab`, which an
  // `end`-matched `/` link would never mark active; the route key collapses both to `/`. One helper
  // feeds the inline links AND the collapsed menus, so a tab reads identically wherever it renders.
  const isActive = (to: string, end?: boolean): boolean =>
    end === true ? routeKey === to : routeKey === to || routeKey.startsWith(`${to}/`);

  const navItems: TopbarMenuItem[] = NAV.map((item) => ({
    to: item.to,
    label: t(item.label),
    end: item.end,
    active: isActive(item.to, item.end),
  }));
  const iconNavItems: TopbarMenuItem[] = ICON_NAV.map((item) => ({
    to: item.to,
    label: t(item.label),
    icon: item.icon,
    active: isActive(item.to),
  }));
  const anyNavActive = navItems.some((item) => item.active);
  const anyIconActive = iconNavItems.some((item) => item.active);

  // On navigation, move keyboard focus to the routed <main id="main-content"> (it already
  // remounts keyed on pathname) so screen-reader/keyboard users land on the new page
  // content instead of being stranded at the top of the tab bar. Guarded against the very
  // first mount so it doesn't steal focus from the boot/autofocus flow; the `tabIndex={-1}`
  // main is focusable without a visible outline (via `:focus:not(:focus-visible)`). Keyed on
  // the ROUTE key, not the pathname: a sub-tab switch inside a page is not a navigation to a
  // new page and must not yank focus out of the tab strip the operator is arrowing through.
  const mainRef = useRef<HTMLElement>(null);
  const firstRender = useRef(true);
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    mainRef.current?.focus();
  }, [routeKey]);

  return (
    <ShellErrorBoundary>
      {/* Safe mode bypasses the appearance layers so a crashing settings/appearance
          configuration cannot take the shell down; the banner explains it and offers exit. */}
      {safe ? <SafeModeBanner /> : <AppearanceEffects />}
      {safe ? null : <LeatherBackground />}
      <TitleBar />

      {/* Warn before typed work is lost — on tab close, in-app navigation, and the
          desktop window close. Mounted above the auth gate (and so above every routed
          surface) but INSIDE the router, which `useBlocker` requires. It renders nothing
          until a registered surface is actually dirty. */}
      <UnsavedChangesGuard />

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
        <nav className="topbar" data-topbar-tier={tier} aria-label={t('nav.aria')}>
          {/* Left track: the burger (once the tabs have collapsed) then the brand (dropped only at
              the narrowest tier). The burger holds the SAME NAV items the inline strip does. */}
          <div className="topbar__lead">
            {tabsCollapsed ? (
              <TopbarMenu
                label={tt('topbar.nav.menu')}
                icon={<Icon.Menu />}
                items={navItems}
                align="start"
                active={anyNavActive}
                testId="topbar-tabs-menu"
              />
            ) : null}
            {showBrand ? <span className="topbar__brand">{t('common.brand')}</span> : null}
          </div>

          {/* Centre track: the inline tab strip, only while it fits (wide tier). Below 960px it is
              not rendered — the burger above is the single representation. */}
          {tabsCollapsed ? null : (
            <div className="topbar__nav" data-testid="tab-bar">
              {navItems.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  aria-current={item.active ? 'page' : undefined}
                  className={item.active ? 'nav__link is-active' : 'nav__link'}
                >
                  {item.label}
                </NavLink>
              ))}
            </div>
          )}

          {/* Right track. The utility glyphs (Arquivo/Ferramentas/Configurações — and any icon a
              later task appends to ICON_NAV) render inline while they fit; at the narrowest tier they
              fold into the "more" overflow menu, which is fed by the SAME iconNavItems array, so an
              added glyph needs no change here. The alerts bell and the user picker are the
              always-visible essentials and never collapse. */}
          <div className="topbar__session">
            {utilitiesCollapsed ? (
              <TopbarMenu
                label={tt('topbar.utility.menu')}
                icon={<Icon.MoreHorizontal />}
                items={iconNavItems}
                align="end"
                active={anyIconActive}
                testId="topbar-utility-menu"
              />
            ) : (
              ICON_NAV.map((item) => {
                const active = isActive(item.to);
                const label = t(item.label);
                return (
                  <Tooltip key={item.to} label={label} placement="bottom">
                    <NavLink
                      to={item.to}
                      aria-current={active ? 'page' : undefined}
                      aria-label={label}
                      className={`topbar__icon btn btn--ghost btn--icon btn--iconOnly${
                        active ? ' is-active' : ''
                      }`}
                    >
                      <span className="btn__icon" aria-hidden="true">
                        {item.icon}
                      </span>
                    </NavLink>
                  </Tooltip>
                );
              })
            )}
            {/* Purely visual. `aria-hidden` + no text content, so it separates the utility
                glyphs from the alerts bell for the eye without being announced as anything. */}
            <span className="topbar__divider" aria-hidden="true" />
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
            {/* Keyed on the route key so the routed content remounts and replays the
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
              key={routeKey}
              data-route-key={routeKey}
            >
              <PageErrorBoundary key={routeKey}>
                <Outlet />
              </PageErrorBoundary>
            </main>

            <footer className="footer">
              {t('common.footer', { version: displayVersion(UI_VERSION) })}
            </footer>
          </div>
        </div>
      </AuthGate>
    </ShellErrorBoundary>
  );
}
