/**
 * Route table (plan t5 §Routes). The server SPA-falls-back every unknown path to
 * `index.html`, so `createBrowserRouter` with clean URLs works in production and in
 * the Tauri WebView alike. Deep-linkable book/ata URLs are the point — a sealed
 * ata's `/atas/:id` is a stable reference.
 *
 * Sections and sub-tabs are PATH segments (t97): `/settings/operations/email`, not
 * `/configuracoes?sec=operacoes&sub=email`. Every optional trailing `:sec?`/`:sub?` here is
 * one surface's sub-navigation. Static siblings (`entities/:id/import`, `books/:id/new-act`) are
 * ranked above the dynamic section segment by React Router, so they never collide.
 *
 * Slugs are ENGLISH (t97b) — the programming base is English and pt-PT is the user-facing
 * language, and an address is an identifier rather than copy. Every Portuguese address still
 * resolves, permanently: {@link LegacySlugRedirect} on the catch-all translates both the slugs
 * and the pre-t97 query params in a single `replace`. See {@link ./legacySlugs}.
 *
 * `handle.navDepth` is how many leading segments identify the PAGE. The shell keys the routed
 * content on that prefix, so a sub-tab switch no longer looks like a route change and does not
 * remount the page (which would throw away Configurações' unsaved working copy).
 */
import { Suspense, lazy, type ComponentType, type ReactNode } from 'react';
import {
  Navigate,
  createBrowserRouter,
  useLocation,
  useParams,
  useRouteError,
} from 'react-router-dom';
import { Layout } from './layout';
import { LegacyNavRedirect } from './LegacyNavRedirect';
import { LegacySlugRedirect } from './LegacySlugRedirect';
import { RouteLoading } from './RouteLoading';
import { CrashScreen } from './CrashScreen';
import { useT } from '../i18n';

/**
 * React Router `errorElement` for the top-level routes. In a v6 DATA router, an error
 * thrown while rendering a route element — including a `React.lazy` chunk-load rejection —
 * is caught by React Router's OWN error boundary via `errorElement`, NOT by a React error
 * boundary wrapped around `<RouterProvider>`. Without this, RR shows its built-in default
 * error page (or, for the routes OUTSIDE `Layout`, an unguarded blank screen).
 *
 * Reuses the editorial {@link CrashScreen} (read-only). React Router renders this INSTEAD
 * OF the route element, so the normal {@link Layout} landmark may not exist; provide the
 * same `main#main-content` skip-link target here for data-router failures.
 */
export function RouteCrash() {
  const t = useT();
  const error = useRouteError();
  return (
    <>
      <a className="skip-link" href="#main-content">
        {t('nav.skipToContent')}
      </a>
      <main id="main-content" tabIndex={-1} className="route-transition">
        <CrashScreen
          error={error instanceof Error ? error : new Error(String(error))}
          componentStack={null}
        />
      </main>
    </>
  );
}

function lazyRoute<TModule, TName extends keyof TModule & string>(
  load: () => Promise<TModule>,
  exportName: TName,
) {
  const Component = lazy(async () => {
    const module = await load();
    return { default: module[exportName] as ComponentType };
  });
  return (
    <Suspense fallback={<RouteLoading />}>
      <Component />
    </Suspense>
  );
}

const usersSettingsPath = (hash = '') => `/settings/users${hash}`;

/** The section levels each surface used to address through the query string, per route. */
const legacy = (levels: string[][], depth: number, element: ReactNode, base?: string) => (
  <LegacyNavRedirect levels={levels} depth={depth} base={base}>
    {element}
  </LegacyNavRedirect>
);

/**
 * `/users/:id/edit` → `/users/:id` (t89). The edit screen IS the route now, so this only
 * normalises the older `/edit` spelling; the fragment is carried so a bookmarked `#acesso` still
 * lands on the access section.
 */
export function LegacyUserEditRedirect() {
  const { id } = useParams();
  const { hash } = useLocation();
  return (
    <Navigate
      to={id ? `/users/${encodeURIComponent(id)}${hash}` : usersSettingsPath(hash)}
      replace
    />
  );
}

export function LegacyUsersRedirect() {
  const { hash } = useLocation();
  return <Navigate to={usersSettingsPath(hash)} replace />;
}

/**
 * `/operations/:view?` → `/admin/:view` (t36). The standalone Operações integrations surface folded
 * into Administração; its three areas keep their slugs (groups/connectors/repositories), and the
 * bare address that showed Grupos lands on `/admin/groups`. The tenant picker and every per-panel
 * selection travel as query params, so `?tenant=…` and the rest are preserved verbatim, and the
 * old address is `replace`d so it never becomes a Back-button stop. pt-PT `/operacoes/*` reaches
 * here first through `legacySlugs` (`operacoes → operations`), so no slug-table change is needed.
 */
export function LegacyOperationsRedirect() {
  const { view } = useParams();
  const { search, hash } = useLocation();
  const sub = view ?? 'groups';
  return <Navigate to={`/admin/${encodeURIComponent(sub)}${search}${hash}`} replace />;
}

/**
 * `/settings/operations/:sub?` → `/admin/:sub` (t36). Operações left Configurações for the new
 * Administração surface, so the literal address is forwarded at the router level — a static
 * `settings/operations` outranks the generic `settings/:sec?/:sub?`, so SettingsPage never renders
 * for it. The RETIRED settings aliases that resolved INTO operations (`/settings/email`,
 * `/settings/mcp`, `/settings/api`, `/settings/api-keys`, `/settings/data`) are forwarded by
 * SettingsPage itself (t36-e2), which owns their table. Query + fragment are preserved; bare
 * `/settings/operations` lands on `/admin` (its Serviços default).
 */
export function LegacySettingsOperationsRedirect() {
  const { sub } = useParams();
  const { search, hash } = useLocation();
  const target = sub ? `/admin/${encodeURIComponent(sub)}` : '/admin';
  return <Navigate to={`${target}${search}${hash}`} replace />;
}

export const routeModuleLoaders = {
  onboarding: () => import('../features/onboarding/OnboardingWizard'),
  externalSigner: () => import('../features/signing/ExternalSignerInvitePage'),
  dashboard: () => import('../features/dashboard/DashboardPage'),
  entities: () => import('../features/entities/EntitiesPage'),
  newEntity: () => import('../features/entities/NewEntityPage'),
  newUser: () => import('../features/users/NewUserPage'),
  editUser: () => import('../features/users/EditUserPage'),
  importEntity: () => import('../features/entities/ImportEntityPage'),
  entityDetail: () => import('../features/entities/EntityDetailPage'),
  entityRegistryImport: () => import('../features/entities/EntityRegistryImportPage'),
  books: () => import('../features/books/BooksPage'),
  newBook: () => import('../features/books/NewBookPage'),
  bookDetail: () => import('../features/books/BookDetailPage'),
  newAta: () => import('../features/books/NewAtaPage'),
  closeBook: () => import('../features/books/CloseBookPage'),
  ataEditor: () => import('../features/acts/AtaEditorPage'),
  templates: () => import('../features/templates/TemplatesCatalogPage'),
  templateDetail: () => import('../features/templates/TemplateDetailPage'),
  ledger: () => import('../features/ledger/LedgerPage'),
  notifications: () => import('../features/notifications/NotificationsPage'),
  admin: () => import('../features/admin/AdminPage'),
  tools: () => import('../features/tools/ToolsPage'),
  settings: () => import('../features/settings/SettingsPage'),
  cae: () => import('../features/cae/CaePage'),
  notFound: () => import('../features/NotFoundPage'),
} as const;

export const router = createBrowserRouter([
  // Full-screen first-run wizard — a SIBLING of the app shell, deliberately OUTSIDE the
  // `Layout` chrome (no tab bar / picker). The AuthGate inside Layout redirects a fresh
  // install here; the wizard redirects back once a user exists (plan t44 §3.2).
  {
    path: '/welcome',
    element: lazyRoute(routeModuleLoaders.onboarding, 'OnboardingWizard'),
    errorElement: <RouteCrash />,
  },
  // The two out-of-shell addresses get EXPLICIT legacy entries rather than falling through to
  // the catch-all: both are reachable while signed out, and the catch-all sits inside the shell
  // behind the auth gate, which would swallow the redirect for exactly those visitors.
  { path: '/bem-vindo', element: <LegacySlugRedirect />, errorElement: <RouteCrash /> },
  { path: '/assinatura-externa', element: <LegacySlugRedirect />, errorElement: <RouteCrash /> },
  // Token-authenticated external invite landing page. It stays outside Layout because token holders
  // may be signed out; the page removes the token from the URL after first read.
  {
    path: '/external-signature',
    element: lazyRoute(routeModuleLoaders.externalSigner, 'ExternalSignerInvitePage'),
    errorElement: <RouteCrash />,
  },
  {
    path: '/',
    element: <Layout />,
    // Root-level `errorElement` covers all children too, so any route render or lazy
    // chunk-load failure inside the shell shows a recoverable fallback, not a blank page.
    errorElement: <RouteCrash />,
    children: [
      // The dashboard's default panel keeps the bare `/` address; the other five are
      // `/dashboard/:tab`. Both share a `navDepth` of 0, so switching panel is not a page change.
      // `?painel=` is promoted here rather than on the catch-all, because `/` DOES match a route
      // and so never falls through to it.
      {
        index: true,
        handle: { navDepth: 0 },
        element: legacy(
          [['painel']],
          0,
          lazyRoute(routeModuleLoaders.dashboard, 'DashboardPage'),
          '/dashboard',
        ),
      },
      {
        path: 'dashboard/:tab?',
        handle: { navDepth: 0 },
        element: lazyRoute(routeModuleLoaders.dashboard, 'DashboardPage'),
      },
      {
        path: 'entities',
        element: lazyRoute(routeModuleLoaders.entities, 'EntitiesPage'),
      },
      // Static create/import segments are declared before `:id`; React Router ranks
      // static routes above dynamic ones regardless, so `/entities/new` never resolves
      // to the detail page.
      {
        path: 'entities/new',
        element: lazyRoute(routeModuleLoaders.newEntity, 'NewEntityPage'),
      },
      {
        path: 'entities/import',
        element: lazyRoute(routeModuleLoaders.importEntity, 'ImportEntityPage'),
      },
      {
        path: 'entities/:id/:sec?',
        handle: { navDepth: 2 },
        element: lazyRoute(routeModuleLoaders.entityDetail, 'EntityDetailPage'),
      },
      {
        path: 'entities/:id/import',
        element: lazyRoute(routeModuleLoaders.entityRegistryImport, 'EntityRegistryImportPage'),
      },
      {
        path: 'books',
        element: lazyRoute(routeModuleLoaders.books, 'BooksPage'),
      },
      {
        path: 'books/new',
        element: lazyRoute(routeModuleLoaders.newBook, 'NewBookPage'),
      },
      {
        path: 'books/:id/:sec?',
        handle: { navDepth: 2 },
        element: lazyRoute(routeModuleLoaders.bookDetail, 'BookDetailPage'),
      },
      {
        path: 'books/:id/new-act',
        element: lazyRoute(routeModuleLoaders.newAta, 'NewAtaPage'),
      },
      {
        path: 'books/:id/close',
        element: lazyRoute(routeModuleLoaders.closeBook, 'CloseBookPage'),
      },
      {
        path: 'acts/:id',
        element: lazyRoute(routeModuleLoaders.ataEditor, 'AtaEditorPage'),
      },
      {
        path: 'templates',
        element: lazyRoute(routeModuleLoaders.templates, 'TemplatesCatalogPage'),
      },
      // The id carries a slash (`csc-ata-ag/v1`) and is therefore URL-encoded by the links
      // that lead here; React Router decodes the param back for `useParams`. The trailing
      // section segment is safe alongside it: `%2F` is not a segment boundary, so the encoded
      // id stays one segment and `/templates/csc-ata-ag%2Fv1/source` splits where it should.
      // `edit` is a SECTION of this route, not a sibling of it — `TemplateDetailPage` hands the
      // `edit` section to its own full-width component. A static `templates/:id/edit` beside
      // `:sec?` would shadow any future section spelled the same way; a closed set cannot.
      {
        path: 'templates/:id/:sec?',
        handle: { navDepth: 2 },
        element: lazyRoute(routeModuleLoaders.templateDetail, 'TemplateDetailPage'),
      },
      {
        path: 'archive/:sec?',
        handle: { navDepth: 1 },
        element: lazyRoute(routeModuleLoaders.ledger, 'LedgerPage'),
      },
      {
        path: 'notifications',
        element: lazyRoute(routeModuleLoaders.notifications, 'NotificationsPage'),
      },
      // Administração (t36): the operations panes + the folded-in integrations subtabs, at their
      // own top-level address. A thin `AdminPage` renders SettingsPage in admin-surface mode.
      {
        path: 'admin/:sub?',
        handle: { navDepth: 1 },
        element: lazyRoute(routeModuleLoaders.admin, 'AdminPage'),
      },
      // The retired standalone Operações surface. Both its own address and the settings-hosted one
      // forward into `/admin/*`, preserving `?tenant=` and every per-panel selection (no-404
      // invariant). The static `settings/operations` is ranked above `settings/:sec?/:sub?` by
      // React Router, so it intercepts the literal address before SettingsPage sees it.
      { path: 'operations/:view?', element: <LegacyOperationsRedirect /> },
      { path: 'settings/operations/:sub?', element: <LegacySettingsOperationsRedirect /> },
      // Two levels: the tool, then that tool's own sub-tab — the PDF validator spelled its
      // second level `?sec=` and Legislação spelled it `?leg=`, and both are the same
      // segment now (`/tools/pdf/asic`, `/tools/legislation/shelf`).
      {
        path: 'tools/:tool?/:sec?',
        handle: { navDepth: 1 },
        element: lazyRoute(routeModuleLoaders.tools, 'ToolsPage'),
      },
      {
        path: 'settings/:sec?/:sub?',
        handle: { navDepth: 1 },
        element: lazyRoute(routeModuleLoaders.settings, 'SettingsPage'),
      },
      // `/cae` now redirects into Ferramentas (deep links preserved).
      { path: 'cae', element: lazyRoute(routeModuleLoaders.cae, 'CaePage') },
      {
        path: 'users',
        element: <LegacyUsersRedirect />,
      },
      // Static `/novo` before `:id` (React Router ranks static above dynamic anyway —
      // mirrors the `entidades/nova` note above).
      // t71: creation is a real screen again (the roster stays in Configurações). The old
      // `?user=novo` settings state now redirects HERE — the reverse of the t50 arrangement —
      // so there is exactly one place a user is created.
      {
        path: 'users/new',
        element: lazyRoute(routeModuleLoaders.newUser, 'NewUserPage'),
      },
      // t89: editing is a real screen too, and the ONLY one — the inline panel that used to
      // render below the roster at `?sec=utilizadores&user=:id` is deleted, and that settings
      // state now redirects HERE so old bookmarks resolve instead of 404-ing.
      { path: 'users/:id/edit', element: <LegacyUserEditRedirect /> },
      // t103: the edit screen is sub-tabbed (general / dsr / roles / access), so the section
      // is a path segment exactly as it is for `entities/:id/:sec?`. `navDepth: 2` keys the
      // shell on `/users/:id`, so switching tab does not remount the screen and discard the
      // identity form's working copy. The static `users/:id/edit` sibling above is ranked
      // higher by React Router, so `edit` can never be read as a section.
      {
        path: 'users/:id/:sec?',
        handle: { navDepth: 2 },
        element: lazyRoute(routeModuleLoaders.editUser, 'EditUserPage'),
      },
      // Last resort, and the whole legacy-slug layer: a Portuguese address matches no English
      // route, arrives here, and is translated + `replace`d. Anything genuinely unknown renders
      // the real Not Found page.
      {
        path: '*',
        element: (
          <LegacySlugRedirect>
            {lazyRoute(routeModuleLoaders.notFound, 'NotFoundPage')}
          </LegacySlugRedirect>
        ),
      },
    ],
  },
]);
