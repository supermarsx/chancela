/**
 * Route table (plan t5 §Routes). The server SPA-falls-back every unknown path to
 * `index.html`, so `createBrowserRouter` with clean URLs works in production and in
 * the Tauri WebView alike. Deep-linkable book/ata URLs are the point — a sealed
 * ata's `/atas/:id` is a stable reference.
 */
import { Suspense, lazy, type ComponentType } from 'react';
import {
  Navigate,
  createBrowserRouter,
  useLocation,
  useParams,
  useRouteError,
} from 'react-router-dom';
import { Layout } from './layout';
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

const usersSettingsPath = (hash = '') => `/configuracoes?sec=utilizadores${hash}`;

/**
 * `/utilizadores/:id/editar` → `/utilizadores/:id` (t89). The edit screen IS the route now, so
 * this only normalises the older `/editar` spelling; the fragment is carried so a bookmarked
 * `#acesso` still lands on the access section.
 */
export function LegacyUserEditRedirect() {
  const { id } = useParams();
  const { hash } = useLocation();
  return (
    <Navigate
      to={id ? `/utilizadores/${encodeURIComponent(id)}${hash}` : usersSettingsPath(hash)}
      replace
    />
  );
}

export function LegacyUsersRedirect() {
  const { hash } = useLocation();
  return <Navigate to={usersSettingsPath(hash)} replace />;
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
  operations: () => import('../features/operations/OperationsPage'),
  ferramentas: () => import('../features/ferramentas/FerramentasPage'),
  settings: () => import('../features/settings/SettingsPage'),
  cae: () => import('../features/cae/CaePage'),
  notFound: () => import('../features/NotFoundPage'),
} as const;

export const router = createBrowserRouter([
  // Full-screen first-run wizard — a SIBLING of the app shell, deliberately OUTSIDE the
  // `Layout` chrome (no tab bar / picker). The AuthGate inside Layout redirects a fresh
  // install here; the wizard redirects back once a user exists (plan t44 §3.2).
  {
    path: '/bem-vindo',
    element: lazyRoute(routeModuleLoaders.onboarding, 'OnboardingWizard'),
    errorElement: <RouteCrash />,
  },
  // Token-authenticated external invite landing page. It stays outside Layout because token holders
  // may be signed out; the page removes the token from the URL after first read.
  {
    path: '/assinatura-externa',
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
      {
        index: true,
        element: lazyRoute(routeModuleLoaders.dashboard, 'DashboardPage'),
      },
      {
        path: 'entidades',
        element: lazyRoute(routeModuleLoaders.entities, 'EntitiesPage'),
      },
      // Static create/import segments are declared before `:id`; React Router ranks
      // static routes above dynamic ones regardless, so `/entidades/nova` never resolves
      // to the detail page.
      {
        path: 'entidades/nova',
        element: lazyRoute(routeModuleLoaders.newEntity, 'NewEntityPage'),
      },
      {
        path: 'entidades/importar',
        element: lazyRoute(routeModuleLoaders.importEntity, 'ImportEntityPage'),
      },
      {
        path: 'entidades/:id',
        element: lazyRoute(routeModuleLoaders.entityDetail, 'EntityDetailPage'),
      },
      {
        path: 'entidades/:id/importar',
        element: lazyRoute(routeModuleLoaders.entityRegistryImport, 'EntityRegistryImportPage'),
      },
      {
        path: 'livros',
        element: lazyRoute(routeModuleLoaders.books, 'BooksPage'),
      },
      {
        path: 'livros/novo',
        element: lazyRoute(routeModuleLoaders.newBook, 'NewBookPage'),
      },
      {
        path: 'livros/:id',
        element: lazyRoute(routeModuleLoaders.bookDetail, 'BookDetailPage'),
      },
      {
        path: 'livros/:id/nova-ata',
        element: lazyRoute(routeModuleLoaders.newAta, 'NewAtaPage'),
      },
      {
        path: 'livros/:id/encerrar',
        element: lazyRoute(routeModuleLoaders.closeBook, 'CloseBookPage'),
      },
      {
        path: 'atas/:id',
        element: lazyRoute(routeModuleLoaders.ataEditor, 'AtaEditorPage'),
      },
      {
        path: 'minutas',
        element: lazyRoute(routeModuleLoaders.templates, 'TemplatesCatalogPage'),
      },
      // The id carries a slash (`csc-ata-ag/v1`) and is therefore URL-encoded by the links
      // that lead here; React Router decodes the param back for `useParams`.
      {
        path: 'minutas/:id',
        element: lazyRoute(routeModuleLoaders.templateDetail, 'TemplateDetailPage'),
      },
      { path: 'templates', element: <Navigate to="/minutas" replace /> },
      {
        path: 'arquivo',
        element: lazyRoute(routeModuleLoaders.ledger, 'LedgerPage'),
      },
      {
        path: 'notificacoes',
        element: lazyRoute(routeModuleLoaders.notifications, 'NotificationsPage'),
      },
      {
        path: 'operacoes',
        element: lazyRoute(routeModuleLoaders.operations, 'OperationsPage'),
      },
      {
        path: 'ferramentas',
        element: lazyRoute(routeModuleLoaders.ferramentas, 'FerramentasPage'),
      },
      {
        path: 'configuracoes',
        element: lazyRoute(routeModuleLoaders.settings, 'SettingsPage'),
      },
      // `/cae` now redirects into Ferramentas (deep links preserved).
      { path: 'cae', element: lazyRoute(routeModuleLoaders.cae, 'CaePage') },
      {
        path: 'utilizadores',
        element: <LegacyUsersRedirect />,
      },
      // Static `/novo` before `:id` (React Router ranks static above dynamic anyway —
      // mirrors the `entidades/nova` note above).
      // t71: creation is a real screen again (the roster stays in Configurações). The old
      // `?user=novo` settings state now redirects HERE — the reverse of the t50 arrangement —
      // so there is exactly one place a user is created.
      {
        path: 'utilizadores/novo',
        element: lazyRoute(routeModuleLoaders.newUser, 'NewUserPage'),
      },
      // t89: editing is a real screen too, and the ONLY one — the inline panel that used to
      // render below the roster at `?sec=utilizadores&user=:id` is deleted, and that settings
      // state now redirects HERE so old bookmarks resolve instead of 404-ing.
      { path: 'utilizadores/:id/editar', element: <LegacyUserEditRedirect /> },
      {
        path: 'utilizadores/:id',
        element: lazyRoute(routeModuleLoaders.editUser, 'EditUserPage'),
      },
      {
        path: '*',
        element: lazyRoute(routeModuleLoaders.notFound, 'NotFoundPage'),
      },
    ],
  },
]);
