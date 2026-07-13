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

/**
 * React Router `errorElement` for the top-level routes. In a v6 DATA router, an error
 * thrown while rendering a route element — including a `React.lazy` chunk-load rejection —
 * is caught by React Router's OWN error boundary via `errorElement`, NOT by a React error
 * boundary wrapped around `<RouterProvider>`. Without this, RR shows its built-in default
 * error page (or, for the routes OUTSIDE `Layout`, an unguarded blank screen).
 *
 * Reuses the editorial {@link CrashScreen} (read-only). It renders without an initialised
 * i18n store: `i18nStore.message()` falls back to the statically-imported pt-PT catalog,
 * so the fallback is safe even when a crash happens before anything else is ready.
 */
export function RouteCrash() {
  const error = useRouteError();
  return (
    <CrashScreen
      error={error instanceof Error ? error : new Error(String(error))}
      componentStack={null}
    />
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

const usersSettingsPath = (user?: string, hash = '') => {
  const query = user ? `?sec=utilizadores&user=${encodeURIComponent(user)}` : '?sec=utilizadores';
  return `/configuracoes${query}${hash}`;
};

export function LegacyUserRedirect() {
  const { id } = useParams();
  const { hash } = useLocation();
  return <Navigate to={usersSettingsPath(id ?? undefined, hash)} replace />;
}

export function LegacyUsersRedirect() {
  const { hash } = useLocation();
  return <Navigate to={usersSettingsPath(undefined, hash)} replace />;
}

export function LegacyNewUserRedirect() {
  const { hash } = useLocation();
  return <Navigate to={usersSettingsPath('novo', hash)} replace />;
}

export const router = createBrowserRouter([
  // Full-screen first-run wizard — a SIBLING of the app shell, deliberately OUTSIDE the
  // `Layout` chrome (no tab bar / picker). The AuthGate inside Layout redirects a fresh
  // install here; the wizard redirects back once a user exists (plan t44 §3.2).
  {
    path: '/bem-vindo',
    element: lazyRoute(() => import('../features/onboarding/OnboardingWizard'), 'OnboardingWizard'),
    errorElement: <RouteCrash />,
  },
  // Token-authenticated external invite landing page. It stays outside Layout because token holders
  // may be signed out; the page removes the token from the URL after first read.
  {
    path: '/assinatura-externa',
    element: lazyRoute(
      () => import('../features/signing/ExternalSignerInvitePage'),
      'ExternalSignerInvitePage',
    ),
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
        element: lazyRoute(() => import('../features/dashboard/DashboardPage'), 'DashboardPage'),
      },
      {
        path: 'entidades',
        element: lazyRoute(() => import('../features/entities/EntitiesPage'), 'EntitiesPage'),
      },
      // Static create/import segments are declared before `:id`; React Router ranks
      // static routes above dynamic ones regardless, so `/entidades/nova` never resolves
      // to the detail page.
      {
        path: 'entidades/nova',
        element: lazyRoute(() => import('../features/entities/NewEntityPage'), 'NewEntityPage'),
      },
      {
        path: 'entidades/importar',
        element: lazyRoute(
          () => import('../features/entities/ImportEntityPage'),
          'ImportEntityPage',
        ),
      },
      {
        path: 'entidades/:id',
        element: lazyRoute(
          () => import('../features/entities/EntityDetailPage'),
          'EntityDetailPage',
        ),
      },
      {
        path: 'entidades/:id/importar',
        element: lazyRoute(
          () => import('../features/entities/EntityRegistryImportPage'),
          'EntityRegistryImportPage',
        ),
      },
      {
        path: 'livros',
        element: lazyRoute(() => import('../features/books/BooksPage'), 'BooksPage'),
      },
      {
        path: 'livros/novo',
        element: lazyRoute(() => import('../features/books/NewBookPage'), 'NewBookPage'),
      },
      {
        path: 'livros/:id',
        element: lazyRoute(() => import('../features/books/BookDetailPage'), 'BookDetailPage'),
      },
      {
        path: 'livros/:id/nova-ata',
        element: lazyRoute(() => import('../features/books/NewAtaPage'), 'NewAtaPage'),
      },
      {
        path: 'livros/:id/encerrar',
        element: lazyRoute(() => import('../features/books/CloseBookPage'), 'CloseBookPage'),
      },
      {
        path: 'atas/:id',
        element: lazyRoute(() => import('../features/acts/AtaEditorPage'), 'AtaEditorPage'),
      },
      {
        path: 'minutas',
        element: lazyRoute(
          () => import('../features/templates/TemplatesCatalogPage'),
          'TemplatesCatalogPage',
        ),
      },
      { path: 'templates', element: <Navigate to="/minutas" replace /> },
      {
        path: 'arquivo',
        element: lazyRoute(() => import('../features/ledger/LedgerPage'), 'LedgerPage'),
      },
      {
        path: 'notificacoes',
        element: lazyRoute(
          () => import('../features/notifications/NotificationsPage'),
          'NotificationsPage',
        ),
      },
      {
        path: 'ferramentas',
        element: lazyRoute(
          () => import('../features/ferramentas/FerramentasPage'),
          'FerramentasPage',
        ),
      },
      {
        path: 'configuracoes',
        element: lazyRoute(() => import('../features/settings/SettingsPage'), 'SettingsPage'),
      },
      // `/cae` now redirects into Ferramentas (deep links preserved).
      { path: 'cae', element: lazyRoute(() => import('../features/cae/CaePage'), 'CaePage') },
      {
        path: 'utilizadores',
        element: <LegacyUsersRedirect />,
      },
      // Static `/novo` before `:id` (React Router ranks static above dynamic anyway —
      // mirrors the `entidades/nova` note above).
      { path: 'utilizadores/novo', element: <LegacyNewUserRedirect /> },
      { path: 'utilizadores/:id/editar', element: <LegacyUserRedirect /> },
      { path: 'utilizadores/:id', element: <LegacyUserRedirect /> },
      {
        path: '*',
        element: lazyRoute(() => import('../features/NotFoundPage'), 'NotFoundPage'),
      },
    ],
  },
]);
