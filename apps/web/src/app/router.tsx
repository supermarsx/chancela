/**
 * Route table (plan t5 §Routes). The server SPA-falls-back every unknown path to
 * `index.html`, so `createBrowserRouter` with clean URLs works in production and in
 * the Tauri WebView alike. Deep-linkable book/ata URLs are the point — a sealed
 * ata's `/atas/:id` is a stable reference.
 */
import { createBrowserRouter } from 'react-router-dom';
import { Layout } from './layout';
import { DashboardPage } from '../features/dashboard/DashboardPage';
import { EntitiesPage } from '../features/entities/EntitiesPage';
import { NewEntityPage } from '../features/entities/NewEntityPage';
import { ImportEntityPage } from '../features/entities/ImportEntityPage';
import { EntityDetailPage } from '../features/entities/EntityDetailPage';
import { EntityRegistryImportPage } from '../features/entities/EntityRegistryImportPage';
import { BooksPage } from '../features/books/BooksPage';
import { NewBookPage } from '../features/books/NewBookPage';
import { BookDetailPage } from '../features/books/BookDetailPage';
import { NewAtaPage } from '../features/books/NewAtaPage';
import { CloseBookPage } from '../features/books/CloseBookPage';
import { AtaEditorPage } from '../features/acts/AtaEditorPage';
import { LedgerPage } from '../features/ledger/LedgerPage';
import { SettingsPage } from '../features/settings/SettingsPage';
import { FerramentasPage } from '../features/ferramentas/FerramentasPage';
import { CaePage } from '../features/cae/CaePage';
import { UserListPage } from '../features/users/UserListPage';
import { NewUserPage } from '../features/users/NewUserPage';
import { EditUserPage } from '../features/users/EditUserPage';
import { OnboardingWizard } from '../features/onboarding/OnboardingWizard';
import { NotFoundPage } from '../features/NotFoundPage';

export const router = createBrowserRouter([
  // Full-screen first-run wizard — a SIBLING of the app shell, deliberately OUTSIDE the
  // `Layout` chrome (no tab bar / picker). The AuthGate inside Layout redirects a fresh
  // install here; the wizard redirects back once a user exists (plan t44 §3.2).
  { path: '/bem-vindo', element: <OnboardingWizard /> },
  {
    path: '/',
    element: <Layout />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: 'entidades', element: <EntitiesPage /> },
      // Static create/import segments are declared before `:id`; React Router ranks
      // static routes above dynamic ones regardless, so `/entidades/nova` never resolves
      // to the detail page.
      { path: 'entidades/nova', element: <NewEntityPage /> },
      { path: 'entidades/importar', element: <ImportEntityPage /> },
      { path: 'entidades/:id', element: <EntityDetailPage /> },
      { path: 'entidades/:id/importar', element: <EntityRegistryImportPage /> },
      { path: 'livros', element: <BooksPage /> },
      { path: 'livros/novo', element: <NewBookPage /> },
      { path: 'livros/:id', element: <BookDetailPage /> },
      { path: 'livros/:id/nova-ata', element: <NewAtaPage /> },
      { path: 'livros/:id/encerrar', element: <CloseBookPage /> },
      { path: 'atas/:id', element: <AtaEditorPage /> },
      { path: 'arquivo', element: <LedgerPage /> },
      { path: 'ferramentas', element: <FerramentasPage /> },
      { path: 'configuracoes', element: <SettingsPage /> },
      // `/cae` now redirects into Ferramentas (deep links preserved).
      { path: 'cae', element: <CaePage /> },
      { path: 'utilizadores', element: <UserListPage /> },
      // Static `/novo` before `:id` (React Router ranks static above dynamic anyway —
      // mirrors the `entidades/nova` note above).
      { path: 'utilizadores/novo', element: <NewUserPage /> },
      { path: 'utilizadores/:id', element: <EditUserPage /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
]);
