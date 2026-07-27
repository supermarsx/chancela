import { Suspense, lazy } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { RouterProvider, createMemoryRouter, matchRoutes } from 'react-router-dom';
import { RouteCrash, routeModuleLoaders, router } from './router';

const BrokenLazyRoute = lazy(async () => {
  throw new Error('lazy chunk unavailable');
});

function BrokenRoute() {
  return (
    <Suspense fallback={<p>A carregar rota...</p>}>
      <BrokenLazyRoute />
    </Suspense>
  );
}

let errorSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  cleanup();
  errorSpy.mockRestore();
});

describe('route error fallback', () => {
  it('keeps every lazy route chunk importable', async () => {
    expect(routeModuleLoaders).toHaveProperty('admin');
    expect(routeModuleLoaders).toHaveProperty('providerCredential');
    expect(routeModuleLoaders).toHaveProperty('citizenCardBridge');
    const modules = await Promise.all(Object.values(routeModuleLoaders).map((load) => load()));

    expect(modules).toHaveLength(Object.keys(routeModuleLoaders).length);
    expect(modules.every((module) => Object.keys(module).length > 0)).toBe(true);
  }, 15_000);

  it('ranks dedicated provider create/edit pages ahead of the generic admin route', () => {
    const create = matchRoutes(router.routes, '/admin/signing/providers/new');
    const edit = matchRoutes(
      router.routes,
      '/admin/signing/providers/csc/encosto-qtsp/entry-a/edit',
    );

    expect(create?.at(-1)?.route.path).toBe('admin/signing/providers/new');
    expect(edit?.at(-1)?.route.path).toBe(
      'admin/signing/providers/:mode/:providerId/:entryId/edit',
    );
  });

  it('ranks the Citizen Card bridge page ahead of the generic admin route', () => {
    const matches = matchRoutes(router.routes, '/admin/signing/citizen-card');
    expect(matches?.at(-1)?.route.path).toBe('admin/signing/citizen-card');
  });

  it('ranks the five privacy register record pages ahead of the settings catch-all', () => {
    // Four segments each; `settings/:sec?/:sub?` matches at most three, so these can neither
    // shadow it nor be shadowed by it. `new` is static, so it always beats `:id`.
    const cases: [address: string, path: string][] = [
      ['/settings/privacy/processors/new', 'settings/privacy/processors/new'],
      ['/settings/privacy/processors/proc-1', 'settings/privacy/processors/:id'],
      ['/settings/privacy/dpias/new', 'settings/privacy/dpias/new'],
      ['/settings/privacy/dpias/dpia-1', 'settings/privacy/dpias/:id'],
      ['/settings/privacy/breach-playbooks/new', 'settings/privacy/breach-playbooks/new'],
      ['/settings/privacy/breach-playbooks/pb-1', 'settings/privacy/breach-playbooks/:id'],
      ['/settings/privacy/transfer-controls/new', 'settings/privacy/transfer-controls/new'],
      ['/settings/privacy/transfer-controls/tc-1', 'settings/privacy/transfer-controls/:id'],
      ['/settings/privacy/retention-policies/new', 'settings/privacy/retention-policies/new'],
      ['/settings/privacy/retention-policies/rp-1', 'settings/privacy/retention-policies/:id'],
    ];
    for (const [address, path] of cases) {
      expect(matchRoutes(router.routes, address)?.at(-1)?.route.path).toBe(path);
    }
    // The register slug and the Retenção sub-tab sit at the same position and must stay distinct:
    // three segments still reaches SettingsPage.
    expect(matchRoutes(router.routes, '/settings/privacy/retention')?.at(-1)?.route.path).toBe(
      'settings/:sec?/:sub?',
    );
  });

  it('gives the privacy record pages NO navDepth, so the unsaved-changes guard stays awake', () => {
    // 🔒 REGRESSION GUARD. `navDepth` is how many leading segments identify the PAGE; `pageKey`
    // falls back to the full pathname without it. Adding `navDepth: 1` here would make these
    // routes share `/settings`'s page key, so leaving a half-written DPIA for the list would no
    // longer look like a page change and the guard would go SILENT — losing the typed work the
    // move off the modal exists to protect.
    const addresses = [
      '/settings/privacy/processors/new',
      '/settings/privacy/processors/proc-1',
      '/settings/privacy/dpias/new',
      '/settings/privacy/dpias/dpia-1',
      '/settings/privacy/breach-playbooks/new',
      '/settings/privacy/breach-playbooks/pb-1',
      '/settings/privacy/transfer-controls/new',
      '/settings/privacy/transfer-controls/tc-1',
      '/settings/privacy/retention-policies/new',
      '/settings/privacy/retention-policies/rp-1',
    ];
    for (const address of addresses) {
      const matched = matchRoutes(router.routes, address)?.at(-1)?.route;
      expect(matched?.handle).toBeUndefined();
    }
  });

  it('renders CrashScreen for a lazy route rejection instead of React Router default UI', async () => {
    const router = createMemoryRouter(
      [
        {
          path: '/',
          element: <BrokenRoute />,
          errorElement: <RouteCrash />,
        },
      ],
      { initialEntries: ['/'] },
    );

    render(<RouterProvider router={router} />);

    const crashHeading = await screen.findByRole('heading', { name: 'Ocorreu um erro' });
    const main = screen.getByRole('main');

    expect(main.id).toBe('main-content');
    expect(document.getElementById('main-content')).toBe(main);
    expect(main.contains(crashHeading)).toBe(true);
    expect(screen.getByText('lazy chunk unavailable')).toBeTruthy();
    expect(screen.queryByText(/Unexpected Application Error/i)).toBeNull();
    expect(screen.queryByText(/Hey developer/i)).toBeNull();
  });
});
