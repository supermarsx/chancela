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
