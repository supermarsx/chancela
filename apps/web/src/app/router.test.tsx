import { Suspense, lazy } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { RouterProvider, createMemoryRouter } from 'react-router-dom';
import { RouteCrash } from './router';

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
