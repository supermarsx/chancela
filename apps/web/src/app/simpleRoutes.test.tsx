import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { RouteLoading } from './RouteLoading';
import { NotFoundPage } from '../features/NotFoundPage';

afterEach(cleanup);

describe('simple route states', () => {
  it('renders an accessible loading status', () => {
    render(<RouteLoading />);
    const status = screen.getByRole('status');
    expect(status.getAttribute('aria-busy')).toBe('true');
  });

  it('renders a translated not-found recovery link', () => {
    render(
      <MemoryRouter>
        <NotFoundPage />
      </MemoryRouter>,
    );
    expect(screen.getByRole('link').getAttribute('href')).toBe('/');
    expect(screen.getByText('Página não encontrada')).toBeTruthy();
  });
});
