import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { PageHeader } from './PageHeader';

afterEach(cleanup);

describe('PageHeader', () => {
  it('renders the title as a level-2 heading', () => {
    render(<PageHeader title="Entidades" />);
    const heading = screen.getByRole('heading', { level: 2, name: 'Entidades' });
    expect(heading).toBeTruthy();
    expect(heading.className).toContain('page-header__title');
  });

  it('renders crumbs, a lede and actions when provided', () => {
    render(
      <PageHeader
        crumbs="Configuração"
        title="Configurações"
        lede="Todo o Chancela é configurável."
        actions={<button type="button">Guardar</button>}
      />,
    );
    expect(screen.getByText('Configuração')).toBeTruthy();
    expect(screen.getByText('Todo o Chancela é configurável.')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Guardar' })).toBeTruthy();
  });

  it('omits the crumbs, lede and actions slots when absent', () => {
    const { container } = render(<PageHeader title="Livros" />);
    expect(container.querySelector('.page-header__crumbs')).toBeNull();
    expect(container.querySelector('.page-header__lede')).toBeNull();
    expect(container.querySelector('.page-header__actions')).toBeNull();
  });
});
