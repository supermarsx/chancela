import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

// A plain left-click on an external link routes through openExternal (which opens the
// OS browser under the desktop shell); stub it so we can assert the interception.
const openExternal = vi.fn();
vi.mock('../desktop/openExternal', () => ({ openExternal: (url: string) => openExternal(url) }));

import { Truncate } from './Truncate';

afterEach(() => {
  cleanup();
  openExternal.mockClear();
});

const LONG = 'https://registo.example.pt/consulta/certidao/permanente/12045-20200115?token=abcdef';

describe('Truncate', () => {
  it('renders a span carrying the full value on its title and the truncate class', () => {
    render(<Truncate text={LONG} />);
    const el = screen.getByTitle(LONG);
    expect(el.tagName).toBe('SPAN');
    expect(el.className).toContain('truncate');
  });

  it('renders a clickable external link that opens in a new tab', () => {
    render(<Truncate text={LONG} href={LONG} mono />);
    const link = screen.getByRole('link');
    expect(link.getAttribute('href')).toBe(LONG);
    expect(link.getAttribute('title')).toBe(LONG);
    expect(link.getAttribute('target')).toBe('_blank');
    expect(link.getAttribute('rel')).toContain('noopener');
    expect(link.className).toContain('truncate');
    expect(link.className).toContain('mono');
  });

  it('does not add target/rel for a relative href', () => {
    render(<Truncate text="/entidades/ent-1" href="/entidades/ent-1" />);
    const link = screen.getByRole('link');
    expect(link.getAttribute('target')).toBeNull();
  });

  it('routes a plain external click through openExternal (opens outside the app)', () => {
    render(<Truncate text={LONG} href={LONG} />);
    const link = screen.getByRole('link');
    // A plain left-click is intercepted and handed to openExternal.
    fireEvent.click(link);
    expect(openExternal).toHaveBeenCalledWith(LONG);
  });

  it('leaves modified clicks (ctrl/⌘) to native behaviour', () => {
    render(<Truncate text={LONG} href={LONG} />);
    const link = screen.getByRole('link');
    fireEvent.click(link, { ctrlKey: true });
    expect(openExternal).not.toHaveBeenCalled();
  });

  it('does not intercept a relative (in-app) href', () => {
    render(<Truncate text="/entidades/ent-1" href="/entidades/ent-1" />);
    fireEvent.click(screen.getByRole('link'));
    expect(openExternal).not.toHaveBeenCalled();
  });
});
