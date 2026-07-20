import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { PrintButton } from './PrintButton';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('PrintButton', () => {
  it('renders a labelled Imprimir action', () => {
    render(<PrintButton />);
    const btn = screen.getByRole('button', { name: /imprimir/i });
    expect(btn.className).toContain('btn--print');
    // Carries the inline printer glyph.
    expect(btn.querySelector('svg')).toBeTruthy();
  });

  it('opens the print dialog via window.print on click', () => {
    const print = vi.fn();
    vi.stubGlobal('print', print);

    render(<PrintButton />);
    fireEvent.click(screen.getByRole('button', { name: /imprimir/i }));

    expect(print).toHaveBeenCalledTimes(1);
  });
});
