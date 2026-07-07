import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { Digest, abbreviateDigest } from './Digest';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const FULL = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7081920a1b2c3d4';

describe('abbreviateDigest', () => {
  it('keeps the first and last eight hex characters around an ellipsis', () => {
    expect(abbreviateDigest(FULL)).toBe(`${FULL.slice(0, 8)}…${FULL.slice(-8)}`);
    expect(abbreviateDigest(FULL, 4)).toBe(`${FULL.slice(0, 4)}…${FULL.slice(-4)}`);
  });

  it('shows short values whole, never lengthening the input', () => {
    expect(abbreviateDigest('abcd')).toBe('abcd');
    expect(abbreviateDigest('0123456789abcdef')).toBe('0123456789abcdef');
  });
});

describe('Digest', () => {
  it('renders the abbreviated value with the full digest on the title', () => {
    render(<Digest value={FULL} />);
    const code = screen.getByTitle(FULL);
    expect(code.textContent).toBe(`${FULL.slice(0, 8)}…${FULL.slice(-8)}`);
    // The full value never appears verbatim in the abbreviated text node.
    expect(code.textContent).not.toBe(FULL);
  });

  it('copies the full value to the clipboard and confirms', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });

    render(<Digest value={FULL} />);
    fireEvent.click(screen.getByRole('button', { name: /copiar/i }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith(FULL));
    expect(await screen.findByLabelText('Copiado')).toBeTruthy();
  });

  it('omits the copy control when copyable is false', () => {
    render(<Digest value={FULL} copyable={false} />);
    expect(screen.queryByRole('button')).toBeNull();
  });
});
