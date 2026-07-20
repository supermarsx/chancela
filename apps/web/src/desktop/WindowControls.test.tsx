import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

// The controls lazily `import('@tauri-apps/api/window')`; stub it so the toggle's
// `setAlwaysOnTop` call can be observed under jsdom without the real IPC bridge. A single
// shared window object lets the test assert against the same spy the component calls.
const win = {
  isMaximized: vi.fn().mockResolvedValue(false),
  onResized: vi.fn().mockResolvedValue(() => {}),
  minimize: vi.fn(),
  toggleMaximize: vi.fn(),
  close: vi.fn(),
  setAlwaysOnTop: vi.fn().mockResolvedValue(undefined),
};
vi.mock('@tauri-apps/api/window', () => ({ getCurrentWindow: () => win }));

import { WindowControls } from './WindowControls';

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('WindowControls always-on-top toggle', () => {
  it('renders first (before minimize) and toggles the Tauri window setAlwaysOnTop state', async () => {
    render(<WindowControls />);

    // Sits ahead of the minimize control: [always-on-top] [minimize] [maximize] [close].
    const buttons = screen.getAllByRole('button');
    expect(buttons[0]).toBe(screen.getByRole('button', { name: 'Manter sempre à frente' }));

    const toggle = buttons[0];
    expect(toggle.getAttribute('aria-pressed')).toBe('false');

    // Turn on → reflects active state (label + aria-pressed) and asks Tauri to pin.
    fireEvent.click(toggle);
    await waitFor(() => expect(win.setAlwaysOnTop).toHaveBeenCalledWith(true));
    expect(
      screen.getByRole('button', { name: 'Sempre à frente: ativado' }).getAttribute('aria-pressed'),
    ).toBe('true');

    // Turn off → reverts.
    fireEvent.click(screen.getByRole('button', { name: 'Sempre à frente: ativado' }));
    await waitFor(() => expect(win.setAlwaysOnTop).toHaveBeenLastCalledWith(false));
    expect(
      screen.getByRole('button', { name: 'Manter sempre à frente' }).getAttribute('aria-pressed'),
    ).toBe('false');
  });

  it('reverts the optimistic toggle state when setAlwaysOnTop fails', async () => {
    win.setAlwaysOnTop.mockRejectedValueOnce(new Error('ACL denied'));
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});

    render(<WindowControls />);

    const toggle = screen.getByRole('button', { name: 'Manter sempre à frente' });
    fireEvent.click(toggle);

    expect(
      screen.getByRole('button', { name: 'Sempre à frente: ativado' }).getAttribute('aria-pressed'),
    ).toBe('true');
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Manter sempre à frente' }).getAttribute('aria-pressed'),
      ).toBe('false'),
    );
    expect(win.setAlwaysOnTop).toHaveBeenCalledWith(true);
    expect(consoleError).toHaveBeenCalledWith(
      'WindowControls: setAlwaysOnTop failed',
      expect.any(Error),
    );
    consoleError.mockRestore();
  });
});
