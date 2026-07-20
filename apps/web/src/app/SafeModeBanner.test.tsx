import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cleanup, screen } from '@testing-library/react';
import { renderWithProviders } from '../test/utils';
import { SafeModeBanner } from './SafeModeBanner';

const root = document.documentElement;

beforeEach(() => {
  root.removeAttribute('data-safe-mode');
  root.removeAttribute('data-theme');
  root.removeAttribute('data-button-texture');
});

afterEach(() => {
  cleanup();
  root.removeAttribute('data-safe-mode');
  root.removeAttribute('data-theme');
  root.removeAttribute('data-button-texture');
});

describe('SafeModeBanner', () => {
  it('bypasses the applied appearance while mounted and restores it on unmount', () => {
    // A persisted dark theme + button texture, as AppearanceEffects would have stamped.
    root.setAttribute('data-theme', 'dark');
    root.setAttribute('data-button-texture', 'on');

    const { unmount } = renderWithProviders(<SafeModeBanner />);

    // Forced back to the minimal, default look: no explicit theme (system), button
    // texture off, and the safe-mode flag that kills motion + hides the leather layer.
    expect(root.getAttribute('data-safe-mode')).toBe('on');
    expect(root.getAttribute('data-theme')).toBeNull();
    expect(root.getAttribute('data-button-texture')).toBe('off');

    unmount();

    // The prior appearance is restored (a clean exit reloads anyway, but the effect is
    // self-contained).
    expect(root.getAttribute('data-safe-mode')).toBeNull();
    expect(root.getAttribute('data-theme')).toBe('dark');
    expect(root.getAttribute('data-button-texture')).toBe('on');
  });

  it('shows the safe-mode banner with an exit and a reset action', () => {
    renderWithProviders(<SafeModeBanner />);
    expect(screen.getByText('Modo de segurança')).toBeTruthy();
    expect(screen.getByText('as preferências não estão aplicadas')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Sair do modo de segurança' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Repor definições' })).toBeTruthy();
  });
});
