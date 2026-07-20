/**
 * BootSplash gating tests (plan t50 W4).
 *
 * The splash is a decorative overlay that MUST be skipped entirely under either
 * kill-switch — reduced-motion or safe mode — and must never gate the app. These assert
 * the structure/gating (present/absent, pointer-events off, self-unmount), not pixels or
 * animation timing.
 *
 * jsdom does not implement `window.matchMedia`, so each test installs a minimal stub with
 * an explicit `matches` value; a missing stub would (correctly) be treated as "no motion".
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, render, screen } from '@testing-library/react';
import { BootSplash } from './BootSplash';

const SAFE_MODE_FLAG_KEY = 'chancela.safeMode';

/** Install a matchMedia stub whose `(prefers-reduced-motion: reduce)` query resolves to `reduce`. */
function stubMatchMedia(reduce: boolean) {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: (query: string) => ({
      matches: reduce,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
}

beforeEach(() => {
  window.localStorage.removeItem(SAFE_MODE_FLAG_KEY);
});

afterEach(() => {
  cleanup();
  window.localStorage.removeItem(SAFE_MODE_FLAG_KEY);
  vi.useRealTimers();
  Reflect.deleteProperty(window, 'matchMedia');
});

describe('BootSplash', () => {
  it('renders nothing under prefers-reduced-motion', () => {
    stubMatchMedia(true);
    render(<BootSplash />);
    expect(screen.queryByTestId('boot-splash')).toBeNull();
  });

  it('renders nothing in safe mode (even when motion is allowed)', () => {
    stubMatchMedia(false);
    window.localStorage.setItem(SAFE_MODE_FLAG_KEY, '1');
    render(<BootSplash />);
    expect(screen.queryByTestId('boot-splash')).toBeNull();
  });

  it('renders nothing when matchMedia is unavailable (no motion signal)', () => {
    // No stub installed — jsdom has no matchMedia, so the gate must fail closed (no motion).
    render(<BootSplash />);
    expect(screen.queryByTestId('boot-splash')).toBeNull();
  });

  it('mounts a non-interactive status overlay when motion is allowed, then self-unmounts', () => {
    vi.useFakeTimers();
    stubMatchMedia(false);
    render(<BootSplash />);

    const splash = screen.getByTestId('boot-splash');
    // A labelled status region carrying the decorative `.boot-splash` layer (whose CSS
    // makes it `pointer-events: none`, so it never gates the app underneath).
    expect(splash.getAttribute('role')).toBe('status');
    expect(splash.getAttribute('aria-label')).toBeTruthy();
    expect(splash.classList.contains('boot-splash')).toBe(true);

    // It removes itself after its short timer without any external signal.
    act(() => {
      vi.advanceTimersByTime(2000);
    });
    expect(screen.queryByTestId('boot-splash')).toBeNull();
  });
});
