import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render } from '@testing-library/react';

// The desktop controls lazily `import('@tauri-apps/api/window')`; stub it so the
// Tauri code path can be exercised under jsdom without the real IPC bridge.
vi.mock('@tauri-apps/api/window', () => ({
  getCurrentWindow: () => ({
    isMaximized: vi.fn().mockResolvedValue(false),
    onResized: vi.fn().mockResolvedValue(() => {}),
    minimize: vi.fn(),
    toggleMaximize: vi.fn(),
    close: vi.fn(),
  }),
}));

import { TitleBar } from './TitleBar';

const asRecord = window as unknown as Record<string, unknown>;

afterEach(() => {
  cleanup();
  delete asRecord.__TAURI_INTERNALS__;
});

describe('TitleBar', () => {
  it('renders nothing in a plain browser environment (no Tauri)', () => {
    // jsdom has no `__TAURI_INTERNALS__`, so this mirrors the browser build:
    // the bar must add zero DOM and never touch @tauri-apps/api.
    expect('__TAURI_INTERNALS__' in window).toBe(false);
    const { container } = render(<TitleBar />);
    expect(container.firstChild).toBeNull();
  });

  it('makes the whole bar a native "deep" drag region inside the shell, excluding buttons', () => {
    asRecord.__TAURI_INTERNALS__ = {};
    const { container } = render(<TitleBar />);

    const bar = container.querySelector('.titlebar');
    // Drag is delegated to Tauri's native, synchronous mousedown handler via the
    // attribute (not a JS `startDragging()` call that would land too late on
    // Windows/WebView2). "deep" so clicks on the decorative seal/wordmark still
    // drag instead of swallowing the gesture.
    expect(bar?.getAttribute('data-tauri-drag-region')).toBe('deep');

    // The min/max/close controls must NOT carry the attribute — Tauri
    // auto-excludes clickable elements so their clicks are never hijacked.
    const buttons = container.querySelectorAll('button');
    expect(buttons.length).toBe(3);
    buttons.forEach((b) => expect(b.hasAttribute('data-tauri-drag-region')).toBe(false));
  });
});
