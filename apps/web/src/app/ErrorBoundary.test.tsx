import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';

// WindowControls (rendered by the shell fallback) lazily imports the window API; stub it
// so the Tauri code path is exercisable under jsdom.
vi.mock('@tauri-apps/api/window', () => ({
  getCurrentWindow: () => ({
    isMaximized: vi.fn().mockResolvedValue(false),
    onResized: vi.fn().mockResolvedValue(() => {}),
    minimize: vi.fn(),
    toggleMaximize: vi.fn(),
    close: vi.fn(),
  }),
}));

import { PageErrorBoundary, ShellErrorBoundary } from './ErrorBoundary';
import { CRASH_THRESHOLD } from './safeMode';

const asRecord = window as unknown as Record<string, unknown>;

function Boom(): never {
  throw new Error('rebentou');
}

// React logs caught render errors to console.error; silence it so the suite output stays
// readable (the assertions cover the behaviour).
let errorSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  window.localStorage.clear();
  errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  cleanup();
  errorSpy.mockRestore();
  window.localStorage.clear();
  delete asRecord.__TAURI_INTERNALS__;
});

describe('PageErrorBoundary', () => {
  it('renders the crash screen when a child throws', () => {
    render(
      <PageErrorBoundary>
        <Boom />
      </PageErrorBoundary>,
    );
    expect(screen.getByRole('heading', { name: 'Ocorreu um erro' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Reiniciar aplicação' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Copiar diagnóstico' })).toBeTruthy();
    // The thrown message surfaces for context.
    expect(screen.getByText('rebentou')).toBeTruthy();
  });

  it('renders its children untouched when nothing throws', () => {
    render(
      <PageErrorBoundary>
        <p>conteúdo</p>
      </PageErrorBoundary>,
    );
    expect(screen.getByText('conteúdo')).toBeTruthy();
    expect(screen.queryByRole('heading', { name: 'Ocorreu um erro' })).toBeNull();
  });
});

describe('ShellErrorBoundary', () => {
  it('keeps working window controls in the DOM when the shell crashes (desktop)', () => {
    asRecord.__TAURI_INTERNALS__ = {};
    render(
      <ShellErrorBoundary>
        <Boom />
      </ShellErrorBoundary>,
    );

    // The minimal fallback strip still exposes the three window controls, so the window is
    // never trapped — the whole point of the outer boundary.
    expect(screen.getByRole('button', { name: 'Minimizar' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Maximizar' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Fechar' })).toBeTruthy();
    // And the crash notice renders below it.
    expect(screen.getByRole('heading', { name: 'Ocorreu um erro' })).toBeTruthy();
  });

  it('omits the titlebar strip in a plain browser (no window to control)', () => {
    render(
      <ShellErrorBoundary>
        <Boom />
      </ShellErrorBoundary>,
    );
    expect(screen.queryByRole('button', { name: 'Fechar' })).toBeNull();
    expect(screen.getByRole('heading', { name: 'Ocorreu um erro' })).toBeTruthy();
  });
});

describe('crash-loop counter', () => {
  it('records each caught crash toward the safe-mode threshold', () => {
    // One caught crash is well below the threshold, so no auto-safe-mode reload is
    // triggered; the counter simply advances.
    render(
      <PageErrorBoundary>
        <Boom />
      </PageErrorBoundary>,
    );
    const log = JSON.parse(window.localStorage.getItem('chancela.crashLog') ?? '[]');
    expect(Array.isArray(log)).toBe(true);
    expect(log.length).toBe(1);
    expect(log.length).toBeLessThan(CRASH_THRESHOLD);
  });
});
