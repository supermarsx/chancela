import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ToastProvider } from './ToastProvider';
import { useToast } from './useToast';
import { ApiError } from '../../api/client';

/**
 * jsdom ships no `window.matchMedia`, and the provider treats its absence as "no motion" (the
 * instant path). To exercise the animated exit we install a stub whose
 * `(prefers-reduced-motion: reduce)` query resolves to `reduce`. `afterEach` removes it and
 * clears any safe-mode flag so the default (motionless) env is restored for the other tests.
 */
function installMatchMedia(reduce: boolean) {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: (query: string) => ({
      matches: query.includes('reduce') ? reduce : false,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }),
  });
}

afterEach(() => {
  cleanup();
  Reflect.deleteProperty(window, 'matchMedia');
  delete document.documentElement.dataset.safeMode;
});

/**
 * A tiny control surface that turns each toast API method into a clickable button, so
 * tests drive the provider the way a real feature does — through a `useToast()` call
 * inside the provider — and every push runs inside React's act() via fireEvent.
 */
function Controls() {
  const toast = useToast();
  return (
    <>
      <button onClick={() => toast.success('Definições guardadas')}>push-success</button>
      <button onClick={() => toast.info('A sincronizar')}>push-info</button>
      <button onClick={() => toast.error('Falha ao guardar')}>push-error</button>
      <button onClick={() => toast.error(new ApiError(422, { error: 'NIF inválido' }))}>
        push-apierror
      </button>
      <button onClick={() => toast.error({ weird: true })}>push-nonerror</button>
      <button onClick={() => toast.success('curta', { duration: 0 })}>push-sticky</button>
    </>
  );
}

function renderToasts() {
  return render(
    <ToastProvider>
      <Controls />
    </ToastProvider>,
  );
}

describe('ToastProvider + useToast', () => {
  it('renders a pushed success toast with its message and status role', () => {
    renderToasts();
    fireEvent.click(screen.getByText('push-success'));

    const toast = screen.getByRole('status');
    expect(toast.textContent).toContain('Definições guardadas');
    expect(toast.getAttribute('aria-live')).toBe('polite');
  });

  it('gives error toasts the assertive alert role and success/info the polite status role', () => {
    renderToasts();
    fireEvent.click(screen.getByText('push-error'));
    fireEvent.click(screen.getByText('push-info'));

    const alert = screen.getByRole('alert');
    expect(alert.textContent).toContain('Falha ao guardar');
    expect(alert.getAttribute('aria-live')).toBe('assertive');

    const status = screen.getByRole('status');
    expect(status.textContent).toContain('A sincronizar');
    expect(status.getAttribute('aria-live')).toBe('polite');
  });

  it('auto-dismisses after the default duration', () => {
    vi.useFakeTimers();
    try {
      renderToasts();
      fireEvent.click(screen.getByText('push-success'));
      expect(screen.queryByRole('status')).not.toBeNull();

      act(() => {
        vi.advanceTimersByTime(5000);
      });
      expect(screen.queryByRole('status')).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('keeps a sticky (duration 0) toast until it is dismissed', () => {
    vi.useFakeTimers();
    try {
      renderToasts();
      fireEvent.click(screen.getByText('push-sticky'));
      act(() => {
        vi.advanceTimersByTime(60_000);
      });
      expect(screen.getByRole('status').textContent).toContain('curta');
    } finally {
      vi.useRealTimers();
    }
  });

  it('dismisses a toast when its dismiss button is pressed', () => {
    renderToasts();
    fireEvent.click(screen.getByText('push-success'));
    expect(screen.queryByRole('status')).not.toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Dispensar' }));
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('stacks multiple toasts at once', () => {
    renderToasts();
    fireEvent.click(screen.getByText('push-success'));
    fireEvent.click(screen.getByText('push-info'));
    fireEvent.click(screen.getByText('push-error'));

    const region = screen.getByRole('region', { name: 'Notificações' });
    expect(region.querySelectorAll('.toast')).toHaveLength(3);
  });

  it('extracts the message from an ApiError passed to error()', () => {
    renderToasts();
    fireEvent.click(screen.getByText('push-apierror'));
    expect(screen.getByRole('alert').textContent).toContain('NIF inválido');
  });

  it('falls back to a generic message for a non-Error thrown to error()', () => {
    renderToasts();
    fireEvent.click(screen.getByText('push-nonerror'));
    expect(screen.getByRole('alert').textContent).toContain('Ocorreu um erro inesperado.');
  });

  it('pauses auto-dismiss while a toast is hovered', () => {
    vi.useFakeTimers();
    try {
      renderToasts();
      fireEvent.click(screen.getByText('push-success'));
      const toast = screen.getByRole('status');

      fireEvent.mouseEnter(toast);
      act(() => {
        vi.advanceTimersByTime(10_000);
      });
      // Still present: the countdown is paused while hovered.
      expect(screen.queryByRole('status')).not.toBeNull();

      fireEvent.mouseLeave(toast);
      act(() => {
        vi.advanceTimersByTime(5000);
      });
      expect(screen.queryByRole('status')).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('mounts a persistent labelled region even with no toasts', () => {
    render(
      <ToastProvider>
        <span>content</span>
      </ToastProvider>,
    );
    expect(screen.getByRole('region', { name: 'Notificações' })).toBeTruthy();
  });

  it('keeps a dismissed toast mounted through its exit animation, then removes it', () => {
    installMatchMedia(false); // motion on → the animated exit path
    vi.useFakeTimers();
    try {
      renderToasts();
      fireEvent.click(screen.getByText('push-success'));

      fireEvent.click(screen.getByRole('button', { name: 'Dispensar' }));
      // Still mounted, now marked as leaving so `toast-out` can play.
      const leaving = screen.getByRole('status');
      expect(leaving.className).toContain('toast--exiting');

      // Removed only after the exit duration elapses (removal is timer-driven, not animationend).
      act(() => {
        vi.advanceTimersByTime(200);
      });
      expect(screen.queryByRole('status')).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('removes a toast instantly under prefers-reduced-motion (no exit animation)', () => {
    installMatchMedia(true); // reduced motion
    renderToasts();
    fireEvent.click(screen.getByText('push-success'));

    fireEvent.click(screen.getByRole('button', { name: 'Dispensar' }));
    // Gone at once — never enters the exiting state, nothing left animating.
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('removes a toast instantly in safe mode (no exit animation)', () => {
    installMatchMedia(false);
    document.documentElement.dataset.safeMode = 'on';
    renderToasts();
    fireEvent.click(screen.getByText('push-success'));

    fireEvent.click(screen.getByRole('button', { name: 'Dispensar' }));
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('ignores a repeated dismiss while a toast is already exiting', () => {
    installMatchMedia(false);
    vi.useFakeTimers();
    try {
      renderToasts();
      fireEvent.click(screen.getByText('push-success'));
      const dismissBtn = screen.getByRole('button', { name: 'Dispensar' });

      fireEvent.click(dismissBtn);
      fireEvent.click(dismissBtn); // second click must not double-schedule or throw
      expect(screen.getByRole('status').className).toContain('toast--exiting');

      act(() => {
        vi.advanceTimersByTime(200);
      });
      expect(screen.queryByRole('status')).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('throws when useToast is called without a provider', () => {
    function Bare() {
      useToast();
      return null;
    }
    // Silence the expected React error log for the intentional throw.
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => render(<Bare />)).toThrow(/ToastProvider/);
    spy.mockRestore();
  });
});
