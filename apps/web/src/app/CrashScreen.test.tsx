import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { buildDiagnostics, CrashScreen } from './CrashScreen';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('buildDiagnostics', () => {
  it('bundles the error, stack, route, version and timestamp', () => {
    const error = new Error('rebentou');
    error.name = 'TypeError';
    error.stack = 'TypeError: rebentou\n    at Boom (page.tsx:10:5)';
    const now = new Date('2026-07-07T12:00:00.000Z');

    const text = buildDiagnostics({
      error,
      componentStack: '\n    at Page\n    at Layout',
      now,
    });

    expect(text).toContain('Chancela — diagnóstico de falha');
    expect(text).toContain('2026-07-07T12:00:00.000Z');
    expect(text).toContain('Erro: TypeError: rebentou');
    expect(text).toContain('at Boom (page.tsx:10:5)');
    expect(text).toContain('Componentes:');
    expect(text).toContain('at Page');
    // The version line is present (value comes from the __APP_VERSION__ build global).
    expect(text).toContain('Versão da interface:');
    // The desktop panic-log path pattern is named generically.
    expect(text).toContain('crash/panic-');
  });

  it('degrades gracefully when there is no error or component stack', () => {
    const text = buildDiagnostics({ error: null, now: new Date('2026-07-07T00:00:00.000Z') });
    expect(text).toContain('Erro: (desconhecido)');
    expect(text).toContain('(sem pilha)');
    expect(text).not.toContain('Componentes:');
  });

  it('copies diagnostics and stack text with explicit success feedback', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    const error = new Error('route failed');
    error.stack = 'Error: route failed\n at Route';
    render(<CrashScreen error={error} componentStack={'\n at Page'} />);

    expect(screen.getByText('route failed')).toBeTruthy();
    expect(screen.getByText('at Page')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Copiar diagnóstico' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    expect(await screen.findByRole('button', { name: 'Diagnóstico copiado' })).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Copiar pilha' }));
    await waitFor(() => expect(writeText).toHaveBeenLastCalledWith(error.stack));
    expect(screen.getByRole('button', { name: 'Copiado' })).toBeTruthy();
  });

  it('keeps copy actions available when the clipboard rejects', async () => {
    const writeText = vi.fn().mockRejectedValue(new Error('denied'));
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    render(<CrashScreen error={null} />);

    fireEvent.click(screen.getByRole('button', { name: 'Copiar diagnóstico' }));
    fireEvent.click(screen.getByRole('button', { name: 'Copiar pilha' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(2));
    expect(screen.getByRole('button', { name: 'Copiar diagnóstico' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Copiar pilha' })).toBeTruthy();
  });
});
