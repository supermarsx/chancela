import { describe, expect, it } from 'vitest';
import { buildDiagnostics } from './CrashScreen';

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
});
