/**
 * The editorial crash screen (t26) — what the page error boundary renders when a route
 * or page throws. It stays inside the shell (the title bar above it is untouched, so the
 * window still drags/minimizes/closes), and offers the two recovery actions the brief
 * pins: restart the application and copy a diagnostics bundle. The stack trace is tucked
 * into a collapsible `<details>` with its own click-to-copy control (the Digest idiom).
 *
 * Copy is best-effort: if the clipboard is unavailable the full text is still visible in
 * the expanded stack, so nothing is hidden.
 */
import { useState } from 'react';
import { Button, Tooltip } from '../ui';
import { Copy, Check, Refresh } from '../ui/icons';
import { isTauri } from '../desktop/tauri';
import { relaunchApp } from '../desktop/relaunch';
import { UI_VERSION, displayVersion } from '../api/versionCheck';
import { useT } from '../i18n';

/**
 * Build the copyable diagnostics bundle: the error, its stack, the React component
 * stack, the current route, the build/runtime versions and a timestamp. Pure and
 * exported so it can be asserted directly.
 *
 * The desktop panic log (written by the Rust panic hook) is referenced only by its
 * generic path pattern — this crate is not the API's lock, so there is no endpoint to
 * surface the real file; naming the pattern lets a user find it themselves.
 */
export function buildDiagnostics(args: {
  error: Error | null;
  componentStack?: string | null;
  now?: Date;
}): string {
  const { error, componentStack } = args;
  const now = args.now ?? new Date();
  const href = typeof window !== 'undefined' ? window.location.href : '(desconhecido)';
  const userAgent = typeof navigator !== 'undefined' ? navigator.userAgent : '(desconhecido)';
  const environment = isTauri() ? 'Aplicação de secretária (Tauri)' : 'Navegador';

  const lines = [
    'Chancela — diagnóstico de falha',
    `Data: ${now.toISOString()}`,
    `Rota: ${href}`,
    `Ambiente: ${environment}`,
    `Versão da interface: ${displayVersion(UI_VERSION)}`,
    `User agent: ${userAgent}`,
    '',
    `Erro: ${error ? `${error.name}: ${error.message}` : '(desconhecido)'}`,
    '',
    'Pilha:',
    error?.stack ?? '(sem pilha)',
  ];

  if (componentStack) {
    lines.push('', 'Componentes:', componentStack.trim());
  }

  lines.push(
    '',
    'Nota: na aplicação de secretária pode existir um registo de falha em ' +
      '<dir-de-dados>/crash/panic-<data-hora>.log.',
  );

  return lines.join('\n');
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

interface CrashScreenProps {
  error: Error | null;
  componentStack?: string | null;
}

export function CrashScreen({ error, componentStack }: CrashScreenProps) {
  const t = useT();
  const [copiedDiag, setCopiedDiag] = useState(false);
  const [copiedStack, setCopiedStack] = useState(false);

  const stack = error?.stack ?? '(sem pilha)';

  async function copyDiagnostics() {
    const ok = await copyText(buildDiagnostics({ error, componentStack }));
    if (ok) {
      setCopiedDiag(true);
      window.setTimeout(() => setCopiedDiag(false), 1500);
    }
  }

  async function copyStack() {
    const ok = await copyText(stack);
    if (ok) {
      setCopiedStack(true);
      window.setTimeout(() => setCopiedStack(false), 1500);
    }
  }

  return (
    <div className="crash" role="alert">
      <div className="crash__inner">
        <p className="crash__eyebrow">Chancela</p>
        <h1 className="crash__title">{t('crash.title')}</h1>
        <p className="crash__lede">{t('crash.lede')}</p>

        {error?.message ? <p className="crash__message">{error.message}</p> : null}

        <div className="crash__actions">
          <Button variant="primary" icon={<Refresh />} onClick={() => void relaunchApp()}>
            {t('crash.restart')}
          </Button>
          <Button
            variant="secondary"
            icon={copiedDiag ? <Check /> : <Copy />}
            onClick={() => void copyDiagnostics()}
          >
            {copiedDiag ? t('crash.copyDiagnosticsDone') : t('crash.copyDiagnostics')}
          </Button>
        </div>

        <details className="crash__details">
          <summary className="crash__summary">{t('crash.detailsSummary')}</summary>
          <div className="crash__stack-head">
            <span className="crash__stack-label">{t('crash.stackLabel')}</span>
            <Tooltip label={copiedStack ? t('common.copied') : t('crash.copyStack')}>
              <button
                type="button"
                className="digest__copy"
                onClick={() => void copyStack()}
                aria-label={copiedStack ? t('common.copied') : t('crash.copyStack')}
              >
                {copiedStack ? <Check /> : <Copy />}
              </button>
            </Tooltip>
          </div>
          <pre className="crash__stack mono">{stack}</pre>
          {componentStack ? (
            <pre className="crash__stack crash__stack--components mono">
              {componentStack.trim()}
            </pre>
          ) : null}
        </details>

        <p className="crash__note">
          Na aplicação de secretária, um registo de falha pode ter sido gravado em{' '}
          <code className="mono">&lt;dir-de-dados&gt;/crash/panic-&lt;data-hora&gt;.log</code>.
        </p>
      </div>
    </div>
  );
}
