/**
 * React error boundaries for the shell (t26).
 *
 * Two are wired in {@link Layout}, nested on purpose:
 *  - The **page** boundary wraps only the routed `<Outlet />`, BELOW the title bar in the
 *    tree, so a page/route crash is caught there while the title bar keeps working (drag,
 *    minimize, maximize, close) — the user is never trapped in a dead window.
 *  - The **shell** boundary wraps everything, including the title bar itself, so if the
 *    title bar throws its fallback swaps in a minimal strip that STILL renders working
 *    window controls.
 *
 * Every caught error feeds the crash-loop counter ({@link recordCrash}); three crashes
 * inside the window auto-enter safe mode and reload into it, breaking a boot loop caused
 * by a crashing appearance/settings configuration.
 */
import { Component, type ErrorInfo, type ReactNode } from 'react';
import { CrashScreen } from './CrashScreen';
import { WindowControls } from '../desktop/WindowControls';
import { isTauri } from '../desktop/tauri';
import { enterSafeMode, isSafeMode, recordCrash } from './safeMode';

interface FallbackArgs {
  error: Error;
  componentStack: string | null;
}

interface ErrorBoundaryProps {
  children: ReactNode;
  fallback: (args: FallbackArgs) => ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
  componentStack: string | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null, componentStack: null };

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { error };
  }

  componentDidCatch(_error: Error, info: ErrorInfo): void {
    this.setState({ componentStack: info.componentStack ?? null });

    // Count the crash. If we've hit a loop and are not already in safe mode, persist the
    // safe-mode flag and reload into it — a fresh boot that forces defaults and does NOT
    // apply the (possibly crashing) settings. The `!isSafeMode()` guard prevents an
    // infinite reload once we're already minimal.
    const looping = recordCrash();
    if (looping && !isSafeMode()) {
      enterSafeMode();
      try {
        window.location.reload();
      } catch {
        // jsdom / no-navigation environments: nothing more to do, the flag is set.
      }
    }
  }

  render(): ReactNode {
    const { error, componentStack } = this.state;
    if (error) return this.props.fallback({ error, componentStack });
    return this.props.children;
  }
}

/** Page boundary fallback: the full editorial crash screen inside the shell. */
export function PageErrorBoundary({ children }: { children: ReactNode }) {
  return (
    <ErrorBoundary
      fallback={({ error, componentStack }) => (
        <CrashScreen error={error} componentStack={componentStack} />
      )}
    >
      {children}
    </ErrorBoundary>
  );
}

/**
 * Shell boundary fallback: a minimal title-bar strip that keeps the window controls
 * alive (so the window can still be moved/closed even when the real title bar crashed),
 * with the crash screen below it.
 */
export function ShellErrorBoundary({ children }: { children: ReactNode }) {
  return (
    <ErrorBoundary
      fallback={({ error, componentStack }) => (
        <div className="shell-crash">
          {isTauri() ? (
            <div className="titlebar titlebar--fallback" data-tauri-drag-region="deep">
              <div className="titlebar__brand">
                <span className="titlebar__wordmark">Chancela</span>
              </div>
              <WindowControls />
            </div>
          ) : null}
          <CrashScreen error={error} componentStack={componentStack} />
        </div>
      )}
    >
      {children}
    </ErrorBoundary>
  );
}
