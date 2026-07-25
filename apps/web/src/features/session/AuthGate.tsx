/**
 * Auth-gating shell (plan t44 §3, R1/R2). Wraps the app chrome inside {@link Layout} and
 * decides, from the UNAUTHENTICATED roster + the current session, what a visitor may see:
 *
 *  - first-run (no user exists → `onboarding_required`) → redirect to the `/welcome`
 *    wizard (a sibling route outside this chrome);
 *  - users exist but nobody is signed in → the {@link SignIn} surface (a mid-session 401
 *    lands here too: the client clears the token, the session query flips to `{user:null}`
 *    and this guard re-renders into sign-in — R2, "never a raw 401");
 *  - signed in → the app chrome (the guarded `children`).
 *
 * It reads the roster (unauth, never 401s) — deliberately NOT the auth-gated
 * `GET /v1/users`, which would 401 signed-out (the chicken-and-egg lockout). It is
 * independent of theme/safe-mode state (the safe banner + leather render above it in
 * Layout), so a fresh install still onboards in safe mode.
 */
import type { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { useSession, useSessionRoster } from '../../api/hooks';
import { useT } from '../../i18n';
import { Button } from '../../ui';
import { RequiredActionGate } from './RequiredActionGate';
import { SignIn } from './SignIn';

export function AuthGate({ children }: { children: ReactNode }) {
  const t = useT();
  const session = useSession();
  const roster = useSessionRoster();

  // Signed in → the app. Checked first so that immediately after the wizard/sign-in primes
  // the session cache (and after any roster staleness) the operator lands in the app,
  // never bounced back to the wizard.
  //
  // A walled session (t21) is signed in too — it holds a `user` AND a `required_action` the
  // server recomputes every `GET /v1/session`, and it 403s every route outside a tiny
  // allow-list until the action is done. So intercept it HERE, before the chrome: render the
  // matching wall instead of `children`. This is the one place required_action is handled, so
  // one-step sign-in, a completed 2FA challenge and a plain reload all land on the wall until it
  // clears (the wall re-reads the session on success, so the app appears the instant it lifts).
  if (session.data?.user) {
    if (session.data.required_action) {
      return <RequiredActionGate action={session.data.required_action} user={session.data.user} />;
    }
    return <>{children}</>;
  }

  // Still resolving who we are — hold a stable branded boot screen rather than flashing
  // sign-in. This is the one full-application loading fallback; route/content skeletons remain
  // local to the surfaces whose shape they describe.
  if (session.isLoading || roster.isLoading) {
    return (
      <GateBoot busy>
        <div className="gate-boot__brand" aria-hidden="true">
          <span className="gate-boot__crest">C</span>
          <span className="gate-boot__wordmark">{t('common.brand')}</span>
        </div>
        <span className="sr-only">{t('common.loading')}</span>
        <div
          className="gate-boot__progress"
          role="progressbar"
          aria-label={t('common.loading')}
          aria-valuetext={t('common.loading')}
        >
          <span className="gate-boot__progress-bar" aria-hidden="true" />
        </div>
      </GateBoot>
    );
  }

  // Roster is the authoritative signed-out signal; if it could not load, offer a retry
  // instead of a dead app.
  if (roster.isError || !roster.data) {
    return (
      <GateBoot>
        <p className="gate-boot__error">{t('session.gate.error')}</p>
        <Button variant="secondary" onClick={() => void roster.refetch()}>
          {t('session.gate.retry')}
        </Button>
      </GateBoot>
    );
  }

  // Fresh install: no user exists → the onboarding wizard.
  if (roster.data.onboarding_required) return <Navigate to="/welcome" replace />;

  // Users exist, nobody signed in → sign in.
  return <SignIn />;
}

/**
 * A minimal, centred boot panel used while the gate resolves or when it needs a retry.
 *
 * `busy` marks the subtree as in-flux; it is deliberately NOT set on the retry branch,
 * which is a settled error, not a wait. A failed gate must read as an error, never as a
 * permanent shimmer.
 */
function GateBoot({ children, busy = false }: { children: ReactNode; busy?: boolean }) {
  return (
    <div className="gate-boot" role="status" aria-busy={busy || undefined}>
      <div className="gate-boot__inner">{children}</div>
    </div>
  );
}
