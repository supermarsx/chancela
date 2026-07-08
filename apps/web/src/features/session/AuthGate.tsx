/**
 * Auth-gating shell (plan t44 §3, R1/R2). Wraps the app chrome inside {@link Layout} and
 * decides, from the UNAUTHENTICATED roster + the current session, what a visitor may see:
 *
 *  - first-run (no user exists → `onboarding_required`) → redirect to the `/bem-vindo`
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
import { SignIn } from './SignIn';

export function AuthGate({ children }: { children: ReactNode }) {
  const t = useT();
  const session = useSession();
  const roster = useSessionRoster();

  // Signed in → the app. Checked first so that immediately after the wizard/sign-in primes
  // the session cache (and after any roster staleness) the operator lands in the app,
  // never bounced back to the wizard.
  if (session.data?.user) return <>{children}</>;

  // Still resolving who we are — hold a quiet boot screen rather than flashing sign-in.
  if (session.isLoading || roster.isLoading) {
    return <GateBoot>{t('common.loading')}</GateBoot>;
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
  if (roster.data.onboarding_required) return <Navigate to="/bem-vindo" replace />;

  // Users exist, nobody signed in → sign in.
  return <SignIn />;
}

/** A minimal, centred boot panel used while the gate resolves or when it needs a retry. */
function GateBoot({ children }: { children: ReactNode }) {
  return (
    <div className="gate-boot" role="status">
      <div className="gate-boot__inner">{children}</div>
    </div>
  );
}
