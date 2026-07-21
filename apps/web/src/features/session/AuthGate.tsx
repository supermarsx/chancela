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
import { Button, Skeleton } from '../../ui';
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
  // Even at boot the shape is known: this panel resolves into either the retry message or
  // the sign-in card, both a short centred stack. So it skeletons that stack. `GateBoot` is
  // itself the `role="status"` element and the announcement rides in it as visually-hidden
  // text — no visible caption, and no silence for a screen reader either.
  if (session.isLoading || roster.isLoading) {
    return (
      <GateBoot busy>
        <span className="sr-only">{t('common.loading')}</span>
        <Skeleton height="1.4rem" width="11rem" />
        <Skeleton height="0.85rem" width="16rem" />
        <Skeleton height="2.4rem" width="13rem" />
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
