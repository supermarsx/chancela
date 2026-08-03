/**
 * Segurança — everything that authenticates you, and the one action for when that has gone wrong.
 *
 * ## Ordered by escalation, not by topic
 *
 *  1. **What you hold** — `UserAccessManager`: the sign-in password, the one-time recovery phrase
 *     and the PKI audit-attestation key. Imported, not reimplemented: it already forks on
 *     `isCrossUser` (session user ≠ subject) and renders the self-service flow when they match, so
 *     mounting it here with the session's own `UserView` gives exactly the self half of a component
 *     the administrative screen renders in full. Its cross-user proof rules and the copy that
 *     explains them are untouched.
 *  2. **Second factor** — {@link TwoFactorSection}, `isSelf`. Self-only enrolment is not a policy
 *     choice this screen makes; the server enforces it (`totp::require_self`), because the secret
 *     has to reach the holder's own authenticator. An administrator may *require* a factor on this
 *     account and may not enrol one, and that asymmetry is preserved by passing `isSelf` rather
 *     than by hiding controls.
 *  3. **Passkeys** — `PasskeySection`, again the administrative screen's own module with `isSelf`
 *     fixed true. Its fork mirrors the server's split: the list is self-or-`user.manage`, but
 *     enrol, rename and revoke are self-only, so the constant is what turns the administrator's
 *     read-only list into the full self-service block.
 *  4. **How you re-prove yourself** — {@link StepUpMethodCard}: the default method a guarded action's
 *     step-up gate opens on. A convenience default only — every method you hold stays available in
 *     the gate, and the server verifies whatever proof is presented. Only the methods this account
 *     actually holds are selectable.
 *  5. **What is signed in as you** — {@link SessionsSection}, self-scoped by the shape of
 *     `GET /v1/sessions`.
 *  6. **Lock the account** — {@link AccountSuspendCard}, step-up gated and one-way.
 *
 * ## Nothing here needs an administrative permission
 *
 * Every endpoint reached from this section is self-service server-side. The `UserView` comes from
 * `GET /v1/session`, never from the `user.read`-gated user routes. A user who holds `user.manage`
 * additionally sees a pointer to the administrative view of their own account, because for them
 * the two surfaces really are different places and it is worth saying which one they are on.
 */
import { Link } from 'react-router-dom';
import type { UserView } from '../../api/types';
import { useT } from '../../i18n';
import { Badge, Card, Field } from '../../ui';
import { PasskeySection } from '../users/PasskeySection';
import { UserAccessManager } from '../users/UserAccessManager';
import { editUserSectionPath } from '../users/paths';
import { useCan } from '../session/permissions';
import { SessionsSection } from './SessionsSection';
import { TwoFactorSection } from './TwoFactorSection';
import { StepUpMethodCard } from './StepUpMethodCard';
import { AccountSuspendCard } from './AccountSuspendCard';

/**
 * The credential posture at a glance — the booleans and the fingerprint `UserView` already
 * publishes, above the manager that changes them.
 *
 * Read-only on purpose even though the controls are inches below: this card answers "what do I
 * currently hold", which is the question someone arrives at this screen with, and the cards below
 * answer "change it". No key or password material reaches the DOM, a URL, a log or an error.
 */
function PostureCard({ user }: { user: UserView }) {
  const t = useT();
  const can = useCan();
  return (
    <Card title={t('users.security.title')}>
      <div className="stack">
        <p className="field__hint">{t('account.security.lede')}</p>
        <div className="form settings-rows">
          <Field label={t('users.secret.label')} hint={t('users.security.password.hint')}>
            {user.has_secret ? (
              <Badge tone="ok">{t('users.secret.has')}</Badge>
            ) : (
              <Badge tone="neutral">{t('users.secret.none')}</Badge>
            )}
          </Field>
          <Field label={t('users.recovery.label')} hint={t('users.security.recovery.hint')}>
            {user.has_recovery_phrase ? (
              <Badge tone="accent">{t('users.recovery.has')}</Badge>
            ) : (
              <Badge tone="neutral">{t('users.recovery.none')}</Badge>
            )}
          </Field>
          <Field label={t('users.key.label')} hint={t('users.security.key.hint')}>
            {user.has_attestation_key ? (
              <span className="stack--tight">
                <Badge tone="ok">{t('users.key.has')}</Badge>
                {user.attestation_key_fingerprint ? (
                  <code className="mono">{user.attestation_key_fingerprint}</code>
                ) : null}
              </span>
            ) : (
              <Badge tone="neutral">{t('users.key.none')}</Badge>
            )}
          </Field>
        </div>
        {/* Only for someone who can actually open it. For everyone else the administrative screen
            is not merely uninteresting — it is a 403, and pointing at it would be a broken promise. */}
        {can('user.manage') ? (
          <p className="field__hint">
            <Link to={editUserSectionPath(user.id, 'access')}>
              {t('account.security.adminView')}
            </Link>
          </p>
        ) : null}
      </div>
    </Card>
  );
}

export function AccountSecuritySection({ user }: { user: UserView }) {
  return (
    <div className="stack">
      <PostureCard user={user} />

      {/* The self half of the administrative credential manager — same module, `isCrossUser` false
          because the session user IS the subject. */}
      <UserAccessManager user={user} />

      <TwoFactorSection user={user} isSelf />

      {/* Chaves de acesso — the SAME `PasskeySection` the administrative Segurança tab renders,
          with `isSelf` fixed true because on this surface it always is. Its own `isSelf` fork
          mirrors the server's split (the list is self-or-`user.manage`; enrol, rename and revoke
          are self-only), so passing the constant is what turns it into the full self-service block
          rather than the administrator's read-only list. */}
      <PasskeySection user={user} isSelf />

      {/* The default step-up method a guarded action's re-auth gate opens on. A convenience default:
          the gate still offers every method held as a fallback and the server verifies whatever
          proof is presented, so this changes no security posture — only which arm shows first. */}
      <StepUpMethodCard />

      <SessionsSection />

      <AccountSuspendCard />
    </div>
  );
}
