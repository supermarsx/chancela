/**
 * **A minha conta** (`/account/:sec?`) — the self-service account area.
 *
 * ## The defect this exists to fix
 *
 * There was no self-service surface at all. A user reached their own settings through
 * `/settings/users/{id}` — the *administrative* roster — and the edit screen forked internally on
 * `isSelf`. That fork is good and is reused verbatim here; the defect was only that the door went
 * through administration. Practically: `GET /v1/users` is `user.read`\@Global and
 * `PATCH /v1/users/{id}` is `user.manage`\@Global, so a user holding neither could not reach the
 * roster, could not open their own edit screen, and had **no route to their own security settings**.
 *
 * ## Zero administrative permissions, by construction
 *
 * Nothing on this surface reads `GET /v1/users` or `GET /v1/users/{id}`. The current user's
 * `UserView` comes from `GET /v1/session`, which every signed-in principal may read, and every
 * mutation reached from here is one the server already treats as self-service:
 *
 * | what | endpoint | gate |
 * |---|---|---|
 * | display name / e-mail / language | `PATCH /v1/me/profile` | session, self |
 * | password, recovery phrase, audit key | `…/users/{id}/secret`, `/recovery`, `/attestation-key` | session, self-service arm |
 * | second factor | `…/users/{id}/two-factor/*` | session, `require_self` |
 * | active sign-ins | `/v1/sessions*` | session, caller-scoped |
 * | suspend my account | `POST /v1/me/suspend` | session, self + step-up |
 *
 * The one capability that is NOT self-service is data export: `GET /v1/privacy/users/{id}/export`
 * is `privacy.manage`\@Global with no self arm. That is surfaced honestly rather than papered over
 * — see {@link AccountProfileSection}.
 *
 * ## Information architecture: three sections, English slugs, in the PATH
 *
 * `/account` (Perfil) · `/account/security` · `/account/preferences`, through `useSectionNav`
 * exactly as `/users/:id/:sec?` and `/books/:id/:sec?` do. The section is derived from the pathname
 * on every render and never mirrored into state, so each tab is deep-linkable, identical after a
 * reload, and answerable by Back. `navDepth: 1` keys the shell on `/account`, so switching tab does
 * not remount the screen and discard the profile form's working copy.
 *
 * The split is by **who may change it and how it fails**, not by topic:
 *
 *  - **Perfil** — the facts about you an administrator would otherwise have to type for you, plus
 *    the honest statement of what only an administrator may change (roles, activation, whether a
 *    second factor is required). Nothing here is a credential.
 *  - **Segurança** — everything that authenticates you, and the one action for when that has gone
 *    wrong. Ordered by escalation: what you hold → what is currently signed in as you → lock it.
 *  - **Preferências** — durable per-user state that is neither identity nor credential.
 *
 * ## Reuse, not a second implementation
 *
 * Every credential block here is the SAME module the administrative screen renders —
 * `UserAccessManager`, {@link TwoFactorSection}, {@link SessionsSection}, `LanguagePreferenceSection`
 * — imported, not copied. Two implementations of "change my password" is how one of them quietly
 * stops matching the server, and this codebase has removed that defect twice already (t71, t89).
 */
import { useSession } from '../../api/hooks';
import { useSectionNav } from '../../app/navPath';
import { useT } from '../../i18n';
import { Card, Icon, InlineWarning, PageHeader, Skeleton, SkeletonDeflist, SubNav } from '../../ui';
import type { MessageKey } from '../../i18n/types';
import { ACCOUNT_PATH } from './paths';
import { AccountProfileSection } from './AccountProfileSection';
import { AccountSecuritySection } from './AccountSecuritySection';
import { AccountPreferencesSection } from './AccountPreferencesSection';

/** The area's sections. English slugs; `profile` is the fallback and carries no segment. */
export type AccountSection = 'profile' | 'security' | 'preferences';

const ACCOUNT_SECTIONS: { id: AccountSection; label: MessageKey; icon: React.ReactNode }[] = [
  { id: 'profile', label: 'account.subnav.profile', icon: <Icon.IdCard /> },
  { id: 'security', label: 'account.subnav.security', icon: <Icon.Shield /> },
  // `Sliders`, not `Cog`: the cog is Configurações' own glyph in the top bar, and reusing it for a
  // section of a different surface would say these are the same place.
  { id: 'preferences', label: 'account.subnav.preferences', icon: <Icon.Sliders /> },
];

const isAccountSection = (value: string | undefined): value is AccountSection =>
  ACCOUNT_SECTIONS.some((section) => section.id === value);

export function AccountPage() {
  const t = useT();
  const session = useSession();

  // A PUSH, not a replace: a tab is somewhere the operator navigated, so Back returns to the
  // previous tab rather than leaving the screen — the rule every other tabbed surface follows.
  const { section, select } = useSectionNav<AccountSection>({
    base: ACCOUNT_PATH,
    parse: (raw) => (isAccountSection(raw) ? raw : 'profile'),
    fallback: 'profile',
  });

  const user = session.data?.user ?? null;

  // The shell's `AuthGate` already keeps the signed-out visitor off every routed surface, so this
  // is the in-flight read rather than a signed-out state — but it is written as a real branch
  // instead of a `!` because a surface whose whole subject is "you" must never render a form bound
  // to nobody.
  if (!user) {
    return (
      <div className="stack form-page">
        <PageHeader
          title={
            session.isLoading ? <Skeleton width="14rem" height="1.6rem" /> : t('account.title')
          }
        />
        {session.isLoading ? (
          <Card>
            <SkeletonDeflist />
          </Card>
        ) : (
          <Card title={t('account.title')}>
            <InlineWarning tone="info" title={t('account.signedOut.title')}>
              <p>{t('account.signedOut.body')}</p>
            </InlineWarning>
          </Card>
        )}
      </div>
    );
  }

  return (
    <div className="stack form-page">
      <PageHeader title={t('account.title')} lede={t('account.lede')}>
        <SubNav
          items={ACCOUNT_SECTIONS.map((s) => ({ id: s.id, label: t(s.label), icon: s.icon }))}
          active={section}
          onSelect={select}
          ariaLabel={t('account.subnav.aria')}
        />
      </PageHeader>

      {/* One section at a time; the panel replays the route-enter fade on each switch. */}
      <div className="route-transition stack" key={section}>
        {section === 'profile' ? (
          <AccountProfileSection user={user} />
        ) : section === 'security' ? (
          <AccountSecuritySection user={user} />
        ) : (
          <AccountPreferencesSection />
        )}
      </div>
    </div>
  );
}
