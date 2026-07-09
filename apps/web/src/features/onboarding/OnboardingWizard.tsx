/**
 * First-run onboarding wizard (`/bem-vindo`, plan t44 §3.2). A full-screen, editorial
 * gilt surface rendered as a sibling route OUTSIDE the app {@link Layout} chrome: no
 * PageHeader, no tab bar, no session picker — just the guided setup an operator sees on a
 * fresh install.
 *
 * ## Frozen step order (t29 §5.1)
 *   welcome → organization name → first user → mandatory password → mandatory recovery
 *   phrase → finish (mark onboarding complete).
 *
 * ## Why the backend calls are sequenced the way they are (the t41 gating reality)
 * Every domain mutation now requires a session (t41), so the wizard cannot PUT the org
 * name or set a secret while signed out. The only signed-out affordances are the
 * bootstrap `POST /v1/users` (allowed when zero users exist) and the temporary passwordless
 * `POST /v1/session`. So the wizard:
 *   1. creates the first user (bootstrap) AND immediately signs in — after the "first user"
 *      step, giving every later step a live session;
 *   2. sets the mandatory password and issues the mandatory recovery phrase WHILE signed in;
 *   3. at finish, PUTs the org name + `onboarding.completed = true` (also session-gated),
 *      then lands the now-signed-in operator in the app.
 *
 * ## Honest copy (t29 §0/§6, plan R3)
 * The password is a local tamper speed-bump, NOT at-rest encryption; there is no admin
 * reset (a lost password makes the attestation key unrecoverable); the attestation key is
 * an attestation, "não uma assinatura qualificada".
 */
import { useMemo, useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { api } from '../../api/client';
import {
  DEFAULT_SETTINGS,
  type PasswordPolicyRuleCode,
  type PasswordPolicyView,
  type PasswordRuleView,
} from '../../api/types';
import { keys, usePasswordPolicy, useSessionRoster, useSettings } from '../../api/hooks';
import { setSessionToken } from '../../api/session';
import { useQueryClient } from '@tanstack/react-query';
import { useT } from '../../i18n';
import { Button, Field, Icon, Input, InlineWarning, useToast } from '../../ui';
import { TitleBar } from '../../desktop/TitleBar';
import { isValidUsername, usernameError } from '../users/username';

type Step = 'welcome' | 'org' | 'user' | 'password' | 'key';

/** The substantive steps that carry a "Passo x de N" counter (welcome is the cover). */
const NUMBERED: Step[] = ['org', 'user', 'password', 'key'];

export function OnboardingWizard() {
  const t = useT();
  const toast = useToast();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const roster = useSessionRoster();
  const settings = useSettings();
  const passwordPolicy = usePasswordPolicy();

  const [step, setStep] = useState<Step>('welcome');
  const [org, setOrg] = useState('');
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [userId, setUserId] = useState<string | null>(null);
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [recoveryIssued, setRecoveryIssued] = useState(false);
  const [recoveryPhrase, setRecoveryPhrase] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [localError, setLocalError] = useState<string | null>(null);

  const usernameFieldError = usernameError(username);
  const passwordChecks = useMemo(
    () => evaluatePasswordPolicy(passwordPolicy.data, pw, username, t),
    [passwordPolicy.data, pw, t, username],
  );
  const passwordStrengthReady = passwordPolicy.data
    ? passwordPolicy.data.allow_weak_passwords
      ? pw.length > 0
      : passwordChecks.every((check) => check.met)
    : false;
  const passwordMatchState = pw2.length === 0 ? 'empty' : pw === pw2 ? 'ok' : 'mismatch';
  const passwordReady = passwordStrengthReady && passwordMatchState === 'ok';

  // Entrance guard: if a user already exists (onboarding not required) and we have not yet
  // begun the flow, this route was reached in error — send the operator to the app (the
  // AuthGate there routes them to sign-in). Once we have created a user, we stay put.
  if (roster.data && !roster.data.onboarding_required && userId === null && step === 'welcome') {
    return <Navigate to="/" replace />;
  }

  async function createUserAndSignIn() {
    if (!isValidUsername(username)) return;
    setBusy(true);
    setError(null);
    try {
      const user = await api.createUser({
        username,
        display_name: displayName.trim() || undefined,
      });
      // Sign in passwordless right away so the remaining (session-gated) steps work.
      const result = await api.createSession({ user_id: user.id });
      setSessionToken(result.token);
      qc.setQueryData(keys.session, await api.getSession());
      setUserId(user.id);
      void qc.invalidateQueries({ queryKey: keys.roster });
      void qc.invalidateQueries({ queryKey: keys.users });
      setStep('password');
    } catch (e) {
      setError(e);
      toast.error(e);
    } finally {
      setBusy(false);
    }
  }

  async function submitPassword() {
    setLocalError(null);
    if (pw.length === 0) {
      setLocalError(t('onboarding.password.required'));
      return;
    }
    if (!passwordPolicy.data) {
      setLocalError(t('onboarding.password.policyUnavailable'));
      return;
    }
    if (!passwordStrengthReady) {
      setLocalError(t('onboarding.password.policyIncomplete'));
      return;
    }
    if (pw !== pw2) {
      setLocalError(t('onboarding.password.mismatch'));
      return;
    }
    if (!userId) return;
    setBusy(true);
    setError(null);
    try {
      await api.setUserSecret(userId, { password: pw });
      void qc.invalidateQueries({ queryKey: keys.roster });
      void qc.invalidateQueries({ queryKey: keys.users });
      setStep('key');
    } catch (e) {
      setError(e);
      toast.error(e);
    } finally {
      setBusy(false);
    }
  }

  async function issueRecoveryPhrase() {
    if (!userId) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.issueRecovery(userId, { current_password: pw });
      setRecoveryIssued(true);
      setRecoveryPhrase(result.recovery_phrase);
      void qc.invalidateQueries({ queryKey: keys.users });
      void qc.invalidateQueries({ queryKey: keys.roster });
      toast.success(t('onboarding.key.generated'));
    } catch (e) {
      setError(e);
      toast.error(e);
    } finally {
      setBusy(false);
    }
  }

  async function finish() {
    setBusy(true);
    setError(null);
    try {
      const base = settings.data ?? DEFAULT_SETTINGS;
      await api.putSettings({
        ...base,
        organization: { ...base.organization, name: org.trim() || base.organization.name },
        onboarding: { completed: true, completed_at: new Date().toISOString() },
      });
      void qc.invalidateQueries({ queryKey: keys.settings });
      void qc.invalidateQueries({ queryKey: keys.roster });
      toast.success(t('toast.onboarding.completed'));
      navigate('/', { replace: true });
    } catch (e) {
      setError(e);
      toast.error(e);
    } finally {
      setBusy(false);
    }
  }

  const counter =
    step !== 'welcome'
      ? t('onboarding.step', { current: NUMBERED.indexOf(step) + 1, total: NUMBERED.length })
      : null;

  return (
    <div className="onboarding">
      <TitleBar />
      <div className="onboarding__scroll">
        <div className="onboarding__card" role="region" aria-label={t('onboarding.welcome.title')}>
          <p className="onboarding__brand">{t('common.brand')}</p>
          {counter ? (
            <p className="onboarding__step" aria-live="polite">
              {counter}
            </p>
          ) : null}

          {step === 'welcome' ? (
            <section className="onboarding__body">
              <h1 className="onboarding__title">{t('onboarding.welcome.title')}</h1>
              <p className="onboarding__lede">{t('onboarding.welcome.body')}</p>
              <div className="onboarding__actions">
                <Button variant="primary" onClick={() => setStep('org')}>
                  {t('onboarding.welcome.start')}
                </Button>
              </div>
            </section>
          ) : null}

          {step === 'org' ? (
            <form
              className="onboarding__body"
              onSubmit={(e) => {
                e.preventDefault();
                setStep('user');
              }}
            >
              <h1 className="onboarding__title">{t('onboarding.org.title')}</h1>
              <p className="onboarding__lede">{t('onboarding.org.body')}</p>
              <Field label={t('onboarding.org.label')} htmlFor="ob-org">
                <Input
                  id="ob-org"
                  value={org}
                  onChange={(e) => setOrg(e.target.value)}
                  placeholder={t('onboarding.org.placeholder')}
                  autoFocus
                />
              </Field>
              <div className="onboarding__actions">
                <Button type="button" variant="ghost" onClick={() => setStep('welcome')}>
                  {t('onboarding.back')}
                </Button>
                {/* Org is optional (t73): the operator may advance — and finish onboarding —
                    without naming an organisation. A blank org round-trips to the settings
                    default (`organization.name: null`), so no validation gate here. */}
                <Button type="submit" variant="primary">
                  {t('onboarding.next')}
                </Button>
              </div>
            </form>
          ) : null}

          {step === 'user' ? (
            <form
              className="onboarding__body"
              onSubmit={(e) => {
                e.preventDefault();
                void createUserAndSignIn();
              }}
            >
              <h1 className="onboarding__title">{t('onboarding.user.title')}</h1>
              <p className="onboarding__lede">{t('onboarding.user.body')}</p>
              <Field
                label={t('users.field.username.label')}
                htmlFor="ob-username"
                hint={t('users.field.username.hint')}
                error={usernameFieldError}
              >
                <Input
                  id="ob-username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder={t('users.field.username.placeholder')}
                  autoComplete="off"
                  autoCapitalize="off"
                  spellCheck={false}
                  autoFocus
                />
              </Field>
              <Field label={t('users.field.displayName.label')} htmlFor="ob-display">
                <Input
                  id="ob-display"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder={t('users.field.displayName.placeholder')}
                  autoComplete="off"
                />
              </Field>
              {error ? <InlineWarning tone="error">{errorMessage(error, t)}</InlineWarning> : null}
              <div className="onboarding__actions">
                <Button
                  type="button"
                  variant="ghost"
                  disabled={busy}
                  onClick={() => setStep('org')}
                >
                  {t('onboarding.back')}
                </Button>
                <Button
                  type="submit"
                  variant="primary"
                  disabled={busy || !isValidUsername(username)}
                >
                  {busy ? t('common.saving') : t('onboarding.next')}
                </Button>
              </div>
            </form>
          ) : null}

          {step === 'password' ? (
            <form
              className="onboarding__body"
              onSubmit={(e) => {
                e.preventDefault();
                void submitPassword();
              }}
            >
              <h1 className="onboarding__title">{t('onboarding.password.title')}</h1>
              <p className="onboarding__lede">{t('onboarding.password.body')}</p>
              <Field
                label={t('onboarding.password.new')}
                htmlFor="ob-pw"
                hint={t('onboarding.password.hint')}
              >
                <Input
                  id="ob-pw"
                  type="password"
                  value={pw}
                  onChange={(e) => setPw(e.target.value)}
                  autoComplete="new-password"
                  autoFocus
                />
              </Field>
              {passwordPolicy.isLoading ? (
                <p className="password-policy__loading">{t('onboarding.password.policyLoading')}</p>
              ) : passwordPolicy.error ? (
                <InlineWarning tone="error">{errorMessage(passwordPolicy.error, t)}</InlineWarning>
              ) : (
                <PasswordPolicyChecklist checks={passwordChecks} />
              )}
              <Field label={t('onboarding.password.confirm')} htmlFor="ob-pw2" error={localError}>
                <Input
                  id="ob-pw2"
                  type="password"
                  value={pw2}
                  onChange={(e) => setPw2(e.target.value)}
                  autoComplete="new-password"
                />
              </Field>
              <p
                className={`password-match password-match--${passwordMatchState}`}
                aria-live="polite"
              >
                {passwordMatchLabel(passwordMatchState, t)}
              </p>
              {error ? <InlineWarning tone="error">{errorMessage(error, t)}</InlineWarning> : null}
              <div className="onboarding__actions">
                <Button type="submit" variant="primary" disabled={busy || !passwordReady}>
                  {busy ? t('common.saving') : t('onboarding.next')}
                </Button>
              </div>
            </form>
          ) : null}

          {step === 'key' ? (
            <section className="onboarding__body">
              <h1 className="onboarding__title">{t('onboarding.key.title')}</h1>
              <p className="onboarding__lede">{t('onboarding.key.body')}</p>
              {recoveryPhrase ? (
                <InlineWarning tone="warn" title={t('users.recovery.shownOnceTitle')}>
                  <p>{t('users.recovery.shownOnceBody')}</p>
                  <p className="access-manager__recovery-phrase">
                    <code className="mono">{recoveryPhrase}</code>
                  </p>
                </InlineWarning>
              ) : recoveryIssued ? (
                <InlineWarning tone="info">{t('onboarding.key.generated')}</InlineWarning>
              ) : (
                <div className="onboarding__actions onboarding__actions--start">
                  <Button
                    type="button"
                    variant="secondary"
                    icon={<Icon.Seal />}
                    disabled={busy}
                    onClick={() => void issueRecoveryPhrase()}
                  >
                    {busy ? t('common.saving') : t('onboarding.key.generate')}
                  </Button>
                </div>
              )}
              {error ? <InlineWarning tone="error">{errorMessage(error, t)}</InlineWarning> : null}
              <div className="onboarding__actions">
                <span />
                <Button
                  type="button"
                  variant="primary"
                  disabled={busy || !recoveryIssued}
                  onClick={() => void finish()}
                >
                  {busy ? t('onboarding.finishing') : t('onboarding.finish.enter')}
                </Button>
              </div>
            </section>
          ) : null}
        </div>
      </div>
    </div>
  );
}

interface PasswordCheck {
  code: PasswordPolicyRuleCode;
  label: string;
  met: boolean;
}

function PasswordPolicyChecklist({ checks }: { checks: PasswordCheck[] }) {
  return (
    <ul className="password-policy" aria-live="polite">
      {checks.map((check) => (
        <li
          key={check.code}
          className={`password-policy__item ${
            check.met ? 'password-policy__item--met' : 'password-policy__item--unmet'
          }`}
        >
          <span className="password-policy__icon">
            {check.met ? <Icon.Check /> : <Icon.Close />}
          </span>
          <span>{check.label}</span>
        </li>
      ))}
    </ul>
  );
}

function evaluatePasswordPolicy(
  policy: PasswordPolicyView | undefined,
  password: string,
  username: string,
  t: ReturnType<typeof useT>,
): PasswordCheck[] {
  if (!policy) return [];
  return policy.rules.map((rule) => ({
    code: rule.code,
    label: passwordRuleLabel(rule, policy, t),
    met: passwordRuleMet(rule.code, password, username, policy),
  }));
}

function passwordRuleLabel(
  rule: PasswordRuleView,
  policy: PasswordPolicyView,
  t: ReturnType<typeof useT>,
): string {
  switch (rule.code) {
    case 'length':
      return t('password.policy.length', { min: policy.min_length });
    case 'lowercase':
      return t('password.policy.lowercase');
    case 'uppercase':
      return t('password.policy.uppercase');
    case 'digit':
      return t('password.policy.digit');
    case 'special':
      return t('password.policy.special');
    case 'not_username':
      return t('password.policy.notUsername');
    case 'not_common':
      return t('password.policy.notCommon');
    case 'no_repeats':
      return t('password.policy.noRepeats', { count: policy.max_identical_run });
    case 'no_sequential':
      return t('password.policy.noSequential', { count: policy.max_sequential_run });
    default:
      return rule.requirement;
  }
}

function passwordRuleMet(
  code: PasswordPolicyRuleCode,
  password: string,
  username: string,
  policy: PasswordPolicyView,
): boolean {
  switch (code) {
    case 'length':
      return Array.from(password).length >= policy.min_length;
    case 'lowercase':
      return /[a-z]/.test(password);
    case 'uppercase':
      return /[A-Z]/.test(password);
    case 'digit':
      return /\d/.test(password);
    case 'special':
      return Array.from(password).some((char) => !/[\p{L}\p{N}\s]/u.test(char));
    case 'not_username':
      return !containsUsername(password, username);
    case 'not_common':
      return !isCommonPassword(password);
    case 'no_repeats':
      return !hasIdenticalRun(password, policy.max_identical_run);
    case 'no_sequential':
      return !hasSequentialRun(password, policy.max_sequential_run);
  }
}

function passwordMatchLabel(
  state: 'empty' | 'ok' | 'mismatch',
  t: ReturnType<typeof useT>,
): string {
  switch (state) {
    case 'empty':
      return t('password.match.empty');
    case 'ok':
      return t('password.match.ok');
    case 'mismatch':
      return t('password.match.mismatch');
  }
}

function leet(value: string): string {
  return Array.from(value)
    .map((char) => {
      switch (char) {
        case '0':
          return 'o';
        case '1':
        case '!':
          return 'i';
        case '3':
          return 'e';
        case '4':
        case '@':
          return 'a';
        case '5':
        case '$':
          return 's';
        case '7':
        case '+':
          return 't';
        case '8':
          return 'b';
        case '9':
          return 'g';
        default:
          return char.toLowerCase();
      }
    })
    .join('');
}

function containsUsername(password: string, username: string): boolean {
  const user = username.trim().toLowerCase();
  if (Array.from(user).length < 3) return false;
  const lowerPassword = password.toLowerCase();
  return lowerPassword.includes(user) || leet(password).includes(leet(user));
}

const COMMON_PASSWORDS = new Set([
  '123456',
  '123456789',
  'admin',
  'admin123',
  'chancela',
  'letmein',
  'password',
  'qwerty',
  'welcome',
]);

function isCommonPassword(password: string): boolean {
  const lower = password.toLowerCase();
  const trimmed = lower.replace(/[^a-z]+$/g, '');
  return (
    COMMON_PASSWORDS.has(lower) ||
    COMMON_PASSWORDS.has(leet(lower)) ||
    COMMON_PASSWORDS.has(trimmed) ||
    COMMON_PASSWORDS.has(leet(trimmed))
  );
}

function hasIdenticalRun(password: string, run: number): boolean {
  let previous: string | null = null;
  let count = 1;
  for (const char of Array.from(password)) {
    if (char === previous) {
      count += 1;
      if (count >= run) return true;
    } else {
      previous = char;
      count = 1;
    }
  }
  return false;
}

function hasSequentialRun(password: string, run: number): boolean {
  const chars = Array.from(password);
  if (chars.length < run) return false;
  let asc = 1;
  let desc = 1;
  for (let i = 1; i < chars.length; i += 1) {
    const previous = chars[i - 1].codePointAt(0) ?? 0;
    const current = chars[i].codePointAt(0) ?? 0;
    asc = current - previous === 1 ? asc + 1 : 1;
    desc = previous - current === 1 ? desc + 1 : 1;
    if (asc >= run || desc >= run) return true;
  }
  return false;
}

/** Prefer an `Error`/`ApiError` message; fall back to the generic toast copy. */
function errorMessage(error: unknown, t: ReturnType<typeof useT>): string {
  return error instanceof Error ? error.message : t('toast.genericError');
}
