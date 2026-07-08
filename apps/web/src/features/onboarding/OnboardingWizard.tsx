/**
 * First-run onboarding wizard (`/bem-vindo`, plan t44 §3.2). A full-screen, editorial
 * gilt surface rendered as a sibling route OUTSIDE the app {@link Layout} chrome: no
 * PageHeader, no tab bar, no session picker — just the guided setup an operator sees on a
 * fresh install.
 *
 * ## Frozen step order (t29 §5.1)
 *   welcome → organization name → first user → optional password → optional attestation
 *   key (only if a password was set) → finish (sign in + mark onboarding complete).
 *
 * ## Why the backend calls are sequenced the way they are (the t41 gating reality)
 * Every domain mutation now requires a session (t41), so the wizard cannot PUT the org
 * name or set a secret while signed out. The only signed-out affordances are the
 * bootstrap `POST /v1/users` (allowed when zero users exist) and the passwordless
 * `POST /v1/session`. So the wizard:
 *   1. creates the first user (bootstrap) AND immediately signs in passwordless — after
 *      the "first user" step, giving every later step a live session;
 *   2. sets the optional password and generates the optional attestation key WHILE signed
 *      in (both are session-gated);
 *   3. at finish, PUTs the org name + `onboarding.completed = true` (also session-gated),
 *      then lands the now-signed-in operator in the app.
 *
 * ## Honest copy (t29 §0/§6, plan R3)
 * The password is a local tamper speed-bump, NOT at-rest encryption; there is no admin
 * reset (a lost password makes the attestation key unrecoverable); the attestation key is
 * an attestation, "não uma assinatura qualificada".
 */
import { useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { api } from '../../api/client';
import { DEFAULT_SETTINGS } from '../../api/types';
import { keys, useSessionRoster, useSettings } from '../../api/hooks';
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

  const [step, setStep] = useState<Step>('welcome');
  const [org, setOrg] = useState('');
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [userId, setUserId] = useState<string | null>(null);
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [keyGenerated, setKeyGenerated] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [localError, setLocalError] = useState<string | null>(null);

  // Entrance guard: if a user already exists (onboarding not required) and we have not yet
  // begun the flow, this route was reached in error — send the operator to the app (the
  // AuthGate there routes them to sign-in). Once we have created a user, we stay put.
  if (roster.data && !roster.data.onboarding_required && userId === null && step === 'welcome') {
    return <Navigate to="/" replace />;
  }

  const usernameFieldError = usernameError(username);

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
      qc.setQueryData(keys.session, { user: result.user });
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
    if (pw.length < 8) {
      setLocalError(t('onboarding.password.hint'));
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

  async function generateKey() {
    if (!userId) return;
    setBusy(true);
    setError(null);
    try {
      await api.createAttestationKey(userId, { current_password: pw });
      setKeyGenerated(true);
      void qc.invalidateQueries({ queryKey: keys.users });
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
                <Button type="submit" variant="primary" disabled={org.trim().length === 0}>
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
              <Field label={t('onboarding.password.confirm')} htmlFor="ob-pw2" error={localError}>
                <Input
                  id="ob-pw2"
                  type="password"
                  value={pw2}
                  onChange={(e) => setPw2(e.target.value)}
                  autoComplete="new-password"
                />
              </Field>
              {error ? <InlineWarning tone="error">{errorMessage(error, t)}</InlineWarning> : null}
              <div className="onboarding__actions">
                <Button type="button" variant="ghost" disabled={busy} onClick={() => void finish()}>
                  {t('onboarding.skip')}
                </Button>
                <Button type="submit" variant="primary" disabled={busy || pw.length === 0}>
                  {busy ? t('common.saving') : t('onboarding.next')}
                </Button>
              </div>
            </form>
          ) : null}

          {step === 'key' ? (
            <section className="onboarding__body">
              <h1 className="onboarding__title">{t('onboarding.key.title')}</h1>
              <p className="onboarding__lede">{t('onboarding.key.body')}</p>
              {keyGenerated ? (
                <InlineWarning tone="info">{t('onboarding.key.generated')}</InlineWarning>
              ) : (
                <div className="onboarding__actions onboarding__actions--start">
                  <Button
                    type="button"
                    variant="secondary"
                    icon={<Icon.Seal />}
                    disabled={busy}
                    onClick={() => void generateKey()}
                  >
                    {busy ? t('common.saving') : t('onboarding.key.generate')}
                  </Button>
                </div>
              )}
              {error ? <InlineWarning tone="error">{errorMessage(error, t)}</InlineWarning> : null}
              <div className="onboarding__actions">
                {keyGenerated ? (
                  <span />
                ) : (
                  <Button
                    type="button"
                    variant="ghost"
                    disabled={busy}
                    onClick={() => void finish()}
                  >
                    {t('onboarding.skip')}
                  </Button>
                )}
                <Button
                  type="button"
                  variant="primary"
                  disabled={busy}
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

/** Prefer an `Error`/`ApiError` message; fall back to the generic toast copy. */
function errorMessage(error: unknown, t: ReturnType<typeof useT>): string {
  return error instanceof Error ? error.message : t('toast.genericError');
}
