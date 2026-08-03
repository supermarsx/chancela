/**
 * "How you re-prove yourself" — the acting user's default step-up re-auth method (t10 follow-on).
 *
 * A guarded action (closing a book, a factory reset, …) asks the operator to re-prove their identity
 * before it proceeds. They may always do so with whichever method they hold — a passkey, a live TOTP
 * code, or their password — and this card only chooses which one the confirmation gate opens on. It
 * is a convenience default, never an authorization input: the server verifies whatever proof is
 * actually presented regardless of what is stored here, and every other method stays available as a
 * fallback in the gate.
 *
 * Only methods the account actually holds are selectable: TOTP unlocks once a second factor is
 * confirmed (`has_totp`), and the passkey option only where a passkey ceremony can run at all (a
 * WebAuthn-capable browser). The recovery phrase is deliberately not offerable as a default — it is
 * a single-use break-glass credential, not a routine re-auth. A method that becomes unavailable
 * later costs nothing: the gate silently falls back to the password.
 */
import type { StepUpMethodPreference } from '../../api/types';
import { useSession, useUpdateStepUpMethod, useUserPreferences } from '../../api/hooks';
import { passkeysAvailable } from '../session/webauthn';
import { useT } from '../../i18n';
import { Card, Field, Select, useToast } from '../../ui';

/** The empty select value standing for "no preference" (the password arm first). */
const NO_PREFERENCE = '';

export function StepUpMethodCard() {
  const t = useT();
  const toast = useToast();
  const session = useSession();
  const preferences = useUserPreferences();
  const update = useUpdateStepUpMethod();

  const hasTotp = session.data?.user?.has_totp ?? false;
  const passkeyAvailable = passkeysAvailable();
  const current = preferences.data?.step_up_method ?? NO_PREFERENCE;

  const options: { value: string; label: string; disabled?: boolean }[] = [
    { value: NO_PREFERENCE, label: t('account.stepup.opt.default') },
    { value: 'password', label: t('account.stepup.opt.password') },
    // Kept visible but unselectable when the method is not held, so the operator learns the choice
    // exists and what unlocks it (the design system's preferred pattern over a silently absent
    // option) — while still keeping the CURRENT value selectable even if capability lapsed.
    {
      value: 'totp_code',
      label: t('account.stepup.opt.totp'),
      disabled: !hasTotp && current !== 'totp_code',
    },
    {
      value: 'passkey',
      label: t('account.stepup.opt.passkey'),
      disabled: !passkeyAvailable && current !== 'passkey',
    },
  ];

  function change(value: string) {
    const method = value === NO_PREFERENCE ? null : (value as StepUpMethodPreference);
    update.mutate(method, {
      // The mutation already rolls the cache back on error; surface the server's message so a failed
      // save is never silent.
      onError: (error) => toast.error(error),
    });
  }

  return (
    <Card title={t('account.stepup.title')}>
      <div className="stack">
        <p className="field__hint">{t('account.stepup.lede')}</p>
        <Field
          label={t('account.stepup.label')}
          htmlFor="stepup-method"
          hint={t('account.stepup.hint')}
        >
          <Select
            id="stepup-method"
            options={options}
            value={current}
            disabled={preferences.isLoading || update.isPending}
            onChange={(e) => change(e.target.value)}
          />
        </Field>
      </div>
    </Card>
  );
}
