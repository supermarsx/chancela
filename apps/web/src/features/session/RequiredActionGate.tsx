/**
 * The required-action wall (t21 Screen B) — the signed-IN half of the TOTP web-lockout fix.
 *
 * ## Why this exists
 * `POST /v1/session` (and a completed 2FA challenge, and every `GET /v1/session` on reload) can
 * hand back a real token together with a `required_action`: the account has a session but is
 * **gated** until it does one thing. The server then 403s every route outside a tiny allow-list
 * (`lib.rs::session_wall_gate`), so if the SPA rendered the app chrome the operator would face a
 * wall of failed requests with no way to satisfy the gate. `AuthGate` therefore intercepts a
 * walled session HERE, before the chrome, and renders the matching wall instead of `children`.
 *
 * ## One place, three entry paths
 * `required_action` is read from `GET /v1/session` — the single source of truth the server
 * recomputes every request. So this wall covers, uniformly and without special-casing:
 *  - a one-step sign-in that returned `required_action`;
 *  - a two-step (2FA) challenge whose completion carried `required_action`;
 *  - a page reload of an already-walled session.
 * Every one of them funnels through the session cache, and clearing the underlying condition (the
 * wall invalidates `keys.session` on success) lifts the wall the instant the server stops
 * reporting it — no reload, no sign-out. If one condition clears into another (change the password,
 * then still owe a second factor) the refreshed session simply swaps this wall for the next.
 *
 * ## The two walls
 *  - **`change_password`** — the account holds a temporary/admin-set password and must set its
 *    own. Reuses {@link useSetUserSecret} with `{ password, current_password }`; the server clears
 *    `force_password_change` on any successful self set-secret.
 *  - **`enrol_two_factor`** — the account is configured to require a second factor and has none.
 *    Reuses {@link useEnrolTotp}/{@link useConfirmTotp} + {@link QrCode}, the same enrol → QR →
 *    confirm → backup-codes flow the Segurança tab ships, compacted for the wall.
 *
 * ## No trap, and no raw 401
 * Neither wall can be dismissed into the app, but both offer a **sign-out** escape
 * ({@link useDeleteSession}) so an operator who cannot complete the action is never stuck — the
 * same fail-closed posture the server takes. A wrong current-password or a wrong activation code is
 * a credential-proof `401` the API client leaves the session token alone for: it is surfaced as an
 * inline field reject, never a sign-out or a route change. No secret material (the new password, the
 * enrolment secret, the backup codes) is logged, put in a URL, or kept past the flow.
 *
 * Copy comes entirely from the task-owned {@link useAuthWallT} fallback module — this component adds
 * no shared-catalog keys (`common.brand` is the app's own existing brand string, read for the
 * header exactly as {@link SignIn} does).
 */
import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { ApiError } from '../../api/client';
import type { RequiredAction, UserView } from '../../api/types';
import {
  keys,
  useConfirmTotp,
  useDeleteSession,
  useEnrolTotp,
  usePasswordPolicy,
  useSetUserSecret,
} from '../../api/hooks';
import { useT } from '../../i18n';
import { Button, Field, Icon, InlineWarning, Input } from '../../ui';
import { QrCode } from '../pairing/QrCode';
import { useAuthWallT } from './authWallCopy';

/**
 * A refused credential proof — the `401` the API client flags `credentialProof` (so it does NOT
 * clear the session token). Mirrors the same helper in `EditUserPage`: a wrong current password or
 * a wrong activation code is a proof failure to surface inline, never an expired session to eject.
 */
function isRefused(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 401 || e.credentialProof === true);
}

/** A non-credential submit failure, shown inline: the server's own message when it has one (a
 *  password-policy reason is worth reading), the generic wall copy otherwise. */
function submitMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

export function RequiredActionGate({ action, user }: { action: RequiredAction; user: UserView }) {
  const t = useT();
  const st = useAuthWallT();
  const signOut = useDeleteSession();

  return (
    <div className="signin">
      <div className="signin__card">
        <p className="signin__brand">{t('common.brand')}</p>

        {action === 'change_password' ? (
          <ChangePasswordWall user={user} />
        ) : (
          <EnrolTwoFactorWall user={user} />
        )}

        {/* The escape hatch: an operator who cannot complete the action is never trapped. Signing
            out clears the session query → AuthGate falls back to the sign-in surface. */}
        <div className="signin__alt">
          <Button
            type="button"
            variant="ghost"
            icon={<Icon.SignOut />}
            disabled={signOut.isPending}
            onClick={() => signOut.mutate()}
          >
            {st('session.wall.signOut')}
          </Button>
        </div>
      </div>
    </div>
  );
}

/**
 * The change-password wall. Proves the current (temporary/admin-set) password and sets a new one;
 * the server enforces the active policy, so the requirements are shown for guidance and a
 * rejection is surfaced inline with the server's reason rather than a live client re-check.
 */
function ChangePasswordWall({ user }: { user: UserView }) {
  const st = useAuthWallT();
  const qc = useQueryClient();
  const policy = usePasswordPolicy();
  const setSecret = useSetUserSecret(user.id);

  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [currentError, setCurrentError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  // Live-checked in the confirm field; also blocks submit. The rest of the policy is the server's
  // to enforce (its reason is surfaced on failure) — this is the one rule the client owns.
  const mismatch = confirm !== '' && confirm !== next;
  const ready = current !== '' && next !== '' && confirm !== '' && !mismatch;

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setCurrentError(null);
    setFormError(null);
    if (!ready) return;
    setSecret.mutate(
      { password: next, current_password: current },
      {
        onSuccess: () => {
          // The server has cleared `force_password_change`; re-read the session so the wall lifts
          // (or swaps to the next required action). The hook already invalidated users/roster.
          void qc.invalidateQueries({ queryKey: keys.session });
        },
        onError: (err) => {
          // A wrong CURRENT password is the credential-proof 401 (no sign-out) → inline on that
          // field. Anything else (a policy rejection, say) → the server's message inline.
          if (isRefused(err)) setCurrentError(st('session.wall.changePassword.badCurrent'));
          else setFormError(submitMessage(err, st('session.wall.changePassword.error')));
        },
      },
    );
  }

  return (
    <form className="signin__form" onSubmit={submit}>
      <h1 className="signin__title">{st('session.wall.changePassword.title')}</h1>
      <p className="signin__subtitle">{st('session.wall.changePassword.intro')}</p>

      <Field
        label={st('session.wall.changePassword.currentLabel')}
        htmlFor="wall-pw-current"
        error={currentError}
      >
        <Input
          id="wall-pw-current"
          type="password"
          value={current}
          onChange={(e) => {
            setCurrent(e.target.value);
            setCurrentError(null);
          }}
          autoComplete="current-password"
          autoFocus
        />
      </Field>
      <Field label={st('session.wall.changePassword.newLabel')} htmlFor="wall-pw-new">
        <Input
          id="wall-pw-new"
          type="password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          autoComplete="new-password"
        />
      </Field>
      <Field
        label={st('session.wall.changePassword.confirmLabel')}
        htmlFor="wall-pw-confirm"
        error={mismatch ? st('session.wall.changePassword.mismatch') : null}
      >
        <Input
          id="wall-pw-confirm"
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="new-password"
        />
      </Field>

      {policy.data && policy.data.rules.length > 0 ? (
        <InlineWarning tone="info">
          <ul className="stack--tight">
            {policy.data.rules.map((rule) => (
              <li key={rule.code}>{rule.requirement}</li>
            ))}
          </ul>
        </InlineWarning>
      ) : null}

      {formError ? <InlineWarning tone="error">{formError}</InlineWarning> : null}

      <div className="signin__actions signin__actions--single">
        <Button type="submit" variant="primary" disabled={!ready || setSecret.isPending}>
          {setSecret.isPending
            ? st('session.wall.changePassword.submitting')
            : st('session.wall.changePassword.submit')}
        </Button>
      </div>
    </form>
  );
}

/**
 * The enrol-2FA wall. The compact enrol → QR + manual secret → confirm-with-a-code → backup-codes
 * flow the Segurança tab ships. The secret, provisioning URI and backup codes are shown once and
 * live only in local state for the flow's lifetime; the wall lifts (re-reads the session) when the
 * operator dismisses the backup codes, so they are never lost to an early refresh.
 */
function EnrolTwoFactorWall({ user }: { user: UserView }) {
  const st = useAuthWallT();
  const qc = useQueryClient();
  const enrol = useEnrolTotp(user.id);
  const confirm = useConfirmTotp(user.id);

  const [enrolment, setEnrolment] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState('');
  const [codeError, setCodeError] = useState<string | null>(null);
  const [enrolError, setEnrolError] = useState<string | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);

  const busy = enrol.isPending || confirm.isPending;

  function startEnrol() {
    setEnrolError(null);
    setCodeError(null);
    enrol.mutate(undefined, {
      onSuccess: (res) => setEnrolment({ secret: res.secret, uri: res.provisioning_uri }),
      onError: (err) => setEnrolError(submitMessage(err, st('session.wall.enrol.error'))),
    });
  }

  function cancelEnrol() {
    setEnrolment(null);
    setCode('');
    setCodeError(null);
    setEnrolError(null);
  }

  function submitCode(e: React.FormEvent) {
    e.preventDefault();
    setCodeError(null);
    confirm.mutate(
      { code: code.trim() },
      {
        onSuccess: (res) => {
          setEnrolment(null);
          setCode('');
          setBackupCodes(res.backup_codes);
        },
        onError: (err) => {
          // A wrong activation code is the credential-proof 401 → inline, keep the field editable.
          if (isRefused(err)) setCodeError(st('session.wall.enrol.badCode'));
          else setEnrolError(submitMessage(err, st('session.wall.enrol.error')));
        },
      },
    );
  }

  function finish() {
    // The factor is confirmed and `two_factor_required` is satisfied; re-read the session so the
    // wall lifts. Done only now — the operator has seen (and saved) the once-shown backup codes.
    setBackupCodes(null);
    void qc.invalidateQueries({ queryKey: keys.session });
  }

  return (
    <div className="signin__form">
      <h1 className="signin__title">{st('session.wall.enrol.title')}</h1>
      <p className="signin__subtitle">{st('session.wall.enrol.intro')}</p>

      {backupCodes ? (
        // The recovery codes take over the wall while shown once — nothing else is actionable
        // until the operator dismisses them, exactly as the Segurança enrol flow does.
        <InlineWarning tone="warn" title={st('session.wall.enrol.backupTitle')}>
          <p>{st('session.wall.enrol.backupIntro')}</p>
          <ul className="totp-backup-codes">
            {backupCodes.map((c) => (
              <li key={c}>
                <code className="mono">{c}</code>
              </li>
            ))}
          </ul>
          <div className="signin__actions signin__actions--single">
            <Button type="button" variant="primary" onClick={finish}>
              {st('session.wall.enrol.done')}
            </Button>
          </div>
        </InlineWarning>
      ) : enrolment ? (
        // Mid-enrolment: the QR + manual secret (shown once), then the activation code.
        <form className="form settings-rows" onSubmit={submitCode}>
          <div className="totp-enrol">
            <QrCode value={enrolment.uri} title={st('session.wall.enrol.scanHint')} size={200} />
            <div className="stack--tight">
              <p className="field__hint">{st('session.wall.enrol.scanHint')}</p>
              <p className="totp-enrol__secret">
                <span className="field__hint">{st('session.wall.enrol.secretLabel')}</span>{' '}
                <code className="mono">{enrolment.secret}</code>
              </p>
            </div>
          </div>
          <Field
            label={st('session.wall.enrol.codeLabel')}
            htmlFor="wall-totp-code"
            error={codeError}
          >
            <Input
              id="wall-totp-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              spellCheck={false}
              autoFocus
            />
          </Field>
          {enrolError ? <InlineWarning tone="error">{enrolError}</InlineWarning> : null}
          <div className="form__actions">
            <Button type="button" variant="ghost" disabled={busy} onClick={cancelEnrol}>
              {st('signin.challenge.back')}
            </Button>
            <Button type="submit" variant="primary" disabled={busy || code.trim() === ''}>
              {confirm.isPending
                ? st('session.wall.enrol.confirming')
                : st('session.wall.enrol.confirm')}
            </Button>
          </div>
        </form>
      ) : (
        // Not yet enrolling: the call to action.
        <>
          {enrolError ? <InlineWarning tone="error">{enrolError}</InlineWarning> : null}
          <div className="signin__actions signin__actions--single">
            <Button
              type="button"
              variant="primary"
              icon={<Icon.Shield />}
              disabled={busy}
              onClick={startEnrol}
            >
              {enrol.isPending
                ? st('session.wall.enrol.confirming')
                : st('session.wall.enrol.confirm')}
            </Button>
          </div>
        </>
      )}
    </div>
  );
}
