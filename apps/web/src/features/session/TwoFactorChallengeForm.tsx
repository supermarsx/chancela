/**
 * Screen A of the TOTP web-lockout fix (plan t21 §1) — the **two-step-verification challenge**.
 *
 * It is a transient sub-state of {@link SignIn}, NOT a route: `POST /v1/session` answered with a
 * challenge instead of a token, so no session exists yet. The operator's password already proved out
 * server-side; this screen collects the second factor and completes the sign-in via
 * {@link useCompleteChallenge} (`POST /v1/session/challenge`).
 *
 * ## Uniform-401 honesty (plan D4)
 * The server returns the SAME opaque 401 for a wrong code, a spent/expired challenge, and the
 * 5-attempt cap — the client cannot tell them apart. So a rejected code is always an **inline,
 * field-level** reject ("código incorreto"): the card never unmounts, never toasts a raw 401, never
 * routes, and the session is left untouched (the `credentialProof` tag on the `ApiError`, set by
 * `CREDENTIAL_PROOF_PATH`, guarantees the token store is not cleared). A persistent "Voltar" escape
 * back to the password form is always offered, and a local mirror of the server's 5-attempt cap sends
 * the operator back to the password step once the challenge is certainly spent.
 *
 * ## Backup codes (plan D5)
 * When the challenge accepts a recovery code (`methods` includes `backup_code`) the same single field
 * takes it — the server decides which factor was supplied by the code's shape. This screen IS the
 * lockout-recovery path, so the hint is shown whenever the option is live.
 *
 * The `challenge_id` and the `code` are credentials: never logged, never put in a URL, and dropped
 * from state the moment they are consumed (the code field clears on every reject).
 */
import { useEffect, useState } from 'react';
import { ApiError } from '../../api/client';
import type { TwoFactorChallengeView, UserView } from '../../api/types';
import { useCompleteChallenge } from '../../api/hooks';
import { Button, Field, Input, useToast } from '../../ui';
import { useAuthWallT } from './authWallCopy';

const CODE_FIELD_ID = 'signin-2fa-code';

/** The server's own cap (`TWO_FACTOR_MAX_ATTEMPTS`); mirrored locally so the certainly-spent
 *  challenge sends the operator back to the password step rather than looping on a dead handle. */
const MAX_ATTEMPTS = 5;

interface TwoFactorChallengeFormProps {
  /** The challenge arm of `POST /v1/session`: the opaque handle, accepted factors, and expiry. */
  challenge: TwoFactorChallengeView;
  /**
   * The code completed the challenge and {@link useCompleteChallenge} already established the
   * session; the host records the account (respecting its "remember" opt-out) and toasts success.
   */
  onCompleted: (user: UserView) => void;
  /**
   * Leave the challenge and return to the password form. Called by "Voltar" (no notice), by the
   * local attempt cap (`restart` notice), and on expiry (`expired` notice); the host surfaces the
   * notice above the sign-in form.
   */
  onLeave: (notice?: string) => void;
}

export function TwoFactorChallengeForm({
  challenge,
  onCompleted,
  onLeave,
}: TwoFactorChallengeFormProps) {
  const st = useAuthWallT();
  const toast = useToast();
  const complete = useCompleteChallenge();

  const [code, setCode] = useState('');
  const [attempts, setAttempts] = useState(0);
  const [rejected, setRejected] = useState(false);

  const acceptsBackup = challenge.methods.includes('backup_code');
  const busy = complete.isPending;

  // A soft mirror of the server's TTL: when the challenge expires the handle is spent, so drop back
  // to the password step with an honest "expirou" notice instead of letting the operator keep typing
  // codes the server will only ever 401. `onLeave` is stable (host `useCallback`) and `st` memoised,
  // so this arms exactly once per challenge and clears on unmount.
  useEffect(() => {
    const ms = new Date(challenge.expires_at).getTime() - Date.now();
    if (!Number.isFinite(ms)) return;
    if (ms <= 0) {
      onLeave(st('signin.challenge.expired'));
      return;
    }
    const id = setTimeout(() => onLeave(st('signin.challenge.expired')), ms);
    return () => clearTimeout(id);
  }, [challenge.expires_at, onLeave, st]);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const value = code.trim();
    if (value.length === 0) return;
    setRejected(false);
    complete.mutate(
      { challenge_id: challenge.challenge_id, code: value },
      {
        onSuccess: (result) => onCompleted(result.user),
        onError: (err) => {
          // A 401 is a credential-proof failure (wrong/spent/expired/capped — indistinguishable):
          // inline reject, drop the consumed code, keep the card mounted, refocus. Anything else
          // (500, network) is surfaced through the toast; a raw 401 is never rendered.
          if (err instanceof ApiError && err.status === 401) {
            const next = attempts + 1;
            setAttempts(next);
            setCode('');
            if (next >= MAX_ATTEMPTS) {
              onLeave(st('signin.challenge.restart'));
              return;
            }
            setRejected(true);
            document.getElementById(CODE_FIELD_ID)?.focus();
          } else {
            toast.error(err);
          }
        },
      },
    );
  }

  return (
    <form className="signin__form" onSubmit={submit}>
      <Field
        label={st('signin.challenge.codeLabel')}
        htmlFor={CODE_FIELD_ID}
        error={rejected ? st('signin.challenge.badCode') : null}
        hint={acceptsBackup ? st('signin.challenge.backupHint') : undefined}
      >
        <Input
          id={CODE_FIELD_ID}
          name="one-time-code"
          type="text"
          value={code}
          onChange={(e) => {
            setCode(e.target.value);
            setRejected(false);
          }}
          placeholder={st('signin.challenge.codePlaceholder')}
          inputMode="numeric"
          autoComplete="one-time-code"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          autoFocus
        />
      </Field>

      <div className="signin__actions signin__actions--single">
        <Button type="submit" variant="primary" disabled={busy || code.trim().length === 0}>
          {busy ? st('signin.challenge.confirming') : st('signin.challenge.confirm')}
        </Button>
      </div>

      {/* The persistent escape: abandons the challenge and returns to the password form. Left
          enabled through the brief completion window so the operator is never trapped. */}
      <div className="signin__actions">
        <Button type="button" variant="ghost" onClick={() => onLeave()}>
          {st('signin.challenge.back')}
        </Button>
      </div>
    </form>
  );
}
