/**
 * The two proofs a server-gated action demands, as ONE implementation (t94).
 *
 * `ConfirmActionModal` owned these fields inline, which was fine while every gated action was a
 * single dialog with a single confirmation. The CMD production test signature is not: the server
 * floors `ConfirmationAction::CmdTestSignature` at `ConfirmWithReauthAndPhrase` and re-checks the
 * proof on BOTH phases independently, so the phrase and the step-up have to be collected twice
 * inside one stepped flow. Copying the fields into that flow would have left two implementations
 * of a security gate free to drift apart, so they moved here instead and both surfaces call this.
 *
 *  - **Type-to-confirm phrase** — the operator re-types the EXACT phrase the server expects. The
 *    gate is not `ready` until the typed text matches byte-for-byte; the server re-checks it too.
 *  - **Step-up re-auth** (§8-F) — the acting user re-proves identity with their password, a
 *    one-time recovery phrase, or (t10) an assertion from one of their own passkeys. A valid
 *    session token alone is never enough.
 *
 * The passkey arm exists because without it a **passkey-only account cannot satisfy any gate
 * without spending its recovery phrase** — which is single-use, so a second destructive action
 * would find it gone. That is a lockout produced by two individually-correct rules, which is
 * exactly the shape that survives review. Two properties keep it from being a widening: the
 * assertion answers a challenge minted by `POST /v1/reauth/passkey/options` and scoped to step-up
 * (a captured sign-in assertion is not a weaker match, it is not a match), and the server checks
 * the credential belongs to the acting user — redeeming a challenge proves a ceremony started,
 * never by whom.
 *
 * This hook owns only the FIELDS and whether they are satisfied. It deliberately does not own the
 * submit, the error state or the 403 → `confirm.reauth.required` mapping: those belong to whatever
 * surface is doing the mutating, and the two surfaces present them differently (a dialog footer vs
 * a step body). The rendered markup, the label copy and the field ids are unchanged from when this
 * lived in `ConfirmActionModal`, so every existing call site and test sees exactly what it saw.
 */
import { useEffect, useRef, useState, type ReactNode } from 'react';
import type { PasskeyCredentialJson, ReAuth } from '../api/types';
import { api } from '../api/client';
import { useSession, useUserPreferences } from '../api/hooks';
import { useT } from '../i18n';
import {
  describeCeremonyFailure,
  passkeysAvailable,
  runAssertionCeremony,
} from '../features/session/webauthn';

/**
 * Which credential the operator is proving with. A set of alternatives, deliberately not a rung on
 * `ConfirmationStrictness` — that ladder answers *how hard*, and this answers *with what*. Adding a
 * rung would silently change the strictness every deployment had already chosen.
 *
 * `totp` is a live code from the acting user's own confirmed second factor — an equal-strength
 * alternative to the password for what step-up defends against (a session-only attacker holds
 * neither). It is offered only when the account actually holds a confirmed factor (`has_totp`); the
 * passkey arm stays offered on browser capability alone, because — unlike TOTP, whose held-state
 * `UserView` already publishes — asking "does this account hold a passkey?" would build the very
 * enumeration oracle the sign-in surface removed.
 */
type ProofKind = 'password' | 'recovery' | 'passkey' | 'totp';

export interface ConfirmationGateOptions {
  /**
   * The gathered proofs are cleared whenever this value changes.
   *
   * A dialog passes its `open` flag (fresh proofs each time it opens). A multi-phase flow passes
   * its phase, because a phase boundary is exactly where the server stops trusting the previous
   * proof — carrying a typed phrase across it would let the UI imply one confirmation covered two
   * requests. It must NOT change on a failed attempt: a rejected OTP should not also cost the
   * operator their phrase and password.
   */
  resetKey: unknown;
  /** The exact type-to-confirm phrase; omit for no phrase gate. */
  phrase?: string;
  /** Require step-up re-auth — password, recovery phrase, or a passkey assertion. */
  requireReauth?: boolean;
  /** Unique prefix for the field ids, so two gates can never collide on one page. */
  idPrefix: string;
  /** Fired when the operator switches proof kind, so a caller can clear a stale error. */
  onProofKindChange?: () => void;
}

export interface ConfirmationGate {
  /** The phrase and step-up fields, in the order every gated surface shows them. */
  fields: ReactNode;
  /** True once both proofs are satisfied. The caller ANDs this with its own gates. */
  ready: boolean;
  /** The proof to send. `{}` when `requireReauth` is false. */
  reauth: ReAuth;
}

export function useConfirmationGate({
  resetKey,
  phrase,
  requireReauth = false,
  idPrefix,
  onProofKindChange,
}: ConfirmationGateOptions): ConfirmationGate {
  const t = useT();
  // The acting user's held methods and their preferred default, read from the caches the app has
  // already primed. `has_totp` gates the TOTP arm; the step-up preference picks which arm opens
  // first. Both are read-only hints — the server verifies whatever proof is actually presented — so
  // an absent/stale value simply falls back to the password arm, today's behaviour.
  const session = useSession();
  const preferences = useUserPreferences();
  const hasTotp = session.data?.user?.has_totp ?? false;
  const passkeyAvailable = passkeysAvailable();
  const preferred = preferences.data?.step_up_method;

  // The arm to open on: the user's preference when they can actually satisfy it, else the password.
  // Recovery is never a default (it is single-use break-glass), so it is never resolved here.
  const defaultKind: ProofKind =
    preferred === 'totp_code' && hasTotp
      ? 'totp'
      : preferred === 'passkey' && passkeyAvailable
        ? 'passkey'
        : 'password';
  // Read at reset time via a ref so a preference that finishes loading AFTER the gate opened still
  // seeds the next reset, without a mid-dialog preference refetch wiping a proof the operator has
  // already started entering.
  const defaultKindRef = useRef(defaultKind);
  defaultKindRef.current = defaultKind;
  // Whether the operator has taken over the proof kind — by switching arms or entering a proof. Once
  // they have, a preference that only now finishes loading must not yank them onto a different arm.
  const touchedRef = useRef(false);

  const [typed, setTyped] = useState('');
  const [kind, setKind] = useState<ProofKind>(defaultKind);
  const [password, setPassword] = useState('');
  const [recovery, setRecovery] = useState('');
  const [totp, setTotp] = useState('');
  // The gathered step-up assertion, and any local ceremony failure. Held here rather than
  // submitted immediately because the gate's job is to *have* a proof when the caller submits —
  // the assertion answers a challenge issued for step-up and is spent by the operation, not by
  // being collected.
  const [assertion, setAssertion] = useState<PasskeyCredentialJson | null>(null);
  const [ceremony, setCeremony] = useState<'idle' | 'running' | 'failed'>('idle');

  useEffect(() => {
    setTyped('');
    setKind(defaultKindRef.current);
    setPassword('');
    setRecovery('');
    setTotp('');
    setAssertion(null);
    setCeremony('idle');
    touchedRef.current = false;
  }, [resetKey]);

  // Apply the preferred arm once the preference (and the `has_totp` it is gated on) finishes
  // loading, but only while the operator has not taken over — so a dialog opened before the caches
  // were warm still lands on the user's chosen method, without ever overriding a manual switch or a
  // proof already being entered.
  useEffect(() => {
    if (!touchedRef.current) setKind(defaultKind);
  }, [defaultKind]);

  /**
   * Run a **step-up-scoped** assertion.
   *
   * `beginPasskeyStepUp` is `POST /v1/reauth/passkey/options`, and the scoping is the whole
   * security of this arm: the challenge it mints is bound to this session's user and to the
   * step-up purpose, so an assertion captured during a sign-in answers nothing here. Reaching for
   * the sign-in options endpoint instead would compile, work in a happy-path test, and make every
   * destructive gate satisfiable by a replayed sign-in.
   */
  async function collectAssertion() {
    touchedRef.current = true;
    setCeremony('running');
    setAssertion(null);
    try {
      const options = await api.beginPasskeyStepUp();
      setAssertion(await runAssertionCeremony(options));
      setCeremony('idle');
    } catch (error) {
      // Cancelling is an ordinary act and leaves the gate exactly as it was, ready to try again.
      setCeremony(describeCeremonyFailure(error) === 'cancelled' ? 'idle' : 'failed');
    }
  }

  const phraseOk = phrase === undefined || typed === phrase;
  const reauthOk =
    !requireReauth ||
    (kind === 'passkey'
      ? assertion !== null
      : kind === 'totp'
        ? totp.trim().length > 0
        : (kind === 'recovery' ? recovery.trim() : password).length > 0);

  /** Switch proof kind, discarding whatever the previous one had gathered. */
  function switchTo(next: ProofKind) {
    touchedRef.current = true;
    setKind(next);
    setAssertion(null);
    setCeremony('idle');
    onProofKindChange?.();
  }

  // Every method the operator may switch TO from the current arm, in a stable order. Password and
  // recovery are always offerable; the passkey arm on browser capability alone (see the note on
  // `ProofKind`); the TOTP arm only when the account holds a confirmed factor. The current arm is
  // excluded — you do not switch to where you already are.
  const otherMethods = (
    [
      ['password', true],
      ['recovery', true],
      ['totp', hasTotp],
      ['passkey', passkeyAvailable],
    ] as const
  )
    .filter(([method, available]) => available && method !== kind)
    .map(([method]) => method);

  /** The switch-link copy key for a method offered as an alternative to the current arm. */
  const switchLabel: Record<Exclude<ProofKind, 'recovery'> | 'recovery', string> = {
    password: t('confirm.reauth.usePassword'),
    recovery: t('confirm.reauth.useRecovery'),
    passkey: t('confirm.reauth.usePasskey'),
    totp: t('confirm.reauth.useTotp'),
  };

  const fields = (
    <>
      {phrase !== undefined ? (
        <div className="field">
          <label className="field__label" htmlFor={`${idPrefix}-phrase`}>
            {t('confirm.phraseLabel', { phrase })}
          </label>
          <input
            id={`${idPrefix}-phrase`}
            className="control mono"
            value={typed}
            autoComplete="off"
            autoCapitalize="characters"
            spellCheck={false}
            placeholder={phrase}
            onChange={(e) => setTyped(e.target.value)}
          />
          {typed.length > 0 && !phraseOk ? (
            <p className="field__error" role="alert">
              {t('confirm.phraseMismatch')}
            </p>
          ) : null}
        </div>
      ) : null}

      {requireReauth ? (
        <div className="field">
          {/* A `<label for>` for the two text inputs; a plain caption for the passkey arm, where
              the control is a BUTTON. A button is labelable, so a `<label for>` pointing at it
              would *replace* its accessible name — the control would read as "Chave de acesso"
              while visibly saying "Confirmar no aparelho", which is exactly the label-in-name
              mismatch that makes voice control unable to activate it. */}
          {kind === 'passkey' ? (
            <p className="field__label">{t('confirm.reauth.passkey')}</p>
          ) : (
            <label className="field__label" htmlFor={`${idPrefix}-reauth`}>
              {kind === 'recovery'
                ? t('confirm.reauth.recovery')
                : kind === 'totp'
                  ? t('confirm.reauth.totp')
                  : t('confirm.reauth.password')}
            </label>
          )}
          {kind === 'passkey' ? (
            // A button rather than an input: there is nothing to type, so it names itself.
            <>
              <button
                id={`${idPrefix}-reauth`}
                type="button"
                className="btn btn--secondary"
                disabled={ceremony === 'running'}
                onClick={() => void collectAssertion()}
              >
                {ceremony === 'running'
                  ? t('confirm.reauth.passkey.pending')
                  : assertion
                    ? t('confirm.reauth.passkey.again')
                    : t('confirm.reauth.passkey.action')}
              </button>
              {assertion ? (
                <p className="field__hint" role="status">
                  {t('confirm.reauth.passkey.ready')}
                </p>
              ) : null}
              {ceremony === 'failed' ? (
                <p className="field__error" role="alert">
                  {t('confirm.reauth.passkey.failed')}
                </p>
              ) : null}
            </>
          ) : kind === 'recovery' ? (
            <input
              id={`${idPrefix}-reauth`}
              className="control"
              type="text"
              value={recovery}
              autoComplete="off"
              onChange={(e) => {
                touchedRef.current = true;
                setRecovery(e.target.value);
              }}
            />
          ) : kind === 'totp' ? (
            <input
              id={`${idPrefix}-reauth`}
              className="control mono"
              type="text"
              value={totp}
              inputMode="numeric"
              autoComplete="one-time-code"
              autoCapitalize="off"
              spellCheck={false}
              maxLength={6}
              onChange={(e) => {
                touchedRef.current = true;
                setTotp(e.target.value);
              }}
            />
          ) : (
            <input
              id={`${idPrefix}-reauth`}
              className="control"
              type="password"
              value={password}
              autoComplete="current-password"
              onChange={(e) => {
                touchedRef.current = true;
                setPassword(e.target.value);
              }}
            />
          )}
          {/* One "prove it another way" line offering every method the operator holds but the
              current arm. The password and recovery-phrase links are always present; the TOTP link
              only when the account holds a confirmed factor (`has_totp`); the passkey link on
              browser capability alone — the gate deliberately never asks whether THIS account holds
              a passkey, because that answer is an enumeration oracle (see the note on `ProofKind`).
              A user without one simply finds the ceremony returns nothing usable. */}
          <p className="field__hint">
            {t('confirm.reauth.hint')}
            {otherMethods.map((method) => (
              <span key={method}>
                {' '}
                <button type="button" className="linkish" onClick={() => switchTo(method)}>
                  {switchLabel[method]}
                </button>
              </span>
            ))}
          </p>
        </div>
      ) : null}
    </>
  );

  return {
    fields,
    ready: phraseOk && reauthOk,
    reauth: !requireReauth
      ? {}
      : kind === 'passkey'
        ? // `assertion` is non-null whenever `ready` is, but the gate cannot compel a caller to
          // check `ready` first, so an empty proof is sent rather than a malformed one — the
          // server answers a missing proof with the same uniform 403 as a wrong one.
          assertion
          ? { passkey: { credential: assertion } }
          : {}
        : kind === 'totp'
          ? { totp_code: totp.trim() }
          : kind === 'recovery'
            ? { recovery_phrase: recovery.trim() }
            : { password },
  };
}
