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
 *  - **Step-up re-auth** (§8-F) — the acting user re-proves identity with their password OR a
 *    one-time recovery phrase. A valid session token alone is never enough.
 *
 * This hook owns only the FIELDS and whether they are satisfied. It deliberately does not own the
 * submit, the error state or the 403 → `confirm.reauth.required` mapping: those belong to whatever
 * surface is doing the mutating, and the two surfaces present them differently (a dialog footer vs
 * a step body). The rendered markup, the label copy and the field ids are unchanged from when this
 * lived in `ConfirmActionModal`, so every existing call site and test sees exactly what it saw.
 */
import { useEffect, useState, type ReactNode } from 'react';
import type { ReAuth } from '../api/types';
import { useT } from '../i18n';

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
  /** Require password / recovery-phrase step-up re-auth. */
  requireReauth?: boolean;
  /** Unique prefix for the field ids, so two gates can never collide on one page. */
  idPrefix: string;
  /** Fired when the operator switches between password and recovery phrase (clear a stale error). */
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
  const [typed, setTyped] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const [password, setPassword] = useState('');
  const [recovery, setRecovery] = useState('');

  useEffect(() => {
    setTyped('');
    setUseRecovery(false);
    setPassword('');
    setRecovery('');
  }, [resetKey]);

  const phraseOk = phrase === undefined || typed === phrase;
  const reauthValue = useRecovery ? recovery.trim() : password;
  const reauthOk = !requireReauth || reauthValue.length > 0;

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
          <label className="field__label" htmlFor={`${idPrefix}-reauth`}>
            {useRecovery ? t('confirm.reauth.recovery') : t('confirm.reauth.password')}
          </label>
          {useRecovery ? (
            <input
              id={`${idPrefix}-reauth`}
              className="control"
              type="text"
              value={recovery}
              autoComplete="off"
              onChange={(e) => setRecovery(e.target.value)}
            />
          ) : (
            <input
              id={`${idPrefix}-reauth`}
              className="control"
              type="password"
              value={password}
              autoComplete="current-password"
              onChange={(e) => setPassword(e.target.value)}
            />
          )}
          <p className="field__hint">
            {t('confirm.reauth.hint')}{' '}
            <button
              type="button"
              className="linkish"
              onClick={() => {
                setUseRecovery((v) => !v);
                onProofKindChange?.();
              }}
            >
              {useRecovery ? t('confirm.reauth.usePassword') : t('confirm.reauth.useRecovery')}
            </button>
          </p>
        </div>
      ) : null}
    </>
  );

  return {
    fields,
    ready: phraseOk && reauthOk,
    reauth: !requireReauth ? {} : useRecovery ? { recovery_phrase: recovery.trim() } : { password },
  };
}
