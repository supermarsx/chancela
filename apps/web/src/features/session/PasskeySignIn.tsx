/**
 * Passkey sign-in (t10) — the discoverable-credential half of the entry screen.
 *
 * ## Conditional mediation is the designed flow; the button is the fallback
 *
 * `mediation: 'conditional'` asks the browser to offer this instance's passkeys **inside the
 * username field's own autofill dropdown**, with no modal and no click. It is armed on mount and
 * the promise simply stays pending until the operator picks a credential — which is why it needs
 * an `AbortController`: an outstanding conditional request is the only kind that must be
 * explicitly cancelled, and leaving one live would make the modal button below throw
 * `InvalidStateError` ("a request is already pending") rather than open a prompt.
 *
 * Three conditions all have to hold, and the component reports honestly when they do not rather
 * than pretending the modal button *is* conditional mediation:
 *
 *  - `PublicKeyCredential.isConditionalMediationAvailable()` must exist and resolve `true`;
 *  - the field it attaches to must carry `autocomplete="username webauthn"` — the token is what
 *    tells the browser which control to decorate, and without it the request is armed against
 *    nothing and silently never fires;
 *  - the instance must have passkeys configured, which is not knowable while signed out.
 *
 * That last one deserves its own note, because it is the reason this component asks the server
 * for options *before* it knows whether anyone can answer them. There is deliberately **no**
 * endpoint answering "does this account have a passkey?" — that is a user-enumeration oracle, and
 * `create_session`'s dummy verifier exists to close exactly that. So the affordance is offered on
 * capability, never on account state, and a `422` from an unconfigured instance is swallowed into
 * "not offered" rather than shown: telling a signed-out visitor how this deployment is configured
 * is the same leak by a longer route.
 *
 * ## Why no username is collected, and why that is the secure direction
 *
 * The browser resolves the credential from what it holds and returns the account's user handle
 * inside the assertion; the server never receives — and never asks for — an identifier. A
 * username-first passkey flow would have to ask.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';
import { keys } from '../../api/hooks';
import { setSessionToken } from '../../api/session';
import type { SessionResult } from '../../api/types';
import { useT } from '../../i18n';
import type { MessageKey } from '../../i18n/types';
import { Button, Icon, useToast } from '../../ui';
import {
  conditionalMediationAvailable,
  describeCeremonyFailure,
  passkeysAvailable,
  runAssertionCeremonyWithPrf,
  type AssertionWithPrf,
  type CeremonyFailure,
} from './webauthn';

/**
 * Refusal copy per failure. `cancelled` is absent by design — dismissing a prompt is not an error
 * and toasting it would punish the ordinary act of changing one's mind.
 */
const FAILURE_COPY: Record<Exclude<CeremonyFailure, 'cancelled'>, MessageKey> = {
  already_enrolled: 'signin.passkey.error.failed',
  rp_id_mismatch: 'signin.passkey.error.rpIdMismatch',
  unsupported: 'signin.passkey.error.unsupported',
  not_user_verified: 'signin.passkey.error.notUserVerified',
  failed: 'signin.passkey.error.failed',
};

/** The autocomplete token the username field must carry for conditional mediation to attach. */
export const PASSKEY_USERNAME_AUTOCOMPLETE = 'username webauthn';

export interface PasskeySignInProps {
  /** Called with the signed-in user once the session token is live. */
  onSignedIn: (user: SessionResult['user']) => void;
  /** Disables the button while the host has another sign-in in flight. */
  disabled?: boolean;
}

export function PasskeySignIn({ onSignedIn, disabled }: PasskeySignInProps) {
  const t = useT();
  const toast = useToast();
  const qc = useQueryClient();
  const [available, setAvailable] = useState(false);
  const [pending, setPending] = useState(false);
  // Held in a ref rather than state: aborting is an imperative act on a request that outlives any
  // render, and putting it in state would re-arm the effect every time it changed.
  const conditional = useRef<AbortController | null>(null);

  /**
   * Complete a sign-in from a credential the browser produced.
   *
   * The `CreateSessionOutcome` union is narrowed rather than assumed. A user-verified assertion is
   * already possession plus verification, so the server does not raise a two-factor challenge for
   * one — but "does not today" and "cannot" are different claims, and the second is not this
   * component's to make.
   */
  const complete = useCallback(
    async ({ credential, prfSecret }: AssertionWithPrf) => {
      // `prf_secret` is sent only when the credential produced a PRF output; its presence is what
      // lets the server mint a passwordless session, its absence is the honest password fallback.
      const outcome = await api.createPasskeySession({
        credential,
        ...(prfSecret ? { prf_secret: prfSecret } : {}),
      });
      if ('two_factor_challenge' in outcome) {
        throw new Error('a passkey assertion unexpectedly raised a two-factor challenge');
      }
      setSessionToken(outcome.token);
      qc.setQueryData(keys.session, await api.getSession());
      void qc.invalidateQueries({ queryKey: keys.roster });
      onSignedIn(outcome.user);
    },
    [onSignedIn, qc],
  );

  function report(error: unknown) {
    const failure = describeCeremonyFailure(error);
    if (failure === 'cancelled') return;
    // An error carrying a status came back from the server and already says something true in the
    // operator's language; only a DOM exception needs translating here.
    if (error instanceof Error && !('status' in error)) toast.error(t(FAILURE_COPY[failure]));
    else toast.error(error);
  }

  // Arm conditional mediation once, on mount. Everything about this is best-effort: an
  // unconfigured instance, an unsupported browser and an aborted request all land in the same
  // place — the visible button stays available and the operator loses nothing.
  useEffect(() => {
    if (!passkeysAvailable()) return;
    let cancelled = false;
    const controller = new AbortController();
    conditional.current = controller;

    void (async () => {
      if (!(await conditionalMediationAvailable())) return;
      let options;
      try {
        options = await api.beginPasskeySignIn();
      } catch {
        // Almost always a `422` from an instance with no RP ID configured. Silent by design: a
        // signed-out visitor learning how this deployment is configured is a leak, and there is
        // nothing for them to act on either way.
        return;
      }
      if (cancelled) return;
      setAvailable(true);
      try {
        const assertion = await runAssertionCeremonyWithPrf(options, {
          mediation: 'conditional',
          signal: controller.signal,
        });
        if (cancelled) return;
        await complete(assertion);
      } catch (error) {
        // An abort is this component unmounting or the operator taking the modal path instead —
        // both ordinary, neither worth a message.
        if (!cancelled) report(error);
      }
    })();

    return () => {
      cancelled = true;
      controller.abort();
      conditional.current = null;
    };
    // Mount-only: re-arming on every render would abort a live autofill prompt mid-choice.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // The visible button is offered on capability alone. It stays even when the conditional probe
  // said no, because a browser without autofill mediation can still run the modal ceremony
  // perfectly well — and hiding it there would remove passkey sign-in from every such browser.
  if (!passkeysAvailable()) return null;

  async function signIn() {
    // The outstanding conditional request must go first: two concurrent requests are an
    // `InvalidStateError`, which would surface as "failed" for a flow that is simply already busy.
    conditional.current?.abort();
    conditional.current = null;
    setPending(true);
    try {
      const options = await api.beginPasskeySignIn();
      await complete(await runAssertionCeremonyWithPrf(options));
    } catch (error) {
      report(error);
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="signin__alt">
      <Button
        type="button"
        variant="secondary"
        icon={<Icon.Shield />}
        disabled={disabled || pending}
        onClick={() => void signIn()}
      >
        {pending ? t('signin.passkey.pending') : t('signin.passkey.action')}
      </Button>
      <p className="field__hint">
        {available ? t('signin.passkey.hint.autofill') : t('signin.passkey.hint')}
      </p>
    </div>
  );
}
