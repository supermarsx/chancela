/**
 * WebAuthn PRF → attestation-key unwrap secret (t10, `docs/passkeys.md` "PRF stability"), **wired**.
 *
 * A passkey with a working PRF extension unlocks the attestation key with no password at sign-in.
 * This module is the client-side crypto for that: it turns a credential's PRF output into the secret
 * that opens the credential's server-side wrap. It is one `crypto.subtle.deriveBits` HKDF call and
 * two constants; nothing here is hand-rolled and nothing could become so.
 *
 * ## The client adds `prf`; the server does not
 *
 * `docs/passkeys.md` said the server would request `prf` on the `get()` ceremony. **That is
 * impossible with `webauthn_rp`:** the library rejects an assertion from a *non*-PRF credential when
 * the ceremony requested `prf`, and a discoverable sign-in cannot know in advance which credential
 * will answer — so requesting `prf` would break sign-in for every non-PRF authenticator. Instead the
 * **browser** adds `extensions.prf.eval.first = {@link PRF_EVAL_SALT}` (see `./webauthn`), the server
 * verifies those paths with `error_on_unsolicited_extensions: false`, and the raw output is stripped
 * ({@link stripPrfResults}) so only the derived KEK — never the PRF output — leaves the browser. The
 * Rust module header records this correction to the doc.
 *
 * ## Two constant salts, and why constant is correct
 *
 * - {@link PRF_EVAL_SALT} is the `first` input fed to the authenticator. Constant, not
 *   per-credential: a discoverable sign-in does not learn which credential answers until the
 *   assertion returns (the property that removes the enumeration oracle), so a per-credential salt is
 *   impossible; and CTAP2.1 already keeps the per-credential seed (`CredRandomWithUV`) *inside* the
 *   authenticator, so this only supplies domain separation between relying parties. Two credentials
 *   of one user still derive **different** outputs, so each still carries its own wrap — Invariant 2
 *   is untouched. There is deliberately **no `prf_salt` on `PasskeyCredential`**.
 * - {@link ATTESTATION_KEK_SALT} is the HKDF salt. Raw PRF output is **input keying material, not a
 *   key** (Yubico is explicit): uniform, but the same value for every relying-party use of the
 *   credential. One HKDF-SHA256 extraction with this salt and the versioned {@link ATTESTATION_KEK_INFO}
 *   label binds it to this product and this purpose.
 *
 * ## Stability is the residual risk, and the password wrap is the safety net
 *
 * A PRF output that moves (the iOS 18.0→18.4 incident) makes the derived KEK stop opening the wrap.
 * That is survivable **only because the wrap is never the only wrap**: the attestation key keeps its
 * password wrap on the server, so a moved output degrades to the password prompt, never to key loss.
 * Real-hardware PRF stability (across sign-ins, across a browser restart) remains the one external
 * confirmation this wiring does not itself prove — a software authenticator proves the plumbing, not
 * the hardware.
 */

/**
 * The purpose label mixed into the derivation.
 *
 * **Versioned, and the version is not decoration.** If the derivation ever changes shape, the old
 * label must keep deriving the old secret or every attestation key wrapped under it becomes
 * unopenable — which is the exact failure iOS 18.4 caused by moving PRF output out from under
 * shipping data. A new scheme takes a new label and a migration, never an edit to this string.
 */
export const ATTESTATION_KEK_INFO = 'chancela-attestation-kek-v1';

/**
 * The `first` input the authenticator evaluates its PRF against (`extensions.prf.eval.first`).
 *
 * A fixed, instance-independent constant — the browser injects it into every sign-in and PRF-wrap
 * `get()`, and the same bytes must reappear at enrolment and at sign-in or the derived KEK would
 * differ and open nothing. Its exact value is arbitrary (it is domain separation, not a secret); the
 * versioned string keeps it self-documenting. Changing it re-derives every PRF output and orphans
 * every wrap, so a new scheme takes a new value, never an edit to this one.
 */
export const PRF_EVAL_SALT: Uint8Array = new TextEncoder().encode(
  'chancela.attestation.passkey.prf.eval.v1',
);

/**
 * The HKDF salt mixed into {@link deriveAttestationKek}. Constant and versioned for the same reason
 * as {@link ATTESTATION_KEK_INFO}: it is part of the derivation's identity, so moving it would strand
 * every attestation key already wrapped under the old value.
 */
export const ATTESTATION_KEK_SALT: Uint8Array = new TextEncoder().encode(
  'chancela.attestation.passkey.kek.salt.v1',
);

/** Length of the derived secret, in bits — 256, matching the XChaCha20-Poly1305 KEK input. */
const DERIVED_BITS = 256;

/**
 * Derive the attestation-key unwrap secret from a PRF output.
 *
 * `prfOutput` is `getClientExtensionResults().prf.results.first`; `salt` is the **stable,
 * server-supplied** salt — instance-wide, for the reason in the module header, and emphatically
 * *not* the challenge. A challenge is fresh per ceremony, so deriving against one would produce a
 * different secret every sign-in and unwrap nothing on the second attempt. Per-credential
 * separation is not this value's job and never was: the authenticator's own seed already provides
 * it.
 *
 * Returns raw bytes. The caller base64url-encodes them for transport and calls {@link zeroize} on
 * both the PRF output and this result as soon as they are consumed.
 */
export async function deriveAttestationKek(
  prfOutput: ArrayBuffer | Uint8Array,
  salt: ArrayBuffer | Uint8Array,
): Promise<Uint8Array> {
  const ikm = prfOutput instanceof Uint8Array ? prfOutput : new Uint8Array(prfOutput);
  if (ikm.length === 0) {
    throw new Error('PRF output is empty; the authenticator did not evaluate the extension');
  }
  // `false` for extractable: the IKM is a one-shot input and nothing may read it back out of the
  // key object. The derivation is the only thing it is for.
  const key = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: (salt instanceof Uint8Array ? salt : new Uint8Array(salt)) as BufferSource,
      info: new TextEncoder().encode(ATTESTATION_KEK_INFO) as BufferSource,
    },
    key,
    DERIVED_BITS,
  );
  return new Uint8Array(bits);
}

/**
 * Overwrite a secret buffer in place.
 *
 * Best-effort by nature: JavaScript engines copy and move values freely, so this cannot promise the
 * bytes are gone from memory. What it *does* do is bound how long a live reference holds readable
 * key material, which is the same treatment `password` gets on this path and the reason the ruling
 * asks for it. Not doing it because it is imperfect would be choosing the strictly worse option.
 */
export function zeroize(secret: Uint8Array): void {
  secret.fill(0);
}
