/**
 * WebAuthn PRF → attestation-key unwrap secret (t10, `docs/passkeys.md` "PRF stability").
 *
 * ## Read this before wiring anything to it: THE PRF WRAP IS DEFERRED BY RULING
 *
 * **This is a decision, not a gap in the schedule** (`docs/passkeys.md`, amended at `7c84183b`).
 * No PRF-derived KEK goes near the attestation scalar until one browser session on a real
 * PRF-capable platform authenticator has confirmed all four of:
 *
 * - the PRF output is present at all;
 * - it is **stable across two consecutive sign-ins**;
 * - it is **stable across a browser restart**;
 * - all of the above **with the constant salt** this module derives against.
 *
 * Nobody in this codebase has yet evaluated a real PRF output against real hardware, and
 * conditional mediation is unverified for the same reason. Key custody is the wrong place to spend
 * an unverified assumption — the iOS 18.0→18.4 incident is what happens when that assumption is
 * spent and turns out to be wrong.
 *
 * **What ships instead:** enrolment provisions a PRF-capable credential, sign-in authenticates,
 * and the attestation key is unlocked by the **password** at first attestation. Do not build the
 * passwordless-unwrap path into the ceremony ahead of that verification.
 *
 * Three things would also have to change server-side, and they are listed here so that a reader
 * who does get the hardware confirmation knows the shape of the work rather than rediscovering it.
 * They are **not** a checklist that, once ticked, releases the ruling above:
 *
 * 1. **`POST /v1/session/passkey` takes only `{ credential }`.** `PasskeySignIn` has no field for a
 *    derived secret, and serde ignores unknown members — so a secret sent today would travel over
 *    the wire, be dropped on the floor, and unlock nothing. Transmitting key material to be
 *    discarded is strictly worse than not deriving it.
 * 2. **There is no salt setting.** Nothing server-side publishes the stable value the derivation
 *    needs, and a locally-invented one derives a different key on every device and every reload.
 * 3. **The server never *asks* for `prf` on the sign-in ceremony, and a client cannot add it.**
 *    This is the one that would waste a day. `begin_authentication` builds
 *    `DiscoverableCredentialRequestOptions::passkey(&rp.rp_id)` with default extensions, and
 *    verification runs with `webauthn_rp`'s `error_on_unsolicited_extensions` at its `true`
 *    default — so an assertion carrying an `extensions.prf.eval` the server did not request is
 *    **refused**, not ignored. PRF at sign-in is not client-addable; it needs
 *    `webauthn_rp::request::auth::Extension::prf` set server-side.
 *    `an_unsolicited_extension_at_sign_in_is_refused` in `crates/chancela-api/tests/passkeys.rs`
 *    pins exactly this.
 *
 * So this module is **the derivation and nothing else**, verified against published vectors rather
 * than against a caller. It has no production call site and deliberately fabricates none — which is
 * the shape the ruling asks for. {@link stripPrfResults} in `./webauthn` is the only PRF-related
 * behaviour that ships.
 *
 * ## The salt is a CONSTANT — per-credential is ruled out, not merely unimplemented
 *
 * `docs/passkeys.md` previously said the salt was *"server-supplied, per-credential, stable"*. The
 * ruling closes that: a **constant** salt, and explicitly **no `prf_salt` on `PasskeyCredential`**.
 *
 * The reason is the discoverable-credential constraint, not a preference. A discoverable sign-in
 * does not learn which credential will answer until the assertion comes back — that is the entire
 * point of dropping the username, and the reason this product has no enumeration oracle — so the
 * server cannot pick that credential's salt when it mints the challenge. Both escapes break a
 * frozen ruling rather than merely costing something:
 *
 * - `evalByCredential` (`webauthn_rp`'s `CredentialSpecificExtension::prf`) needs a populated
 *   `allowCredentials`, i.e. a username-first flow — the oracle itself;
 * - splitting into two ceremonies costs **two biometric prompts per sign-in**.
 *
 * A constant is sound rather than a compromise: CTAP2.1 keeps the per-credential seed
 * (`CredRandomWithUV`) inside the authenticator, so the salt only does domain separation — binding
 * the output to this product rather than to another relying party using the same passkey. Two
 * credentials of one user therefore still derive **different** secrets, so each still carries its
 * own wrap and Invariant 2 is untouched.
 *
 * ## What the derivation is, and why it is not just the PRF output
 *
 * Raw PRF output is **input keying material, not a key** — Yubico is explicit about this, and the
 * reason is structural: the authenticator produces it by HMAC over its per-credential seed, so it
 * is uniform, but it is also the *same* value for every relying-party use of that credential. One
 * HKDF-SHA256 extraction with a salt and a versioned `info` label binds it to this product and this
 * purpose, so the same passkey used for something else derives something else.
 *
 * One `crypto.subtle.deriveBits` call. Nothing hand-rolled, and nothing that could become
 * hand-rolled: HKDF is a WebCrypto primitive here, not an implementation.
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
