/**
 * The browser half of the WebAuthn ceremonies (t10) — everything between the server's options blob
 * and the credential JSON that goes back.
 *
 * The server speaks the **JSON** dialect of WebAuthn in both directions: `webauthn_rp` serialises
 * `PublicKeyCredentialCreationOptionsJSON` / `…RequestOptionsJSON` with base64url members, and it
 * parses the response through `from_json_relaxed`, which takes exactly what
 * `PublicKeyCredential.toJSON()` produces. So this module is a codec, not a re-modelling: it
 * decodes the base64url members the DOM API insists on receiving as `BufferSource`, and it hands
 * the response back verbatim.
 *
 * ## Four things here are load-bearing rather than plumbing
 *
 * 1. **PRF results are stripped before the credential is sent** ({@link stripPrfResults}). This is
 *    the one place the "the server never sees the PRF output" ruling is actually enforced, and it
 *    is not enforced anywhere else in the stack: `toJSON()` serialises
 *    `clientExtensionResults.prf.results` along with everything else, so a ceremony that evaluated
 *    PRF and then posted its own `toJSON()` would put the unwrap secret in a request body, in
 *    plaintext, as a side effect of asking for it. See {@link stripPrfResults} for why it strips
 *    `results` and keeps `enabled`.
 * 2. **A UV-less assertion is refused here, by name** ({@link assertionWasUserVerified}). CTAP2.1
 *    derives PRF from a different seed depending on whether user verification happened, so a
 *    UV-less assertion cannot unwrap anything — and the server's refusal for it is the same
 *    uniform "not recognised" as a wrong credential. Posting it would trade a precise local fact
 *    for an indistinguishable remote one.
 * 3. **`SecurityError` names the misconfiguration** ({@link describeCeremonyFailure}). A wrong
 *    `auth.passkeys.rp_id` fails *inside the browser*; the server never sees the request and
 *    therefore can never report it. If this did not translate the DOM exception, the only symptom
 *    of the single most expensive misconfiguration in this feature would be a button that does
 *    nothing.
 * 4. **Tauri is refused before the API is touched** ({@link passkeySupport}). The desktop shell
 *    serves the app from `tauri.localhost`, so the only RP ID a page there may assert is
 *    `tauri.localhost` — and WebKitGTK implements no WebAuthn at all.
 */
import { isTauri } from '../../desktop/tauri';
import type { CeremonyOptionsView, PasskeyCredentialJson } from '../../api/types';

// =================================================================================================
// base64url
// =================================================================================================

/** Decode a base64url string (no padding) to bytes. */
export function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/gu, '+').replace(/_/gu, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

/** Encode bytes as base64url with no padding — the encoding every WebAuthn JSON member uses. */
export function toBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/u, '');
}

// =================================================================================================
// Capability
// =================================================================================================

/** Why passkeys are unavailable on this client, or `null` when they are available. */
export type PasskeyUnavailableReason = 'desktop_shell' | 'browser';

/**
 * Whether this client can run a passkey ceremony at all, and if not, which honest sentence to show.
 *
 * The two reasons are genuinely different and must not be collapsed: `browser` means "this browser
 * cannot do it, try another"; `desktop_shell` means "this will never work here, do it in a
 * browser". Telling a Tauri user their browser is too old would send them to reinstall something
 * that cannot help.
 *
 * The Tauri check comes **first** and is not a fallback. WebView2 on Windows *does* implement
 * WebAuthn, so a capability probe inside the desktop shell answers "yes" and then every enrolment
 * produces a credential bound to `tauri.localhost` that the deployment's own domain can never use.
 * A working API is exactly the wrong thing to test for here.
 */
export function passkeySupport(): PasskeyUnavailableReason | null {
  if (isTauri()) return 'desktop_shell';
  if (typeof window === 'undefined') return 'browser';
  const supported =
    typeof window.PublicKeyCredential === 'function' &&
    typeof navigator.credentials?.create === 'function' &&
    typeof navigator.credentials?.get === 'function';
  return supported ? null : 'browser';
}

/** Shorthand for {@link passkeySupport} returning no reason. */
export function passkeysAvailable(): boolean {
  return passkeySupport() === null;
}

/**
 * Whether the browser will offer passkeys in an autofill dropdown (`mediation: 'conditional'`).
 *
 * Never throws and never rejects: the method is absent on older browsers and has been observed to
 * reject rather than resolve `false`, and a sign-in screen must not fail to render because a
 * capability probe was unhappy. A `false` here means the modal button is the whole flow, which is
 * a working sign-in — not a degraded one.
 */
export async function conditionalMediationAvailable(): Promise<boolean> {
  if (!passkeysAvailable()) return false;
  const probe = window.PublicKeyCredential?.isConditionalMediationAvailable;
  if (typeof probe !== 'function') return false;
  try {
    return await probe.call(window.PublicKeyCredential);
  } catch {
    return false;
  }
}

// =================================================================================================
// Options decoding
// =================================================================================================

/** The subset of the options JSON this module has to rewrite; everything else passes through. */
interface OptionsJson {
  challenge?: unknown;
  user?: { id?: unknown; [key: string]: unknown };
  excludeCredentials?: { id?: unknown; [key: string]: unknown }[];
  allowCredentials?: { id?: unknown; [key: string]: unknown }[];
  [key: string]: unknown;
}

function decodeIfString(value: unknown): unknown {
  // `.buffer` rather than the view: `BufferSource` accepts both, and handing over the
  // `ArrayBuffer` avoids any question of a view's byteOffset being honoured.
  return typeof value === 'string' ? fromBase64Url(value).buffer : value;
}

function decodeDescriptors(list: unknown): unknown {
  if (!Array.isArray(list)) return list;
  return list.map((entry) =>
    entry && typeof entry === 'object'
      ? { ...(entry as object), id: decodeIfString((entry as { id?: unknown }).id) }
      : entry,
  );
}

/**
 * Turn the server's `PublicKeyCredentialCreationOptionsJSON` into the `BufferSource`-carrying
 * dictionary `navigator.credentials.create` wants.
 *
 * Hand-decoded rather than routed through `PublicKeyCredential.parseCreationOptionsFromJSON`,
 * which would be the tidier call and is the wrong one here: it is absent on Safari before 18 and
 * on every Firefox before 135, so it would have to be feature-detected with this code as the
 * fallback anyway — and then the fallback would be the path almost nobody exercises while being
 * the one that has to be right. One path, always taken, is the testable arrangement.
 */
export function toCreationOptions(
  json: Record<string, unknown>,
): PublicKeyCredentialCreationOptions {
  const options = { ...json } as OptionsJson;
  options.challenge = decodeIfString(options.challenge);
  if (options.user && typeof options.user === 'object') {
    options.user = { ...options.user, id: decodeIfString(options.user.id) };
  }
  if ('excludeCredentials' in options) {
    options.excludeCredentials = decodeDescriptors(
      options.excludeCredentials,
    ) as OptionsJson['excludeCredentials'];
  }
  return options as unknown as PublicKeyCredentialCreationOptions;
}

/** The request-options twin of {@link toCreationOptions}. */
export function toRequestOptions(json: Record<string, unknown>): PublicKeyCredentialRequestOptions {
  const options = { ...json } as OptionsJson;
  options.challenge = decodeIfString(options.challenge);
  if ('allowCredentials' in options) {
    options.allowCredentials = decodeDescriptors(
      options.allowCredentials,
    ) as OptionsJson['allowCredentials'];
  }
  return options as unknown as PublicKeyCredentialRequestOptions;
}

// =================================================================================================
// Response encoding
// =================================================================================================

interface CredentialResponseParts {
  clientDataJSON: ArrayBuffer;
  attestationObject?: ArrayBuffer;
  authenticatorData?: ArrayBuffer;
  signature?: ArrayBuffer;
  userHandle?: ArrayBuffer | null;
  getTransports?: () => string[];
}

/**
 * The `RegistrationResponseJSON` / `AuthenticationResponseJSON` the server parses.
 *
 * Built by hand for the same reason {@link toCreationOptions} decodes by hand — `toJSON()` is
 * recent enough that the fallback would be the untested path — and because the shape has one
 * non-obvious member placement the server depends on: `transports` sits **inside `response`**
 * while `clientExtensionResults` sits at the **top level**. Putting `transports` at the top level
 * produces JSON that looks right, parses, and silently arrives with no transport hints — which
 * then feed `excludeCredentials` on the next enrolment, where a missing hint is a credential the
 * authenticator may quietly overwrite.
 */
export function credentialToJson(credential: PublicKeyCredential): PasskeyCredentialJson {
  const response = credential.response as unknown as CredentialResponseParts;
  const json: Record<string, unknown> = {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    // `AuthenticationExtensionsClientOutputs` is a closed lib.dom interface with no index
    // signature, and `prf` is not among its members in this TypeScript's DOM lib — so the cast is
    // to the shape the value actually has at runtime, not a widening of a known one.
    clientExtensionResults: stripPrfResults(
      credential.getClientExtensionResults() as unknown as Record<string, unknown>,
    ),
  };
  if (credential.authenticatorAttachment) {
    json.authenticatorAttachment = credential.authenticatorAttachment;
  }
  const inner: Record<string, unknown> = {
    clientDataJSON: toBase64Url(response.clientDataJSON),
  };
  if (response.attestationObject) {
    inner.attestationObject = toBase64Url(response.attestationObject);
    inner.transports = typeof response.getTransports === 'function' ? response.getTransports() : [];
  }
  if (response.authenticatorData) inner.authenticatorData = toBase64Url(response.authenticatorData);
  if (response.signature) inner.signature = toBase64Url(response.signature);
  if (response.userHandle) inner.userHandle = toBase64Url(response.userHandle);
  json.response = inner;
  return json;
}

/**
 * Remove `prf.results` from the client extension results, keeping `prf.enabled`.
 *
 * **This is the boundary the PRF ruling rests on, and it is a client-side boundary because there
 * is nowhere else to put it.** `getClientExtensionResults().prf.results.first` is the PRF output:
 * the input to the key that unwraps the attestation scalar. It arrives in the same object as
 * `enabled`, and the natural act of serialising the whole credential would send it to the server —
 * not as a design decision anyone made, but as a consequence of the object having two members with
 * very different meanings.
 *
 * `enabled` is kept, and must be: it is a boolean saying whether the authenticator provisioned an
 * `hmac-secret` at creation, the server records it as `prf_capable`, and it is what the enrolment
 * screen keys its "this passkey will still ask for your password" sentence on. Dropping it would
 * make every credential look PRF-incapable.
 *
 * **"The server rejects it anyway, so this is redundant" is the argument that would delete this
 * function, and it is wrong.** `webauthn_rp`'s relaxed deserialiser *forbids* a populated
 * `prf.results` on a posted response — it requires the member to be absent, null, or carry
 * `first: null` — so a raw `toJSON()` carrying real PRF output does not quietly leak: it fails to
 * parse and comes back as `passkey_assertion_invalid`. That is worse, not better. The secret has
 * already crossed the wire by then, where a proxy log or an error report can hold it, and the
 * symptom the operator sees is a sign-in that mysteriously stopped working. Without this strip the
 * failure mode is *both* problems at once.
 *
 * Structured-cloned rather than mutated: the extension-results object belongs to the DOM call that
 * produced it, and a caller reading it after this ran would find it quietly altered.
 */
export function stripPrfResults(results: Record<string, unknown>): Record<string, unknown> {
  const prf = results.prf;
  if (!prf || typeof prf !== 'object' || !('results' in prf)) return { ...results };
  const { results: _discarded, ...rest } = prf as Record<string, unknown>;
  return { ...results, prf: rest };
}

// =================================================================================================
// User verification
// =================================================================================================

/** Offset of the flags byte in `authenticatorData`: 32 bytes of `rpIdHash`, then flags. */
const AUTHENTICATOR_DATA_FLAGS_OFFSET = 32;
/** `UV` — bit 2 of the flags byte (WebAuthn L3 §6.1). */
const USER_VERIFIED_FLAG = 0x04;

/**
 * Whether the authenticator performed user verification for this specific assertion.
 *
 * Reads one documented flag bit out of `authenticatorData`; no parsing beyond an index, and
 * emphatically no cryptography. The value is not *trusted* here — the server re-derives it from
 * the same bytes after verifying the signature over them, which is the only reading that counts.
 * This one exists so the refusal can be specific: without it, a UV-less assertion is posted, the
 * library rejects it with `UserNotVerified`, and the user is told "chave de acesso não
 * reconhecida" — that their credential is wrong, when their credential was right and their
 * authenticator merely skipped biometrics.
 *
 * Returns `true` when the buffer is too short to hold a flags byte. A malformed assertion is the
 * server's to refuse, and guessing "not verified" here would report a *device* problem for what is
 * actually a broken response.
 */
export function assertionWasUserVerified(authenticatorData: ArrayBuffer): boolean {
  const bytes = new Uint8Array(authenticatorData);
  if (bytes.length <= AUTHENTICATOR_DATA_FLAGS_OFFSET) return true;
  return (bytes[AUTHENTICATOR_DATA_FLAGS_OFFSET] & USER_VERIFIED_FLAG) !== 0;
}

// =================================================================================================
// Failures
// =================================================================================================

/**
 * What went wrong in the browser, as a stable code the caller maps to copy.
 *
 * These are the DOM exceptions `navigator.credentials` throws, which the server never sees — the
 * request was never made. Left untranslated they are a button that appears to do nothing.
 */
export type CeremonyFailure =
  /** The user dismissed the prompt, or it timed out. Not an error to shout about. */
  | 'cancelled'
  /** This authenticator already holds a credential for this account (`excludeCredentials` hit). */
  | 'already_enrolled'
  /** The RP ID does not match the origin — `auth.passkeys.rp_id` is wrong for this deployment. */
  | 'rp_id_mismatch'
  /** The authenticator could not do what was asked (no supported algorithm, no resident key…). */
  | 'unsupported'
  /** The authenticator did not verify the user, so the assertion cannot unwrap anything. */
  | 'not_user_verified'
  /** Anything else. */
  | 'failed';

/** A ceremony refused before the request was made, carrying the reason as a stable code. */
export class PasskeyCeremonyError extends Error {
  readonly failure: CeremonyFailure;

  constructor(failure: CeremonyFailure) {
    super(failure);
    this.name = 'PasskeyCeremonyError';
    this.failure = failure;
  }
}

/**
 * Classify a `navigator.credentials` rejection.
 *
 * `AbortError` maps to `cancelled` rather than `failed`: it is what an aborted conditional-
 * mediation request throws when the operator uses the modal button instead, which is an ordinary
 * thing to do and not a failure at all.
 *
 * `SecurityError` is the expensive one. It is what a browser throws when the requested RP ID is
 * not a registrable suffix of the page's origin — the exact failure mode of a mis-set
 * `auth.passkeys.rp_id`, which passes every server-side validation because no server-side code can
 * see the browser's opinion of it.
 */
export function describeCeremonyFailure(error: unknown): CeremonyFailure {
  if (error instanceof PasskeyCeremonyError) return error.failure;
  if (!(error instanceof Error)) return 'failed';
  switch (error.name) {
    case 'NotAllowedError':
    case 'AbortError':
      return 'cancelled';
    case 'InvalidStateError':
      return 'already_enrolled';
    case 'SecurityError':
      return 'rp_id_mismatch';
    case 'NotSupportedError':
    case 'ConstraintError':
      return 'unsupported';
    default:
      return 'failed';
  }
}

// =================================================================================================
// The ceremonies
// =================================================================================================

/**
 * Run the enrolment ceremony and return the credential JSON to POST.
 *
 * User verification is **not** re-checked here, and the omission is deliberate rather than an
 * oversight: at registration the UV flag lives inside `attestationObject`, which is CBOR, and
 * parsing attacker-adjacent CBOR in the browser to reproduce a check the server already performs
 * (the library refuses a UV-clear registration with `UserNotVerified`) would add a second parser
 * on the credential path to improve one error message. The assertion path is checked because there
 * the flag is one array index away — see {@link assertionWasUserVerified}.
 */
export async function runEnrolmentCeremony(
  options: CeremonyOptionsView,
): Promise<PasskeyCredentialJson> {
  const credential = (await navigator.credentials.create({
    publicKey: toCreationOptions(options.public_key),
  })) as PublicKeyCredential | null;
  if (!credential) throw new PasskeyCeremonyError('cancelled');
  return credentialToJson(credential);
}

/** How the assertion prompt is presented. */
export interface AssertionCeremonyOptions {
  /**
   * `'conditional'` puts the passkey in the browser's autofill dropdown on a field marked
   * `autocomplete="username webauthn"` and shows **no modal**; the promise stays pending until the
   * operator picks one. `'optional'` opens the modal immediately.
   */
  mediation?: CredentialMediationRequirement;
  /** Aborts a pending conditional request — the only way to stop one. */
  signal?: AbortSignal;
}

/**
 * Run an assertion ceremony (sign-in or step-up) and return the credential JSON to POST.
 *
 * Refuses a UV-less assertion locally with `not_user_verified` instead of posting it. That refusal
 * is key custody, not policy: the server would reject it too, but as the same opaque "chave de
 * acesso não reconhecida" it gives a wrong credential, and the two need different answers from the
 * person holding the authenticator.
 */
export async function runAssertionCeremony(
  options: CeremonyOptionsView,
  { mediation, signal }: AssertionCeremonyOptions = {},
): Promise<PasskeyCredentialJson> {
  const credential = (await navigator.credentials.get({
    publicKey: toRequestOptions(options.public_key),
    ...(mediation ? { mediation } : {}),
    ...(signal ? { signal } : {}),
  })) as PublicKeyCredential | null;
  if (!credential) throw new PasskeyCeremonyError('cancelled');
  const response = credential.response as unknown as CredentialResponseParts;
  if (response.authenticatorData && !assertionWasUserVerified(response.authenticatorData)) {
    throw new PasskeyCeremonyError('not_user_verified');
  }
  return credentialToJson(credential);
}
