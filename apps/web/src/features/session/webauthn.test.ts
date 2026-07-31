/**
 * The browser ceremony codec (t10).
 *
 * Weighted towards the four things in `webauthn.ts` that are load-bearing rather than plumbing —
 * PRF stripping, the UV flag, the `SecurityError` translation and the Tauri suppression — because
 * each of them fails *silently* if it regresses: a leaked PRF output looks like a working sign-in,
 * a posted UV-less assertion looks like a wrong credential, and a missing Tauri check looks like a
 * working enrolment right up until the credential turns out to be bound to `tauri.localhost`.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

const tauriMock = vi.hoisted(() => ({ isTauri: vi.fn(() => false) }));
vi.mock('../../desktop/tauri', () => tauriMock);

import {
  assertionWasUserVerified,
  conditionalMediationAvailable,
  credentialToJson,
  describeCeremonyFailure,
  fromBase64Url,
  PasskeyCeremonyError,
  passkeySupport,
  passkeysAvailable,
  runAssertionCeremony,
  runEnrolmentCeremony,
  stripPrfResults,
  toBase64Url,
  toCreationOptions,
  toRequestOptions,
} from './webauthn';
import type { CeremonyOptionsView } from '../../api/types';

afterEach(() => {
  tauriMock.isTauri.mockReturnValue(false);
  vi.unstubAllGlobals();
});

describe('base64url', () => {
  it('round-trips bytes through the unpadded url alphabet', () => {
    // 0xFB 0xFF exercises both substituted characters: standard base64 would emit `+` and `/`.
    const bytes = new Uint8Array([0, 1, 250, 251, 255, 62, 63]);
    const encoded = toBase64Url(bytes);
    expect(encoded).not.toMatch(/[+/=]/u);
    expect([...fromBase64Url(encoded)]).toEqual([...bytes]);
  });

  it('decodes a value whose length needs padding restored', () => {
    // 1, 2 and 3 bytes cover every remainder class; an unpadded decoder that forgets one of them
    // throws on exactly one input length and passes every test that only uses the other two.
    for (const length of [1, 2, 3, 4, 5]) {
      const bytes = new Uint8Array(length).fill(7);
      expect([...fromBase64Url(toBase64Url(bytes))]).toEqual([...bytes]);
    }
  });
});

describe('options decoding', () => {
  it('turns the base64url members of creation options into buffers and leaves the rest alone', () => {
    const options = toCreationOptions({
      rp: { id: 'example.pt', name: 'example.pt' },
      user: { id: toBase64Url(new Uint8Array([9, 9])), name: 'amelia.marques' },
      challenge: toBase64Url(new Uint8Array([1, 2, 3])),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      excludeCredentials: [{ type: 'public-key', id: toBase64Url(new Uint8Array([4])) }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      attestation: 'none',
    });
    expect(options.challenge).toBeInstanceOf(ArrayBuffer);
    expect([...new Uint8Array(options.challenge as ArrayBuffer)]).toEqual([1, 2, 3]);
    expect(options.user.id).toBeInstanceOf(ArrayBuffer);
    expect(options.excludeCredentials?.[0].id).toBeInstanceOf(ArrayBuffer);
    // Untouched pass-through: the server's frozen constraint set must reach the browser verbatim.
    expect(options.authenticatorSelection).toEqual({
      residentKey: 'required',
      userVerification: 'required',
    });
    expect(options.attestation).toBe('none');
  });

  it('decodes request options without inventing an allowCredentials list', () => {
    // A discoverable sign-in sends NO allowCredentials — that is what lets the browser answer from
    // what it holds without the server being told who exists. Adding an empty array would be a
    // different request.
    const options = toRequestOptions({
      challenge: toBase64Url(new Uint8Array([5])),
      rpId: 'example.pt',
      userVerification: 'required',
    });
    expect(options.challenge).toBeInstanceOf(ArrayBuffer);
    expect('allowCredentials' in options).toBe(false);
  });
});

describe('stripPrfResults', () => {
  it('removes the PRF output and keeps the capability flag', () => {
    // The whole PRF ruling in one assertion: `results.first` is the secret that unwraps the
    // attestation key and must never reach the server, while `enabled` is a boolean the server
    // records as `prf_capable` and keys the degradation copy on.
    const stripped = stripPrfResults({
      credProps: { rk: true },
      prf: { enabled: true, results: { first: 'AAAA-secret-material' } },
    });
    expect(stripped.prf).toEqual({ enabled: true });
    expect(JSON.stringify(stripped)).not.toContain('secret-material');
    expect(stripped.credProps).toEqual({ rk: true });
  });

  it('leaves results untouched when there are none, and never mutates its input', () => {
    const original = { prf: { enabled: false } };
    expect(stripPrfResults(original)).toEqual({ prf: { enabled: false } });

    const withResults = { prf: { enabled: true, results: { first: 'x' } } };
    stripPrfResults(withResults);
    expect(withResults.prf.results).toEqual({ first: 'x' });
  });

  it('passes through extension results that carry no prf member at all', () => {
    expect(stripPrfResults({ credProps: { rk: true } })).toEqual({ credProps: { rk: true } });
    expect(stripPrfResults({})).toEqual({});
  });
});

describe('credentialToJson', () => {
  /** A minimal `PublicKeyCredential` shaped like what the DOM hands back. */
  function fakeCredential(response: Record<string, unknown>, extensions = {}) {
    return {
      id: 'Y3JlZA',
      rawId: new Uint8Array([1, 2]).buffer,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      getClientExtensionResults: () => extensions,
      response,
    } as unknown as PublicKeyCredential;
  }

  it('nests transports inside response and keeps extension results at the top level', () => {
    // The one placement the server depends on. `transports` at the top level produces JSON that
    // parses, arrives with no transport hints, and then feeds `excludeCredentials` on the next
    // enrolment — where a missing hint is a credential the authenticator may quietly overwrite.
    const json = credentialToJson(
      fakeCredential({
        clientDataJSON: new Uint8Array([3]).buffer,
        attestationObject: new Uint8Array([4]).buffer,
        getTransports: () => ['internal', 'hybrid'],
      }),
    ) as Record<string, Record<string, unknown>>;
    expect(json.response.transports).toEqual(['internal', 'hybrid']);
    expect(json.transports).toBeUndefined();
    expect(json.clientExtensionResults).toEqual({});
    expect(json.response.clientExtensionResults).toBeUndefined();
    expect(json.authenticatorAttachment).toBe('platform');
  });

  it('strips the PRF output on the way out, so a leak needs two mistakes rather than one', () => {
    const json = credentialToJson(
      fakeCredential(
        {
          clientDataJSON: new Uint8Array([3]).buffer,
          authenticatorData: new Uint8Array(37).buffer,
          signature: new Uint8Array([5]).buffer,
          userHandle: new Uint8Array([6]).buffer,
        },
        { prf: { results: { first: 'unwrap-secret' } } },
      ),
    );
    expect(JSON.stringify(json)).not.toContain('unwrap-secret');
  });

  it('omits an absent userHandle rather than sending null', () => {
    const json = credentialToJson(
      fakeCredential({
        clientDataJSON: new Uint8Array([3]).buffer,
        authenticatorData: new Uint8Array(37).buffer,
        signature: new Uint8Array([5]).buffer,
        userHandle: null,
      }),
    ) as Record<string, Record<string, unknown>>;
    expect('userHandle' in json.response).toBe(false);
  });
});

describe('assertionWasUserVerified', () => {
  /** `authenticatorData` = 32 bytes of rpIdHash, one flags byte, four counter bytes. */
  function authenticatorData(flags: number): ArrayBuffer {
    const bytes = new Uint8Array(37);
    bytes[32] = flags;
    return bytes.buffer;
  }

  it('reads the UV bit and nothing else', () => {
    // UP alone (0x01) is possession without verification: the exact case that authenticates but
    // derives a different PRF seed and therefore cannot unwrap.
    expect(assertionWasUserVerified(authenticatorData(0x01))).toBe(false);
    expect(assertionWasUserVerified(authenticatorData(0x05))).toBe(true);
    // BE/BS set, UV clear — backup flags must not be mistaken for verification.
    expect(assertionWasUserVerified(authenticatorData(0x19))).toBe(false);
  });

  it('does not report a device problem for a malformed response', () => {
    // Too short to hold a flags byte at all. Guessing "not verified" here would tell the user to
    // turn on their fingerprint reader for what is actually a broken assertion.
    expect(assertionWasUserVerified(new Uint8Array(4).buffer)).toBe(true);
  });
});

describe('describeCeremonyFailure', () => {
  function domException(name: string): Error {
    const error = new Error(name);
    error.name = name;
    return error;
  }

  it('names the RP ID misconfiguration the server can never see', () => {
    // A wrong `auth.passkeys.rp_id` fails inside the browser; the request is never made. Without
    // this arm, the single most expensive misconfiguration in the feature is a button that does
    // nothing.
    expect(describeCeremonyFailure(domException('SecurityError'))).toBe('rp_id_mismatch');
  });

  it('treats an abort as a cancellation, not a failure', () => {
    // An aborted conditional-mediation request is what happens when the operator uses the modal
    // button instead. Reporting it would toast an error for an ordinary choice.
    expect(describeCeremonyFailure(domException('AbortError'))).toBe('cancelled');
    expect(describeCeremonyFailure(domException('NotAllowedError'))).toBe('cancelled');
  });

  it('classifies the remaining ceremony outcomes', () => {
    expect(describeCeremonyFailure(domException('InvalidStateError'))).toBe('already_enrolled');
    expect(describeCeremonyFailure(domException('NotSupportedError'))).toBe('unsupported');
    expect(describeCeremonyFailure(domException('ConstraintError'))).toBe('unsupported');
    expect(describeCeremonyFailure(domException('TypeError'))).toBe('failed');
    expect(describeCeremonyFailure('not an error')).toBe('failed');
    expect(describeCeremonyFailure(new PasskeyCeremonyError('not_user_verified'))).toBe(
      'not_user_verified',
    );
  });
});

describe('passkeySupport', () => {
  it('refuses the desktop shell even when the WebView implements WebAuthn', () => {
    // WebView2 on Windows DOES implement WebAuthn, so a capability probe answers "yes" and then
    // every credential is bound to `tauri.localhost`, which the deployment's own domain can never
    // use. A working API is precisely the wrong thing to test for here.
    tauriMock.isTauri.mockReturnValue(true);
    vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});
    expect(passkeySupport()).toBe('desktop_shell');
    expect(passkeysAvailable()).toBe(false);
  });

  it('reports an unsupported browser separately from the desktop shell', () => {
    // Different reasons need different sentences: "try another browser" versus "this will never
    // work here, use a browser".
    vi.stubGlobal('PublicKeyCredential', undefined);
    expect(passkeySupport()).toBe('browser');
  });

  it('is available when the API is present in an ordinary browser', () => {
    vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});
    vi.stubGlobal('navigator', { credentials: { create: () => {}, get: () => {} } });
    expect(passkeySupport()).toBeNull();
  });
});

describe('conditionalMediationAvailable', () => {
  it('answers false instead of throwing when the probe rejects', async () => {
    // The probe has been observed to reject rather than resolve `false`. A sign-in screen must not
    // fail to render because a capability question was unhappy.
    const rejecting = function PublicKeyCredential() {} as unknown as Record<string, unknown>;
    rejecting.isConditionalMediationAvailable = () => Promise.reject(new Error('nope'));
    vi.stubGlobal('PublicKeyCredential', rejecting);
    vi.stubGlobal('navigator', { credentials: { create: () => {}, get: () => {} } });
    await expect(conditionalMediationAvailable()).resolves.toBe(false);
  });

  it('answers false when the method does not exist', async () => {
    vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});
    vi.stubGlobal('navigator', { credentials: { create: () => {}, get: () => {} } });
    await expect(conditionalMediationAvailable()).resolves.toBe(false);
  });

  it('reports true when the browser says so', async () => {
    const supporting = function PublicKeyCredential() {} as unknown as Record<string, unknown>;
    supporting.isConditionalMediationAvailable = () => Promise.resolve(true);
    vi.stubGlobal('PublicKeyCredential', supporting);
    vi.stubGlobal('navigator', { credentials: { create: () => {}, get: () => {} } });
    await expect(conditionalMediationAvailable()).resolves.toBe(true);
  });
});

describe('the ceremonies', () => {
  /** `authenticatorData` with the given flags byte, 37 bytes as an assertion carries it. */
  function authData(flags: number): ArrayBuffer {
    const bytes = new Uint8Array(37);
    bytes[32] = flags;
    return bytes.buffer;
  }

  // The parameters are declared, not inferred: an untyped `vi.fn()` records a zero-length argument
  // tuple, and the assertions below are entirely about WHAT was passed to the DOM call.
  function credentials(result: unknown) {
    const create = vi.fn((_options: CredentialCreationOptions) => Promise.resolve(result));
    const get = vi.fn((_options: CredentialRequestOptions) => Promise.resolve(result));
    vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});
    vi.stubGlobal('navigator', { credentials: { create, get } });
    return { create, get };
  }

  const REGISTRATION: CeremonyOptionsView = {
    purpose: 'registration',
    public_key: {
      rp: { id: 'example.pt', name: 'example.pt' },
      user: { id: toBase64Url(new Uint8Array([1])), name: 'amelia.marques' },
      challenge: toBase64Url(new Uint8Array([2, 3])),
      excludeCredentials: [],
    },
  };
  const ASSERTION: CeremonyOptionsView = {
    purpose: 'sign_in',
    public_key: { challenge: toBase64Url(new Uint8Array([4])), rpId: 'example.pt' },
  };

  function registrationCredential() {
    return {
      id: 'Y3JlZA',
      rawId: new Uint8Array([1, 2]).buffer,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      getClientExtensionResults: () => ({ prf: { enabled: true } }),
      response: {
        clientDataJSON: new Uint8Array([3]).buffer,
        attestationObject: new Uint8Array([4]).buffer,
        getTransports: () => ['internal'],
      },
    };
  }

  function assertionCredential(flags: number) {
    return {
      id: 'Y3JlZA',
      rawId: new Uint8Array([1, 2]).buffer,
      type: 'public-key',
      getClientExtensionResults: () => ({ prf: { results: { first: 'unwrap-secret' } } }),
      response: {
        clientDataJSON: new Uint8Array([3]).buffer,
        authenticatorData: authData(flags),
        signature: new Uint8Array([5]).buffer,
        userHandle: new Uint8Array([6]).buffer,
      },
    };
  }

  it('hands the decoded creation options to the browser and returns the credential JSON', async () => {
    const { create } = credentials(registrationCredential());
    const json = (await runEnrolmentCeremony(REGISTRATION)) as Record<string, unknown>;

    const passed = create.mock.calls[0][0] as unknown as {
      publicKey: PublicKeyCredentialCreationOptions;
    };
    expect(passed.publicKey.challenge).toBeInstanceOf(ArrayBuffer);
    expect(json.clientExtensionResults).toEqual({ prf: { enabled: true } });
  });

  it('treats a null credential as a cancellation rather than a failure', async () => {
    // `navigator.credentials.create` resolving null is how some clients report a dismissed prompt.
    // Reading `.response` off it would throw a TypeError and be reported as "failed".
    credentials(null);
    await expect(runEnrolmentCeremony(REGISTRATION)).rejects.toBeInstanceOf(PasskeyCeremonyError);
    await expect(runEnrolmentCeremony(REGISTRATION)).rejects.toMatchObject({
      failure: 'cancelled',
    });
  });

  it('refuses a UV-less assertion locally instead of posting it', async () => {
    // Key custody, not policy. The server would also refuse it — as the same opaque "chave de
    // acesso não reconhecida" it gives a wrong credential — and the person holding the
    // authenticator needs a different answer from that one.
    credentials(assertionCredential(0x01));
    await expect(runAssertionCeremony(ASSERTION)).rejects.toMatchObject({
      failure: 'not_user_verified',
    });
  });

  it('accepts a user-verified assertion and strips its PRF output', async () => {
    const { get } = credentials(assertionCredential(0x05));
    const json = await runAssertionCeremony(ASSERTION);
    expect(JSON.stringify(json)).not.toContain('unwrap-secret');
    expect((get.mock.calls[0][0] as { mediation?: string }).mediation).toBeUndefined();
  });

  it('passes conditional mediation and its abort signal straight through', async () => {
    // Both are load-bearing: the mediation mode is what puts the passkey in the autofill dropdown
    // instead of a modal, and the signal is the only way to stop a request that stays pending
    // until the operator chooses.
    const { get } = credentials(assertionCredential(0x05));
    const controller = new AbortController();
    await runAssertionCeremony(ASSERTION, { mediation: 'conditional', signal: controller.signal });

    const passed = get.mock.calls[0][0] as { mediation?: string; signal?: AbortSignal };
    expect(passed.mediation).toBe('conditional');
    expect(passed.signal).toBe(controller.signal);
  });
});
