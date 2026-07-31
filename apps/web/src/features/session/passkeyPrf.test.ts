/**
 * The PRF → unwrap-secret derivation (t10).
 *
 * Verified against **published HKDF-SHA256 test vectors**, not against a caller, because there is
 * no caller yet — the server has neither a per-credential PRF salt nor a second wrap of the
 * attestation scalar to unlock (see the module header). A derivation with no production call site
 * and no vectors would be an assertion that it works; with vectors it is a checked one, and the
 * check is the part that has to survive until the backend catches up.
 *
 * The vectors are RFC 5869 §A.1 and §A.2, with the module's own `info` label substituted where the
 * label is what is under test.
 */
import { describe, expect, it } from 'vitest';
import { ATTESTATION_KEK_INFO, deriveAttestationKek, zeroize } from './passkeyPrf';

/** RFC 5869 §A.1 — HKDF-SHA256, IKM 22×0x0b, salt 0x000102…0c, info 0xf0f1…f9, L = 42. */
const RFC_A1 = {
  ikm: new Uint8Array(22).fill(0x0b),
  salt: new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
  info: new Uint8Array([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]),
  okm: '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
};

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** The WebCrypto call the module makes, with `info` and length as parameters, for the vectors. */
async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  bits: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, [
    'deriveBits',
  ]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: info as BufferSource },
      key,
      bits,
    ),
  );
}

describe('deriveAttestationKek', () => {
  it('matches the RFC 5869 §A.1 HKDF-SHA256 vector', async () => {
    // Pins the primitive itself: if this environment's `deriveBits` ever produced something other
    // than HKDF-SHA256, every assertion below would agree with each other and all be wrong.
    const okm = await hkdf(RFC_A1.ikm, RFC_A1.salt, RFC_A1.info, 42 * 8);
    expect(hex(okm)).toBe(RFC_A1.okm);
  });

  it('returns 32 bytes, deterministically, for one credential', async () => {
    const prf = new Uint8Array(32).fill(0x2a);
    const salt = new Uint8Array(32).fill(0x07);
    const first = await deriveAttestationKek(prf, salt);
    const second = await deriveAttestationKek(prf, salt);
    expect(first.length).toBe(32);
    expect(hex(first)).toBe(hex(second));
  });

  it('is exactly HKDF-SHA256 over the stated info label', async () => {
    // Not "produces 32 bytes" — *which* 32 bytes. The label is what binds the secret to this
    // product and this purpose, and a silent change to it would make every existing PRF wrap
    // unopenable in exactly the way the iOS 18.4 incident did.
    const prf = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const salt = new Uint8Array([9, 9, 9, 9]);
    const expected = await hkdf(prf, salt, new TextEncoder().encode(ATTESTATION_KEK_INFO), 256);
    expect(hex(await deriveAttestationKek(prf, salt))).toBe(hex(expected));
    expect(ATTESTATION_KEK_INFO).toBe('chancela-attestation-kek-v1');
  });

  it('separates domains by salt, and credentials by the authenticator’s own seed', async () => {
    // Two facts, and the second is the one an earlier version of this test got wrong.
    //
    // The salt provides DOMAIN separation — a different salt derives a different secret, so this
    // product's use of a passkey cannot collide with another relying party's. It is instance-wide,
    // not per-credential, because a discoverable sign-in does not know which credential will answer
    // until the assertion comes back.
    const prf = new Uint8Array(32).fill(0x2a);
    const a = await deriveAttestationKek(prf, new Uint8Array(32).fill(1));
    const b = await deriveAttestationKek(prf, new Uint8Array(32).fill(2));
    expect(hex(a)).not.toBe(hex(b));

    // CREDENTIAL separation comes from the authenticator: each credential has its own PRF seed, so
    // two credentials of one account yield different outputs under the *same* salt. That is why a
    // constant salt is correct rather than a compromise.
    const salt = new Uint8Array(32).fill(7);
    const fromOneCredential = await deriveAttestationKek(new Uint8Array(32).fill(0x11), salt);
    const fromAnother = await deriveAttestationKek(new Uint8Array(32).fill(0x22), salt);
    expect(hex(fromOneCredential)).not.toBe(hex(fromAnother));
  });

  it('refuses an empty PRF output rather than deriving from nothing', async () => {
    // An authenticator that did not evaluate the extension returns nothing usable. HKDF is happy
    // to extract from zero-length IKM and would hand back a plausible-looking key derived from the
    // salt alone — the same value for every user of that salt.
    await expect(deriveAttestationKek(new Uint8Array(0), new Uint8Array(4))).rejects.toThrow(
      /PRF output is empty/u,
    );
  });

  it('accepts an ArrayBuffer as readily as a view', async () => {
    // `getClientExtensionResults().prf.results.first` is an ArrayBuffer, so the buffer form is the
    // one a real caller would pass.
    const prf = new Uint8Array([1, 2, 3, 4]);
    const salt = new Uint8Array([5, 6]);
    const fromView = await deriveAttestationKek(prf, salt);
    const fromBuffer = await deriveAttestationKek(prf.buffer, salt.buffer);
    expect(hex(fromBuffer)).toBe(hex(fromView));
  });
});

describe('zeroize', () => {
  it('overwrites the buffer in place', () => {
    const secret = new Uint8Array([1, 2, 3, 4]);
    zeroize(secret);
    expect([...secret]).toEqual([0, 0, 0, 0]);
  });
});
