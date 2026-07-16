import { describe, expect, it } from 'vitest';
import {
  base64ToBytes,
  bytesToBase64,
  canonicalZkAssociatedData,
  decryptZkObject,
  encryptZkObject,
  sha256Hex,
} from './zkCrypto';

function buffer(value: string): ArrayBuffer {
  return new TextEncoder().encode(value).buffer;
}

function key(seed: number): string {
  return bytesToBase64(Uint8Array.from({ length: 32 }, (_, index) => (seed + index) % 256));
}

describe('trusted-client zero-knowledge cryptography', () => {
  it('uses the exact cross-language canonical associated-data representation', () => {
    const text = new TextDecoder().decode(
      canonicalZkAssociatedData(
        'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA',
        'BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB',
        7,
      ),
    );
    expect(text).toBe(
      'chancela-zk-v1\u0000aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\u0000bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\u00007',
    );
  });

  it('encrypts, wraps, verifies, and decrypts without placing raw keys or plaintext in the manifest', async () => {
    const plaintext = buffer('opaque preservation package fixture');
    const byok = key(3);
    const encrypted = await encryptZkObject({
      plaintext,
      repositoryId: '11111111-1111-4111-8111-111111111111',
      objectId: '22222222-2222-4222-8222-222222222222',
      version: 1,
      byokBase64: byok,
      recipientId: 'Primary custodian',
      now: new Date('2026-07-16T12:00:00.000Z'),
    });

    expect(encrypted.manifest.algorithm).toBe('aes256_gcm');
    expect(base64ToBytes(encrypted.manifest.nonce_base64)).toHaveLength(12);
    expect(encrypted.manifest.ciphertext_len).toBe(plaintext.byteLength + 16);
    expect(encrypted.manifest.ciphertext_sha256).toBe(await sha256Hex(encrypted.ciphertext));
    expect(encrypted.manifest.wrapped_keys).toEqual([
      expect.objectContaining({
        recipient_kind: 'bring_your_own_key',
        algorithm: 'aes256_kw_byok',
        key_reference: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      }),
    ]);
    const serialized = JSON.stringify(encrypted.manifest);
    expect(serialized).not.toContain('opaque preservation package fixture');
    expect(serialized).not.toContain(byok);
    expect(serialized).not.toMatch(/"(?:cek|private_key|recovery_share|plaintext)"/);

    const decrypted = await decryptZkObject(encrypted.manifest, encrypted.ciphertext, byok);
    expect(new Uint8Array(decrypted)).toEqual(new Uint8Array(plaintext));
  });

  it('fails closed for wrong custody keys, tampered ciphertext, invalid key width, and empty input', async () => {
    const encrypted = await encryptZkObject({
      plaintext: buffer('fixture'),
      repositoryId: '11111111-1111-4111-8111-111111111111',
      objectId: '22222222-2222-4222-8222-222222222222',
      version: 1,
      byokBase64: key(1),
      recipientId: 'Custodian',
    });
    await expect(decryptZkObject(encrypted.manifest, encrypted.ciphertext, key(8))).rejects.toThrow(
      'not a recipient',
    );

    const tampered = encrypted.ciphertext.slice(0);
    new Uint8Array(tampered)[0] ^= 0xff;
    await expect(decryptZkObject(encrypted.manifest, tampered, key(1))).rejects.toThrow(
      'failed SHA-256',
    );

    await expect(
      encryptZkObject({
        plaintext: buffer('fixture'),
        repositoryId: '11111111-1111-4111-8111-111111111111',
        objectId: '22222222-2222-4222-8222-222222222222',
        version: 1,
        byokBase64: bytesToBase64(new Uint8Array(31)),
        recipientId: 'Custodian',
      }),
    ).rejects.toThrow('exactly 32 bytes');
    await expect(
      encryptZkObject({
        plaintext: new ArrayBuffer(0),
        repositoryId: '11111111-1111-4111-8111-111111111111',
        objectId: '22222222-2222-4222-8222-222222222222',
        version: 1,
        byokBase64: key(1),
        recipientId: 'Custodian',
      }),
    ).rejects.toThrow('non-empty');
  });
});
