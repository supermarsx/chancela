import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  arrayBufferToBase64,
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  canonicalZkAssociatedData,
  decryptZkObject,
  encryptZkObject,
  sha256Hex,
  ZK_MAX_CIPHERTEXT_BYTES,
} from './zkCrypto';

function buffer(value: string): ArrayBuffer {
  return new TextEncoder().encode(value).buffer;
}

function key(seed: number): string {
  return bytesToBase64(Uint8Array.from({ length: 32 }, (_, index) => (seed + index) % 256));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

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

  it('refuses input the repository could never store or address', async () => {
    const base = {
      repositoryId: '11111111-1111-4111-8111-111111111111',
      objectId: '22222222-2222-4222-8222-222222222222',
      byokBase64: key(1),
      recipientId: 'Custodian',
    };
    await expect(
      encryptZkObject({ ...base, plaintext: new ArrayBuffer(ZK_MAX_CIPHERTEXT_BYTES), version: 1 }),
    ).rejects.toThrow('64 MiB');
    await expect(
      encryptZkObject({ ...base, plaintext: new ArrayBuffer(8), version: 0 }),
    ).rejects.toThrow('start at one');
    await expect(
      encryptZkObject({ ...base, plaintext: new ArrayBuffer(8), version: 1, recipientId: '  ' }),
    ).rejects.toThrow('public key-custodian label');
  });

  it('rejects a client key that is not base64 at all', () => {
    expect(() => base64ToBytes('not base64 !!')).toThrow('valid base64');
  });

  it('refuses ciphertext whose length contradicts the manifest before hashing it', async () => {
    const encrypted = await encryptZkObject({
      plaintext: new TextEncoder().encode('fixture').buffer as ArrayBuffer,
      repositoryId: '11111111-1111-4111-8111-111111111111',
      objectId: '22222222-2222-4222-8222-222222222222',
      version: 1,
      byokBase64: key(1),
      recipientId: 'Custodian',
    });
    await expect(
      decryptZkObject(encrypted.manifest, encrypted.ciphertext.slice(1), key(1)),
    ).rejects.toThrow('length does not match');
  });

  it('reports a wrapped key that the client key cannot unwrap as an authentication failure', async () => {
    const encrypted = await encryptZkObject({
      plaintext: new TextEncoder().encode('fixture').buffer as ArrayBuffer,
      repositoryId: '11111111-1111-4111-8111-111111111111',
      objectId: '22222222-2222-4222-8222-222222222222',
      version: 1,
      byokBase64: key(1),
      recipientId: 'Custodian',
    });
    // Keep the recipient's key reference (so the slot still matches) but corrupt the wrapped CEK.
    const wrapped = base64ToBytes(encrypted.manifest.wrapped_keys[0].wrapped_cek_base64);
    wrapped[0] ^= 0xff;
    const manifest = {
      ...encrypted.manifest,
      wrapped_keys: [
        { ...encrypted.manifest.wrapped_keys[0], wrapped_cek_base64: bytesToBase64(wrapped) },
      ],
    };
    await expect(decryptZkObject(manifest, encrypted.ciphertext, key(1))).rejects.toThrow(
      'could not authenticate and decrypt',
    );
  });

  it('base64-encodes buffers larger than one conversion chunk without truncating them', async () => {
    const bytes = new Uint8Array(0x8000 + 5).fill(7);
    const encoded = await arrayBufferToBase64(bytes.buffer);
    expect(base64ToBytes(encoded)).toHaveLength(bytes.length);
    expect(bytesToHex(bytes.subarray(0, 2))).toBe('0707');
  });

  it('fails closed when the client has no WebCrypto subtle implementation', async () => {
    vi.stubGlobal('crypto', {});
    await expect(sha256Hex(new ArrayBuffer(4))).rejects.toThrow('WebCrypto is not available');
  });
});
