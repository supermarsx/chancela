import type { OpaqueBlobManifest } from '../../api/types';

export const ZK_MAX_CIPHERTEXT_BYTES = 64 * 1024 * 1024;
const AES_KEY_BYTES = 32;
const GCM_NONCE_BYTES = 12;

function webCrypto(): Crypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error('WebCrypto is not available in this client');
  }
  return globalThis.crypto;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunk = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
  let decoded: string;
  try {
    decoded = atob(value.trim());
  } catch {
    throw new Error('The client key must be valid base64');
  }
  const bytes = new Uint8Array(decoded.length);
  for (let index = 0; index < decoded.length; index += 1) bytes[index] = decoded.charCodeAt(index);
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(bytes: BufferSource): Promise<string> {
  return bytesToHex(new Uint8Array(await webCrypto().subtle.digest('SHA-256', bytes)));
}

/** Canonical authenticated data required by `chancela-zk`, including NUL delimiters. */
export function canonicalZkAssociatedData(
  repositoryId: string,
  objectId: string,
  version: number,
): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(
    `chancela-zk-v1\0${repositoryId.toLowerCase()}\0${objectId.toLowerCase()}\0${version}`,
  );
}

async function importByok(value: string): Promise<{ key: CryptoKey; reference: string }> {
  const raw = base64ToBytes(value);
  if (raw.byteLength !== AES_KEY_BYTES) {
    raw.fill(0);
    throw new Error('The client key must decode to exactly 32 bytes');
  }
  const reference = `sha256:${await sha256(raw)}`;
  try {
    const key = await webCrypto().subtle.importKey('raw', raw, 'AES-KW', false, [
      'wrapKey',
      'unwrapKey',
    ]);
    return { key, reference };
  } finally {
    raw.fill(0);
  }
}

export interface EncryptZkObjectInput {
  plaintext: ArrayBuffer;
  repositoryId: string;
  objectId: string;
  version: number;
  byokBase64: string;
  recipientId: string;
  now?: Date;
}

export interface EncryptZkObjectResult {
  manifest: OpaqueBlobManifest;
  ciphertext: ArrayBuffer;
  keyReference: string;
}

/**
 * Encrypt an immutable object entirely in the trusted browser boundary. The returned manifest
 * contains only opaque ciphertext metadata and a wrapped CEK; the BYOK and raw CEK are absent.
 */
export async function encryptZkObject({
  plaintext,
  repositoryId,
  objectId,
  version,
  byokBase64,
  recipientId,
  now = new Date(),
}: EncryptZkObjectInput): Promise<EncryptZkObjectResult> {
  if (plaintext.byteLength === 0) throw new Error('Choose a non-empty preservation package');
  // AES-GCM appends a 16-byte tag. Enforce the server's ciphertext limit before any upload.
  if (plaintext.byteLength + 16 > ZK_MAX_CIPHERTEXT_BYTES) {
    throw new Error('The encrypted package would exceed the 64 MiB repository limit');
  }
  if (!Number.isSafeInteger(version) || version < 1) {
    throw new Error('Object versions must start at one');
  }
  const recipient = recipientId.trim();
  if (!recipient) throw new Error('A public key-custodian label is required');

  const crypto = webCrypto();
  const { key: wrappingKey, reference } = await importByok(byokBase64);
  const contentKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
  const nonce = crypto.getRandomValues(new Uint8Array(GCM_NONCE_BYTES));
  const aad = canonicalZkAssociatedData(repositoryId, objectId, version);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
    contentKey,
    plaintext,
  );
  const wrappedKey = await crypto.subtle.wrapKey('raw', contentKey, wrappingKey, 'AES-KW');
  const createdAt = now.toISOString();
  const manifest: OpaqueBlobManifest = {
    schema_version: 1,
    associated_data: {
      repository_id: repositoryId,
      object_id: objectId,
      version,
    },
    algorithm: 'aes256_gcm',
    nonce_base64: bytesToBase64(nonce),
    ciphertext_sha256: await sha256(ciphertext),
    ciphertext_len: ciphertext.byteLength,
    encrypted_metadata: null,
    wrapped_keys: [
      {
        slot_id: crypto.randomUUID(),
        recipient_kind: 'bring_your_own_key',
        recipient_id: recipient,
        algorithm: 'aes256_kw_byok',
        key_reference: reference,
        wrapped_cek_base64: bytesToBase64(new Uint8Array(wrappedKey)),
        created_at: createdAt,
      },
    ],
    created_at: createdAt,
  };
  return { manifest, ciphertext, keyReference: reference };
}

export async function decryptZkObject(
  manifest: OpaqueBlobManifest,
  ciphertext: ArrayBuffer,
  byokBase64: string,
): Promise<ArrayBuffer> {
  const crypto = webCrypto();
  if (ciphertext.byteLength !== manifest.ciphertext_len) {
    throw new Error('Downloaded ciphertext length does not match its immutable manifest');
  }
  if ((await sha256(ciphertext)) !== manifest.ciphertext_sha256) {
    throw new Error('Downloaded ciphertext failed SHA-256 verification');
  }
  const { key: wrappingKey, reference } = await importByok(byokBase64);
  const slot = manifest.wrapped_keys.find(
    (candidate) =>
      candidate.recipient_kind === 'bring_your_own_key' &&
      candidate.algorithm === 'aes256_kw_byok' &&
      candidate.key_reference === reference,
  );
  if (!slot) throw new Error('This client key is not a recipient in the object manifest');
  const wrapped = base64ToBytes(slot.wrapped_cek_base64);
  try {
    const contentKey = await crypto.subtle.unwrapKey(
      'raw',
      wrapped,
      wrappingKey,
      'AES-KW',
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    );
    const ad = manifest.associated_data;
    return await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: base64ToBytes(manifest.nonce_base64),
        additionalData: canonicalZkAssociatedData(ad.repository_id, ad.object_id, ad.version),
        tagLength: 128,
      },
      contentKey,
      ciphertext,
    );
  } catch (error) {
    throw new Error('The client key could not authenticate and decrypt this object', {
      cause: error,
    });
  } finally {
    wrapped.fill(0);
  }
}

export async function arrayBufferToBase64(bytes: ArrayBuffer): Promise<string> {
  return bytesToBase64(new Uint8Array(bytes));
}

export async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  return sha256(bytes);
}
