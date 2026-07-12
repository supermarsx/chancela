/**
 * Seal spec/content tests (t67-e12): the 2 MiB image cap and PNG/JPEG format gate enforced
 * client-side (mirroring the server), and the backend-DTO assembly for template vs image seals.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SEAL_IMAGE_MAX_BYTES } from '../../../api/types';
import {
  bytesToBase64,
  buildSealBody,
  nameDateTemplate,
  readSealImage,
  sealImageFormatFromMime,
  signedByTemplate,
} from './sealSpec';

beforeEach(() => {
  // jsdom does not implement object URLs; the success path mints one for the preview.
  URL.createObjectURL = vi.fn(() => 'blob:mock');
  URL.revokeObjectURL = vi.fn();
});
afterEach(() => {
  vi.restoreAllMocks();
});

/**
 * A minimal `File` stub: jsdom's `File`/`Blob` does not implement `arrayBuffer()`, so provide the
 * exact surface `readSealImage` consumes (`type` + `arrayBuffer()`).
 */
function fakeFile(bytes: Uint8Array, type: string): File {
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  return { type, arrayBuffer: () => Promise.resolve(buffer) } as unknown as File;
}

describe('sealImageFormatFromMime', () => {
  it('maps PNG and JPEG (incl. jpg) and rejects the rest', () => {
    expect(sealImageFormatFromMime('image/png')).toBe('png');
    expect(sealImageFormatFromMime('image/jpeg')).toBe('jpeg');
    expect(sealImageFormatFromMime('image/jpg')).toBe('jpeg');
    expect(sealImageFormatFromMime('image/gif')).toBeNull();
    expect(sealImageFormatFromMime('application/pdf')).toBeNull();
  });
});

describe('readSealImage', () => {
  it('rejects an unsupported format', async () => {
    const file = fakeFile(new Uint8Array([1, 2, 3]), 'image/gif');
    const result = await readSealImage(file);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('unsupported_format');
  });

  it('rejects an empty image', async () => {
    const file = fakeFile(new Uint8Array([]), 'image/png');
    const result = await readSealImage(file);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('empty');
  });

  it('rejects an image over the 2 MiB cap', async () => {
    const file = fakeFile(new Uint8Array(SEAL_IMAGE_MAX_BYTES + 1), 'image/png');
    const result = await readSealImage(file);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('too_large');
      if (result.error.code === 'too_large') {
        expect(result.error.maxBytes).toBe(SEAL_IMAGE_MAX_BYTES);
      }
    }
  });

  it('accepts a valid small PNG and base64-encodes its bytes', async () => {
    const bytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]); // PNG signature
    const file = fakeFile(bytes, 'image/png');
    const result = await readSealImage(file);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.content.format).toBe('png');
      expect(result.content.base64).toBe(bytesToBase64(bytes));
      expect(result.content.byteSize).toBe(bytes.length);
      expect(result.content.previewUrl).toBe('blob:mock');
    }
  });
});

describe('buildSealBody', () => {
  const rect = { x: 100, y: 662, w: 200, h: 80 };

  it('assembles a name_date template seal', () => {
    const body = buildSealBody(0, rect, nameDateTemplate('Amélia Marques', '2026-07-12'));
    expect(body).toEqual({
      invisible: false,
      page: 0,
      x: 100,
      y: 662,
      w: 200,
      h: 80,
      template: { kind: 'name_date', name: 'Amélia Marques', date: '2026-07-12' },
    });
  });

  it('assembles a signed_by template seal', () => {
    const body = buildSealBody(
      2,
      rect,
      signedByTemplate('Assinado por', 'Amélia Marques', '2026-07-12'),
    );
    expect(body.template).toEqual({
      kind: 'signed_by',
      heading: 'Assinado por',
      name: 'Amélia Marques',
      date: '2026-07-12',
    });
    expect(body.page).toBe(2);
  });

  it('assembles an image seal with format and no template', () => {
    const body = buildSealBody(1, rect, {
      kind: 'image',
      base64: 'QUJD',
      format: 'jpeg',
      previewUrl: 'blob:mock',
      byteSize: 3,
    });
    expect(body.image_base64).toBe('QUJD');
    expect(body.image_format).toBe('jpeg');
    expect(body.template).toBeUndefined();
  });
});
