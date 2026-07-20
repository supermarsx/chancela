/**
 * Seal content + spec assembly for the visual seal designer (t67-e12).
 *
 * Turns the designer's on-screen state (a placed box + a chosen content source) into the
 * backend {@link SealAppearanceBody}. Content is either a predefined text template or an
 * uploaded raster image; the image path enforces the same 2 MiB decoded-byte cap the server
 * does (`SEAL_IMAGE_MAX_BYTES`) and the same PNG/JPEG format set, failing early with a
 * localizable reason code rather than letting a too-large or unsupported image reach a 422.
 */
import {
  SEAL_IMAGE_MAX_BYTES,
  type SealAppearanceBody,
  type SealImageFormat,
  type SealTemplateBody,
} from '../../../api/types';
import type { PdfRect } from './coordinates';

/** The seal's content: a text template, or an uploaded raster image (with a preview URL). */
export type SealContent =
  | { kind: 'template'; template: SealTemplateBody }
  | {
      kind: 'image';
      /** Base64 of the raster bytes (no data-URL prefix) — what goes on the wire. */
      base64: string;
      format: SealImageFormat;
      /** A preview URL for the on-screen seal box (object URL for uploads, data URL for edits). */
      previewUrl: string;
      /** True when the preview URL is an object URL minted by the designer and must be revoked. */
      revokePreview: boolean;
      /** The decoded byte size, for the "N KB" hint. */
      byteSize: number;
    };

/** Why a chosen image was rejected before it could be sent (mapped to i18n by the caller). */
export type SealImageError =
  | { code: 'unsupported_format' }
  | { code: 'too_large'; byteSize: number; maxBytes: number }
  | { code: 'empty' };

export type SealImageResult =
  | { ok: true; content: Extract<SealContent, { kind: 'image' }> }
  | { ok: false; error: SealImageError };

/** Map a File's MIME type to the backend seal image format, or `null` if unsupported. */
export function sealImageFormatFromMime(mime: string): SealImageFormat | null {
  const m = mime.toLowerCase();
  if (m === 'image/png') return 'png';
  if (m === 'image/jpeg' || m === 'image/jpg') return 'jpeg';
  return null;
}

/** Base64-encode raw bytes in chunks (avoids a huge spread on `String.fromCharCode`). */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

/** Estimate decoded bytes for an existing base64 seal without needing the original File. */
export function decodedBase64ByteSize(base64: string): number {
  const compact = base64.replace(/\s/g, '');
  if (compact.length === 0) return 0;
  const padding = compact.endsWith('==') ? 2 : compact.endsWith('=') ? 1 : 0;
  return Math.max(0, Math.floor((compact.length * 3) / 4) - padding);
}

/**
 * Reconstruct image content from a previously applied seal. The original upload `File` is gone,
 * but the request DTO has enough information to preview and re-apply the same raster bytes.
 */
export function imageContentFromSeal(
  seal: SealAppearanceBody | null | undefined,
): Extract<SealContent, { kind: 'image' }> | null {
  if (!seal?.image_base64 || !seal.image_format) return null;
  const mime = seal.image_format === 'png' ? 'image/png' : 'image/jpeg';
  return {
    kind: 'image',
    base64: seal.image_base64,
    format: seal.image_format,
    previewUrl: `data:${mime};base64,${seal.image_base64}`,
    revokePreview: false,
    byteSize: decodedBase64ByteSize(seal.image_base64),
  };
}

/**
 * Read + validate a chosen seal image. Enforces the format set and the 2 MiB decoded cap
 * client-side (defense-in-depth against the server's own limit), returning a typed error the
 * UI localizes rather than throwing. On success it also mints an object URL for the preview.
 */
export async function readSealImage(file: File): Promise<SealImageResult> {
  const format = sealImageFormatFromMime(file.type);
  if (!format) {
    return { ok: false, error: { code: 'unsupported_format' } };
  }
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  if (bytes.length === 0) {
    return { ok: false, error: { code: 'empty' } };
  }
  if (bytes.length > SEAL_IMAGE_MAX_BYTES) {
    return {
      ok: false,
      error: { code: 'too_large', byteSize: bytes.length, maxBytes: SEAL_IMAGE_MAX_BYTES },
    };
  }
  return {
    ok: true,
    content: {
      kind: 'image',
      base64: bytesToBase64(bytes),
      format,
      previewUrl: URL.createObjectURL(file),
      revokePreview: true,
      byteSize: bytes.length,
    },
  };
}

/** Build the `name_date` template content (bold name over a date/detail line). */
export function nameDateTemplate(name: string, date: string): SealContent {
  return { kind: 'template', template: { kind: 'name_date', name, date } };
}

/** Build the `signed_by` template content (small heading, bold name, date line). */
export function signedByTemplate(heading: string, name: string, date: string): SealContent {
  return { kind: 'template', template: { kind: 'signed_by', heading, name, date } };
}

/**
 * Assemble the backend seal body from a placed rectangle, target page, and chosen content.
 * `invisible` is always `false` here (this function is only reached once the user has opted
 * into a visible seal); an omitted seal is represented by the caller passing `undefined`, not
 * by this function.
 */
export function buildSealBody(
  page: number,
  rect: PdfRect,
  content: SealContent,
): SealAppearanceBody {
  const base: SealAppearanceBody = {
    invisible: false,
    page,
    x: rect.x,
    y: rect.y,
    w: rect.w,
    h: rect.h,
  };
  if (content.kind === 'template') {
    return { ...base, template: content.template };
  }
  return { ...base, image_base64: content.base64, image_format: content.format };
}
