import { afterEach, describe, expect, it, vi } from 'vitest';
import type { PdfSignatureValidationResponse } from '../../api/types';
import {
  externalValidatorArrayBufferToBase64,
  externalValidatorHex,
  externalValidatorSha256Hex,
  formatExternalValidatorBytes,
  normalizeRawReportContentType,
  rawReportContentType,
  readExternalValidatorFileAsArrayBuffer,
  readExternalValidatorFileAsText,
  safeSourceFilename,
} from './ExternalValidatorReportsPanel';
import {
  formatPdfValidatorBytes,
  pdfValidationEvidenceTone,
  pdfValidationFindingTone,
  pdfValidationReportFilename,
  pdfValidationReportJson,
  pdfValidationStatusLabel,
  pdfValidationStatusTone,
  pdfValidatorArrayBufferToBase64,
  pdfValidatorBoolText,
  pdfValidatorHex,
  pdfValidatorSha256Hex,
  readPdfValidatorFileAsArrayBuffer,
} from './PdfSignatureValidatorPanel';

const t = ((key: string) => key) as Parameters<typeof formatPdfValidatorBytes>[1];

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('validator file and presentation helpers', () => {
  it('encodes bytes, hex, and sizes across every supported scale', () => {
    const bytes = new Uint8Array([0, 1, 254, 255]).buffer;
    expect(externalValidatorArrayBufferToBase64(bytes)).toBe('AAH+/w==');
    expect(pdfValidatorArrayBufferToBase64(bytes)).toBe('AAH+/w==');
    expect(externalValidatorHex(bytes)).toBe('0001feff');
    expect(pdfValidatorHex(bytes)).toBe('0001feff');

    for (const format of [formatExternalValidatorBytes, formatPdfValidatorBytes]) {
      expect(format(-1, t)).toBe('pdfValidator.size.unknown');
      expect(format(Number.NaN, t)).toBe('pdfValidator.size.unknown');
      expect(format(512, t)).toBe('512 bytes');
      expect(format(1536, t)).toBe('1.5 KB');
      expect(format(15 * 1024, t)).toBe('15 KB');
      expect(format(2 * 1024 * 1024, t)).toBe('2.0 MB');
      expect(format(3 * 1024 * 1024 * 1024, t)).toBe('3.0 GB');
    }
  });

  it('hashes with WebCrypto and reports an unavailable digest honestly', async () => {
    const digest = new Uint8Array([0xde, 0xad]).buffer;
    vi.stubGlobal('crypto', { subtle: { digest: vi.fn().mockResolvedValue(digest) } });
    await expect(externalValidatorSha256Hex(new ArrayBuffer(0))).resolves.toBe('dead');
    await expect(pdfValidatorSha256Hex(new ArrayBuffer(0))).resolves.toBe('dead');

    vi.stubGlobal('crypto', undefined);
    await expect(externalValidatorSha256Hex(new ArrayBuffer(0))).resolves.toBeNull();
    await expect(pdfValidatorSha256Hex(new ArrayBuffer(0))).resolves.toBeNull();
  });

  it('uses native file readers when present', async () => {
    const bytes = new Uint8Array([7, 8]).buffer;
    await expect(
      readExternalValidatorFileAsText({ text: async () => 'metadata' } as File),
    ).resolves.toBe('metadata');
    await expect(
      readExternalValidatorFileAsArrayBuffer({ arrayBuffer: async () => bytes } as File),
    ).resolves.toBe(bytes);
    await expect(
      readPdfValidatorFileAsArrayBuffer({ arrayBuffer: async () => bytes } as File),
    ).resolves.toBe(bytes);
  });

  it('supports FileReader text and byte fallbacks, including failures', async () => {
    class Reader {
      result: string | ArrayBuffer | null = null;
      error: Error | null = null;
      onload: null | (() => void) = null;
      onerror: null | (() => void) = null;

      readAsText(file: File) {
        this.result = file.name === 'empty.txt' ? null : 'fallback text';
        this.onload?.();
      }

      readAsArrayBuffer(file: File) {
        if (file.name === 'wrong.bin') this.result = 'not bytes';
        else this.result = new Uint8Array([9]).buffer;
        this.onload?.();
      }
    }
    vi.stubGlobal('FileReader', Reader);
    const noNative = (name: string) => ({ name }) as File;

    await expect(readExternalValidatorFileAsText(noNative('ok.txt'))).resolves.toBe(
      'fallback text',
    );
    await expect(readExternalValidatorFileAsText(noNative('empty.txt'))).resolves.toBe('');
    await expect(readExternalValidatorFileAsArrayBuffer(noNative('ok.bin'))).resolves.toEqual(
      new Uint8Array([9]).buffer,
    );
    await expect(readPdfValidatorFileAsArrayBuffer(noNative('ok.bin'))).resolves.toEqual(
      new Uint8Array([9]).buffer,
    );
    await expect(readExternalValidatorFileAsArrayBuffer(noNative('wrong.bin'))).rejects.toThrow(
      'file read did not return bytes',
    );
    await expect(readPdfValidatorFileAsArrayBuffer(noNative('wrong.bin'))).rejects.toThrow(
      'file read did not return bytes',
    );

    Reader.prototype.readAsText = function () {
      this.error = new Error('text failed');
      this.onerror?.();
    };
    Reader.prototype.readAsArrayBuffer = function () {
      this.error = new Error('bytes failed');
      this.onerror?.();
    };
    await expect(readExternalValidatorFileAsText(noNative('bad.txt'))).rejects.toThrow(
      'text failed',
    );
    await expect(readExternalValidatorFileAsArrayBuffer(noNative('bad.bin'))).rejects.toThrow(
      'bytes failed',
    );
    await expect(readPdfValidatorFileAsArrayBuffer(noNative('bad.bin'))).rejects.toThrow(
      'bytes failed',
    );
  });

  it('normalizes report media types and safe filenames', () => {
    expect(normalizeRawReportContentType(' Application/JSON; charset=utf-8 ')).toBe(
      'application/json',
    );
    expect(normalizeRawReportContentType('text/html')).toBeNull();
    expect(normalizeRawReportContentType(undefined)).toBeNull();

    expect(rawReportContentType({ name: 'report.any', type: 'application/pdf' } as File)).toBe(
      'application/pdf',
    );
    expect(rawReportContentType({ name: 'REPORT.JSON', type: '' } as File)).toBe(
      'application/json',
    );
    expect(rawReportContentType({ name: 'report.pdf', type: '' } as File)).toBe('application/pdf');
    expect(rawReportContentType({ name: 'report.xml', type: '' } as File)).toBe('application/xml');
    expect(rawReportContentType({ name: 'report.txt', type: '' } as File)).toBe('text/plain');
    expect(rawReportContentType({ name: 'report.bin', type: '' } as File)).toBe(
      'application/octet-stream',
    );

    expect(safeSourceFilename('report 01.pdf')).toBe('report 01.pdf');
    expect(safeSourceFilename('')).toBeNull();
    expect(safeSourceFilename('a'.repeat(256))).toBeNull();
    expect(safeSourceFilename('../report.pdf')).toBeNull();
    expect(safeSourceFilename('folder\\report.pdf')).toBeNull();
    expect(safeSourceFilename('relatório.pdf')).toBeNull();
    expect(safeSourceFilename('bad\u0001name.pdf')).toBeNull();
  });

  it('maps PDF validation states, findings, and evidence honestly', () => {
    expect(pdfValidatorBoolText(true, t)).toBe('common.yes');
    expect(pdfValidatorBoolText(false, t)).toBe('common.no');
    expect(
      (['valid', 'invalid', 'indeterminate', 'unsigned'] as const).map(pdfValidationStatusTone),
    ).toEqual(['ok', 'error', 'warn', 'neutral']);
    expect(
      (['valid', 'invalid', 'indeterminate', 'unsigned'] as const).map((status) =>
        pdfValidationStatusLabel(status, t),
      ),
    ).toEqual([
      'pdfValidator.status.valid',
      'pdfValidator.status.invalid',
      'pdfValidator.status.indeterminate',
      'pdfValidator.status.unsigned',
    ]);
    expect(['error', 'warning', 'info'].map(pdfValidationFindingTone)).toEqual([
      'error',
      'warn',
      'neutral',
    ]);
    expect(
      [
        'valid',
        'available',
        'INVALID',
        'failed-check',
        'indeterminate',
        'unavailable',
        'unsupported',
        'gap',
        'unknown',
      ].map(pdfValidationEvidenceTone),
    ).toEqual(['ok', 'ok', 'error', 'error', 'warn', 'warn', 'warn', 'warn', 'neutral']);
  });

  it('serializes validation reports with stable safe download names', () => {
    const report = {
      filename: 'Relatório Final.PDF',
      status: 'valid',
    } as PdfSignatureValidationResponse;
    expect(pdfValidationReportFilename(report)).toBe('relatorio-final-validation-report.json');
    expect(pdfValidationReportJson(report)).toBe(`${JSON.stringify(report, null, 2)}\n`);
    expect(
      pdfValidationReportFilename({ filename: '---.pdf' } as PdfSignatureValidationResponse),
    ).toBe('pdf-validation-report.json');
    expect(pdfValidationReportFilename({} as PdfSignatureValidationResponse)).toBe(
      'pdf-validation-report.json',
    );
  });
});
