/**
 * QR encoder correctness (wp27-e5). The Galois-field arithmetic and Reed–Solomon
 * generator polynomials are pinned against the published ISO/IEC 18004 values (the
 * unambiguous anchor for a hand-rolled encoder), the format/version BCH is checked by
 * divisibility, and the assembled matrix is checked for the mandatory function-pattern
 * structure a scanner locks onto.
 */
import { describe, expect, it } from 'vitest';
import {
  encodeQr,
  formatInformation,
  rsGeneratorPoly,
  versionInformation,
} from './qr';

/** GF(256) log table via the exponent list the encoder builds internally. */
function gfLog(): number[] {
  const exp: number[] = [];
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    exp[i] = x;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  const log = new Array<number>(256).fill(0);
  for (let i = 0; i < 255; i += 1) log[exp[i]] = i;
  return log;
}

describe('QR Galois field + Reed–Solomon', () => {
  it('reproduces the degree-10 generator polynomial from the spec (as α exponents)', () => {
    // ISO/IEC 18004 Annex A generator polynomial for 10 EC codewords.
    const expected = [0, 251, 67, 46, 61, 118, 70, 64, 94, 32, 45];
    const log = gfLog();
    const poly = rsGeneratorPoly(10);
    expect(poly.length).toBe(11);
    expect(poly.map((c) => log[c])).toEqual(expected);
  });

  it('reproduces the degree-7 generator polynomial from the spec', () => {
    const expected = [0, 87, 229, 146, 149, 238, 102, 21];
    const log = gfLog();
    expect(rsGeneratorPoly(7).map((c) => log[c])).toEqual(expected);
  });

  it('leaves the leading generator coefficient as α^0 = 1', () => {
    expect(rsGeneratorPoly(16)[0]).toBe(1);
    expect(rsGeneratorPoly(26)[0]).toBe(1);
  });
});

describe('QR format & version information (BCH)', () => {
  it('produces a valid BCH format codeword for every mask', () => {
    const seen = new Set<number>();
    for (let mask = 0; mask < 8; mask += 1) {
      const format = formatInformation(mask);
      expect(format).toBeGreaterThan(0);
      expect(format).toBeLessThan(1 << 15);
      // Un-masking with 0x5412 must leave a multiple of the format generator 0x537.
      let v = format ^ 0x5412;
      while (32 - Math.clz32(v) >= 11) v ^= 0x537 << (32 - Math.clz32(v) - 11);
      expect(v, `mask ${mask} format is a valid BCH codeword`).toBe(0);
      seen.add(format);
    }
    expect(seen.size).toBe(8);
  });

  it('produces a valid 18-bit BCH version codeword divisible by the version generator', () => {
    for (let version = 7; version <= 10; version += 1) {
      const info = versionInformation(version);
      expect(info >>> 12).toBe(version);
      let v = info;
      while (32 - Math.clz32(v) >= 13) v ^= 0x1f25 << (32 - Math.clz32(v) - 13);
      expect(v, `version ${version} info is a valid BCH codeword`).toBe(0);
    }
  });
});

/** The seven finder-pattern rows (top-left corner), 1:1:3:1:1 with its inner 3x3. */
const FINDER_ROWS = [
  [true, true, true, true, true, true, true],
  [true, false, false, false, false, false, true],
  [true, false, true, true, true, false, true],
  [true, false, true, true, true, false, true],
  [true, false, true, true, true, false, true],
  [true, false, false, false, false, false, true],
  [true, true, true, true, true, true, true],
];

describe('QR matrix structure', () => {
  const deepLink = 'https://companion.example.com/pair#c=9b1f6c0000004000800000000000a1de';
  const encoded = encodeQr(deepLink);

  it('is a square boolean matrix sized 17 + 4·version', () => {
    expect(encoded.size).toBe(encoded.version * 4 + 17);
    expect(encoded.matrix.length).toBe(encoded.size);
    for (const row of encoded.matrix) {
      expect(row.length).toBe(encoded.size);
      for (const cell of row) expect(typeof cell).toBe('boolean');
    }
  });

  it('places the three finder patterns a scanner locks onto', () => {
    const { matrix, size } = encoded;
    for (let r = 0; r < 7; r += 1) {
      for (let c = 0; c < 7; c += 1) {
        expect(matrix[r][c]).toBe(FINDER_ROWS[r][c]); // top-left
        expect(matrix[r][size - 7 + c]).toBe(FINDER_ROWS[r][c]); // top-right
        expect(matrix[size - 7 + r][c]).toBe(FINDER_ROWS[r][c]); // bottom-left
      }
    }
  });

  it('lays alternating timing patterns and sets the dark module', () => {
    const { matrix, size } = encoded;
    for (let i = 8; i < size - 8; i += 1) {
      expect(matrix[6][i]).toBe(i % 2 === 0);
      expect(matrix[i][6]).toBe(i % 2 === 0);
    }
    expect(matrix[size - 8][8]).toBe(true);
  });

  it('selects a small version for a short deep-link and is deterministic', () => {
    expect(encoded.version).toBeGreaterThanOrEqual(1);
    expect(encoded.version).toBeLessThanOrEqual(5);
    const again = encodeQr(deepLink);
    expect(again.matrix).toEqual(encoded.matrix);
  });

  it('grows the version with the payload length', () => {
    const shorter = encodeQr('https://a.example/p#c=1');
    const longer = encodeQr(`https://a.example/p#c=${'a'.repeat(120)}`);
    expect(longer.version).toBeGreaterThan(shorter.version);
  });

  it('throws rather than emit an unscannable matrix when the payload is too large', () => {
    expect(() => encodeQr('x'.repeat(500))).toThrow(RangeError);
  });
});
