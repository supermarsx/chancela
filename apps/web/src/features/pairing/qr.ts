/**
 * Zero-dependency QR Code encoder (wp27-e5, planner Q2 = hand-rolled, no new npm dep).
 *
 * The repo prefers zero new dependencies (it hand-rolled HKDF for t77), so the desktop
 * "connect a phone" panel renders its pairing deep-link as a QR matrix produced entirely
 * in-tree rather than pulling a QR library. This module implements the ISO/IEC 18004
 * pipeline needed to encode a short URL: **byte mode**, error-correction level **M**,
 * automatic version selection over **versions 1–10** (the deep-link is always well under
 * the ~213-byte v10-M ceiling), Reed–Solomon over GF(256), the eight data masks with the
 * standard penalty scoring, and BCH-coded format/version information.
 *
 * The output is a square boolean matrix (`true` = dark module), quiet zone NOT included —
 * the SVG renderer ({@link ./QrCode}) draws the 4-module quiet border. Correctness of the
 * Galois-field arithmetic and generator polynomials is pinned by `qr.test.ts` against the
 * published spec values, and the format/version BCH is self-checked by divisibility.
 *
 * Scope note: only what the pairing deep-link needs. No numeric/alphanumeric/kanji modes,
 * no versions above 10, no structured-append. If a future caller needs a longer payload,
 * extend {@link VERSION_M} and the alignment table rather than reaching for a dependency.
 */

/** Error-correction level. This module only ever emits **M** (see {@link encodeQr}). */
const EC_LEVEL_M = 0b00;

/**
 * Per-version (level M) error-correction characteristics for versions 1–10:
 * `ecPerBlock` = EC codewords per block, `groups` = `[blockCount, dataCodewordsPerBlock]`
 * pairs. Values are the ISO/IEC 18004 block table for level M.
 */
interface VersionSpec {
  ecPerBlock: number;
  groups: [number, number][];
}

const VERSION_M: Record<number, VersionSpec> = {
  1: { ecPerBlock: 10, groups: [[1, 16]] },
  2: { ecPerBlock: 16, groups: [[1, 28]] },
  3: { ecPerBlock: 26, groups: [[1, 44]] },
  4: { ecPerBlock: 18, groups: [[2, 32]] },
  5: { ecPerBlock: 24, groups: [[2, 43]] },
  6: { ecPerBlock: 16, groups: [[4, 27]] },
  7: { ecPerBlock: 18, groups: [[4, 31]] },
  8: {
    ecPerBlock: 22,
    groups: [
      [2, 38],
      [2, 39],
    ],
  },
  9: {
    ecPerBlock: 22,
    groups: [
      [3, 36],
      [2, 37],
    ],
  },
  10: {
    ecPerBlock: 26,
    groups: [
      [4, 43],
      [1, 44],
    ],
  },
};

/** Centre coordinates of the alignment patterns per version (level-independent). */
const ALIGNMENT_POSITIONS: Record<number, number[]> = {
  1: [],
  2: [6, 18],
  3: [6, 22],
  4: [6, 26],
  5: [6, 30],
  6: [6, 34],
  7: [6, 22, 38],
  8: [6, 24, 42],
  9: [6, 26, 46],
  10: [6, 28, 50],
};

const MAX_VERSION = 10;

// --- Galois field GF(256) -------------------------------------------------------
// Primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D), generator element α = 2.

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);

(function initGaloisField() {
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  // Mirror the exponent table so gfMul can index without a modulo on the sum.
  for (let i = 255; i < 512; i += 1) GF_EXP[i] = GF_EXP[i - 255];
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

/**
 * The Reed–Solomon generator polynomial of the given degree, returned as coefficients
 * (highest-order first) in GF(256). `(x - α^0)(x - α^1)…(x - α^{degree-1})`.
 */
export function rsGeneratorPoly(degree: number): number[] {
  let poly = [1];
  for (let i = 0; i < degree; i += 1) {
    const next = new Array<number>(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j += 1) {
      next[j] ^= poly[j]; // x · poly (degree shift up)
      next[j + 1] ^= gfMul(poly[j], GF_EXP[i]); // α^i · poly
    }
    poly = next;
  }
  return poly;
}

/** The `ecLen` Reed–Solomon error-correction codewords for one data block. */
function rsEncodeBlock(data: number[], ecLen: number): number[] {
  const generator = rsGeneratorPoly(ecLen);
  const remainder = new Array<number>(ecLen).fill(0);
  for (const byte of data) {
    const factor = byte ^ remainder[0];
    remainder.shift();
    remainder.push(0);
    if (factor !== 0) {
      for (let i = 0; i < ecLen; i += 1) {
        remainder[i] ^= gfMul(generator[i + 1], factor);
      }
    }
  }
  return remainder;
}

// --- Bit buffer -----------------------------------------------------------------

class BitBuffer {
  readonly bits: number[] = [];

  put(value: number, length: number): void {
    for (let i = length - 1; i >= 0; i -= 1) {
      this.bits.push((value >>> i) & 1);
    }
  }

  get length(): number {
    return this.bits.length;
  }
}

// --- Data encoding --------------------------------------------------------------

function totalDataCodewords(spec: VersionSpec): number {
  return spec.groups.reduce((sum, [count, size]) => sum + count * size, 0);
}

/** The maximum byte-mode payload (in bytes) a level-M version can carry. */
function byteCapacity(version: number): number {
  const spec = VERSION_M[version];
  const countBits = version >= 10 ? 16 : 8;
  const availableBits = totalDataCodewords(spec) * 8 - 4 - countBits;
  return Math.floor(availableBits / 8);
}

/** Smallest level-M version (1–10) whose byte-mode capacity holds `byteLength`. */
function chooseVersion(byteLength: number): number {
  for (let version = 1; version <= MAX_VERSION; version += 1) {
    if (byteLength <= byteCapacity(version)) return version;
  }
  throw new RangeError(
    `payload of ${byteLength} bytes exceeds QR byte-mode level-M version-${MAX_VERSION} capacity`,
  );
}

/** UTF-8 encode; the QR byte-mode reader interprets the bytes as ISO-8859-1/UTF-8. */
function utf8Bytes(text: string): number[] {
  return Array.from(new TextEncoder().encode(text));
}

/**
 * Assemble the final interleaved data+EC codeword stream for `version` from the raw
 * byte payload: mode header, terminator, pad bytes, per-block Reed–Solomon, then the
 * standard block interleave.
 */
function buildCodewords(bytes: number[], version: number): number[] {
  const spec = VERSION_M[version];
  const dataCount = totalDataCodewords(spec);
  const countBits = version >= 10 ? 16 : 8;

  const buffer = new BitBuffer();
  buffer.put(0b0100, 4); // byte mode
  buffer.put(bytes.length, countBits);
  for (const byte of bytes) buffer.put(byte, 8);

  // Terminator (up to 4 zero bits) then pad to a byte boundary.
  const capacityBits = dataCount * 8;
  const terminator = Math.min(4, capacityBits - buffer.length);
  buffer.put(0, terminator);
  while (buffer.length % 8 !== 0) buffer.bits.push(0);

  // Data codewords, then alternating pad codewords 0xEC / 0x11 to fill.
  const dataCodewords: number[] = [];
  for (let i = 0; i < buffer.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j += 1) byte = (byte << 1) | buffer.bits[i + j];
    dataCodewords.push(byte);
  }
  const pad = [0xec, 0x11];
  for (let i = 0; dataCodewords.length < dataCount; i += 1) {
    dataCodewords.push(pad[i % 2]);
  }

  // Split into blocks per the group table; compute EC per block.
  const dataBlocks: number[][] = [];
  const ecBlocks: number[][] = [];
  let offset = 0;
  for (const [count, size] of spec.groups) {
    for (let b = 0; b < count; b += 1) {
      const block = dataCodewords.slice(offset, offset + size);
      offset += size;
      dataBlocks.push(block);
      ecBlocks.push(rsEncodeBlock(block, spec.ecPerBlock));
    }
  }

  // Interleave data codewords column-wise, then EC codewords column-wise.
  const result: number[] = [];
  const maxData = Math.max(...dataBlocks.map((b) => b.length));
  for (let i = 0; i < maxData; i += 1) {
    for (const block of dataBlocks) if (i < block.length) result.push(block[i]);
  }
  for (let i = 0; i < spec.ecPerBlock; i += 1) {
    for (const block of ecBlocks) result.push(block[i]);
  }
  return result;
}

// --- Matrix construction --------------------------------------------------------

type Cell = boolean | null;

function matrixSize(version: number): number {
  return version * 4 + 17;
}

function emptyMatrix(size: number): Cell[][] {
  return Array.from({ length: size }, () => new Array<Cell>(size).fill(null));
}

function placeFinder(matrix: Cell[][], row: number, col: number): void {
  for (let r = -1; r <= 7; r += 1) {
    for (let c = -1; c <= 7; c += 1) {
      const rr = row + r;
      const cc = col + c;
      if (rr < 0 || rr >= matrix.length || cc < 0 || cc >= matrix.length) continue;
      const onFinder =
        (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
        (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
        (r >= 2 && r <= 4 && c >= 2 && c <= 4);
      matrix[rr][cc] = onFinder;
    }
  }
}

function placeAlignment(matrix: Cell[][], version: number): void {
  const positions = ALIGNMENT_POSITIONS[version];
  for (const row of positions) {
    for (const col of positions) {
      // Skip the three that overlap the finder patterns.
      if (matrix[row][col] !== null) continue;
      for (let r = -2; r <= 2; r += 1) {
        for (let c = -2; c <= 2; c += 1) {
          const ring = Math.max(Math.abs(r), Math.abs(c));
          matrix[row + r][col + c] = ring !== 1;
        }
      }
    }
  }
}

function placeTiming(matrix: Cell[][]): void {
  const size = matrix.length;
  for (let i = 8; i < size - 8; i += 1) {
    const on = i % 2 === 0;
    if (matrix[6][i] === null) matrix[6][i] = on;
    if (matrix[i][6] === null) matrix[i][6] = on;
  }
}

/** Reserve (mark non-null, value irrelevant — overwritten later) the format-info modules. */
function reserveFormatAreas(matrix: Cell[][], version: number): void {
  const size = matrix.length;
  for (let i = 0; i <= 8; i += 1) {
    if (i !== 6) {
      if (matrix[8][i] === null) matrix[8][i] = false;
      if (matrix[i][8] === null) matrix[i][8] = false;
    }
  }
  for (let i = 0; i < 8; i += 1) {
    if (matrix[8][size - 1 - i] === null) matrix[8][size - 1 - i] = false;
    if (matrix[size - 1 - i][8] === null) matrix[size - 1 - i][8] = false;
  }
  matrix[size - 8][8] = true; // dark module (always set)
  if (version >= 7) {
    for (let i = 0; i < 6; i += 1) {
      for (let j = 0; j < 3; j += 1) {
        matrix[size - 11 + j][i] = false;
        matrix[i][size - 11 + j] = false;
      }
    }
  }
}

/** A boolean grid marking every function (non-data) module, for the zigzag placement. */
function functionMask(version: number): boolean[][] {
  const size = matrixSize(version);
  const probe = emptyMatrix(size);
  placeFinder(probe, 0, 0);
  placeFinder(probe, 0, size - 7);
  placeFinder(probe, size - 7, 0);
  placeAlignment(probe, version);
  placeTiming(probe);
  reserveFormatAreas(probe, version);
  return probe.map((row) => row.map((cell) => cell !== null));
}

/** Lay the codeword bitstream into the data region in the standard upward/downward zigzag. */
function placeData(matrix: Cell[][], codewords: number[], reserved: boolean[][]): void {
  const size = matrix.length;
  const bits: number[] = [];
  for (const cw of codewords) {
    for (let i = 7; i >= 0; i -= 1) bits.push((cw >>> i) & 1);
  }
  let bitIndex = 0;
  let upward = true;
  for (let col = size - 1; col > 0; col -= 2) {
    const c = col === 6 ? col - 1 : col; // skip the vertical timing column
    for (let step = 0; step < size; step += 1) {
      const row = upward ? size - 1 - step : step;
      for (let k = 0; k < 2; k += 1) {
        const cc = c - k;
        if (reserved[row][cc]) continue;
        matrix[row][cc] = bitIndex < bits.length ? bits[bitIndex] === 1 : false;
        bitIndex += 1;
      }
    }
    upward = !upward;
  }
}

function maskCondition(mask: number, row: number, col: number): boolean {
  switch (mask) {
    case 0:
      return (row + col) % 2 === 0;
    case 1:
      return row % 2 === 0;
    case 2:
      return col % 3 === 0;
    case 3:
      return (row + col) % 3 === 0;
    case 4:
      return (Math.floor(row / 2) + Math.floor(col / 3)) % 2 === 0;
    case 5:
      return ((row * col) % 2) + ((row * col) % 3) === 0;
    case 6:
      return (((row * col) % 2) + ((row * col) % 3)) % 2 === 0;
    default:
      return (((row + col) % 2) + ((row * col) % 3)) % 2 === 0;
  }
}

function applyMask(matrix: Cell[][], reserved: boolean[][], mask: number): boolean[][] {
  const size = matrix.length;
  const out: boolean[][] = [];
  for (let r = 0; r < size; r += 1) {
    const row: boolean[] = [];
    for (let c = 0; c < size; c += 1) {
      let value = matrix[r][c] === true;
      if (!reserved[r][c] && maskCondition(mask, r, c)) value = !value;
      row.push(value);
    }
    out.push(row);
  }
  return out;
}

// --- Format & version information (BCH) -----------------------------------------

/** BCH remainder of `value` under generator `poly` (leaving `value` in the high bits). */
function bchRemainder(value: number, poly: number, dataBits: number): number {
  const polyBits = 32 - Math.clz32(poly);
  let v = value;
  while (32 - Math.clz32(v) >= polyBits) {
    v ^= poly << (32 - Math.clz32(v) - polyBits);
  }
  void dataBits;
  return v;
}

/** The 15-bit format-information code for level M and the chosen mask. */
export function formatInformation(mask: number): number {
  const data = (EC_LEVEL_M << 3) | mask; // 5 bits
  const bch = bchRemainder(data << 10, 0x537, 5);
  return ((data << 10) | bch) ^ 0x5412;
}

/** The 18-bit version-information code (versions 7+). */
export function versionInformation(version: number): number {
  const bch = bchRemainder(version << 12, 0x1f25, 6);
  return (version << 12) | bch;
}

function placeFormatInformation(matrix: boolean[][], mask: number): void {
  const size = matrix.length;
  const format = formatInformation(mask);
  // 15 bits, LSB-first around the top-left, split across the two standard runs.
  const bit = (i: number) => ((format >>> i) & 1) === 1;
  for (let i = 0; i <= 5; i += 1) matrix[8][i] = bit(i);
  matrix[8][7] = bit(6);
  matrix[8][8] = bit(7);
  matrix[7][8] = bit(8);
  for (let i = 9; i <= 14; i += 1) matrix[14 - i][8] = bit(i);

  for (let i = 0; i <= 7; i += 1) matrix[size - 1 - i][8] = bit(i);
  for (let i = 8; i <= 14; i += 1) matrix[8][size - 15 + i] = bit(i);
  matrix[size - 8][8] = true; // dark module
}

function placeVersionInformation(matrix: boolean[][], version: number): void {
  if (version < 7) return;
  const size = matrix.length;
  const info = versionInformation(version);
  for (let i = 0; i < 18; i += 1) {
    const on = ((info >>> i) & 1) === 1;
    const row = Math.floor(i / 3);
    const col = i % 3;
    matrix[row][size - 11 + col] = on;
    matrix[size - 11 + col][row] = on;
  }
}

// --- Mask penalty scoring (ISO/IEC 18004 §8.8.2) --------------------------------

function penalty(matrix: boolean[][]): number {
  const size = matrix.length;
  let score = 0;

  // Rule 1: runs of ≥5 same-colour modules in a row/column.
  for (let r = 0; r < size; r += 1) {
    let runRow = 1;
    let runCol = 1;
    for (let c = 1; c < size; c += 1) {
      if (matrix[r][c] === matrix[r][c - 1]) runRow += 1;
      else runRow = 1;
      if (runRow === 5) score += 3;
      else if (runRow > 5) score += 1;
      if (matrix[c][r] === matrix[c - 1][r]) runCol += 1;
      else runCol = 1;
      if (runCol === 5) score += 3;
      else if (runCol > 5) score += 1;
    }
  }

  // Rule 2: 2x2 blocks of the same colour.
  for (let r = 0; r < size - 1; r += 1) {
    for (let c = 0; c < size - 1; c += 1) {
      const v = matrix[r][c];
      if (v === matrix[r][c + 1] && v === matrix[r + 1][c] && v === matrix[r + 1][c + 1]) {
        score += 3;
      }
    }
  }

  // Rule 3: finder-like 1:1:3:1:1 patterns (with a 4-module light run) in rows/columns.
  const pattern1 = [true, false, true, true, true, false, true, false, false, false, false];
  const pattern2 = [false, false, false, false, true, false, true, true, true, false, true];
  const matches = (get: (i: number) => boolean, start: number, pat: boolean[]) => {
    for (let i = 0; i < pat.length; i += 1) if (get(start + i) !== pat[i]) return false;
    return true;
  };
  for (let r = 0; r < size; r += 1) {
    for (let c = 0; c <= size - 11; c += 1) {
      if (matches((i) => matrix[r][i], c, pattern1)) score += 40;
      if (matches((i) => matrix[r][i], c, pattern2)) score += 40;
      if (matches((i) => matrix[i][r], c, pattern1)) score += 40;
      if (matches((i) => matrix[i][r], c, pattern2)) score += 40;
    }
  }

  // Rule 4: overall dark-module balance.
  let dark = 0;
  for (let r = 0; r < size; r += 1) for (let c = 0; c < size; c += 1) if (matrix[r][c]) dark += 1;
  const ratio = (dark * 100) / (size * size);
  score += Math.floor(Math.abs(ratio - 50) / 5) * 10;

  return score;
}

// --- Public API -----------------------------------------------------------------

export interface QrMatrix {
  /** Module grid: `matrix[row][col]`, `true` = dark. Quiet zone NOT included. */
  matrix: boolean[][];
  /** Side length in modules. */
  size: number;
  /** The level-M version actually chosen. */
  version: number;
}

/**
 * Encode `text` as a byte-mode, level-M QR matrix, choosing the smallest version (1–10)
 * that fits and the lowest-penalty of the eight data masks. Throws {@link RangeError} if
 * the payload exceeds the version-10 capacity (~213 bytes) — the caller (pairing panel)
 * keeps its payload far below that, and shows a copyable deep-link regardless.
 */
export function encodeQr(text: string): QrMatrix {
  const bytes = utf8Bytes(text);
  const version = chooseVersion(bytes.length);
  const size = matrixSize(version);
  const codewords = buildCodewords(bytes, version);

  const base = emptyMatrix(size);
  placeFinder(base, 0, 0);
  placeFinder(base, 0, size - 7);
  placeFinder(base, size - 7, 0);
  placeAlignment(base, version);
  placeTiming(base);
  reserveFormatAreas(base, version);
  const reserved = functionMask(version);
  placeData(base, codewords, reserved);

  let best: boolean[][] | null = null;
  let bestScore = Infinity;
  for (let mask = 0; mask < 8; mask += 1) {
    const masked = applyMask(base, reserved, mask);
    placeFormatInformation(masked, mask);
    placeVersionInformation(masked, version);
    const score = penalty(masked);
    if (score < bestScore) {
      bestScore = score;
      best = masked;
    }
  }

  return { matrix: best as boolean[][], size, version };
}
