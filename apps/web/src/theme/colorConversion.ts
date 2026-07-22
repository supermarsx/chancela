/**
 * Pure hex ↔ HSV colour conversion for the themed colour picker.
 *
 * The picker's 2D saturation/brightness area and hue slider work in HSV, but the
 * colour model everywhere else (store, `applyColorOverrides`, the settings document)
 * speaks hex. These two helpers are the only bridge between them, and they are the
 * *only* colour maths not already in {@link ./appearance}: `parseHexColor` (hex → rgb),
 * `isHexColor`, luminance and ink derivation all live there and are reused, never
 * duplicated.
 *
 * No DOM, no React — pure functions, directly unit-testable.
 *
 * Conventions:
 *   - **Hue** `h` in degrees, `[0, 360)`.
 *   - **Saturation** `s` and **Value/brightness** `v` as fractions, `[0, 1]`.
 * `hsvToHex` always yields a normalised lowercase 6-digit `#rrggbb`, so a
 * hex → HSV → hex round-trip is byte-stable (a `#rgb` shorthand widens to `#rrggbb`).
 */
import { parseHexColor } from './appearance';

/** A colour in HSV space: hue in degrees `[0, 360)`, saturation & value in `[0, 1]`. */
export interface Hsv {
  /** Hue in degrees, `[0, 360)`. */
  h: number;
  /** Saturation, `[0, 1]`. */
  s: number;
  /** Value / brightness, `[0, 1]`. */
  v: number;
}

/** Clamp a number to the `[0, 1]` range (NaN folds to 0). */
function clamp01(n: number): number {
  if (Number.isNaN(n)) return 0;
  return Math.min(1, Math.max(0, n));
}

/**
 * Convert a `#rgb`/`#rrggbb` hex to HSV, or `null` when the hex is malformed.
 *
 * Delegates hex parsing to {@link parseHexColor} (so shorthand, casing and validation
 * behave identically to the rest of the theme layer); a grey/black/white input yields
 * `s = 0` and, being hueless, a conventional `h = 0`.
 */
export function hexToHsv(hex: string): Hsv | null {
  const rgb = parseHexColor(hex);
  if (!rgb) return null;

  const [r, g, b] = rgb.map((c) => c / 255) as [number, number, number];
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const delta = max - min;

  let h = 0;
  if (delta !== 0) {
    if (max === r) h = ((g - b) / delta) % 6;
    else if (max === g) h = (b - r) / delta + 2;
    else h = (r - g) / delta + 4;
    h *= 60;
    if (h < 0) h += 360;
  }

  const s = max === 0 ? 0 : delta / max;
  const v = max;
  return { h, s, v };
}

/**
 * Convert an HSV colour to a normalised lowercase `#rrggbb` hex.
 *
 * Inputs are tolerated liberally: hue wraps modulo 360, saturation and value clamp to
 * `[0, 1]`. The inverse of {@link hexToHsv} up to 8-bit rounding, so
 * `hsvToHex(hexToHsv(hex))` reproduces the original colour.
 */
export function hsvToHex({ h, s, v }: Hsv): string {
  const hue = ((h % 360) + 360) % 360;
  const sat = clamp01(s);
  const val = clamp01(v);

  const c = val * sat;
  const x = c * (1 - Math.abs(((hue / 60) % 2) - 1));
  const m = val - c;

  let r = 0;
  let g = 0;
  let b = 0;
  if (hue < 60) {
    r = c;
    g = x;
  } else if (hue < 120) {
    r = x;
    g = c;
  } else if (hue < 180) {
    g = c;
    b = x;
  } else if (hue < 240) {
    g = x;
    b = c;
  } else if (hue < 300) {
    r = x;
    b = c;
  } else {
    r = c;
    b = x;
  }

  const toByte = (n: number): string =>
    Math.round((n + m) * 255)
      .toString(16)
      .padStart(2, '0');
  return `#${toByte(r)}${toByte(g)}${toByte(b)}`;
}
