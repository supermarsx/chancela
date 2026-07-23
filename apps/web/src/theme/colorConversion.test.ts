import { describe, expect, it } from 'vitest';
import { hexToHsv, hsvToHex, type Hsv } from './colorConversion';

/** Normalise a hex the way the picker's store does: lowercase, `#rgb` widened to `#rrggbb`. */
function normaliseHex(hex: string): string {
  const body = hex.slice(1).toLowerCase();
  const wide =
    body.length === 3 ? body[0]! + body[0]! + body[1]! + body[1]! + body[2]! + body[2]! : body;
  return `#${wide}`;
}

describe('hexToHsv', () => {
  it('maps the primary axes of the colour cube', () => {
    expect(hexToHsv('#ff0000')).toEqual({ h: 0, s: 1, v: 1 }); // red
    expect(hexToHsv('#00ff00')).toEqual({ h: 120, s: 1, v: 1 }); // green
    expect(hexToHsv('#0000ff')).toEqual({ h: 240, s: 1, v: 1 }); // blue
    expect(hexToHsv('#ffff00')).toEqual({ h: 60, s: 1, v: 1 }); // yellow
    expect(hexToHsv('#00ffff')).toEqual({ h: 180, s: 1, v: 1 }); // cyan
    expect(hexToHsv('#ff00ff')).toEqual({ h: 300, s: 1, v: 1 }); // magenta
  });

  it('treats greys as hueless, unsaturated columns of the value axis', () => {
    expect(hexToHsv('#000000')).toEqual({ h: 0, s: 0, v: 0 }); // black
    expect(hexToHsv('#ffffff')).toEqual({ h: 0, s: 0, v: 1 }); // white
    const mid = hexToHsv('#808080');
    expect(mid).not.toBeNull();
    expect(mid!.h).toBe(0);
    expect(mid!.s).toBe(0);
    expect(mid!.v).toBeCloseTo(128 / 255, 6);
  });

  it('expands `#rgb` shorthand identically to the full form', () => {
    expect(hexToHsv('#abc')).toEqual(hexToHsv('#aabbcc'));
    expect(hexToHsv('#0f0')).toEqual(hexToHsv('#00ff00'));
  });

  it('accepts either casing', () => {
    expect(hexToHsv('#FF0000')).toEqual(hexToHsv('#ff0000'));
    expect(hexToHsv('#AaBbCc')).toEqual(hexToHsv('#aabbcc'));
  });

  it('returns null for malformed input', () => {
    for (const bad of [
      '',
      '#',
      '#12',
      '#1234',
      '#12345',
      '#1234567',
      'ff0000',
      '#gggggg',
      '#xyz',
    ]) {
      expect(hexToHsv(bad)).toBeNull();
    }
  });
});

describe('hsvToHex', () => {
  it('inverts the primary axes to normalised lowercase 6-digit hex', () => {
    expect(hsvToHex({ h: 0, s: 1, v: 1 })).toBe('#ff0000');
    expect(hsvToHex({ h: 120, s: 1, v: 1 })).toBe('#00ff00');
    expect(hsvToHex({ h: 240, s: 1, v: 1 })).toBe('#0000ff');
    expect(hsvToHex({ h: 0, s: 0, v: 0 })).toBe('#000000');
    expect(hsvToHex({ h: 0, s: 0, v: 1 })).toBe('#ffffff');
  });

  it('wraps hue modulo 360 (including negatives)', () => {
    expect(hsvToHex({ h: 360, s: 1, v: 1 })).toBe(hsvToHex({ h: 0, s: 1, v: 1 }));
    expect(hsvToHex({ h: 480, s: 1, v: 1 })).toBe(hsvToHex({ h: 120, s: 1, v: 1 }));
    expect(hsvToHex({ h: -120, s: 1, v: 1 })).toBe(hsvToHex({ h: 240, s: 1, v: 1 }));
  });

  it('clamps out-of-range saturation and value', () => {
    expect(hsvToHex({ h: 0, s: 2, v: 1 })).toBe('#ff0000'); // s clamps to 1
    expect(hsvToHex({ h: 0, s: 1, v: 5 })).toBe('#ff0000'); // v clamps to 1
    expect(hsvToHex({ h: 0, s: -1, v: 1 })).toBe('#ffffff'); // s clamps to 0 → grey at v
    expect(hsvToHex({ h: 0, s: 1, v: -1 })).toBe('#000000'); // v clamps to 0 → black
  });

  it('folds NaN saturation/value to 0 rather than emitting `#NaNNaNNaN`', () => {
    expect(hsvToHex({ h: 0, s: Number.NaN, v: 1 })).toBe('#ffffff');
    expect(hsvToHex({ h: 0, s: 1, v: Number.NaN })).toBe('#000000');
  });
});

describe('round-trip stability', () => {
  const samples = [
    // Theme palette (COLOR_SEEDS in SettingsPage.tsx).
    '#b8963e',
    '#6b4d12',
    '#f7f3ea',
    '#fffdf8',
    // Brand constants referenced by the picker preset row.
    '#000000',
    '#ffffff',
    '#808080',
    '#123456',
    '#abcdef',
    '#0f0f0f',
    '#fedcba',
    '#00ff88',
    '#ff8800',
  ];

  it('hex → HSV → hex reproduces the original colour byte-for-byte', () => {
    for (const hex of samples) {
      const hsv = hexToHsv(hex);
      expect(hsv, hex).not.toBeNull();
      expect(hsvToHex(hsv as Hsv), hex).toBe(normaliseHex(hex));
    }
  });

  it('is stable across the full 6-bit-per-channel grid', () => {
    const steps = [0, 51, 102, 153, 204, 255];
    for (const r of steps) {
      for (const g of steps) {
        for (const b of steps) {
          const hex = `#${[r, g, b].map((c) => c.toString(16).padStart(2, '0')).join('')}`;
          const hsv = hexToHsv(hex);
          expect(hsv, hex).not.toBeNull();
          expect(hsvToHex(hsv as Hsv), hex).toBe(hex);
        }
      }
    }
  });
});
