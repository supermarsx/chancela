import { describe, expect, it } from 'vitest';
import { leatherGrainDataUri, randomSeed } from './leather';

describe('leather grain', () => {
  it('returns a valid, self-contained SVG data URI (no network)', () => {
    const uri = leatherGrainDataUri(12345, 0.7);
    expect(uri.startsWith('data:image/svg+xml,')).toBe(true);
    // Offline parity: everything is inline; nothing points off-origin.
    expect(uri).not.toMatch(/https?:/);

    const svg = decodeURIComponent(uri.slice('data:image/svg+xml,'.length));
    expect(svg).toContain('<svg');
    expect(svg).toContain('feTurbulence');
    expect(svg).toContain("type='fractalNoise'");
    // The injected seed lands in the filter so the field is reproducible.
    expect(svg).toContain("seed='12345'");
  });

  it('varies the grain per load (randomized seed)', () => {
    // Overwhelmingly unlikely to collide across the seed space; guards the
    // "different hide each session" promise.
    const uris = new Set(Array.from({ length: 8 }, () => leatherGrainDataUri()));
    expect(uris.size).toBeGreaterThan(1);
  });

  it('draws seeds from a sane integer range', () => {
    for (let i = 0; i < 50; i++) {
      const s = randomSeed();
      expect(Number.isInteger(s)).toBe(true);
      expect(s).toBeGreaterThanOrEqual(0);
      expect(s).toBeLessThan(100_000);
    }
  });
});
