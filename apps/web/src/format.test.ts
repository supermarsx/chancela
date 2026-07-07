import { describe, it, expect } from 'vitest';
import { formatAtaNumber } from './format';

describe('formatAtaNumber', () => {
  it('zero-pads the sequence to four digits and appends the year', () => {
    expect(formatAtaNumber(7, 2026)).toBe('Ata n.º 0007/2026');
  });

  it('does not truncate sequences past four digits', () => {
    expect(formatAtaNumber(12345, 2026)).toBe('Ata n.º 12345/2026');
  });

  it('rejects non-positive or non-integer sequences', () => {
    expect(() => formatAtaNumber(0, 2026)).toThrow(RangeError);
    expect(() => formatAtaNumber(-1, 2026)).toThrow(RangeError);
    expect(() => formatAtaNumber(1.5, 2026)).toThrow(RangeError);
  });
});
