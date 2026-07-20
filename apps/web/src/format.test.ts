import { describe, it, expect, afterEach } from 'vitest';
import {
  NO_DATE,
  formatAtaNumber,
  formatDate,
  formatDateTime,
  formatRelative,
  formatTimestamp,
  isoAttribute,
} from './format';
import { i18nStore } from './i18n';

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

  it('rejects non-positive or non-integer years', () => {
    expect(() => formatAtaNumber(1, 0)).toThrow(RangeError);
    expect(() => formatAtaNumber(1, -2026)).toThrow(RangeError);
    expect(() => formatAtaNumber(1, 2026.5)).toThrow(RangeError);
  });
});

// The instant the user reported seeing raw in the UI: RFC 3339 with NANOSECOND precision,
// straight off the wire. Every assertion below exists so that string never reaches a reader.
const NANOS = '2026-07-20T22:41:06.589989639Z';

describe('date and timestamp formatting', () => {
  afterEach(() => {
    i18nStore.setActiveLocale('pt-PT');
  });

  describe('formatDate', () => {
    it('renders a calendar day with no time component', () => {
      const rendered = formatDate('2026-07-20');
      expect(rendered).toContain('2026');
      // A bare date must never grow a `00:00` tail; a colon is the tell.
      expect(rendered).not.toContain(':');
    });

    it('renders no time even when the input carries one', () => {
      expect(formatDate(NANOS)).not.toContain(':');
    });
  });

  describe('formatDateTime', () => {
    it('renders to the minute and never leaks sub-second precision', () => {
      const rendered = formatDateTime(NANOS);
      expect(rendered).toMatch(/\d{1,2}:\d{2}/);
      expect(rendered).not.toContain('589989639');
      expect(rendered).not.toContain('589');
      expect(rendered).not.toContain('T');
    });
  });

  describe('formatTimestamp', () => {
    it('renders evidentiary precision to the second, with a time zone, without nanoseconds', () => {
      const rendered = formatTimestamp(NANOS);
      expect(rendered).toMatch(/\d{1,2}:\d{2}:\d{2}/);
      expect(rendered).not.toContain('589989639');
      // A local wall-clock time with no zone is ambiguous in an audit trail.
      expect(rendered).not.toBe(formatDateTime(NANOS));
    });
  });

  describe('the active locale drives the output', () => {
    it('formats the same instant differently in pt-PT and en-US', () => {
      i18nStore.setActiveLocale('pt-PT');
      const portuguese = formatDate('2026-07-20T10:00:00Z');
      i18nStore.setActiveLocale('en-US');
      const english = formatDate('2026-07-20T10:00:00Z');

      expect(portuguese).not.toBe(english);
      expect(portuguese).toContain('julho');
      expect(english).toContain('July');
    });

    it('takes an explicit locale override without touching the active one', () => {
      i18nStore.setActiveLocale('pt-PT');
      expect(formatDate('2026-07-20T10:00:00Z', 'de-DE')).toContain('Juli');
      expect(i18nStore.getActiveLocale()).toBe('pt-PT');
    });

    it('formats relative time in the active locale', () => {
      const now = new Date('2026-07-20T12:00:00Z');
      const threeMinutesEarlier = new Date('2026-07-20T11:57:00Z');

      i18nStore.setActiveLocale('pt-PT');
      expect(formatRelative(threeMinutesEarlier, now)).toBe('há 3 minutos');
      i18nStore.setActiveLocale('en-US');
      expect(formatRelative(threeMinutesEarlier, now)).toBe('3 minutes ago');
    });
  });

  describe('formatRelative', () => {
    const now = new Date('2026-07-20T12:00:00Z');

    it('picks the largest unit that fits', () => {
      expect(formatRelative(new Date('2026-07-20T11:00:00Z'), now)).toBe('há 1 hora');
      // `numeric: 'auto'` prefers the idiomatic word where the locale has one.
      expect(formatRelative(new Date('2026-07-19T12:00:00Z'), now)).toBe('ontem');
      expect(formatRelative(new Date('2026-07-17T12:00:00Z'), now)).toBe('há 3 dias');
      expect(formatRelative(new Date('2025-07-20T12:00:00Z'), now)).toBe('ano passado');
      expect(formatRelative(new Date('2024-07-20T12:00:00Z'), now)).toBe('há 2 anos');
    });

    it('handles future instants and the sub-second case', () => {
      expect(formatRelative(new Date('2026-07-20T12:05:00Z'), now)).toBe('dentro de 5 minutos');
      expect(formatRelative(new Date('2026-07-20T12:00:00.400Z'), now)).toBe('agora');
    });
  });

  describe('invalid and missing values', () => {
    const rejected = [null, undefined, '', 'not-a-date', Number.NaN, new Date('nope')];

    it('renders the placeholder rather than "Invalid Date", "NaN", or the raw string', () => {
      for (const value of rejected) {
        for (const format of [formatDate, formatDateTime, formatTimestamp]) {
          expect(format(value)).toBe(NO_DATE);
        }
        expect(formatRelative(value)).toBe(NO_DATE);
      }
    });

    it('never emits a datetime attribute it cannot stand behind', () => {
      for (const value of rejected) {
        expect(isoAttribute(value)).toBeUndefined();
      }
    });
  });

  describe('isoAttribute', () => {
    it('preserves the original precision verbatim so a verifier loses nothing', () => {
      expect(isoAttribute(NANOS)).toBe(NANOS);
    });

    it('derives an ISO string for Date and epoch-millis inputs', () => {
      expect(isoAttribute(new Date('2026-07-20T22:41:06.589Z'))).toBe('2026-07-20T22:41:06.589Z');
      expect(isoAttribute(Date.parse('2026-07-20T22:41:06.589Z'))).toBe(
        '2026-07-20T22:41:06.589Z',
      );
    });
  });
});
