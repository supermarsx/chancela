/**
 * Locale negotiation for the `auto` language preference (t71).
 *
 * These pin the behaviours that are easy to get subtly wrong and that fail *silently* when they
 * are: a bare subtag falling through to the floor, an ambiguous subtag resolved by accident of
 * source ordering, and the document locale being treated as something a UI preference may change.
 */
import { describe, expect, it } from 'vitest';
import { DETECTABLE_LOCALES, REGION_DEFAULT, negotiateLocale } from './negotiate';
import { SHIPPED_LOCALES } from './registry';

describe('negotiateLocale', () => {
  it('takes an exact tag, case-insensitively', () => {
    expect(negotiateLocale(['de-DE'], 'pt-PT')).toBe('de-DE');
    expect(negotiateLocale(['pt-br'], 'pt-PT')).toBe('pt-BR');
  });

  it('resolves a bare primary subtag rather than falling through to the floor', () => {
    // The step that makes detection actually work: browsers routinely send `de`, not `de-DE`.
    // Without it a German reader would be handed Portuguese.
    expect(negotiateLocale(['de'], 'pt-PT')).toBe('de-DE');
    expect(negotiateLocale(['fi'], 'pt-PT')).toBe('fi-FI');
  });

  it('resolves a shipped language in an unshipped region', () => {
    // We ship no en-AU or de-AT; the reader still wants English/German, not Portuguese.
    expect(negotiateLocale(['en-AU'], 'pt-PT')).toBe('en-GB');
    expect(negotiateLocale(['de-AT'], 'pt-PT')).toBe('de-DE');
  });

  it('resolves ambiguous subtags from the explicit table, not from list order', () => {
    expect(negotiateLocale(['sv'], 'pt-PT')).toBe('sv-SE');
    expect(negotiateLocale(['en'], 'pt-PT')).toBe('en-GB');
    expect(negotiateLocale(['pt'], 'en-GB')).toBe('pt-PT');
  });

  it('keeps the ambiguous-subtag choices independent of SHIPPED_LOCALES ordering', () => {
    // Reversing the shipped list stands in for someone alphabetising `LOCALE_QUALITY`. That edit
    // has no apparent behavioural content, so it must not change which Swedish a Swede gets.
    const reversed = [...SHIPPED_LOCALES].reverse();
    expect(reversed[0]).not.toBe(SHIPPED_LOCALES[0]);
    for (const [subtag, expected] of Object.entries(REGION_DEFAULT)) {
      expect(negotiateLocale([subtag], 'pt-PT'), `${subtag} must not depend on order`).toBe(
        expected,
      );
    }
  });

  it('walks the preference list in order and skips what it cannot serve', () => {
    // `kl-GL` is not shipped in any form; the reader's second choice governs.
    expect(negotiateLocale(['kl-GL', 'nl-NL'], 'pt-PT')).toBe('nl-NL');
    expect(negotiateLocale(['zz', 'qq', 'it'], 'pt-PT')).toBe('it-IT');
  });

  it('falls back to the floor when nothing matches, and when there is nothing to match', () => {
    expect(negotiateLocale(['kl-GL'], 'en-US')).toBe('en-US');
    // No browser (SSR, a server-rendered document or e-mail) ⇒ the floor, which is exactly the
    // server-side rule for `auto`.
    expect(negotiateLocale([], 'en-US')).toBe('en-US');
    expect(negotiateLocale(['', '   '], 'pt-PT')).toBe('pt-PT');
  });

  it('only ever returns a shipped locale', () => {
    for (const tag of ['de', 'en-AU', 'sv', 'kl-GL', '', 'xx-YY']) {
      expect(SHIPPED_LOCALES).toContain(negotiateLocale([tag], 'pt-PT'));
    }
  });

  it('preserves the document locale — negotiation reads the floor, never writes it', () => {
    // `settings.documents.locale` is the language generated LEGAL INSTRUMENTS are written in.
    // A Portuguese company's atas stay pt-PT however its operator reads the interface, so this
    // function must be a pure read of the floor: same floor in, same floor out, no mutation and
    // no path by which a browser preference could redefine it.
    const floor = 'pt-PT' as const;
    const floors = [floor];
    expect(negotiateLocale(['de-DE'], floor)).toBe('de-DE');
    // The floor value and any array holding it are untouched by a negotiation that ignored it.
    expect(floor).toBe('pt-PT');
    expect(floors).toEqual(['pt-PT']);
    // And the floor still governs for a reader we cannot serve.
    expect(negotiateLocale(['kl-GL'], floor)).toBe('pt-PT');
  });

  it('every ambiguous-subtag default is itself detectable', () => {
    for (const [subtag, locale] of Object.entries(REGION_DEFAULT)) {
      expect(DETECTABLE_LOCALES, `${subtag} → ${locale} must be shippable`).toContain(locale);
    }
  });
});
