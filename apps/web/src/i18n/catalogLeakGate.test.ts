/** Hard localization release gate: no unreviewed source-copy values in any shipped catalog. */
import { describe, expect, it } from 'vitest';
import { daDK } from './locales/da-DK';
import { deDE } from './locales/de-DE';
import { enGB } from './locales/en-GB';
import { enUS } from './locales/en-US';
import { esES } from './locales/es-ES';
import { fiFI } from './locales/fi-FI';
import { frFR } from './locales/fr-FR';
import { itIT } from './locales/it-IT';
import { nlNL } from './locales/nl-NL';
import { plPL } from './locales/pl-PL';
import { ptBR } from './locales/pt-BR';
import { ptPT } from './locales/pt-PT';
import { svFI } from './locales/sv-FI';
import { svSE } from './locales/sv-SE';
import { REVIEWED_IDENTICAL_VALUES } from './reviewedIdenticalValues';

const CATALOGS = {
  'en-US': enUS,
  'en-GB': enGB,
  'pt-BR': ptBR,
  'da-DK': daDK,
  'de-DE': deDE,
  'es-ES': esES,
  'fi-FI': fiFI,
  'fr-FR': frFR,
  'it-IT': itIT,
  'nl-NL': nlNL,
  'pl-PL': plPL,
  'sv-FI': svFI,
  'sv-SE': svSE,
} as const;

const SHARED_VALUES = new Set([
  'Chancela',
  'NIPC',
  'NIF',
  'CAE',
  'TSA',
  'TSL',
  'CMD',
  'CC',
  'IBAN',
  'RGPD',
  'GDPR',
  'PDF',
  'PDF/A',
  'SHA-256',
  'PKCS#12',
  'PKCS#12/PFX',
  'ISO',
  'URL',
  'API',
  'ID',
  'TXT',
  'PFX',
  'e-mail',
  'email',
  'E-mail',
]);

function languageNeutral(value: string): boolean {
  const trimmed = value.trim();
  return (
    trimmed === '' ||
    SHARED_VALUES.has(trimmed) ||
    !/\p{L}/u.test(value) ||
    /^(\s*\{[^}]+\}\s*)+$/u.test(value)
  );
}

function identicalReviewedValues(catalog: Record<string, string>): string[] {
  return [
    ...new Set(
      Object.entries(ptPT)
        .filter(([key, source]) => catalog[key] === source && !languageNeutral(source))
        .map(([, source]) => source),
    ),
  ].sort((left, right) => left.localeCompare(right, 'pt'));
}

function placeholders(value: string): string[] {
  return [...value.matchAll(/\{[^}]+\}/gu)].map((match) => match[0]).sort();
}

describe('hard catalog localization gate', () => {
  it.each(Object.entries(CATALOGS))(
    '%s has exactly the explicit reviewed-identical value set',
    (locale, catalog) => {
      const reviewed = REVIEWED_IDENTICAL_VALUES[locale as keyof typeof REVIEWED_IDENTICAL_VALUES];
      expect(identicalReviewedValues(catalog), `${locale} copied pt-PT values changed`).toEqual([
        ...reviewed,
      ]);
    },
  );

  it.each(Object.entries(CATALOGS))(
    '%s preserves every interpolation placeholder from the source catalog',
    (locale, catalog) => {
      const localizedCatalog = catalog as Record<string, string>;
      const mismatches = Object.entries(ptPT).flatMap(([key, source]) => {
        const expected = placeholders(source);
        const actual = placeholders(localizedCatalog[key] ?? '');
        return JSON.stringify(actual) === JSON.stringify(expected)
          ? []
          : [
              `${key}: expected ${expected.join(', ') || 'none'}; got ${actual.join(', ') || 'none'}`,
            ];
      });
      expect(mismatches, `${locale}\n${mismatches.join('\n')}`).toEqual([]);
    },
  );

  it('keeps pt-BR observably Brazilian without translating legal document names as “minutes”', () => {
    const allCopy = Object.values(ptBR).join('\n');
    expect(allCopy).not.toMatch(
      /\b(?:utilizador(?:es)?|ficheiro(?:s)?|ecrã|registo(?:s)?|registar|registad[ao]s?)\b/iu,
    );
    expect(ptBR['common.save']).toBe('Salvar');
    expect(ptBR['common.saving']).toBe('Salvando…');
    expect(ptBR['acts.singular']).toBe('Ata');
    expect(ptBR['books.atas']).toBe('Atas');
    expect(ptBR['templates.title']).toBe('Minutas');
    expect(ptBR['entities.fiscalYearEnd.saving']).toBe('Salvando…');
    expect(ptBR['entities.fiscalYearEnd.save']).toBe('Salvar fechamento');

    const brazilianCatalog = ptBR as Record<string, string>;
    const differentValues = Object.entries(ptPT).filter(
      ([key, value]) => brazilianCatalog[key] !== value,
    );
    expect(differentValues.length).toBeGreaterThan(Object.keys(ptPT).length / 2);
  });
});
