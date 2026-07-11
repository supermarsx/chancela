/**
 * i18n framework tests: the completeness contract (every shipped locale carries exactly
 * the source key set), `{param}` interpolation, and the store's locale fallback. The
 * completeness matrix is the guard that lets t19-e3b/e3c fill their locale files without
 * being able to drift the frozen key set.
 */
import { describe, it, expect } from 'vitest';
import { ptPT } from './locales/pt-PT';
import { enUS } from './locales/en-US';
import { enGB } from './locales/en-GB';
import { deDE } from './locales/de-DE';
import { daDK } from './locales/da-DK';
import { esES } from './locales/es-ES';
import { fiFI } from './locales/fi-FI';
import { frFR } from './locales/fr-FR';
import { itIT } from './locales/it-IT';
import { nlNL } from './locales/nl-NL';
import { plPL } from './locales/pl-PL';
import { svFI } from './locales/sv-FI';
import { svSE } from './locales/sv-SE';
import { interpolate } from './interpolate';
import { i18nStore } from './store';
import { LOCALE_LOADERS, LOCALE_QUALITY, SHIPPED_LOCALES } from './registry';

const sourceKeys = Object.keys(ptPT).sort();

describe('catalog completeness matrix', () => {
  it('the source catalog has a non-trivial key set', () => {
    expect(sourceKeys.length).toBeGreaterThan(200);
  });

  it('uses natural pt-PT wording for the registry catch-all filter', () => {
    expect(ptPT['entities.filters.registry.all']).toBe('Qualquer estado');
    expect(ptPT['entities.filters.registry.all']).not.toBe('Todo o registo');
  });

  it('keeps missing-attendance reminder copy in European Portuguese', () => {
    expect(ptPT['notifications.reminder.act.attendance.title']).toBe(
      'Registar presenças: {act_title}',
    );
    expect(ptPT['notifications.reminder.act.attendance.body']).toContain('Registe');
    expect(ptPT['notifications.reminder.act.attendance.action']).toBe('Registar presenças');
    expect(ptPT['notifications.reminder.act.attendance.title']).not.toContain('Registrar');
    expect(ptPT['notifications.reminder.act.attendance.body']).not.toContain('Registre');
  });

  it('keeps PDF validator copy localized in the English catalog', () => {
    expect(enUS['tools.section.pdfValidator']).toBe('PDF validator');
    expect(enUS['pdfValidator.file.label']).toBe('Signed PDF');
    expect(enUS['pdfValidator.action.validate']).toBe('Validate PDF');
    expect(enUS['pdfValidator.notice.title']).not.toBe('Validação técnica local');
  });

  it('keeps representative non-English PDF validator copy out of stale Portuguese', () => {
    for (const catalog of [deDE, svSE]) {
      expect(catalog['pdfValidator.notice.title']).not.toBe('Validação técnica local');
      expect(catalog['pdfValidator.file.label']).not.toBe('PDF assinado');
    }
  });

  it('keeps imported-document guardrail copy localized in the English catalog', () => {
    expect(enUS['documents.import.guardrails.title']).toBe('Preservation limits');
    expect(enUS['documents.import.guardrails.canonical.label']).toBe('Canonical record');
    expect(enUS['documents.import.guardrails.signed.label']).toBe('Signed artifact');
    expect(enUS['documents.import.guardrails.title']).not.toBe('Limites de preservação');
    expect(enUS['documents.import.guardrails.canonical.label']).not.toBe('Registo canónico');
  });

  it('keeps representative non-English guardrail copy out of stale Portuguese', () => {
    for (const catalog of [deDE, svSE]) {
      expect(catalog['documents.import.guardrails.title']).not.toBe('Limites de preservação');
      expect(catalog['documents.import.guardrails.canonical.label']).not.toBe('Registo canónico');
    }
  });

  it('keeps local PKCS#12 signing copy localized outside source Portuguese', () => {
    expect(enUS['signing.provider.pkcs12.title']).toBe('Local PKCS#12/PFX certificate');
    expect(enUS['signing.pkcs12.file.label']).toBe('PKCS#12/PFX file');
    expect(enUS['signing.pkcs12.notice']).not.toContain('ficheiro PFX');
    for (const catalog of [deDE, svFI, svSE]) {
      expect(catalog['signing.signed.localPkcs12Title']).not.toBe(
        ptPT['signing.signed.localPkcs12Title'],
      );
      expect(catalog['signing.provider.pkcs12.title']).not.toBe(
        ptPT['signing.provider.pkcs12.title'],
      );
      expect(catalog['signing.pkcs12.file.label']).not.toBe(ptPT['signing.pkcs12.file.label']);
      expect(catalog['signing.pkcs12.notice']).not.toContain('ficheiro PFX');
    }
  });

  it('keeps external invite signed-PDF evidence copy localized outside source Portuguese', () => {
    const keys = [
      'externalInvite.tracking.title',
      'externalInvite.tracking.body',
      'externalInvite.alreadyAnswered',
      'externalInvite.technical.title',
      'externalInvite.technical.slotStatus',
      'externalInvite.technical.blocked.title',
      'externalInvite.technical.artifact.title',
      'externalInvite.technical.evidenceLevel',
      'externalInvite.technical.scope',
      'externalInvite.technical.digest',
      'externalInvite.technical.timestamp',
      'externalInvite.technical.qualificationClaimed',
      'externalInvite.technical.legalStatusClaimed',
      'externalInvite.upload.guardrail.title',
      'externalInvite.upload.guardrail.body',
      'externalInvite.upload.file.label',
      'externalInvite.upload.file.hint',
      'externalInvite.upload.file.tooLarge',
      'externalInvite.upload.ack',
      'externalInvite.upload.submit',
      'externalInvite.registering',
      'externalInvite.accept',
      'externalInvite.decline',
      'signing.invites.workflow.slotStatus',
    ] as const;
    const portugueseSourcePhrases =
      /Acompanhamento apenas|Resposta já registada|Este estado não é assinatura qualificada|Resultado técnico|Estado do slot|Atualização técnica|Artefacto técnico|Nível de evidência|Âmbito declarado|Qualificação reclamada|Estado legal reclamado|PDF assinado|Selo temporal|Carregamento de evidência|Carregue apenas|O ficheiro é enviado|pode ter no máximo|Reconheço que este carregamento|Carregar PDF|A registar|Aceitar acompanhamento|Declinar/;

    expect(enUS['externalInvite.tracking.title']).toBe('Tracking only');
    expect(enUS['externalInvite.technical.slotStatus']).toBe('Slot status');
    expect(enUS['externalInvite.technical.scope']).toBe('Declared scope');
    expect(enUS['externalInvite.technical.qualificationClaimed']).toBe('Qualification claimed');
    expect(enUS['externalInvite.upload.file.label']).toBe('Signed PDF');
    expect(enUS['externalInvite.upload.file.tooLarge']).toBe(
      'The signed PDF can be at most {max}.',
    );
    expect(enUS['externalInvite.upload.submit']).toBe('Upload PDF and accept');
    expect(enUS['externalInvite.decline']).toBe('Decline');
    expect(enGB['externalInvite.technical.digest']).toBe('Signed PDF SHA-256');
    expect(deDE['externalInvite.tracking.title']).toBe('Nur Nachverfolgung');
    expect(deDE['externalInvite.upload.file.label']).toBe('Signiertes PDF');
    expect(deDE['externalInvite.upload.submit']).toBe('PDF hochladen und annehmen');
    expect(deDE['externalInvite.technical.digest']).toBe('SHA-256 des signierten PDF');

    const nonPortugueseCatalogs = [
      ['da-DK', daDK],
      ['de-DE', deDE],
      ['en-GB', enGB],
      ['en-US', enUS],
      ['es-ES', esES],
      ['fi-FI', fiFI],
      ['fr-FR', frFR],
      ['it-IT', itIT],
      ['nl-NL', nlNL],
      ['pl-PL', plPL],
      ['sv-FI', svFI],
      ['sv-SE', svSE],
    ] as const;

    for (const [locale, catalog] of nonPortugueseCatalogs) {
      for (const key of keys) {
        expect(catalog[key], `${locale} ${key}`).not.toMatch(portugueseSourcePhrases);
      }
    }
  });

  it('keeps external-signing envelope evidence copy localized outside source Portuguese', () => {
    const keys = [
      'signing.envelopes.guardrail.title',
      'signing.envelopes.guardrail.body',
      'signing.envelopes.table.evidence',
      'signing.envelopes.table.actions',
      'signing.envelopes.evidence.none',
      'signing.envelopes.evidence.record',
      'signing.envelopes.evidence.noAction',
      'signing.envelopes.evidence.formTitle',
      'signing.envelopes.evidence.formNotice',
      'signing.envelopes.evidence.defaultLabel',
      'signing.envelopes.evidence.label',
      'signing.envelopes.evidence.reference',
      'signing.envelopes.evidence.digest',
      'signing.envelopes.evidence.identityTitle',
      'signing.envelopes.evidence.identityLabel',
      'signing.envelopes.evidence.identityReference',
      'signing.envelopes.evidence.identityHint',
      'signing.envelopes.evidence.identityMissingTitle',
      'signing.envelopes.evidence.identityMissingBody',
      'signing.envelopes.evidence.submit',
      'signing.envelopes.evidence.recording',
      'signing.envelopes.evidence.recordedToast',
      'signing.envelopes.identity.none',
      'signing.envelopes.identity.contactControl',
      'signing.envelopes.identity.providerIdentity',
      'signing.envelopes.identity.governmentId',
      'signing.envelopes.identity.representativeCapacity',
    ] as const;
    const portugueseSourcePhrases =
      /Acompanhamento operacional|Envelopes e convites|evidência|Evidência|Registar|registar|registad[ao]|Sem ação|Ações|Etiqueta da evidência|Referência da evidência|Digest opcional|identidade incompleta|requisito de identidade|Adicione uma referência|marcar slot assinado|A registar|metadados técnicos|prestadores|assinatura qualificada|validação de confiança|estado legal|finalização da ata|conclusão do envelope|Sem requisito adicional|Controlo do contacto|Declaração de identidade do prestador|Verificação de documento oficial|Capacidade de representação/;

    expect(enUS['signing.envelopes.evidence.formTitle']).toBe('Operator technical evidence');
    expect(enGB['signing.envelopes.evidence.recording']).toBe('Recording…');
    expect(deDE['signing.envelopes.evidence.formTitle']).toBe('Technischer Nachweis des Bedieners');
    expect(svSE['signing.envelopes.evidence.record']).toBe('Registrera bevis');
    expect(esES['signing.envelopes.identity.contactControl']).toBe('Control del contacto');
    expect(deDE['signing.envelopes.identity.providerIdentity']).toBe(
      'Identitätsbestätigung des Anbieters',
    );
    expect(svSE['signing.envelopes.identity.representativeCapacity']).toBe(
      'Representationsbehörighet',
    );

    const nonPortugueseCatalogs = [
      ['da-DK', daDK],
      ['de-DE', deDE],
      ['en-GB', enGB],
      ['en-US', enUS],
      ['es-ES', esES],
      ['fi-FI', fiFI],
      ['fr-FR', frFR],
      ['it-IT', itIT],
      ['nl-NL', nlNL],
      ['pl-PL', plPL],
      ['sv-FI', svFI],
      ['sv-SE', svSE],
    ] as const;

    for (const [locale, catalog] of nonPortugueseCatalogs) {
      for (const key of keys) {
        expect(catalog[key], `${locale} ${key}`).not.toMatch(portugueseSourcePhrases);
      }
    }
  });

  it('keeps archive filter and export copy localized outside source Portuguese', () => {
    expect(enUS['ledger.filters.aria']).toBe('Search and filter archive');
    expect(enUS['ledger.archive.format.pdfa']).toBe('Canonical PDF/A');
    expect(enGB['ledger.filters.clear.aria']).toBe('Clear archive filters');
    expect(deDE['ledger.archive.export']).toBe('Archiv exportieren');

    for (const catalog of [enUS, enGB, deDE]) {
      expect(catalog['ledger.filters.aria']).not.toBe(ptPT['ledger.filters.aria']);
      expect(catalog['ledger.filters.advanced']).not.toBe(ptPT['ledger.filters.advanced']);
      expect(catalog['ledger.filters.clear.aria']).not.toBe(ptPT['ledger.filters.clear.aria']);
      expect(catalog['ledger.archive.export']).not.toBe(ptPT['ledger.archive.export']);
      expect(catalog['ledger.archive.format.label']).not.toBe(ptPT['ledger.archive.format.label']);
      expect(catalog['ledger.archive.format.txt']).not.toBe(ptPT['ledger.archive.format.txt']);
    }
  });

  it('every shipped locale is registered with a quality tier', () => {
    for (const locale of SHIPPED_LOCALES) {
      expect(LOCALE_QUALITY[locale]).toBeDefined();
    }
  });

  it('every non-source locale has exactly the source key set (no missing/extra keys)', async () => {
    const catalogs = await Promise.all(
      SHIPPED_LOCALES.filter((locale) => locale !== 'pt-PT').map(async (locale) => {
        const loader = LOCALE_LOADERS[locale];
        expect(loader, `missing loader for ${locale}`).toBeDefined();
        const catalog = await loader!();
        return { locale, catalog };
      }),
    );

    for (const { locale, catalog } of catalogs) {
      const keys = Object.keys(catalog).sort();
      // Symmetric difference is empty ⇒ identical key sets.
      const missing = sourceKeys.filter((k) => !(k in catalog));
      const extra = keys.filter((k) => !(k in ptPT));
      expect(missing, `${locale} missing keys`).toEqual([]);
      expect(extra, `${locale} extra keys`).toEqual([]);
      // No empty values (a stub seed still fills every key).
      for (const k of keys) {
        expect(catalog[k as keyof typeof catalog], `${locale}:${k} empty`).not.toBe('');
      }
    }
  }, 15_000);
});

describe('interpolate', () => {
  it('returns the template unchanged when there are no params', () => {
    expect(interpolate('Sem eventos')).toBe('Sem eventos');
  });

  it('substitutes a named placeholder', () => {
    expect(interpolate('Insc. {event}', { event: 'AP. 5' })).toBe('Insc. AP. 5');
  });

  it('coerces numbers to strings', () => {
    expect(interpolate('Cadeia verificada ({count} eventos)', { count: 3 })).toBe(
      'Cadeia verificada (3 eventos)',
    );
  });

  it('substitutes multiple placeholders', () => {
    expect(interpolate('{padded}/{year}', { padded: '0007', year: 2026 })).toBe('0007/2026');
  });

  it('leaves an unknown placeholder verbatim (a missing param is a visible bug)', () => {
    expect(interpolate('{a} and {b}', { a: 'x' })).toBe('x and {b}');
  });
});

describe('store fallback', () => {
  it('serves the source string for a locale with no loaded catalog', () => {
    // A pending/unloaded locale falls back to pt-PT rather than throwing.
    expect(i18nStore.message('de-DE', 'nav.dashboard')).toBe(ptPT['nav.dashboard']);
  });
});
