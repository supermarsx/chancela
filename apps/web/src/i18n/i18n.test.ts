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
import { ptBR } from './locales/pt-BR';
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

  it('keeps absent-owner dispatch reminder copy advisory and status-aware', () => {
    expect(ptPT['notifications.reminder.absentOwnerDispatch.title']).toBe(
      'Evidência de expedição pendente: {act_title}',
    );
    expect(ptPT['notifications.reminder.absentOwnerDispatch.body']).toContain(
      'O lembrete é apenas consultivo.',
    );
    expect(ptPT['dashboard.workQueue.status.pending']).toBe('Pendente');
    expect(enUS['notifications.reminder.absentOwnerDispatch.body']).toContain(
      'This reminder is advisory only.',
    );
    expect(enUS['dashboard.workQueue.status.pending']).toBe('Pending');
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

  it('keeps generated absent-owner communication copy localized outside source and English fallback text', () => {
    const portugueseLeakageKeys = [
      'documents.generated.title',
      'documents.generated.notice',
      'documents.generated.noClaim.badge',
      'documents.generated.status.title',
      'documents.generated.status.coverage',
      'documents.generated.noClaim.body',
      'documents.generated.evidence.empty.title',
      'documents.generated.form.noticeTitle',
      'documents.generated.form.noticeBody',
      'documents.generated.form.locatorHint',
      'documents.generated.form.submit',
    ] as const;
    const englishFallbackKeys = [
      'documents.generated.sectionAria',
      'documents.generated.title',
      'documents.generated.notice',
      'documents.generated.noClaim.badge',
      'documents.generated.empty.title',
      'documents.generated.empty.body',
      'documents.generated.listAria',
      'documents.generated.downloadPath',
      'documents.generated.viewEvidence',
      'documents.generated.download',
      'documents.generated.status.aria',
      'documents.generated.status.title',
      'documents.generated.status.notRequired',
      'documents.generated.status.coverage',
      'documents.generated.status.coverageValue',
      'documents.generated.status.evidenceAttached',
      'documents.generated.status.completionBasis',
      'documents.generated.noClaim.title',
      'documents.generated.noClaim.body',
      'documents.generated.evidence.notIndicated',
      'documents.generated.evidence.empty.title',
      'documents.generated.evidence.empty.body',
      'documents.generated.evidence.listAria',
      'documents.generated.evidence.actor',
      'documents.generated.evidence.recordedAt',
      'documents.generated.evidence.flags',
      'documents.generated.evidence.flagsValue',
      'documents.generated.form.aria',
      'documents.generated.form.noticeTitle',
      'documents.generated.form.noticeBody',
      'documents.generated.form.dispatchedAt',
      'documents.generated.form.channel',
      'documents.generated.form.reference',
      'documents.generated.form.evidenceReference',
      'documents.generated.form.importedDocument',
      'documents.generated.form.noImportedDocument',
      'documents.generated.form.locatorHint',
      'documents.generated.form.recipients',
      'documents.generated.form.operatorNote',
      'documents.generated.form.submit',
      'documents.generated.form.submitting',
      'documents.generated.form.toast.success',
    ] as const;
    const portugueseSourcePhrases =
      /Comunicações geradas|condóminos ausentes|Sem reivindicação|Evidência registada|Cobertura de destinatários|A Chancela não enviou|Sem linhas de evidência|Registo de evidência|Registe apenas|Indique pelo menos|Registar evidência/;

    expect(enUS['documents.generated.title']).toBe('Generated communications');
    expect(enUS['documents.generated.noClaim.badge']).toBe('No completion claim');
    expect(enUS['documents.generated.form.submit']).toBe('Record evidence');
    expect(deDE['documents.generated.title']).toBe('Generierte Mitteilungen');
    expect(esES['documents.generated.form.submit']).toBe('Registrar evidencia');

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
      for (const key of portugueseLeakageKeys) {
        expect(catalog[key], `${locale} ${key}`).not.toMatch(portugueseSourcePhrases);
      }
    }

    const nonEnglishCatalogs = [
      ['pt-PT', ptPT],
      ['pt-BR', ptBR],
      ['da-DK', daDK],
      ['de-DE', deDE],
      ['es-ES', esES],
      ['fi-FI', fiFI],
      ['fr-FR', frFR],
      ['it-IT', itIT],
      ['nl-NL', nlNL],
      ['pl-PL', plPL],
      ['sv-FI', svFI],
      ['sv-SE', svSE],
    ] as const;

    for (const [locale, catalog] of nonEnglishCatalogs) {
      for (const key of englishFallbackKeys) {
        expect(catalog[key], `${locale} ${key}`).not.toBe(enUS[key]);
      }
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

describe('still-Portuguese leak ratchet', () => {
  // Values that are legitimately byte-identical across locales and must NOT be
  // counted as untranslated leaks. Kept deliberately conservative and documented.
  const SHARED_VALUES = new Set<string>([
    'Chancela', // brand
    // pure acronyms / technical identifiers that read the same in every language
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

  // A value is "allowed" to be identical to the source (i.e. not a leak) when it is a
  // shared brand/acronym token, carries no letters at all (numbers, punctuation,
  // symbols, whitespace), or is composed solely of interpolation placeholders.
  const isAllowed = (value: string): boolean => {
    const trimmed = value.trim();
    if (trimmed === '') return true; // whitespace only
    if (SHARED_VALUES.has(trimmed)) return true; // brand / acronym token
    if (!/\p{L}/u.test(value)) return true; // no letters => language-neutral
    if (/^(\s*\{[^}]+\}\s*)+$/u.test(value)) return true; // interpolation only
    return false;
  };

  const nonSourceCatalogs = [
    ['en-US', enUS],
    ['en-GB', enGB],
    ['pt-BR', ptBR],
    ['da-DK', daDK],
    ['de-DE', deDE],
    ['es-ES', esES],
    ['fi-FI', fiFI],
    ['fr-FR', frFR],
    ['it-IT', itIT],
    ['nl-NL', nlNL],
    ['pl-PL', plPL],
    ['sv-FI', svFI],
    ['sv-SE', svSE],
  ] as const satisfies ReadonlyArray<readonly [string, Record<string, string>]>;

  type NonSourceLocale = (typeof nonSourceCatalogs)[number][0];

  const leakKeys = (catalog: Record<string, string>): string[] => {
    const leaks: string[] = [];
    for (const key of sourceKeys) {
      const source = ptPT[key as keyof typeof ptPT] as string;
      if (catalog[key] === source && !isAllowed(source)) leaks.push(key);
    }
    return leaks;
  };

  const keyIndexRanges = (ranges: string): string => ranges.trim().split(/\s+/g).join(',');

  /**
   * Ratchet baseline: exact key sets of byte-identical still-Portuguese values per
   * locale, encoded as sorted index ranges into `sourceKeys`. This is intentionally not
   * a count baseline: adding one copied pt-PT value while fixing another leaves a
   * different key set and fails, and fixed translations leave stale baseline keys behind
   * until the baseline is lowered.
   */
  const BASELINE_LEAK_KEY_INDEX_RANGES = {
    'en-US': keyIndexRanges(`
      312,318,360,539,562,575,577,622-623,627-628,632-639,651-654,661,663-672,675-676,678-680,683
      688-701,706,725,753,755,825,832,859,912-913,921,1007,1014,1041,1046,1108,1152,1236,1284,1314
      1320,1485-1486,1549,1551,1559,1570,1587,1607,1610,1614,1619,1637,1710,1759,1799,1827,1933,1949
      1990-1995,1999,2001,2004,2011,2063,2114,2244,2251,2258-2268,2296,2306,2337,2339,2342,2437,2517
      2533,2535,2542,2565,2599,2629,2758,2861-2863,2865,2867-2868,2872,2876,2878-2886,2888,2894-2896
      2903-2913,2933-2934,2936,2938-2939,2941,2952,2956-2973,2975-2998,3020,3023
    `),
    'en-GB': keyIndexRanges(`
      312,318,360,539,562,575,577,622-623,627-628,632-639,651-654,661,663-672,675-676,678-680,683
      688-701,706,725,753,755,825,832,859,912-913,921,1007,1014,1041,1046,1108,1152,1236,1284,1314
      1320,1485-1486,1549,1551,1559,1570,1587,1607,1610,1614,1619,1637,1710,1759,1799,1827,1933,1949
      1990-1995,1999,2001,2004,2011,2063,2114,2244,2251,2258-2268,2296,2306,2337,2339,2342,2437,2517
      2533,2535,2542,2565,2599,2629,2758,2861-2863,2865,2867-2868,2872,2876,2878-2886,2888,2894-2896
      2903-2913,2933-2934,2936,2938-2939,2941,2952,2956-2973,2975-2998,3020,3023
    `),
    'pt-BR': keyIndexRanges(`
      0-2,5,7-8,10-12,14,17-20,22-23,25-26,30,33-35,38-42,44-49,51-60,70-75,77-81,83-86,88,90,107
      109-110,112-113,115-137,139-142,146-148,150,152-153,155-159,162-171,173-182,184-188,190-234,236
      238-241,243-247,249-258,260-277,279-281,283-286,290-291,293-294,296-304,306-310,312-315,318-324
      326-328,330,333,336,339-343,347-358,360-363,366-371,373-376,378-381,383-387,390-395,397,399-403
      405-417,419,421-427,429-431,433,447,449,451-457,459,461-466,469,471-477,481-497,501,503-504
      506-512,514,516-520,522,526-559,561-563,565-567,569-571,573,575,577,579,585-640,647,649-654,657
      659-672,675-676,678-680,682-684,686-704,706-723,725,727-731,733,735-736,738-740,742,744-749
      752-753,755-762,764-772,774-815,817-825,827-828,830-832,836-838,843-850,852-857,859-863,869
      871-876,879-881,883-909,911-918,921,925-933,935-942,944-964,967-978,980-985,987-1007,1009-1111
      1117,1120,1122,1125,1128,1131-1132,1134,1136-1145,1147-1155,1158-1160,1162-1174,1176-1180
      1182-1186,1188,1190-1199,1202-1208,1211,1213-1216,1220,1222,1225,1229-1230,1232-1233,1236
      1238-1239,1241,1244-1245,1247-1250,1252,1255-1257,1259-1260,1263-1267,1270-1271,1274-1277
      1279-1280,1282-1288,1290-1300,1302-1317,1319-1321,1323-1328,1330,1332-1333,1346-1351,1353-1362
      1364-1381,1385-1392,1395-1406,1408-1419,1421,1423-1426,1428-1429,1432-1433,1441,1444-1445,1448
      1450-1451,1453-1467,1469-1472,1478-1486,1490-1499,1501-1502,1505-1506,1508,1511,1516,1524-1525
      1529-1530,1534-1538,1541-1542,1544,1546,1548-1551,1553-1556,1559,1561-1562,1565,1570,1576-1578
      1582-1583,1587,1589-1590,1592,1595-1596,1600,1604-1605,1607,1609-1610,1614-1615,1617-1619,1621
      1624-1626,1629,1632-1633,1636-1637,1641,1643-1644,1647-1653,1655,1657-1658,1660-1661,1663-1669
      1671-1676,1678-1691,1693-1696,1698-1702,1704-1707,1709-1710,1712-1720,1723-1728,1732-1747
      1749-1753,1755,1757-1763,1766,1768-1771,1773-1784,1786-1787,1790,1793-1795,1799-1803,1805-1806
      1813-1816,1818-1829,1831-1832,1834-1835,1837-1841,1843,1845-1846,1849,1851-1855,1858-1860
      1862-1867,1914,1916-1917,1919-1922,1925,1928-1929,1932-1934,1936-1937,1939,1941-1943,1945
      1947-1949,1951-1952,1954,1956,1965,1968-1969,1990-1995,1999,2001,2004,2011,2063,2089-2133
      2157-2158,2161-2163,2165-2174,2176-2177,2180,2185-2188,2191-2193,2195,2198-2207,2209-2214
      2216-2218,2220-2221,2225-2238,2242-2248,2250-2252,2254-2255,2258-2268,2271,2273-2278,2280-2284
      2289-2290,2292,2295-2303,2305-2306,2310,2312,2314,2316,2322,2325,2327-2346,2351-2356,2358-2359
      2361,2411,2415,2417,2419,2421,2423,2427-2439,2441-2449,2454,2457-2488,2490-2509,2517,2525-2536
      2538-2581,2599,2606-2607,2612,2614,2617-2618,2622,2624-2632,2636,2638-2641,2643-2669,2671-2685
      2687-2688,2691-2710,2712,2719-2721,2723-2724,2727,2729-2732,2734-2754,2756-2771,2773-2806
      2808-2810,2812-2814,2816-2818,2820-2821,2825-2827,2830-2833,2839-2840,2843-2844,2850-2853,2855
      2857-2889,2891-2973,2975-2998,3000,3004-3007,3009,3013,3015,3020-3021,3023-3029,3036,3043
      3046-3047,3049-3054,3058-3059,3064-3065,3070,3072-3077,3079-3086
    `),
    'da-DK': keyIndexRanges(`
      201-222,312,318,539,562,575,577,622-623,627-628,632-639,651-654,661,663-672,675-676,678-680,683
      688-701,706,725,753,755-762,764-766,775-815,817-825,832,859,912-913,921,949-956,1010,1012
      1014-1031,1033-1037,1041,1046,1050-1052,1055-1056,1064-1067,1108,1152,1236,1284,1314,1320,1404
      1485-1486,1549,1551,1559,1587,1607,1610,1614,1619,1637,1710,1759,1827,1925,1933,1941-1943,1949
      1990-1995,1999,2001,2004,2011,2063,2114,2244,2251,2258-2268,2296,2306,2327-2345,2427-2437
      2463-2480,2483-2488,2490-2509,2517,2525-2528,2530-2535,2538-2579,2581,2599,2626-2632,2639-2640
      2644-2669,2709,2720,2727,2730-2731,2734-2736,2738-2754,2757-2771,2773-2805,2861-2863,2865
      2867-2868,2872,2876,2878-2886,2888,2894-2896,2903-2913,2933-2934,2936,2938-2939,2941,2952
      2956-2973,2975-2998,3020,3023
    `),
    'de-DE': keyIndexRanges(`
      201-222,312,318,360,539,562,575,577,622-623,627-628,632-639,651-654,661,663-672,675-676,678-680
      683,688-701,706,725,753,755-762,764-766,775-815,817-825,832,859,912-913,921,949-956,1041,1046
      1108,1152,1236,1284,1286,1314,1320,1323,1404,1485-1486,1549,1551,1559,1587,1607,1610,1614,1619
      1637,1710,1759,1827,1933,1941-1943,1949,1990-1995,1999,2001,2004,2011,2063,2114,2244,2251
      2258-2268,2296,2306,2327-2345,2427-2437,2463-2480,2483-2488,2490-2509,2517,2525-2528,2530-2535
      2538-2579,2581,2599,2626-2632,2639-2640,2644-2669,2709,2720,2727,2730-2731,2734-2736,2738-2754
      2757-2771,2773-2805,2861-2863,2865,2867-2868,2872,2876,2878-2886,2888,2894-2896,2903-2913
      2933-2934,2936,2938-2939,2941,2952,2956-2973,2975-2998,3020,3023
    `),
    'es-ES': keyIndexRanges(`
      53-54,59,112,118-120,134,173,175,181,184,201-222,255-257,259,262-263,267,271,306-307,312-314,316
      318-319,326-328,340-341,355,381,401,425,451,539,562,575,577,586,598,601,622-623,625,627-628
      632-639,651-654,661,663-672,675-676,678-680,683,688-701,706,710-711,714,717,722,725,730,733,742
      744,748,751,753,755-762,764-767,772,775-815,817-825,830,832,837,856,859,871,873,875,877,879-880
      884,886,896,909,912-914,921,928,932,941,949-956,972-973,977,982-983,987,1000,1003,1007,1010,1012
      1014-1031,1033-1037,1041,1046,1050-1052,1055-1056,1064-1067,1108,1145-1146,1159,1166-1167,1169
      1180,1215,1225,1236,1238,1280,1284,1286,1294-1295,1305,1311,1313-1315,1320,1323,1326,1357
      1364-1365,1367,1373,1380-1382,1393,1402,1404,1485-1486,1544,1549-1551,1553-1554,1556,1559,1561
      1565,1570,1576,1587,1589-1590,1600,1607,1610,1614,1619,1633-1634,1636-1637,1648,1653,1682,1685
      1688-1690,1700-1701,1710,1721,1723,1728,1751,1755,1757,1759,1769,1773,1794,1799,1802,1805,1823
      1825,1827,1841,1925,1933-1934,1937,1941-1943,1949,1990-1995,1999,2001,2004,2011,2063,2114
      2243-2245,2251,2254,2258-2268,2277,2296,2306,2322,2327-2346,2427-2437,2463-2480,2483-2488
      2490-2509,2517,2525-2528,2530-2536,2538-2579,2581,2599,2606-2607,2626-2632,2638-2641,2644-2669
      2677,2691-2692,2709,2720,2723-2724,2727,2730-2732,2734-2736,2738-2754,2757-2771,2773-2805,2828
      2843,2851,2861-2863,2865,2867-2868,2872,2876,2878-2886,2888,2892,2894-2896,2903-2913,2933-2934
      2936,2938-2939,2941,2952,2956-2973,2975-2998,3000,3006,3013,3020,3023,3046-3047,3051,3064,3077
      3084-3086
    `),
    'fi-FI': keyIndexRanges(`
      201-222,312,318,360,539,562,575,577,622-623,627-628,632-639,651-654,661,663-672,675-676,678-680
      683,688-701,706,725,753,755-762,764-766,775-815,817-825,832,859,912-913,921,949-956,1010,1012
      1014-1031,1033-1037,1041,1046,1050-1052,1055-1056,1064-1067,1108,1236,1284,1314,1320,1404
      1485-1486,1549,1551,1559,1587,1607,1610,1619,1637,1710,1759,1827,1933,1941-1943,1949,1990-1995
      1999,2001,2004,2011,2063,2114,2244,2251,2258-2268,2296,2306,2327-2345,2427-2437,2463-2480
      2483-2488,2490-2509,2517,2525-2528,2530-2535,2538-2579,2581,2599,2626-2632,2639-2640,2644-2669
      2709,2720,2727,2730-2731,2734-2736,2738-2754,2757-2771,2773-2805,2861-2863,2865,2867-2868,2872
      2876,2878-2886,2888,2894-2896,2903-2913,2933-2934,2936,2938-2939,2941,2952,2956-2973,2975-2998
      3020,3023
    `),
    'fr-FR': keyIndexRanges(`
      59,201-222,257,312,318-319,360,539,562,575,577,598,622-623,627-628,632-639,651-654,661,663-672
      675-676,678-680,683,688-701,706,725,753,755-762,764-766,775-815,817-825,832,856,859,907,914,921
      949-956,1010,1012,1014-1031,1033-1037,1041,1046,1050-1052,1055-1056,1064-1067,1108,1236,1284
      1314,1320,1404,1485-1486,1549,1551,1559,1587,1607,1610,1614,1619,1637,1685,1759,1799,1823,1827
      1933,1941-1943,1949,1990-1995,1999,2001,2004,2011,2063,2114,2244,2251,2258-2268,2296,2306
      2327-2345,2427-2437,2463-2480,2483-2488,2490-2509,2517,2525-2528,2530-2535,2538-2579,2581,2599
      2626-2632,2639-2640,2644-2669,2709,2720,2727,2730-2732,2734-2736,2738-2754,2757-2771,2773-2805
      2861-2863,2865,2867-2868,2872,2876,2878-2886,2888,2894-2896,2903-2913,2933-2934,2936,2938-2939
      2941,2952,2956-2973,2975-2998,3020,3023
    `),
    'it-IT': keyIndexRanges(`
      128,167,201-222,263,312,318-319,355,360,414,424,451,539,562,575,577,622-623,627-628,632-639
      651-654,661,663-672,675-676,678-680,683,688-701,706,714,725,746,748-750,753,755-762,764-766
      774-815,817-825,832,836,859,880,883,907,912-913,921,928,932,941,949-956,980,988,1003,1010,1012
      1014-1031,1033-1037,1041,1046,1050-1052,1055-1056,1064-1067,1108,1152,1166,1169,1236,1280,1284
      1294,1314,1320,1325-1326,1351,1404,1485-1486,1549,1551,1559,1565,1587,1590,1607,1610,1619,1637
      1710,1759,1769,1773-1774,1806,1827,1835,1840,1925,1933,1941-1943,1949,1990-1995,1999,2001,2004
      2011,2063,2114,2244,2246,2251,2258-2268,2275,2296,2306,2327-2345,2427-2437,2463-2480,2483-2488
      2490-2509,2517,2525-2528,2530-2535,2538-2579,2581,2599,2626-2632,2639-2640,2644-2669,2702
      2704-2705,2709,2720,2724,2727,2730-2731,2734-2736,2738-2754,2757-2771,2773-2805,2861-2863,2865
      2867-2868,2872,2876,2878-2886,2888,2894-2896,2903-2913,2933-2934,2936,2938-2939,2941,2952
      2956-2973,2975-2998,3020,3023,3076
    `),
    'nl-NL': keyIndexRanges(`
      201-222,312,318,360,539,562,575,577,622-623,627-628,632-639,651-654,661,663-672,675-676,678-680
      683,688-701,706,725,753,755-762,764-766,775-815,817-825,832,859,912-913,921,949-956,1010,1012
      1014-1031,1033-1037,1041,1046,1050-1052,1055-1056,1064-1067,1108,1152,1236,1284,1314,1320,1404
      1485-1486,1549,1551,1559,1587,1607,1610,1614,1619,1637,1710,1759,1827,1933,1941-1943,1949
      1990-1995,1999,2001,2004,2011,2063,2114,2244,2251,2258-2268,2296,2306,2327-2345,2427-2437
      2463-2480,2483-2488,2490-2509,2517,2525-2528,2530-2535,2538-2579,2581,2599,2626-2632,2639-2640
      2644-2669,2709,2720,2727,2730-2731,2734-2736,2738-2754,2757-2771,2773-2805,2861-2863,2865
      2867-2868,2872,2876,2878-2886,2888,2894-2896,2903-2913,2933-2934,2936,2938-2939,2941,2952
      2956-2973,2975-2998,3020,3023
    `),
    'pl-PL': keyIndexRanges(`
      201-222,312,318,414,539,562,575,577,622-623,627-628,632-639,651-654,661,663-672,675-676,678-680
      683,688-701,706,725,746,753,755-762,764-766,775-815,817-825,832,859,880,912-913,921,949-956,1010
      1012,1014-1031,1033-1037,1041,1046,1050-1052,1055-1056,1064-1067,1108,1152,1236,1284,1286,1314
      1320,1323,1325,1404,1485-1486,1549,1551,1559,1587,1607,1610,1619,1637,1710,1759,1774,1827,1933
      1941-1943,1949,1990-1995,1999,2001,2004,2011,2063,2114,2244,2251,2258-2268,2296,2306,2327-2345
      2427-2437,2463-2480,2483-2488,2490-2509,2517,2525-2528,2530-2535,2538-2579,2581,2599,2626-2632
      2639-2640,2644-2669,2702,2709,2720,2727,2730-2731,2734-2736,2738-2754,2757-2771,2773-2805
      2861-2863,2865,2867-2868,2872,2876,2878-2886,2888,2894-2896,2903-2913,2933-2934,2936,2938-2939
      2941,2952,2956-2973,2975-2998,3020,3023
    `),
    'sv-FI': keyIndexRanges(`
      201-222,312,318,539,562,575,577,622-623,627-628,632-639,651-654,661,663-672,675-676,678-680,683
      688-701,706,725,753,755-762,764-766,775-815,817-825,832,859,912-913,921,949-956,1010,1012
      1014-1031,1033-1037,1041,1046,1050-1052,1055-1056,1064-1067,1108,1152,1236,1284,1314,1320,1404
      1485-1486,1549,1551,1559,1587,1607,1610,1614,1619,1637,1710,1759,1827,1925,1933,1941-1943,1949
      1990-1995,1999,2001,2004,2011,2063,2114,2244,2251,2258-2268,2296,2306,2327-2345,2427-2437
      2463-2480,2483-2488,2490-2509,2517,2525-2528,2530-2535,2538-2579,2581,2599,2626-2632,2639-2640
      2644-2669,2709,2720,2727,2730-2731,2734-2736,2738-2754,2757-2771,2773-2805,2861-2863,2865
      2867-2868,2872,2876,2878-2886,2888,2894-2896,2903-2913,2933-2934,2936,2938-2939,2941,2952
      2956-2973,2975-2998,3020,3023
    `),
    'sv-SE': keyIndexRanges(`
      201-222,312,318,539,562,575,577,622-623,627-628,632-639,651-654,661,663-672,675-676,678-680,683
      688-701,706,725,753,755-762,764-766,775-815,817-825,832,859,912-913,921,949-956,1010,1012
      1014-1031,1033-1037,1041,1046,1050-1052,1055-1056,1064-1067,1108,1152,1236,1284,1314,1320,1404
      1485-1486,1549,1551,1559,1587,1607,1610,1614,1619,1637,1710,1759,1827,1925,1933,1941-1943,1949
      1990-1995,1999,2001,2004,2011,2063,2114,2244,2251,2258-2268,2296,2306,2327-2345,2427-2437
      2463-2480,2483-2488,2490-2509,2517,2525-2528,2530-2535,2538-2579,2581,2599,2626-2632,2639-2640
      2644-2669,2709,2720,2727,2730-2731,2734-2736,2738-2754,2757-2771,2773-2805,2861-2863,2865
      2867-2868,2872,2876,2878-2886,2888,2894-2896,2903-2913,2933-2934,2936,2938-2939,2941,2952
      2956-2973,2975-2998,3020,3023
    `),
  } as const satisfies Record<NonSourceLocale, string>;

  const baselineLeakKeys = (locale: NonSourceLocale): string[] => {
    const baselineKeys: string[] = [];
    let previousIndex = -1;

    for (const range of BASELINE_LEAK_KEY_INDEX_RANGES[locale].split(',')) {
      const [startText, endText = startText] = range.split('-', 2);
      const start = Number(startText);
      const end = Number(endText);
      if (
        !Number.isInteger(start) ||
        !Number.isInteger(end) ||
        start < 0 ||
        end < start ||
        end >= sourceKeys.length
      ) {
        throw new Error(`${locale} has invalid baseline leak key index range: ${range}`);
      }

      for (let index = start; index <= end; index += 1) {
        if (index <= previousIndex) {
          throw new Error(`${locale} baseline leak key indexes must be sorted and unique`);
        }
        const key = sourceKeys[index];
        if (key === undefined) {
          throw new Error(`${locale} baseline leak key index is out of bounds: ${index}`);
        }
        baselineKeys.push(key);
        previousIndex = index;
      }
    }

    return baselineKeys;
  };

  const summarizeKeys = (keys: readonly string[]): string => {
    if (keys.length === 0) return 'none';
    const preview = keys.slice(0, 20).join(', ');
    return keys.length > 20 ? `${preview}, ... (${keys.length} total)` : `${preview}`;
  };

  it.each(nonSourceCatalogs)(
    'matches the still-Portuguese leak key baseline in %s',
    (locale, catalog) => {
      const baseline = baselineLeakKeys(locale);
      const current = leakKeys(catalog);
      const baselineSet = new Set(baseline);
      const currentSet = new Set(current);
      const added = current.filter((key) => !baselineSet.has(key));
      const removed = baseline.filter((key) => !currentSet.has(key));

      expect(
        added,
        `new still-Portuguese leak keys in ${locale}: ${summarizeKeys(added)}. ` +
          `Translate the copied pt-PT value, or update the exact baseline only if the ` +
          `copy is intentionally accepted debt.`,
      ).toEqual([]);
      expect(
        removed,
        `stale still-Portuguese leak baseline keys in ${locale}: ${summarizeKeys(removed)}. ` +
          `Remove translated keys from BASELINE_LEAK_KEY_INDEX_RANGES instead of keeping ` +
          `a high baseline.`,
      ).toEqual([]);
    },
  );
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
