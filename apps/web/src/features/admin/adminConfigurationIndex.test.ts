/**
 * The admin configuration index: what is searchable, what is deliberately not, and what must
 * never be — in particular that a Tier B secret's value is not merely hidden but unmatchable.
 *
 * Queries here are derived FROM the catalog at run time rather than written out as pt-PT prose,
 * so the tests assert the mechanism (a label is searchable, and the result says it was a label)
 * instead of coupling to a translation somebody may legitimately improve.
 */
import { describe, expect, it } from 'vitest';
import { DEFAULT_SETTINGS, type ServerEnvResponse, type Settings } from '../../api/types';
import { ptPT } from '../../i18n/locales/pt-PT';
import { adminPtPT } from '../../i18n/adminFallback';
import { searchPtPT } from '../../i18n/searchFallback';
import { templatePreviewSamplesPtPT } from '../../i18n/templatePreviewSamplesFallback';
import {
  ADMIN_CONFIGURATION_AREAS,
  ADMIN_CONFIGURATION_COPY_KEYS,
  ADMIN_COPY_DESTINATION_PREFIXES,
  ADMIN_COPY_EXCLUDED_PREFIXES,
  adminConfigurationCopyResolvers,
  buildAdminConfigurationSearchEntries,
  classifyAdminCopyKey,
  matchAdminConfigurationEntries,
  serverEnvValueEntries,
  settingsValueEntries,
  type AdminConfigurationMatch,
  type AdminConfigurationValueEntry,
} from './adminConfigurationIndex';

const AREA_IDS = new Set<string>(ADMIN_CONFIGURATION_AREAS.map((area) => area.id));

const copy = adminConfigurationCopyResolvers('pt-PT', (key) => ptPT[key]);

/** Every permission any destination accepts — the Owner's index. */
const ALL_PERMISSIONS = new Set(ADMIN_CONFIGURATION_AREAS.flatMap((area) => area.permissions));

function settingsFixture(patch: (draft: Settings) => void): Settings {
  const draft = structuredClone(DEFAULT_SETTINGS);
  patch(draft);
  return draft;
}

function serverEnvFixture(vars: ServerEnvResponse['vars']): ServerEnvResponse {
  return {
    vars,
    restart_pending: false,
    overrides_path: '/data/env-overrides.json',
    generated_at: '2026-07-30T00:00:00Z',
  };
}

function envVar(
  patch: Partial<ServerEnvResponse['vars'][number]>,
): ServerEnvResponse['vars'][number] {
  return {
    name: 'CHANCELA_FIXTURE',
    group: 'network',
    tier: 'A',
    editable: true,
    secret: false,
    boundary: false,
    narrow_only: false,
    acknowledgement_required: false,
    excluded_typed_slice: null,
    external_reader: null,
    source: 'default',
    configured: true,
    effective_value: null,
    override_value: null,
    default_value: null,
    restart_pending: false,
    validator: { kind: 'free_text', allowed: null },
    ...patch,
  };
}

interface IndexOptions {
  permissions?: Iterable<string>;
  values?: readonly AdminConfigurationValueEntry[];
}

function search(query: string, options: IndexOptions = {}): AdminConfigurationMatch[] {
  const granted = new Set(options.permissions ?? ALL_PERMISSIONS);
  const entries = buildAdminConfigurationSearchEntries({
    areas: ADMIN_CONFIGURATION_AREAS,
    resolveTitle: (title) => (title.source === 'admin' ? adminPtPT[title.key] : ptPT[title.key]),
    resolveKeywords: (key) => adminPtPT[key],
    canAny: (permission) => granted.has(permission),
    copy,
    values: options.values,
  });
  return matchAdminConfigurationEntries(entries, query);
}

function ids(matches: readonly AdminConfigurationMatch[]): string[] {
  return matches.map((match) => match.entry.id);
}

function kindsFor(matches: readonly AdminConfigurationMatch[], id: string): readonly string[] {
  return matches.find((match) => match.entry.id === id)?.kinds ?? [];
}

describe('catalog → destination mapping', () => {
  it('classifies every key of every catalog the admin surface renders', () => {
    const unmapped = ADMIN_CONFIGURATION_COPY_KEYS.filter(
      (entry) => classifyAdminCopyKey(entry.key).kind === 'unmapped',
    ).map((entry) => `${entry.source}:${entry.key}`);

    // A key that maps nowhere is REPORTED here rather than silently dropped from the corpus:
    // silent dropping is how a search surface quietly stops covering half the app.
    expect(unmapped, `unmapped copy keys:\n${unmapped.join('\n')}`).toEqual([]);
  });

  it('covers all four catalogs, not just the shared one', () => {
    const sources = new Set(ADMIN_CONFIGURATION_COPY_KEYS.map((entry) => entry.source));
    expect([...sources].sort()).toEqual(['admin', 'catalog', 'search', 'templatePreview']);
    expect(ADMIN_CONFIGURATION_COPY_KEYS.length).toBeGreaterThan(
      Object.keys(ptPT).length +
        Object.keys(searchPtPT).length +
        Object.keys(templatePreviewSamplesPtPT).length -
        Object.keys(adminPtPT).length,
    );
  });

  it('maps a meaningful share of the corpus to real destinations', () => {
    const mapped = ADMIN_CONFIGURATION_COPY_KEYS.filter(
      (entry) => classifyAdminCopyKey(entry.key).kind === 'destination',
    );
    expect(mapped.length).toBeGreaterThan(800);
    for (const entry of mapped) {
      const classification = classifyAdminCopyKey(entry.key);
      if (classification.kind !== 'destination') throw new Error('unreachable');
      for (const area of classification.areas) expect(AREA_IDS.has(area)).toBe(true);
    }
  });

  it('has no dead prefix in either table', () => {
    const all = ADMIN_CONFIGURATION_COPY_KEYS.map((entry) => entry.key);
    const matches = (prefix: string) =>
      all.some((key) => key === prefix || key.startsWith(`${prefix}.`));
    const dead = [
      ...ADMIN_COPY_DESTINATION_PREFIXES.map(([prefix]) => prefix),
      ...ADMIN_COPY_EXCLUDED_PREFIXES.map(([prefix]) => prefix),
    ].filter((prefix) => !matches(prefix));
    expect(dead, `prefixes matching no key:\n${dead.join('\n')}`).toEqual([]);
  });

  it('names the reason for every excluded namespace', () => {
    for (const [, reason] of ADMIN_COPY_EXCLUDED_PREFIXES) {
      expect(['not-a-destination', 'settings-section', 'chrome', 'seeded-role-name']).toContain(
        reason,
      );
    }
    expect(classifyAdminCopyKey('settings.privacy.register.title')).toEqual({
      kind: 'excluded',
      reason: 'settings-section',
    });
    expect(classifyAdminCopyKey('admin.finder.placeholder')).toEqual({
      kind: 'excluded',
      reason: 'chrome',
    });
  });

  it('resolves the longest matching prefix, not the first', () => {
    expect(classifyAdminCopyKey('settings.platform.logs.title')).toEqual({
      kind: 'destination',
      areas: ['logs'],
    });
    expect(classifyAdminCopyKey('settings.platform.cardTitle')).toEqual({
      kind: 'destination',
      areas: ['services'],
    });
  });
});

describe('full-text matching', () => {
  it('finds a destination by a field label, and says the hit was a label', () => {
    const matches = search(ptPT['settings.connectorEgress.hostsLabel']);
    expect(ids(matches)).toContain('connectors');
    expect(kindsFor(matches, 'connectors')).toContain('label');
  });

  it('finds a destination by a hint nobody put in the keyword list', () => {
    const matches = search(ptPT['settings.backupRecovery.targetRpo.hint']);
    expect(ids(matches)).toContain('backups');
    expect(kindsFor(matches, 'backups')).toContain('label');
  });

  it('finds a destination by a tooltip that lives in a fallback slice, not the catalog', () => {
    const matches = search(templatePreviewSamplesPtPT['templatePreview.visibility.title']);
    expect(ids(matches)).toContain('template-preview');
  });

  it('finds a destination by a current settings value, and says the hit was a value', () => {
    const settings = settingsFixture((draft) => {
      draft.email.host = 'smtp.fixture.invalid';
    });
    const matches = search('smtp.fixture.invalid', {
      values: settingsValueEntries(settings, copy),
    });
    expect(ids(matches)).toEqual(['email']);
    expect(kindsFor(matches, 'email')).toContain('value');
    expect(matches[0].reasons[0].kind).toBe('value');
  });

  it('finds a destination by a live server-env value', () => {
    const response = serverEnvFixture([
      envVar({ name: 'CHANCELA_BIND', group: 'network', effective_value: '0.0.0.0:8080' }),
    ]);
    const matches = search('0.0.0.0:8080', { values: serverEnvValueEntries(response) });
    // A network var belongs to the Ambiente pane AND to the API pane that transcribes it.
    expect(ids(matches).sort()).toEqual(['api', 'env']);
    expect(kindsFor(matches, 'env')).toContain('value');
  });

  it('is diacritic- and case-insensitive in both directions', () => {
    const accented = search('Criptografia');
    const folded = search('criptografia');
    expect(ids(folded)).toEqual(ids(accented));
    expect(folded.length).toBeGreaterThan(0);

    expect(ids(search('ANFITRIÕES'))).toEqual(ids(search('anfitrioes')));
    expect(ids(search('anfitrioes')).length).toBeGreaterThan(0);
  });

  it('requires every token to match, and explains at most two kinds', () => {
    for (const match of search('base de dados')) {
      expect(match.reasons.length).toBeLessThanOrEqual(2);
      expect(match.reasons.map((reason) => reason.kind)).not.toContain('title');
    }
    expect(ids(search('configuracao-que-nao-existe'))).toEqual([]);
  });
});

describe('secrets', () => {
  const SECRET = 'zgq7-tier-b-fixture-passphrase';

  const response = serverEnvFixture([
    envVar({
      name: 'CHANCELA_DB_PASSWORD',
      group: 'credentials',
      tier: 'B',
      editable: false,
      secret: true,
      configured: true,
      // A server that regressed and DID echo a Tier B value must still not make it matchable.
      effective_value: SECRET,
      override_value: SECRET,
      default_value: SECRET,
    }),
    envVar({ name: 'CHANCELA_LOG_LEVEL', group: 'logging', effective_value: 'info' }),
  ]);

  it("never indexes a Tier B variable's value, from any field", () => {
    const values = serverEnvValueEntries(response);
    const secretEntry = values.find((entry) => entry.label === 'CHANCELA_DB_PASSWORD');
    expect(secretEntry).toBeDefined();
    expect(secretEntry?.values).toEqual([]);
    expect(JSON.stringify(values)).not.toContain(SECRET);
  });

  it('returns no result for a secret value typed into the search box', () => {
    expect(ids(search(SECRET, { values: serverEnvValueEntries(response) }))).toEqual([]);
  });

  it('keeps the non-secret machinery working, so the previous test is not vacuous', () => {
    const values = serverEnvValueEntries(response);
    // The masked variable's NAME is on-screen copy and stays findable...
    expect(ids(search('CHANCELA_DB_PASSWORD', { values }))).toContain('env');
    // ...and a non-secret value in the same response is matchable, proving the filter is the
    // `secret` flag and not a broken value pipeline.
    expect(ids(search('info', { values })).length).toBeGreaterThan(0);
  });

  it('reads no settings-document field outside the allow-list', () => {
    // Distinctive fixture strings: the organisation name and the relay account are the two
    // settings fields most likely to name a real person or company, and neither may reach the
    // index. (They are spelled uniquely because ordinary words legitimately occur in the catalog
    // copy that IS indexed — the assertion has to be about the value source, not the vocabulary.)
    const settings = settingsFixture((draft) => {
      draft.organization.name = 'qtx-organisation-fixture-name';
      draft.email.username = 'qtx-relay-account-fixture';
      draft.email.from_address = 'qtx-mailbox-fixture@example.invalid';
    });
    const values = settingsValueEntries(settings, copy);
    const serialized = JSON.stringify(values);
    expect(serialized).not.toContain('qtx-organisation-fixture-name');
    expect(serialized).not.toContain('qtx-relay-account-fixture');
    expect(serialized).not.toContain('qtx-mailbox-fixture');
    expect(ids(search('qtx-organisation-fixture-name', { values }))).toEqual([]);
    expect(ids(search('qtx-relay-account-fixture', { values }))).toEqual([]);
  });
});

describe('per-principal index', () => {
  it('omits a destination the principal cannot reach, rather than hiding it from results', () => {
    const entries = buildAdminConfigurationSearchEntries({
      areas: ADMIN_CONFIGURATION_AREAS,
      resolveTitle: (title) => (title.source === 'admin' ? adminPtPT[title.key] : ptPT[title.key]),
      resolveKeywords: (key) => adminPtPT[key],
      canAny: (permission) => permission === 'settings.read',
      copy,
    });
    expect(entries.map((entry) => entry.id)).not.toContain('providers');
    // Not one fragment of the hidden destination is present — no label, no route, no keyword.
    const everything = entries.map((entry) => entry.searchText).join('\n');
    expect(everything).not.toContain('/admin/signing');
    expect(everything).not.toContain(
      buildFragmentProbe(ptPT['settings.providerCredentials.cardTitle']),
    );
  });

  it('does not resolve or index values for an unreachable destination', () => {
    const settings = settingsFixture((draft) => {
      draft.signing.tsa_url = 'https://tsa.fixture.invalid/rfc3161';
    });
    const values = settingsValueEntries(settings, copy);
    expect(
      ids(search('tsa.fixture.invalid', { permissions: ['signing.configure'], values })),
    ).toEqual(['tsa']);
    expect(ids(search('tsa.fixture.invalid', { permissions: ['settings.read'], values }))).toEqual(
      [],
    );
  });
});

function buildFragmentProbe(value: string): string {
  return value.normalize('NFD').replace(/[̀-ͯ]/g, '').toLocaleLowerCase().trim();
}
