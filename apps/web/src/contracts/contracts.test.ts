/**
 * Client-vs-contract tests (plan t15 §2.6, t15-e3).
 *
 * The canonical wire fixtures in the top-level `contracts/` directory (authored by
 * t15-e1, consumed here READ-ONLY) are fed through the **real** client parse path:
 * each fixture's raw bytes are returned by a mocked `fetch` with an
 * `application/json` content type, and the actual typed `api.*` function deserialises
 * them via `parseResponse`. We then assert the typed result — every field present,
 * enum encodings recognised, dates/timestamps parseable, digests well-formed.
 *
 * Drift breaks a test on **whichever side moved**:
 *  - if a fixture gains/loses/renames a field, the runtime key-set assertion fails;
 *  - if `api/types.ts` gains/loses/renames a field, the `Record<keyof T, true>` key
 *    map below fails to compile (a missing/excess key), so `tsc -b`/vitest fails.
 *
 * Together they pin the shape; the Rust harness (`e2e_contracts.rs`) pins the same
 * fixtures against live server bytes, so a server/DTO change is caught on both ends.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { api, ApiError } from '../api/client';
import {
  ACT_STATES,
  BOOK_KINDS,
  CAE_LEVELS,
  CAE_REVISIONS,
  CAE_ROLES,
  ENTITY_KINDS,
  LOCALES,
  MEETING_CHANNELS,
  NUMBERING_SCHEMES,
  SIGNATURE_FAMILIES,
  THEME_MODES,
  type ActMesa,
  type ActView,
  type AppearanceSettings,
  type BookView,
  type CaeSourceEntry,
  type CaeUpdates,
  type CaeVersion,
  type CatalogSettings,
  type CaeCatalogView,
  type CaeEntryView,
  type CaeLevelCounts,
  type CaeNode,
  type CaeRefView,
  type Dashboard,
  type DocumentSettings,
  type Entity,
  type EntityCalendarPreset,
  type EntityProfile,
  type InscriptionDetailView,
  type LedgerEventView,
  type OnboardingSettings,
  type OrganizationSettings,
  type RegistryAnnotationView,
  type RegistryEventView,
  type RegistryExtractView,
  type RegistryOfficerView,
  type RegistryProvenanceView,
  type SessionView,
  type Settings,
  type SigningSettings,
  type UserView,
} from '../api/types';

// --- Fixture loading -----------------------------------------------------------
//
// Load each `contracts/*.json` as its raw text (via Vite's `?raw`) so the mocked
// `fetch` returns the exact fixture BYTES, not a re-serialised object — the client's
// real `JSON.parse` runs on the wire representation. `import.meta.glob` (typed by
// `vite/client`) keeps the JSON files out of the TS program, so `tsc -b`'s composite
// rootDir stays confined to `src/` while the fixtures live at the repo root.
const rawFixtures = import.meta.glob('../../../../contracts/*.json', {
  eager: true,
  query: '?raw',
  import: 'default',
}) as Record<string, string>;

function fixture(name: string): string {
  const entry = Object.entries(rawFixtures).find(([path]) => path.endsWith(`/${name}`));
  if (!entry) {
    throw new Error(
      `contract fixture ${name} not found — loaded: ${Object.keys(rawFixtures).join(', ')}`,
    );
  }
  return entry[1];
}

/** Stub `fetch` to return a fixture's raw bytes as an `application/json` response. */
function stubFetch(body: string, status = 200): void {
  vi.stubGlobal(
    'fetch',
    vi
      .fn()
      .mockResolvedValue(
        new Response(body, { status, headers: { 'Content-Type': 'application/json' } }),
      ),
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

// --- Shape helpers -------------------------------------------------------------

/** The optional (`foo?:`) property keys of `T` — those a `skip_serializing_if` field
 *  may legitimately omit from the wire. */
type OptionalKeys<T> = {
  [K in keyof T]-?: Record<never, never> extends Pick<T, K> ? K : never;
}[keyof T];
/** The always-present property keys of `T`. */
type RequiredKeys<T> = Exclude<keyof T, OptionalKeys<T>>;

/**
 * Assert `obj`'s own keys are the REQUIRED keys of the type `T` (expressed as a
 * `Record<RequiredKeys<T>, true>` the caller writes out) plus, at most, the declared
 * OPTIONAL keys. The record forces a compile error if `T`'s required set drifts (a new
 * required field must be added here, a removed one can no longer be); the runtime check
 * fails if the fixture drops a required key or carries an unexpected one. Optional
 * (`skip_serializing_if`) keys are permitted-but-not-required, so a fixture that omits
 * them (e.g. `UserView.attestation_key_fingerprint` when no key is set) still matches.
 */
function assertExactKeys<T>(
  obj: unknown,
  requiredKeys: Record<RequiredKeys<T>, true>,
  label: string,
  optionalKeys: readonly OptionalKeys<T>[] = [],
): T {
  expect(obj, `${label} should be a non-null object`).toBeTypeOf('object');
  expect(obj, `${label} should not be null`).not.toBeNull();
  const actual = Object.keys(obj as object);
  const required = Object.keys(requiredKeys);
  const allowed = new Set([...required, ...(optionalKeys as readonly string[])]);
  for (const key of actual) {
    expect(allowed.has(key), `${label} carries an unexpected key «${key}»`).toBe(true);
  }
  for (const key of required) {
    expect(actual, `${label} is missing required key «${key}»`).toContain(key);
  }
  return obj as T;
}

/** Membership check against a pinned enum encoding array (catches unknown variants). */
function inEnum(arr: readonly string[], value: string, label: string): void {
  expect(arr, `${label}: «${value}» is not a recognised enum encoding`).toContain(value);
}

/** ISO `YYYY-MM-DD` calendar date. */
function assertIsoDate(value: string, label: string): void {
  expect(value, `${label} should be YYYY-MM-DD`).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  expect(Number.isNaN(Date.parse(value)), `${label} should parse as a date`).toBe(false);
}

/** RFC 3339 timestamp (ledger/user timestamps). */
function assertTimestamp(value: string, label: string): void {
  expect(Number.isNaN(Date.parse(value)), `${label} should parse as a timestamp`).toBe(false);
  expect(value, `${label} should look like RFC 3339`).toMatch(/^\d{4}-\d{2}-\d{2}T/);
}

/** Lowercase 64-hex digest / hash. */
function assertHex64(value: string, label: string): void {
  expect(value, `${label} should be a 64-char lowercase hex digest`).toMatch(/^[0-9a-f]{64}$/);
}

// --- Per-contract tests --------------------------------------------------------

describe('contract fixtures parse through the real client', () => {
  it('entity.json → Entity (POST/GET /v1/entities)', async () => {
    stubFetch(fixture('entity.json'));
    const entity: Entity = await api.getEntity('2f1c8e40-0000-4000-8000-000000000001');
    assertExactKeys<Entity>(
      entity,
      {
        id: true,
        name: true,
        nipc: true,
        nipc_validated: true,
        seat: true,
        family: true,
        kind: true,
        profile: true,
        statute: true,
      },
      'Entity',
    );
    expect(entity.id).not.toHaveLength(0);
    expect(entity.nipc).toMatch(/^\d{9}$/);
    expect(typeof entity.nipc_validated).toBe('boolean');
    inEnum(ENTITY_KINDS, entity.kind, 'Entity.kind');
    inEnum(
      ['CommercialCompany', 'Condominium', 'Association', 'Foundation', 'Cooperative'],
      entity.family,
      'Entity.family',
    );

    // Per-family profile (t31) — computed server-side, always present.
    const profile = assertExactKeys<EntityProfile>(
      entity.profile,
      {
        family: true,
        rule_pack_id: true,
        allowed_channels: true,
        signature_policy: true,
        template_family: true,
        calendar_presets: true,
      },
      'Entity.profile',
    );
    inEnum(
      ['CommercialCompany', 'Condominium', 'Association', 'Foundation', 'Cooperative'],
      profile.family,
      'Entity.profile.family',
    );
    inEnum(
      ['QualifiedPreferred', 'QualifiedOrHandwritten', 'ManualAttested'],
      profile.signature_policy,
      'Entity.profile.signature_policy',
    );
    for (const channel of profile.allowed_channels) inEnum(MEETING_CHANNELS, channel, 'channel');
    for (const preset of profile.calendar_presets) {
      assertExactKeys<EntityCalendarPreset>(
        preset,
        { id: true, label: true, months_after_fiscal_year_end: true },
        'Entity.profile.calendar_presets[]',
      );
    }
    // Statute overlay is null (family default) or a structured override object.
    if (entity.statute !== null) expect(entity.statute).toBeTypeOf('object');
  });

  it('book.json → BookView (POST/GET /v1/books)', async () => {
    stubFetch(fixture('book.json'));
    const book: BookView = await api.getBook('3a2b1c00-0000-4000-8000-000000000002');
    assertExactKeys<BookView>(
      book,
      {
        id: true,
        entity_id: true,
        kind: true,
        state: true,
        purpose: true,
        numbering_scheme: true,
        opening_date: true,
        closing_date: true,
        closing_reason: true,
        last_ata_number: true,
        predecessor: true,
        required_signatories_abertura: true,
        required_signatories_encerramento: true,
      },
      'BookView',
    );
    inEnum(BOOK_KINDS, book.kind, 'BookView.kind');
    inEnum(['Created', 'Open', 'Closed'], book.state, 'BookView.state');
    if (book.numbering_scheme) inEnum(NUMBERING_SCHEMES, book.numbering_scheme, 'numbering_scheme');
    if (book.opening_date) assertIsoDate(book.opening_date, 'BookView.opening_date');
    expect(typeof book.last_ata_number).toBe('number');
    expect(Array.isArray(book.required_signatories_abertura)).toBe(true);
  });

  it('act.sealed.json → ActView (GET /v1/acts/{id})', async () => {
    stubFetch(fixture('act.sealed.json'));
    const act: ActView = await api.getAct('4b3c2d00-0000-4000-8000-000000000003');
    assertExactKeys<ActView>(
      act,
      {
        id: true,
        book_id: true,
        title: true,
        channel: true,
        meeting_date: true,
        meeting_time: true,
        place: true,
        mesa: true,
        agenda: true,
        attendance_reference: true,
        members_present: true,
        members_represented: true,
        referenced_documents: true,
        deliberations: true,
        deliberation_items: true,
        telematic_evidence: true,
        attachments: true,
        signatories: true,
        state: true,
        ata_number: true,
        payload_digest: true,
        seal_event_seq: true,
        retifies: true,
      },
      'ActView',
    );
    inEnum(MEETING_CHANNELS, act.channel, 'ActView.channel');
    inEnum(ACT_STATES, act.state, 'ActView.state');
    expect(act.state).toBe('Sealed');
    expect(act.ata_number).toBe(1);
    if (act.meeting_date) assertIsoDate(act.meeting_date, 'ActView.meeting_date');
    if (act.meeting_time) expect(act.meeting_time).toMatch(/^\d{2}:\d{2}$/);
    if (act.payload_digest) assertHex64(act.payload_digest, 'ActView.payload_digest');
    expect(Array.isArray(act.attachments)).toBe(true);
    expect(Array.isArray(act.signatories)).toBe(true);

    // Structured content (t31) — mesa is always present; agenda/deliberations are arrays.
    assertExactKeys<ActMesa>(act.mesa, { presidente: true, secretarios: true }, 'ActView.mesa');
    expect(Array.isArray(act.mesa.secretarios)).toBe(true);
    expect(Array.isArray(act.agenda)).toBe(true);
    for (const item of act.agenda) {
      expect(typeof item.number).toBe('number');
      expect(typeof item.text).toBe('string');
    }
    expect(Array.isArray(act.referenced_documents)).toBe(true);
    expect(Array.isArray(act.deliberation_items)).toBe(true);
  });

  it('ledger.events.json → LedgerEventView[] (GET /v1/ledger/events)', async () => {
    stubFetch(fixture('ledger.events.json'));
    const events: LedgerEventView[] = await api.listLedger();
    expect(Array.isArray(events)).toBe(true);
    expect(events.length).toBeGreaterThan(0);
    const event = assertExactKeys<LedgerEventView>(
      events[0],
      {
        id: true,
        seq: true,
        actor: true,
        justification: true,
        timestamp: true,
        scope: true,
        kind: true,
        payload_digest: true,
        prev_hash: true,
        hash: true,
        attestation: true,
      },
      'LedgerEventView',
    );
    expect(typeof event.seq).toBe('number');
    expect(event.actor).not.toHaveLength(0);
    assertTimestamp(event.timestamp, 'LedgerEventView.timestamp');
    assertHex64(event.payload_digest, 'LedgerEventView.payload_digest');
    assertHex64(event.prev_hash, 'LedgerEventView.prev_hash');
    assertHex64(event.hash, 'LedgerEventView.hash');
    // Attestation is null when unattested, else a {username,fingerprint,algorithm} join (t29).
    if (event.attestation !== null) {
      assertExactKeys(
        event.attestation,
        { username: true, fingerprint: true, algorithm: true },
        'LedgerEventView.attestation',
      );
    }
  });

  it('dashboard.json → Dashboard (GET /v1/dashboard)', async () => {
    stubFetch(fixture('dashboard.json'));
    const dash: Dashboard = await api.dashboard();
    assertExactKeys<Dashboard>(
      dash,
      {
        entities: true,
        books_open: true,
        books_total: true,
        acts_total: true,
        acts_draft: true,
        acts_awaiting_signature: true,
        acts_sealed: true,
        unresolved_compliance: true,
        ledger_length: true,
        ledger_valid: true,
        recent_events: true,
      },
      'Dashboard',
    );
    for (const [k, v] of Object.entries(dash)) {
      if (k === 'ledger_valid' || k === 'recent_events') continue;
      expect(typeof v, `Dashboard.${k} should be a number`).toBe('number');
    }
    expect(typeof dash.ledger_valid).toBe('boolean');
    expect(Array.isArray(dash.recent_events)).toBe(true);
    // recent_events reuse the ledger event shape.
    assertExactKeys<LedgerEventView>(
      dash.recent_events[0],
      {
        id: true,
        seq: true,
        actor: true,
        justification: true,
        timestamp: true,
        scope: true,
        kind: true,
        payload_digest: true,
        prev_hash: true,
        hash: true,
        attestation: true,
      },
      'Dashboard.recent_events[0]',
    );
  });

  it('settings.json → Settings (GET/PUT /v1/settings)', async () => {
    stubFetch(fixture('settings.json'));
    const settings: Settings = await api.getSettings();
    assertExactKeys<Settings>(
      settings,
      {
        schema_version: true,
        organization: true,
        documents: true,
        catalog: true,
        signing: true,
        appearance: true,
        onboarding: true,
      },
      'Settings',
    );
    expect(typeof settings.schema_version).toBe('number');
    assertExactKeys<OrganizationSettings>(
      settings.organization,
      { name: true, default_actor: true },
      'Settings.organization',
    );
    const documents = assertExactKeys<DocumentSettings>(
      settings.documents,
      { locale: true, numbering_scheme_default: true },
      'Settings.documents',
    );
    inEnum(LOCALES, documents.locale, 'Settings.documents.locale');
    inEnum(NUMBERING_SCHEMES, documents.numbering_scheme_default, 'numbering_scheme_default');
    // Catalog section — legacy single URL + the strict fidelity-gated source chain (t23).
    const catalog = assertExactKeys<CatalogSettings>(
      settings.catalog,
      { cae_update_url: true, cae_sources: true, cae_official_source: true },
      'Settings.catalog',
    );
    if (catalog.cae_update_url !== null) {
      expect(typeof catalog.cae_update_url).toBe('string');
    }
    expect(Array.isArray(catalog.cae_sources)).toBe(true);
    expect(typeof catalog.cae_official_source).toBe('boolean');
    for (const source of catalog.cae_sources) {
      const entry = assertExactKeys<CaeSourceEntry>(
        source,
        { url: true, format: true, digest: true },
        'Settings.catalog.cae_sources[]',
      );
      inEnum(['Auto', 'Envelope', 'SimpleJson', 'Pdf'], entry.format, 'cae_sources[].format');
    }
    const signing = assertExactKeys<SigningSettings>(
      settings.signing,
      {
        preferred_family: true,
        tsa_url: true,
        tsl_url: true,
        require_qualified_for_seal: true,
      },
      'Settings.signing',
    );
    inEnum(SIGNATURE_FAMILIES, signing.preferred_family, 'signing.preferred_family');
    expect(typeof signing.require_qualified_for_seal).toBe('boolean');
    const appearance = assertExactKeys<AppearanceSettings>(
      settings.appearance,
      { theme: true, leather_texture: true, texture_intensity: true, button_texture: true },
      'Settings.appearance',
    );
    inEnum(THEME_MODES, appearance.theme, 'Settings.appearance.theme');
    expect(typeof appearance.leather_texture).toBe('boolean');
    expect(typeof appearance.button_texture).toBe('boolean');
    expect(appearance.texture_intensity).toBeGreaterThanOrEqual(0);
    expect(appearance.texture_intensity).toBeLessThanOrEqual(100);
    // Onboarding state (t29) — serde-defaulted, no schema bump.
    const onboarding = assertExactKeys<OnboardingSettings>(
      settings.onboarding,
      { completed: true, completed_at: true },
      'Settings.onboarding',
    );
    expect(typeof onboarding.completed).toBe('boolean');
    if (onboarding.completed_at !== null) assertTimestamp(onboarding.completed_at, 'completed_at');
  });

  it('registry.extract.json → RegistryExtractView (GET /v1/entities/{id}/registry)', async () => {
    stubFetch(fixture('registry.extract.json'));
    const extract: RegistryExtractView = await api.getEntityRegistry(
      '2f1c8e40-0000-4000-8000-000000000001',
    );
    assertExactKeys<RegistryExtractView>(
      extract,
      {
        matricula: true,
        nipc: true,
        firma: true,
        forma_juridica: true,
        legal_form: true,
        sede: true,
        cae: true,
        objeto: true,
        capital: true,
        data_constituicao: true,
        orgaos: true,
        inscricoes: true,
        anotacoes: true,
        provenance: true,
      },
      'RegistryExtractView',
    );
    if (extract.data_constituicao) assertIsoDate(extract.data_constituicao, 'data_constituicao');

    // Role-tagged CAE (plan t14 §2.7): enriched when catalogued, null-fields when not.
    expect(Array.isArray(extract.cae)).toBe(true);
    for (const ref of extract.cae) {
      const cae = assertExactKeys<CaeRefView>(
        ref,
        { code: true, role: true, designation: true, level: true, revision: true },
        'CaeRefView',
      );
      inEnum(CAE_ROLES, cae.role, 'CaeRefView.role');
      if (cae.level) inEnum(CAE_LEVELS, cae.level, 'CaeRefView.level');
      if (cae.revision) inEnum(CAE_REVISIONS, cae.revision, 'CaeRefView.revision');
      // The uncatalogued case is rendered honestly (null designation/level/revision).
      if (cae.designation === null) {
        expect(cae.level).toBeNull();
        expect(cae.revision).toBeNull();
      }
    }

    for (const officer of extract.orgaos) {
      assertExactKeys<RegistryOfficerView>(
        officer,
        {
          name: true,
          role: true,
          appointment_date: true,
          cessation_date: true,
          source_event: true,
        },
        'RegistryOfficerView',
      );
    }
    for (const inscricao of extract.inscricoes) {
      const event = assertExactKeys<RegistryEventView>(
        inscricao,
        {
          number: true,
          kind_hint: true,
          apresentacao: true,
          date: true,
          text: true,
          detail: true,
        },
        'RegistryEventView',
      );
      // Structured detail (t21) — null when unstructured, else apresentação + payload + signatures.
      if (event.detail !== null) {
        const detail = assertExactKeys<InscriptionDetailView>(
          event.detail,
          { apresentacao: true, payload: true, signatures: true },
          'RegistryEventView.detail',
        );
        if (detail.apresentacao !== null) {
          assertExactKeys(
            detail.apresentacao,
            { number: true, date: true, time: true, act_kinds: true },
            'detail.apresentacao',
          );
        }
        if (detail.payload !== null) {
          inEnum(
            ['Constitution', 'Designation', 'Cessation', 'ContractAmendment'],
            detail.payload.type,
            'detail.payload.type',
          );
        }
        for (const sig of detail.signatures) {
          assertExactKeys(sig, { conservatoria: true, oficial: true }, 'detail.signatures[]');
        }
      }
    }

    // Averbamentos / anotações (t21).
    expect(Array.isArray(extract.anotacoes)).toBe(true);
    for (const anotacao of extract.anotacoes) {
      assertExactKeys<RegistryAnnotationView>(
        anotacao,
        { number: true, date: true, publication_url: true, text: true },
        'RegistryExtractView.anotacoes[]',
      );
    }

    // Provenance still carries ONLY the masked access code (§4) plus certidão metadata (t21).
    const provenance = assertExactKeys<RegistryProvenanceView>(
      extract.provenance,
      {
        access_code_masked: true,
        retrieved_at: true,
        source_url: true,
        raw_digest: true,
        conservatoria: true,
        oficial: true,
        subscribed_on: true,
        valid_until: true,
        expired: true,
      },
      'RegistryProvenanceView',
    );
    expect(provenance.access_code_masked, 'access code must be masked').toMatch(
      /^\*{4}-\*{4}-\d{4}$/,
    );
    assertTimestamp(provenance.retrieved_at, 'provenance.retrieved_at');
    assertHex64(provenance.raw_digest, 'provenance.raw_digest');
    if (provenance.expired !== null) expect(typeof provenance.expired).toBe('boolean');
  });

  it('cae.entry.json → CaeEntryView (GET /v1/cae/{code})', async () => {
    stubFetch(fixture('cae.entry.json'));
    const entry: CaeEntryView = await api.getCae('68110');
    assertExactKeys<CaeEntryView>(
      entry,
      { code: true, designation: true, level: true, revision: true, hierarchy: true },
      'CaeEntryView',
    );
    inEnum(CAE_LEVELS, entry.level, 'CaeEntryView.level');
    inEnum(CAE_REVISIONS, entry.revision, 'CaeEntryView.revision');
    expect(Array.isArray(entry.hierarchy)).toBe(true);
    expect(entry.hierarchy.length).toBeGreaterThan(0);
    for (const node of entry.hierarchy) {
      const n = assertExactKeys<CaeNode>(
        node,
        { code: true, designation: true, level: true, revision: true },
        'CaeEntryView.hierarchy[]',
      );
      inEnum(CAE_LEVELS, n.level, 'hierarchy node level');
      inEnum(CAE_REVISIONS, n.revision, 'hierarchy node revision');
    }
    // Hierarchy ends at the node itself (secção → … → self).
    expect(entry.hierarchy[entry.hierarchy.length - 1].code).toBe(entry.code);
  });

  it('cae.catalog.json → CaeCatalogView (GET /v1/cae, no-search metadata)', async () => {
    stubFetch(fixture('cae.catalog.json'));
    const catalog: CaeCatalogView = await api.getCaeCatalog();
    assertExactKeys<CaeCatalogView>(
      catalog,
      {
        origin: true,
        schema_version: true,
        generated_at: true,
        source_note: true,
        digest: true,
        counts: true,
      },
      'CaeCatalogView',
      // `provenance` is present only on a refreshed catalog (t23); embedded/cache omit it.
      ['provenance'],
    );
    inEnum(['Embedded', 'Cache'], catalog.origin, 'CaeCatalogView.origin');
    expect(typeof catalog.schema_version).toBe('number');
    assertTimestamp(catalog.generated_at, 'CaeCatalogView.generated_at');
    assertHex64(catalog.digest, 'CaeCatalogView.digest');
    expect(Object.keys(catalog.counts).sort()).toEqual(['rev3', 'rev4']);
    for (const rev of ['rev3', 'rev4'] as const) {
      const counts = assertExactKeys<CaeLevelCounts>(
        catalog.counts[rev],
        { seccao: true, divisao: true, grupo: true, classe: true, subclasse: true },
        `CaeCatalogView.counts.${rev}`,
      );
      for (const [level, n] of Object.entries(counts)) {
        expect(typeof n, `counts.${rev}.${level} should be a number`).toBe('number');
      }
    }
  });

  it('cae.updates.json → CaeUpdates (GET /v1/cae/updates)', async () => {
    stubFetch(fixture('cae.updates.json'));
    const updates: CaeUpdates = await api.getCaeUpdates();
    assertExactKeys<CaeUpdates>(
      updates,
      { rev3: true, rev4: true, checked_at: true },
      'CaeUpdates',
    );
    assertTimestamp(updates.checked_at, 'CaeUpdates.checked_at');
    for (const rev of ['rev3', 'rev4'] as const) {
      const version = assertExactKeys<CaeVersion>(
        updates[rev],
        { version: true, designation: true },
        `CaeUpdates.${rev}`,
      );
      // SMI version codes are `V#####` (t33).
      expect(version.version, `CaeUpdates.${rev}.version`).toMatch(/^V\d+$/);
      expect(version.designation.length).toBeGreaterThan(0);
    }
  });

  it('user.json → UserView (POST/GET /v1/users)', async () => {
    stubFetch(fixture('user.json'));
    const user: UserView = await api.getUser('6d5e4f00-0000-4000-8000-000000000005');
    assertExactKeys<UserView>(
      user,
      {
        id: true,
        username: true,
        display_name: true,
        created_at: true,
        active: true,
        has_secret: true,
        has_attestation_key: true,
      },
      'UserView',
      // Fingerprint is emitted only when an attestation key is set (t29).
      ['attestation_key_fingerprint'],
    );
    expect(typeof user.has_secret).toBe('boolean');
    expect(typeof user.has_attestation_key).toBe('boolean');
    expect(user.username).toMatch(/^[a-z0-9._-]+$/);
    expect(typeof user.active).toBe('boolean');
    assertTimestamp(user.created_at, 'UserView.created_at');
    // Security invariant (§ contracts README): no password material on the wire.
    expect(user).not.toHaveProperty('password_hash');
    expect(user).not.toHaveProperty('password');
  });

  it('session.json → SessionView (GET /v1/session, populated)', async () => {
    stubFetch(fixture('session.json'));
    const session: SessionView = await api.getSession();
    assertExactKeys<SessionView>(session, { user: true }, 'SessionView');
    expect(session.user, 'populated session carries a user').not.toBeNull();
    const user = assertExactKeys<UserView>(
      session.user,
      {
        id: true,
        username: true,
        display_name: true,
        created_at: true,
        active: true,
        has_secret: true,
        has_attestation_key: true,
      },
      'SessionView.user',
      ['attestation_key_fingerprint'],
    );
    expect(user).not.toHaveProperty('password_hash');
  });
});

// --- Cross-cutting guards ------------------------------------------------------

describe('contract fixtures — cross-cutting guarantees', () => {
  it('every fixture is real, non-empty JSON (the wire bytes a client must parse)', () => {
    const names = Object.keys(rawFixtures).map((p) => p.split('/').pop());
    // The canonical fixtures the README inventories.
    for (const expected of [
      'entity.json',
      'book.json',
      'act.sealed.json',
      'ledger.events.json',
      'dashboard.json',
      'settings.json',
      'registry.extract.json',
      'cae.entry.json',
      'cae.catalog.json',
      'cae.updates.json',
      'user.json',
      'session.json',
    ]) {
      expect(names, `contracts/ should include ${expected}`).toContain(expected);
    }
    for (const [path, text] of Object.entries(rawFixtures)) {
      expect(text.length, `${path} should be non-empty`).toBeGreaterThan(0);
      expect(() => JSON.parse(text), `${path} should be valid JSON`).not.toThrow();
    }
  });

  it('no fixture leaks a full código de acesso or password material', () => {
    for (const [path, text] of Object.entries(rawFixtures)) {
      expect(text, `${path} must not carry a password_hash`).not.toContain('password_hash');
      // The only access code representation allowed on the wire is the mask.
      expect(text, `${path} must not carry a raw access_code field`).not.toMatch(
        /"access_code"\s*:/,
      );
    }
  });

  it('a stale-server HTML shell for a contract route is a typed error, not a parse crash', async () => {
    // The regression the whole suite exists to keep caught: the SPA index.html served
    // where JSON is due must surface as a clear ApiError, never a raw JSON.parse throw.
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response('<!doctype html><title>Chancela</title>', {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        }),
      ),
    );
    const err = await api.getEntity('any').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).message).toContain('HTML em vez de JSON');
  });
});
