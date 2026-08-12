/**
 * The admin configuration search index — the corpus, the key→destination mapping, and the matcher.
 *
 * `AdminConfigurationFinder` used to search a hand-written keyword string per destination, so a
 * setting could only be found by the words somebody remembered to list. An operator does not
 * remember the keyword list; they remember the FIELD ("anfitriões permitidos"), the HINT they read
 * last time, or the VALUE they typed ("smtp.exemplo.pt", "0.0.0.0:8080"). This module makes all
 * three searchable.
 *
 * ## Where the searchable text comes from
 *
 * **The i18n catalogs are the corpus.** Every field label, hint and tooltip on an admin screen is
 * already a key in `src/i18n/locales/*.ts` — complete in fourteen locales — or in one of the three
 * self-contained pt-PT/English fallback slices the admin surface still reads through their own
 * resolvers (`adminFallback`, `searchFallback`, `templatePreviewSamplesFallback`). All four are
 * indexed, so a destination whose copy has not yet folded into the shared catalogs is not a hole
 * in the search surface. The app already resolves each for the active locale, so deriving
 * the index from the catalog means a new field becomes searchable the moment its copy lands, in
 * every language, with no second list to drift. The alternative — a bigger hand-written keyword
 * string — drifts on the first commit that adds a field, and nothing would catch it.
 *
 * A key is attached to a destination by NAMESPACE PREFIX ({@link ADMIN_COPY_DESTINATION_PREFIXES},
 * longest prefix wins). The namespaces really are structured this way — `settings.database.*` is
 * the Base de dados pane, `settings.serverEnv.*` the Ambiente pane — but "structured" is not
 * "total": plenty of copy belongs to screens that are not admin destinations at all (`acts.*`,
 * `books.*`, `settings.privacy.*`). Those are classified, BY NAME, in
 * {@link ADMIN_COPY_EXCLUDED_PREFIXES} with the reason. A key matching neither table is
 * `unmapped`, and `adminConfigurationIndex.test.ts` fails on it with the key listed — silent
 * dropping is how a search surface quietly stops covering half the app.
 *
 * ## Current values
 *
 * Values are indexed from two sources, and the two are treated very differently on purpose.
 *
 * - **The server-env registry** carries a server-declared `secret` flag per variable, so its
 *   values can be filtered mechanically: {@link serverEnvValueEntries} refuses to read
 *   `effective_value`, `override_value` or `default_value` for any var with `secret: true`. That
 *   is a fourth independent guard on top of the three the panel already relies on, and it is the
 *   one that matters here: the server not sending a secret is a promise about the wire, whereas
 *   this is a promise about the index.
 * - **The settings document** carries no such flag, so it is read through an explicit ALLOW-LIST
 *   ({@link SETTINGS_VALUE_SOURCES}) — never a generic walk of the tree. A deny-list over a
 *   several-hundred-field document is how a credential eventually leaks; an allow-list fails the
 *   safe way, by leaving a new field unsearchable until somebody decides it is safe.
 *
 * Nothing here fetches. Both sources are React Query caches the admin surface already holds, read
 * once per index build and never per keystroke.
 *
 * ## Permissions
 *
 * The index is built PER PRINCIPAL, not filtered after the fact: a destination the caller cannot
 * reach never enters their index, and neither does any of its copy or values. A post-filter would
 * still leak through match counts, "no results" versus "no permission", and timing.
 */
import type { MessageKey } from '../../i18n';
import type { Locale, ServerEnvResponse, ServerEnvVarGroup, Settings } from '../../api/types';
import { MESSAGE_KEYS } from '../../i18n/messageKeys';
import { adminEnglish, adminPtPT, type AdminCopyKey } from '../../i18n/adminFallback';
import { searchEnglish, searchPtPT, type SearchCopyKey } from '../../i18n/searchFallback';
import {
  templatePreviewSamplesEnglish,
  templatePreviewSamplesPtPT,
  type TemplatePreviewSamplesCopyKey,
} from '../../i18n/templatePreviewSamplesFallback';

// --- Destinations ----------------------------------------------------------------

export type AdminConfigurationTitle =
  { source: 'catalog'; key: MessageKey } | { source: 'admin'; key: AdminCopyKey };

export type AdminConfigurationKeywordKey = Extract<AdminCopyKey, `admin.finder.keywords.${string}`>;

/**
 * One searchable admin destination. This deliberately contains no rendered React state, so the
 * full-search service reuses and extends the same permission-aware index rather than maintaining
 * a second list of admin routes.
 */
export interface AdminConfigurationAreaDefinition {
  id: string;
  path: string;
  title: AdminConfigurationTitle;
  keywords: AdminConfigurationKeywordKey;
  permissions: readonly string[];
}

const SETTINGS_PERMISSIONS = ['settings.read', 'settings.manage'] as const;

/**
 * Canonical admin configuration index. Keep additions here declarative: the finder, tests and any
 * wider search surface consume the same definitions and automatically inherit route, localisation
 * and permission filtering. Route paths are declared ONCE, here — the copy and value mappings
 * below key off `id`, never off a repeated path literal.
 */
export const ADMIN_CONFIGURATION_AREAS = [
  {
    id: 'services',
    path: '/admin',
    title: { source: 'catalog', key: 'settings.platform.tab.services' },
    keywords: 'admin.finder.keywords.services',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'logs',
    path: '/admin/logs',
    title: { source: 'catalog', key: 'settings.platform.tab.logs' },
    keywords: 'admin.finder.keywords.logs',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'search',
    path: '/admin/search',
    title: { source: 'admin', key: 'admin.search.title' },
    keywords: 'admin.finder.keywords.search',
    permissions: ['search.manage'],
  },
  {
    id: 'template-preview',
    path: '/admin/template-preview',
    title: { source: 'admin', key: 'admin.templatePreview.title' },
    keywords: 'admin.finder.keywords.templatePreview',
    permissions: ['settings.read'],
  },
  {
    id: 'api',
    path: '/admin/api',
    title: { source: 'catalog', key: 'settings.subnav.api' },
    keywords: 'admin.finder.keywords.api',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'api-keys',
    path: '/admin/api-keys',
    title: { source: 'catalog', key: 'settings.apiKeys.cardTitle' },
    keywords: 'admin.finder.keywords.apiKeys',
    permissions: ['user.manage'],
  },
  {
    id: 'database',
    path: '/admin/database',
    title: { source: 'catalog', key: 'settings.database.cardTitle' },
    keywords: 'admin.finder.keywords.database',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'cache',
    path: '/admin/cache',
    title: { source: 'catalog', key: 'settings.cache.cardTitle' },
    keywords: 'admin.finder.keywords.cache',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'storage',
    path: '/admin/storage',
    title: { source: 'catalog', key: 'data.status.tab.storage' },
    keywords: 'admin.finder.keywords.storage',
    permissions: ['data.manage', ...SETTINGS_PERMISSIONS],
  },
  {
    id: 'backups',
    path: '/admin/backups',
    title: { source: 'catalog', key: 'data.status.tab.backup' },
    keywords: 'admin.finder.keywords.backups',
    permissions: ['backup.manage', ...SETTINGS_PERMISSIONS],
  },
  {
    id: 'keys',
    path: '/admin/keys',
    title: { source: 'catalog', key: 'data.status.tab.keys' },
    keywords: 'admin.finder.keywords.keys',
    permissions: ['data.manage', ...SETTINGS_PERMISSIONS],
  },
  {
    id: 'mcp',
    path: '/admin/mcp',
    title: { source: 'catalog', key: 'settings.subnav.mcp' },
    keywords: 'admin.finder.keywords.mcp',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'email',
    path: '/admin/email',
    title: { source: 'catalog', key: 'settings.email.cardTitle' },
    keywords: 'admin.finder.keywords.email',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'env',
    path: '/admin/env',
    title: { source: 'catalog', key: 'settings.serverEnv.title' },
    keywords: 'admin.finder.keywords.env',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'diagnostics',
    path: '/admin/diagnostics',
    title: { source: 'catalog', key: 'settings.diagnostics.title' },
    keywords: 'admin.finder.keywords.diagnostics',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'groups',
    path: '/admin/groups',
    title: { source: 'catalog', key: 'operations.tabs.groups' },
    keywords: 'admin.finder.keywords.groups',
    permissions: ['entity.create', 'entity.update', 'template.manage'],
  },
  {
    id: 'connectors',
    path: '/admin/connectors',
    title: { source: 'catalog', key: 'operations.tabs.connectors' },
    keywords: 'admin.finder.keywords.connectors',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'repositories',
    path: '/admin/repositories',
    title: { source: 'catalog', key: 'operations.tabs.repositories' },
    keywords: 'admin.finder.keywords.repositories',
    permissions: SETTINGS_PERMISSIONS,
  },
  {
    id: 'providers',
    path: '/admin/signing',
    title: { source: 'catalog', key: 'settings.providerCredentials.cardTitle' },
    keywords: 'admin.finder.keywords.providers',
    permissions: ['signing.configure'],
  },
  {
    id: 'policy',
    path: '/admin/signing/policy',
    title: { source: 'catalog', key: 'settings.signing.policy.cardTitle' },
    keywords: 'admin.finder.keywords.policy',
    permissions: ['signing.configure'],
  },
  {
    id: 'tsl',
    path: '/admin/signing/tsl',
    title: { source: 'catalog', key: 'settings.signing.tslSources.title' },
    keywords: 'admin.finder.keywords.tsl',
    permissions: ['signing.configure'],
  },
  {
    id: 'tsa',
    path: '/admin/signing/tsa',
    title: { source: 'catalog', key: 'settings.signing.tsaProviders.title' },
    keywords: 'admin.finder.keywords.tsa',
    permissions: ['signing.configure'],
  },
  {
    id: 'trust-services',
    path: '/admin/signing/trust-services',
    title: { source: 'catalog', key: 'settings.signing.providers.title' },
    keywords: 'admin.finder.keywords.trustServices',
    permissions: ['signing.configure'],
  },
  {
    id: 'cmd',
    path: '/admin/signing/cmd',
    title: { source: 'catalog', key: 'settings.signing.cmd.title' },
    keywords: 'admin.finder.keywords.cmd',
    permissions: ['signing.configure'],
  },
] as const satisfies readonly AdminConfigurationAreaDefinition[];

/** The closed set of destination ids. Every mapping below is keyed on this, never on a path. */
export type AdminConfigurationAreaId = (typeof ADMIN_CONFIGURATION_AREAS)[number]['id'];

// --- Normalisation ---------------------------------------------------------------

/**
 * Diacritic- and case-insensitive fold. `criptografia` must find `Criptografia`, and an operator
 * typing without accents must find accented copy — this is a Portuguese product and typing
 * `configuracao` is the norm, not the exception.
 */
export function normalizeAdminConfigurationSearch(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLocaleLowerCase()
    .trim();
}

/** `{count}` and friends are interpolation slots, not words: they are noise in the index and
 *  nonsense on screen, so they are dropped from both the match text and the display text. */
function stripPlaceholders(value: string): string {
  return value
    .replace(/\{[^{}]*\}/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// --- The copy corpus -------------------------------------------------------------

/** Which typed catalog a copy key is resolved through. */
export type AdminConfigurationCopySource = 'catalog' | 'admin' | 'search' | 'templatePreview';

/** The per-source resolvers for the active locale. */
export interface AdminConfigurationCopyResolvers {
  catalog: (key: MessageKey) => string;
  admin: (key: AdminCopyKey) => string;
  search: (key: SearchCopyKey) => string;
  templatePreview: (key: TemplatePreviewSamplesCopyKey) => string;
}

/**
 * The four typed catalogs the admin surface renders copy from, for one locale.
 *
 * The three fallback slices are self-contained pt-PT/English pairs with their own hooks; this
 * mirrors their (identical) selection rule without a hook, so the whole corpus can be resolved
 * inside one `useMemo` instead of through four unstable per-render closures.
 */
export function adminConfigurationCopyResolvers(
  locale: Locale,
  catalogMessage: (key: MessageKey) => string,
): AdminConfigurationCopyResolvers {
  const source = locale === 'pt-PT';
  return {
    catalog: catalogMessage,
    admin: (key) => (source ? adminPtPT : adminEnglish)[key],
    search: (key) => (source ? searchPtPT : searchEnglish)[key],
    templatePreview: (key) =>
      (source ? templatePreviewSamplesPtPT : templatePreviewSamplesEnglish)[key],
  };
}

/**
 * Copy-key namespace → destination(s). Longest prefix wins; a prefix matches the key itself or
 * anything below it. A key mapped to several destinations really does appear on several screens
 * (the three Dados panes share one panel; the env-table column labels are reused by four panes).
 */
export const ADMIN_COPY_DESTINATION_PREFIXES: readonly (readonly [
  string,
  readonly AdminConfigurationAreaId[],
])[] = [
  // Plataforma: the Registos pane is a slice of the same namespace as Serviços.
  ['settings.platform.logs', ['logs']],
  ['settings.platform.logging', ['logs']],
  ['settings.platform.logLevel', ['logs']],
  ['settings.platform.effectiveLog', ['logs']],
  ['settings.platform.limitations', ['logs']],
  ['settings.platform.auditTail', ['logs']],
  ['settings.platform', ['services']],

  ['settings.api', ['api']],
  ['settings.apiKeys', ['api-keys']],
  ['settings.database', ['database']],
  ['settings.cache', ['cache']],
  ['settings.mcp', ['mcp']],
  ['settings.email', ['email']],
  ['settings.serverEnv', ['env']],
  ['settings.diagnostics', ['diagnostics']],
  // The shared "startup configuration (environment)" table chrome, rendered by all four panes
  // that transcribe launch-time variables as read-only facts.
  ['settings.env', ['api', 'database', 'cache', 'mcp']],
  ['settings.connectorEgress', ['connectors']],
  ['settings.retainedExportCleanup', ['storage']],
  ['settings.zkRoot', ['storage']],
  ['settings.backupRecovery', ['backups']],
  ['settings.providerCredentials', ['providers']],

  // Assinaturas: one namespace, six destinations.
  ['settings.signing.policy', ['policy']],
  ['settings.signing.family', ['policy']],
  ['settings.signing.requireQualified', ['policy']],
  ['settings.signing.fallbackHint', ['policy']],
  ['settings.signing.officialHint', ['policy']],
  ['settings.signing.tslSources', ['tsl']],
  ['settings.signing.tslUrl', ['tsl']],
  // The trust anchors live in the same destination as the sources they authenticate, so an
  // operator searching for "âncora" lands on the pane that holds both.
  ['settings.signing.tslAnchors', ['tsl']],
  // The anchor assistant renders inside that same card, so a search for "sugerir" or "LOTL" has to
  // reach it rather than dead-ending on the manual fields it sits above.
  ['settings.signing.anchorSuggest', ['tsl']],
  // The permitted-broken-algorithm control sits in that same pane: an anchor says WHO may have
  // signed the list, this says WITH WHAT, and a search for either has to reach both.
  ['settings.signing.tslLegacy', ['tsl']],
  // Outbound TLS intermediates share that pane too. An operator arrives here having read
  // "UnknownIssuer" or "certificado intermédio" in an error, not knowing it is a signing setting at
  // all, so the search has to carry them to it.
  ['settings.signing.tlsIntermediates', ['tsl']],
  ['settings.signing.tsaProviders', ['tsa']],
  ['settings.signing.tsaUrl', ['tsa']],
  ['settings.signing.providers', ['trust-services']],
  ['settings.signing.providerStatus', ['trust-services']],
  ['settings.signing.providerMode', ['trust-services']],
  ['settings.signing.source', ['trust-services']],
  ['settings.signing.sourceStatus', ['trust-services']],
  ['settings.signing.table', ['trust-services']],
  ['settings.signing.cmd', ['cmd']],
  ['settings.signing.cardTitle', ['providers']],
  ['settings.signing.note', ['providers']],
  ['settings.signing.reset', ['providers']],

  // Dados: Armazenamento / Cópias / Chaves are three tabs of ONE panel, so most of the namespace
  // is genuinely shared and the tab-specific slices are named explicitly.
  ['data.status.keyRotation', ['keys']],
  ['data.status.tab.keys', ['keys']],
  ['data.status.backup', ['backups']],
  ['data.status.recoveryDrill', ['backups']],
  ['data.status.tab.backup', ['backups']],
  ['data.status.cleanup', ['storage']],
  ['data.status.usage', ['storage']],
  ['data.status.folder', ['storage']],
  ['data.status.folderState', ['storage']],
  ['data.status.durable', ['storage']],
  ['data.status.dataDir', ['storage']],
  ['data.status.encryption', ['storage']],
  ['data.status.tab.storage', ['storage']],
  ['data.status', ['storage', 'backups', 'keys']],
  ['data.cardTitle', ['storage']],
  ['data.destructive', ['storage']],
  ['data.factory', ['storage']],
  ['data.frontend', ['storage']],
  ['data.full', ['storage']],
  ['data.startOver', ['storage']],
  ['data.wipe', ['storage']],

  ['operations.groups', ['groups']],
  ['operations.connectors', ['connectors']],
  ['operations.repositories', ['repositories']],

  // The two destinations whose copy lives in its own fallback slice rather than the catalogs.
  ['admin.search', ['search']],
  ['admin.templatePreview', ['template-preview']],
  ['search.state', ['search']],
  ['templatePreview', ['template-preview']],
];

/** Why a real, translated key is deliberately outside the admin configuration index. */
export type AdminCopyExclusionReason =
  /** Copy for a screen that is not an admin configuration destination at all. */
  | 'not-a-destination'
  /** A Configurações section that lives under `/settings`, outside the admin surface. */
  | 'settings-section'
  /** Navigation, page and finder chrome — it names the surface rather than configuring it. */
  | 'chrome'
  /** A seeded role name, keyed by role id rather than by namespace. */
  | 'seeded-role-name';

/**
 * Copy that exists, is translated, and is deliberately NOT indexed — classified by name so the
 * decision is visible. `adminConfigurationIndex.test.ts` requires this table plus
 * {@link ADMIN_COPY_DESTINATION_PREFIXES} to cover EVERY key in all four catalogs, so a new
 * namespace has to be classified rather than silently vanishing from the search surface.
 */
export const ADMIN_COPY_EXCLUDED_PREFIXES: readonly (readonly [
  string,
  AdminCopyExclusionReason,
])[] = [
  // Configurações sections that are not part of the Administração surface.
  ['settings.about', 'settings-section'],
  ['settings.appearance', 'settings-section'],
  ['settings.autosave', 'settings-section'],
  ['settings.documents', 'settings-section'],
  ['settings.entityTable', 'settings-section'],
  ['settings.identity', 'settings-section'],
  ['settings.language', 'settings-section'],
  ['settings.management', 'settings-section'],
  ['settings.policyTable', 'settings-section'],
  ['settings.privacy', 'settings-section'],
  ['settings.registryAutoUpdate', 'settings-section'],
  ['settings.reminders', 'settings-section'],
  ['settings.users', 'settings-section'],
  // Configurações page chrome. `settings.adminGroup.*` names the Administração nav GROUPS, which
  // organise the destinations rather than configuring anything — the destinations themselves are
  // in `ADMIN_CONFIGURATION_AREAS`, and their titles are already indexed from there.
  ['settings.adminGroup', 'chrome'],
  ['settings.breadcrumb', 'chrome'],
  ['settings.finder', 'chrome'],
  ['settings.page', 'chrome'],
  ['settings.save', 'chrome'],
  ['settings.saveNow', 'chrome'],
  ['settings.saved', 'chrome'],
  ['settings.subnav', 'chrome'],
  // Operações chrome: the tab strip, the tenant picker and the shared action verbs.
  ['operations.common', 'chrome'],
  ['operations.lede', 'chrome'],
  ['operations.tabs', 'chrome'],
  ['operations.tenant', 'chrome'],
  ['operations.title', 'chrome'],
  // Administração chrome, including the finder's own copy and its keyword strings.
  ['admin.finder', 'chrome'],
  ['admin.subnav', 'chrome'],
  ['admin.title', 'chrome'],
  ['nav', 'chrome'],
  ['splash', 'chrome'],
  ['stepper', 'chrome'],
  ['window', 'chrome'],
  // Everything else: product screens, tools, flows and shared vocabulary.
  //
  // `account` is the SELF-SERVICE account area (`/account`), and its exclusion is a statement
  // rather than an oversight: this finder searches instance CONFIGURATION, and the account area is
  // deliberately the one surface that configures nothing about the instance. Indexing it would
  // offer an administrator searching for "sessões" a result that navigates them to their own
  // sign-ins instead of to a setting — and would advertise, inside an admin-permission-gated
  // finder, a surface whose whole point is that it needs no administrative permission at all.
  ['account', 'not-a-destination'],
  ['acts', 'not-a-destination'],
  ['books', 'not-a-destination'],
  ['cae', 'not-a-destination'],
  ['common', 'not-a-destination'],
  ['companionPair', 'not-a-destination'],
  ['compliance', 'not-a-destination'],
  ['confirm', 'not-a-destination'],
  ['crash', 'not-a-destination'],
  ['dashboard', 'not-a-destination'],
  ['degraded', 'not-a-destination'],
  ['documentLayout', 'not-a-destination'],
  ['documents', 'not-a-destination'],
  ['entities', 'not-a-destination'],
  ['enum', 'not-a-destination'],
  ['error', 'not-a-destination'],
  ['externalInvite', 'not-a-destination'],
  ['externalSigning', 'not-a-destination'],
  ['externalValidatorReports', 'not-a-destination'],
  ['fieldHelp', 'not-a-destination'],
  ['format', 'not-a-destination'],
  ['integrity', 'not-a-destination'],
  ['ledger', 'not-a-destination'],
  ['legislacao', 'not-a-destination'],
  ['notFound', 'not-a-destination'],
  ['notifications', 'not-a-destination'],
  ['onboarding', 'not-a-destination'],
  ['pairing', 'not-a-destination'],
  ['password', 'not-a-destination'],
  ['pdfValidator', 'not-a-destination'],
  ['perm', 'not-a-destination'],
  ['rbac', 'not-a-destination'],
  ['registry', 'not-a-destination'],
  ['safemode', 'not-a-destination'],
  // The full-search TOOL at `/tools/search`; only `search.state.*` (the indexer's own lifecycle,
  // which the admin pane renders too) is mapped to a destination above.
  ['search', 'not-a-destination'],
  ['session', 'not-a-destination'],
  ['signin', 'not-a-destination'],
  ['signing', 'not-a-destination'],
  ['templates', 'not-a-destination'],
  ['toast', 'not-a-destination'],
  ['tools', 'not-a-destination'],
  ['trust', 'not-a-destination'],
  ['ui', 'not-a-destination'],
  ['uiLiteral', 'not-a-destination'],
  ['unsaved', 'not-a-destination'],
  ['users', 'not-a-destination'],
];

/** How a copy key is classified against the two tables above. */
export type AdminCopyClassification =
  | { kind: 'destination'; areas: readonly AdminConfigurationAreaId[] }
  | { kind: 'excluded'; reason: AdminCopyExclusionReason }
  | { kind: 'unmapped' };

function matchesPrefix(key: string, prefix: string): boolean {
  return key === prefix || key.startsWith(`${prefix}.`);
}

function longestMatch<T>(key: string, table: readonly (readonly [string, T])[]): T | undefined {
  let best: T | undefined;
  let bestLength = -1;
  for (const [prefix, value] of table) {
    if (prefix.length > bestLength && matchesPrefix(key, prefix)) {
      best = value;
      bestLength = prefix.length;
    }
  }
  return best;
}

/** Classify one copy key. Exported for the mapping test, which asserts nothing is `unmapped`. */
export function classifyAdminCopyKey(key: string): AdminCopyClassification {
  const areas = longestMatch(key, ADMIN_COPY_DESTINATION_PREFIXES);
  if (areas) return { kind: 'destination', areas };
  // Seeded role names are keyed by role id, so they carry no namespace to match on.
  if (!key.includes('.')) return { kind: 'excluded', reason: 'seeded-role-name' };
  const reason = longestMatch(key, ADMIN_COPY_EXCLUDED_PREFIXES);
  if (reason) return { kind: 'excluded', reason };
  return { kind: 'unmapped' };
}

/** One key of one catalog, with the source needed to resolve it. */
export interface AdminConfigurationCopyKey {
  source: AdminConfigurationCopySource;
  key: string;
}

/** Every key of every catalog the admin surface renders, deduplicated across the four sources. */
export const ADMIN_CONFIGURATION_COPY_KEYS: readonly AdminConfigurationCopyKey[] = (() => {
  const seen = new Set<string>();
  const all: AdminConfigurationCopyKey[] = [];
  const push = (source: AdminConfigurationCopySource, keys: readonly string[]) => {
    for (const key of keys) {
      if (seen.has(key)) continue;
      seen.add(key);
      all.push({ source, key });
    }
  };
  push('catalog', MESSAGE_KEYS);
  push('admin', Object.keys(adminPtPT));
  push('search', Object.keys(searchPtPT));
  push('templatePreview', Object.keys(templatePreviewSamplesPtPT));
  return all;
})();

/** The corpus, classified once per process: only the keys that belong to a destination. */
const ADMIN_CONFIGURATION_COPY_INDEX: readonly (AdminConfigurationCopyKey & {
  areas: readonly AdminConfigurationAreaId[];
})[] = ADMIN_CONFIGURATION_COPY_KEYS.flatMap((entry) => {
  const classification = classifyAdminCopyKey(entry.key);
  return classification.kind === 'destination' ? [{ ...entry, areas: classification.areas }] : [];
});

function resolveCopy(
  resolvers: AdminConfigurationCopyResolvers,
  entry: AdminConfigurationCopyKey,
): string {
  switch (entry.source) {
    case 'catalog':
      return resolvers.catalog(entry.key as MessageKey);
    case 'admin':
      return resolvers.admin(entry.key as AdminCopyKey);
    case 'search':
      return resolvers.search(entry.key as SearchCopyKey);
    case 'templatePreview':
      return resolvers.templatePreview(entry.key as TemplatePreviewSamplesCopyKey);
  }
}

// --- Current values --------------------------------------------------------------

/** One live value (or set of values) as one destination's panel shows it. */
export interface AdminConfigurationValueEntry {
  areas: readonly AdminConfigurationAreaId[];
  /** The already-resolved label the panel shows beside the value. */
  label: string;
  /** The value(s) exactly as the panel shows them. Never a secret. */
  values: readonly string[];
}

/**
 * The ALLOW-LIST of settings-document fields worth indexing. Each entry is a deliberate decision
 * that this value is safe for anyone who can already open the destination it belongs to.
 *
 * Excluded on purpose, and not by omission:
 *  - `email.username` / `email.from_address` / `email.from_name` — a relay account and mailbox
 *    identify people; the diagnostics export refuses the same fields.
 *  - `organization.name`, `documents.template_preview_samples.*` — operator-entered free text that
 *    can carry an entity name or, despite the warning on that screen, real personal data.
 *  - every boolean — "true" is not something an operator searches for, and indexing it would put
 *    a `configured`-shaped fact into a corpus that must only hold configuration.
 */
const SETTINGS_VALUE_SOURCES: readonly {
  areas: readonly AdminConfigurationAreaId[];
  label: MessageKey;
  read: (settings: Settings) => readonly (string | number | null | undefined)[];
}[] = [
  { areas: ['email'], label: 'settings.email.host.label', read: (s) => [s.email.host] },
  { areas: ['email'], label: 'settings.email.port.label', read: (s) => [s.email.port] },
  {
    areas: ['email'],
    label: 'settings.email.encryptionField.label',
    read: (s) => [s.email.encryption],
  },
  {
    areas: ['policy'],
    label: 'settings.signing.family.label',
    read: (s) => [s.signing.preferred_family],
  },
  { areas: ['tsa'], label: 'settings.signing.tsaUrl.label', read: (s) => [s.signing.tsa_url] },
  {
    areas: ['tsa'],
    label: 'settings.signing.tsaProviders.title',
    read: (s) => s.signing.tsa_providers.flatMap((p) => [p.name, p.url]),
  },
  { areas: ['tsl'], label: 'settings.signing.tslUrl.label', read: (s) => [s.signing.tsl_url] },
  {
    areas: ['tsl'],
    label: 'settings.signing.tslSources.title',
    read: (s) => s.signing.tsl_sources.flatMap((p) => [p.name, p.url]),
  },
  {
    areas: ['connectors'],
    label: 'settings.connectorEgress.hostsLabel',
    read: (s) => s.connectors.allowed_hosts,
  },
  {
    areas: ['storage'],
    label: 'settings.retainedExportCleanup.minimumAge.label',
    read: (s) => [s.data_management.retained_export_cleanup.minimum_age_days],
  },
  {
    areas: ['storage'],
    label: 'settings.retainedExportCleanup.keepLatest.label',
    read: (s) => [s.data_management.retained_export_cleanup.keep_latest],
  },
  {
    areas: ['storage'],
    label: 'settings.zkRoot.field.label',
    read: (s) => [s.data_management.zk_shared_object_root],
  },
  {
    areas: ['backups'],
    label: 'settings.backupRecovery.maxDrillAge.label',
    read: (s) => [s.data_management.backup_recovery.max_drill_age_days],
  },
  {
    areas: ['backups'],
    label: 'settings.backupRecovery.targetRpo.label',
    read: (s) => [s.data_management.backup_recovery.target_rpo_minutes],
  },
  {
    areas: ['backups'],
    label: 'settings.backupRecovery.targetRto.label',
    read: (s) => [s.data_management.backup_recovery.target_rto_minutes],
  },
];

/** Search settings live in the same document but their labels are in the search slice. */
const SEARCH_SETTINGS_VALUE_SOURCES: readonly {
  label: SearchCopyKey;
  read: (settings: Settings) => readonly (string | number | null | undefined)[];
}[] = [
  { label: 'admin.search.interval.label', read: (s) => [s.search.interval_seconds] },
  { label: 'admin.search.retention.label', read: (s) => [s.search.event_retention_days] },
];

function usableValues(raw: readonly (string | number | null | undefined)[]): string[] {
  const out: string[] = [];
  for (const value of raw) {
    if (value === null || value === undefined) continue;
    const text = String(value).trim();
    if (text !== '' && !out.includes(text)) out.push(text);
  }
  return out;
}

/**
 * Read one allow-listed field. A settings document short of a slice — an older payload, a partial
 * fixture, a cache seeded by a mutation mid-flight — must cost that one value its searchability,
 * never the whole finder: this control sits in the admin page header, so throwing here would take
 * every admin screen down over a missing optional field.
 */
function readSafely(
  read: (settings: Settings) => readonly (string | number | null | undefined)[],
  settings: Settings,
): string[] {
  try {
    return usableValues(read(settings));
  } catch {
    return [];
  }
}

/** The settings-document values, read strictly through the allow-list above. */
export function settingsValueEntries(
  settings: Settings | undefined,
  resolvers: AdminConfigurationCopyResolvers,
): AdminConfigurationValueEntry[] {
  if (!settings) return [];
  const entries: AdminConfigurationValueEntry[] = [];
  for (const source of SETTINGS_VALUE_SOURCES) {
    const values = readSafely(source.read, settings);
    if (values.length > 0) {
      entries.push({ areas: source.areas, label: resolvers.catalog(source.label), values });
    }
  }
  for (const source of SEARCH_SETTINGS_VALUE_SOURCES) {
    const values = readSafely(source.read, settings);
    if (values.length > 0) {
      entries.push({ areas: ['search'], label: resolvers.search(source.label), values });
    }
  }
  return entries;
}

/**
 * Server-env groups that also have a dedicated destination. A variable always belongs to the
 * Ambiente pane; these are the groups whose own pane transcribes the same variable as a fact.
 */
const SERVER_ENV_GROUP_AREAS: Partial<
  Record<ServerEnvVarGroup, readonly AdminConfigurationAreaId[]>
> = {
  logging: ['logs'],
  network: ['api'],
  rate_limit: ['api'],
  hsts: ['api'],
  cors: ['api'],
  database: ['database'],
  postgres_tls: ['database'],
  cache: ['cache'],
  connectors: ['connectors'],
  storage: ['storage'],
  mcp: ['mcp'],
  search: ['search'],
  cmd: ['cmd'],
};

/**
 * The server-env registry as index entries.
 *
 * **The secret rule, enforced here rather than assumed upstream.** A Tier B variable's NAME is
 * on-screen copy and stays searchable; its value is not, and this function never reads
 * `effective_value`, `override_value` or `default_value` for it — nor `configured`, which is a
 * fact ABOUT the secret and has no business in a corpus an operator can probe by typing into it.
 * The server already refuses to echo these values in three independent places; this is the fourth,
 * and the only one that constrains the index itself.
 */
export function serverEnvValueEntries(
  response: ServerEnvResponse | undefined,
): AdminConfigurationValueEntry[] {
  // Same reasoning as `readSafely`: a response without a `vars` array is a degraded registry, not
  // a reason to take the admin page header down.
  if (!Array.isArray(response?.vars)) return [];
  return response.vars.map((v) => {
    const areas: readonly AdminConfigurationAreaId[] = [
      'env',
      ...(SERVER_ENV_GROUP_AREAS[v.group] ?? []),
    ];
    if (v.secret) return { areas, label: v.name, values: [] };
    return {
      areas,
      label: v.name,
      values: usableValues([v.effective_value, v.override_value, v.default_value]),
    };
  });
}

// --- Entries and matching --------------------------------------------------------

/** What kind of text a hit landed on. The operator is told which — a value hit and a label hit
 *  are very different claims about why a destination is being suggested. */
export type AdminConfigurationMatchKind = 'title' | 'keywords' | 'label' | 'value';

/**
 * A hit worth explaining. A title hit is deliberately not one: the title IS the row's own text,
 * so restating it would spend the row's second line saying nothing.
 */
export type AdminConfigurationReasonKind = Exclude<AdminConfigurationMatchKind, 'title'>;

/** Priority for choosing what to show as the reason: the more surprising, the more it needs
 *  explaining. An operator who typed a port number wants to be told it WAS a port number. */
const REASON_KIND_ORDER: readonly AdminConfigurationReasonKind[] = ['value', 'label', 'keywords'];

const MATCH_KIND_ORDER: readonly AdminConfigurationMatchKind[] = [...REASON_KIND_ORDER, 'title'];

/** One matchable piece of text belonging to one destination. */
export interface AdminConfigurationFragment {
  kind: AdminConfigurationMatchKind;
  /** What to show the operator when this fragment is why the destination matched. */
  text: string;
  /** The normalised form actually matched against. */
  search: string;
}

export interface AdminConfigurationSearchEntry extends AdminConfigurationAreaDefinition {
  titleText: string;
  fragments: readonly AdminConfigurationFragment[];
  /** Every fragment folded into one string — the fast reject before per-fragment work. */
  searchText: string;
}

/** One fragment, shown as the reason a destination matched. */
export interface AdminConfigurationReason extends AdminConfigurationFragment {
  kind: AdminConfigurationReasonKind;
}

/** A destination that matched, and the evidence for why. */
export interface AdminConfigurationMatch {
  entry: AdminConfigurationSearchEntry;
  /** Every kind of text that contributed, in {@link MATCH_KIND_ORDER}. */
  kinds: readonly AdminConfigurationMatchKind[];
  /** The fragments to show as the reason, most informative first. */
  reasons: readonly AdminConfigurationReason[];
}

export interface AdminConfigurationIndexInput {
  areas: readonly AdminConfigurationAreaDefinition[];
  resolveTitle: (title: AdminConfigurationTitle) => string;
  resolveKeywords: (key: AdminConfigurationKeywordKey) => string;
  canAny: (permission: string) => boolean;
  /** Omit to index titles and keywords only (the pre-full-text behaviour). */
  copy?: AdminConfigurationCopyResolvers;
  values?: readonly AdminConfigurationValueEntry[];
}

function fragment(
  kind: AdminConfigurationMatchKind,
  text: string,
): AdminConfigurationFragment | null {
  const display = stripPlaceholders(text);
  if (display === '') return null;
  return { kind, text: display, search: normalizeAdminConfigurationSearch(display) };
}

/**
 * Resolve and permission-filter definitions BEFORE any query matching, so a hidden destination
 * never enters the index — not its route, not its labels, not its values, not its match count.
 */
export function buildAdminConfigurationSearchEntries({
  areas,
  resolveTitle,
  resolveKeywords,
  canAny,
  copy,
  values,
}: AdminConfigurationIndexInput): AdminConfigurationSearchEntry[] {
  const permitted = areas.filter((area) => area.permissions.some((p) => canAny(p)));
  const permittedIds = new Set(permitted.map((area) => area.id));

  const extra = new Map<string, AdminConfigurationFragment[]>();
  const add = (
    areaIds: readonly string[],
    kind: AdminConfigurationMatchKind,
    text: string,
  ): void => {
    const built = fragment(kind, text);
    if (!built) return;
    for (const id of areaIds) {
      if (!permittedIds.has(id)) continue;
      const bucket = extra.get(id);
      if (bucket) bucket.push(built);
      else extra.set(id, [built]);
    }
  };

  if (copy) {
    for (const entry of ADMIN_CONFIGURATION_COPY_INDEX) {
      // Resolving 1400-odd strings is the whole cost of the index; skip anything the caller
      // cannot reach before paying it.
      if (!entry.areas.some((id) => permittedIds.has(id))) continue;
      add(entry.areas, 'label', resolveCopy(copy, entry));
    }
  }

  for (const value of values ?? []) {
    add(value.areas, 'label', value.label);
    for (const text of value.values) add(value.areas, 'value', `${value.label}: ${text}`);
  }

  return permitted.map((area) => {
    const titleText = resolveTitle(area.title);
    const fragments = [
      fragment('title', titleText),
      fragment('title', area.id),
      fragment('title', area.path),
      fragment('keywords', resolveKeywords(area.keywords)),
      ...(extra.get(area.id) ?? []),
    ].filter((f): f is AdminConfigurationFragment => f !== null);

    const seen = new Set<string>();
    const unique = fragments.filter((f) => {
      const id = `${f.kind}\u0000${f.search}`;
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    });

    return {
      ...area,
      titleText,
      fragments: unique,
      searchText: unique.map((f) => f.search).join('\n'),
    };
  });
}

/** How many reason lines a result shows. Two is enough to distinguish a value hit from the
 *  label it sits under; more turns a menu row into a paragraph. */
const MAX_REASONS = 2;

/**
 * Match the query against the index. Every token must appear in at least one fragment (the
 * unchanged AND semantics), and the fragments that satisfied it become the result's explanation.
 */
export function matchAdminConfigurationEntries(
  entries: readonly AdminConfigurationSearchEntry[],
  query: string,
): AdminConfigurationMatch[] {
  const tokens = normalizeAdminConfigurationSearch(query).split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return [];

  const matches: AdminConfigurationMatch[] = [];
  for (const entry of entries) {
    if (!tokens.every((token) => entry.searchText.includes(token))) continue;

    const hits = entry.fragments.filter((f) => tokens.some((token) => f.search.includes(token)));
    const kinds = MATCH_KIND_ORDER.filter((kind) => hits.some((f) => f.kind === kind));
    const reasons: AdminConfigurationReason[] = [];
    for (const kind of REASON_KIND_ORDER) {
      const best = hits.find((f) => f.kind === kind);
      if (best) reasons.push({ ...best, kind });
      if (reasons.length === MAX_REASONS) break;
    }
    matches.push({ entry, kinds, reasons });
  }
  return matches;
}
