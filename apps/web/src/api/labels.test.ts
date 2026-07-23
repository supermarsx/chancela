import { describe, expect, it } from 'vitest';
import {
  dashboardAlertSourceLabel,
  dashboardReminderRuleLabel,
  isRetiredRoleId,
  ledgerEventKindLabel,
  roleNameLabel,
} from './labels';
import {
  LABELLED_DASHBOARD_ALERT_SOURCES,
  LABELLED_DASHBOARD_REMINDER_RULES,
  LABELLED_LEDGER_EVENT_KINDS,
  SEEDED_ROLE_NAMES,
} from '../i18n';
import { ptPT } from '../i18n/locales/pt-PT';
import { daDK } from '../i18n/locales/da-DK';
import { deDE } from '../i18n/locales/de-DE';
import { enGB } from '../i18n/locales/en-GB';
import { enUS } from '../i18n/locales/en-US';
import { esES } from '../i18n/locales/es-ES';
import { fiFI } from '../i18n/locales/fi-FI';
import { frFR } from '../i18n/locales/fr-FR';
import { itIT } from '../i18n/locales/it-IT';
import { nlNL } from '../i18n/locales/nl-NL';
import { plPL } from '../i18n/locales/pl-PL';
import { ptBR } from '../i18n/locales/pt-BR';
import { svFI } from '../i18n/locales/sv-FI';
import { svSE } from '../i18n/locales/sv-SE';

/** Every shipped catalog: the pt-PT source plus the 13 code-split locales. */
const ALL_CATALOGS = {
  'pt-PT': ptPT,
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
};

describe('ledgerEventKindLabel', () => {
  it('renders a known kind as source-locale copy, not the wire identifier', () => {
    expect(ledgerEventKindLabel('act.sealed')).toBe('Ata selada');
    expect(ledgerEventKindLabel('entity.statute_updated')).toBe(
      'Estatutos da entidade atualizados',
    );
    expect(ledgerEventKindLabel('registry.imported')).toBe(
      'Certidão do registo comercial importada',
    );
    expect(ledgerEventKindLabel('book.opened')).toBe('Livro aberto');
    expect(ledgerEventKindLabel('template.restored')).toBe('Minuta restaurada');
    expect(ledgerEventKindLabel('template.version.deleted')).toBe('Versão da minuta eliminada');
    expect(ledgerEventKindLabel('template.version.renamed')).toBe('Versão da minuta renomeada');
  });

  it('falls back to the raw identifier for a kind a newer server introduces', () => {
    // Never blank, never "undefined": the id is a usable Arquivo filter value.
    expect(ledgerEventKindLabel('act.teleported')).toBe('act.teleported');
    expect(ledgerEventKindLabel('wholly.unknown.kind')).toBe('wholly.unknown.kind');
    expect(ledgerEventKindLabel('  act.sealed  ')).toBe('Ata selada');
  });

  it('returns the input unchanged for an empty or whitespace kind', () => {
    expect(ledgerEventKindLabel('')).toBe('');
    expect(ledgerEventKindLabel('   ')).toBe('   ');
  });

  it('has a catalog entry for every kind it claims to label', () => {
    // Parity, not a fixed count: the server grows new kinds and the map grows with it. What
    // must never drift is the set claiming a label and the catalog actually carrying one.
    const missing = [...LABELLED_LEDGER_EVENT_KINDS].filter(
      (kind) => !(`enum.ledgerEventKind.${kind}` in ptPT),
    );
    const orphaned = Object.keys(ptPT)
      .filter((key) => key.startsWith('enum.ledgerEventKind.'))
      .map((key) => key.slice('enum.ledgerEventKind.'.length))
      .filter((kind) => !LABELLED_LEDGER_EVENT_KINDS.has(kind));

    expect(missing).toEqual([]);
    expect(orphaned).toEqual([]);
    // The catalog was seeded from the kinds `crates/` emits; a shrink is a regression.
    expect(LABELLED_LEDGER_EVENT_KINDS.size).toBeGreaterThanOrEqual(133);
  });

  it('labels every event kind the Rust crates can append to the ledger', async () => {
    // Parity against the source of truth, not the UI: a kind added server-side must fail here
    // rather than leak a dotted wire identifier into the Arquivo table months later.
    const emitted = await ledgerEventKindsEmittedByCrates();

    // Non-vacuity, per rule: a regex that stops matching must fail loudly instead of passing on
    // an empty set. Each of the four emit shapes below really exists in the tree today.
    for (const [rule, kinds] of Object.entries(emitted.byRule)) {
      expect(kinds.size, `extraction rule "${rule}" matched nothing`).toBeGreaterThan(0);
    }
    // A floor just under the current count, so a partially broken sweep is caught too.
    expect(emitted.kinds.size).toBeGreaterThanOrEqual(130);

    const unlabelled = [...emitted.kinds].filter((kind) => !LABELLED_LEDGER_EVENT_KINDS.has(kind));
    expect(unlabelled.sort()).toEqual([]);
  });
});

/**
 * Every ledger event kind the Rust crates can append, read out of the crate sources.
 *
 * There is no single `kind` literal position to grep: a kind reaches `Ledger::append` through
 * `try_append_event`, a per-module `record_*`/`audit`/`persist_*` helper, a `*_KIND` constant, a
 * `fn *kind()` match, or a `let kind = …` binding. All five shapes are swept; a literal is taken
 * as a kind only if it looks like one (`a.b`, lowercase dotted). Test code is excluded, so a
 * fixture kind never becomes a label obligation.
 */
async function ledgerEventKindsEmittedByCrates(): Promise<{
  kinds: Set<string>;
  byRule: Record<string, Set<string>>;
}> {
  const nodeFs = 'node:fs';
  const { readFileSync, readdirSync, statSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
    readdirSync(path: string): string[];
    statSync(path: string): { isDirectory(): boolean };
  };

  const files: string[] = [];
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const path = `${dir}/${name}`;
      if (statSync(path).isDirectory()) {
        if (name !== 'target' && name !== 'tests') walk(path);
      } else if (name.endsWith('.rs') && !name.endsWith('_tests.rs')) {
        files.push(path);
      }
    }
  };
  walk('../../crates');

  const KIND = /^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$/u;
  const LITERAL = /"([^"\n]+)"/gu;
  const byRule: Record<string, Set<string>> = {
    emitCall: new Set(),
    kindFn: new Set(),
    kindLet: new Set(),
    kindConst: new Set(),
  };
  const take = (rule: keyof typeof byRule, text: string): void => {
    for (const match of text.matchAll(LITERAL)) {
      if (KIND.test(match[1])) byRule[rule].add(match[1]);
    }
  };

  for (const file of files) {
    const source = stripRustTestModules(readFileSync(file, 'utf8'));

    // 1. Any call whose name carries append/record/audit/persist — the emit funnels. The
    //    structured-logging helper is excluded by name: its `target` field is a log channel
    //    (`platform.services`), not a ledger kind, and it never reaches `Ledger::append`.
    for (const match of source.matchAll(
      /(?<![a-z_0-9])([a-z_0-9]*(?:append|record|audit|persist)[a-z_0-9]*)\s*\(/gu,
    )) {
      if (match[1] === 'record_platform_log') continue;
      take('emitCall', balancedBlock(source, match.index + match[0].length));
    }
    // 2. `fn event_kind(self) -> &'static str { match … }`.
    for (const match of source.matchAll(/fn\s+[a-z_0-9]*kind[a-z_0-9]*\s*\([^)]*\)[^{]*\{/gu)) {
      take('kindFn', balancedBlock(source, match.index + match[0].length));
    }
    // 3. `let kind = match …` / `let (kind, why) = if …` — the branch picks the kind.
    for (const match of source.matchAll(/let\s+[^=;\n]*\bkind\b[^=;\n]*=\s*/gu)) {
      const start = match.index;
      const end = source.indexOf(';', start + match[0].length);
      take('kindLet', source.slice(start, end < 0 ? start + 400 : end));
    }
    // 4. `const SUBJECT_ERASED_KIND: &str = "subject.erased";`.
    for (const match of source.matchAll(
      /(?:const|static)\s+[A-Z_0-9]*KIND\b\s*:\s*&(?:'static\s+)?str\s*=\s*("[^"]+")\s*;/gu,
    )) {
      take('kindConst', match[1]);
    }
  }

  const kinds = new Set<string>();
  for (const rule of Object.values(byRule)) for (const kind of rule) kinds.add(kind);
  return { kinds, byRule };
}

/** Drop `#[cfg(test)] mod … { … }` bodies, brace-balanced, so fixtures are not swept as kinds. */
function stripRustTestModules(source: string): string {
  const opener = /#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+[a-z_0-9]+\s*\{/gu;
  let kept = '';
  let cursor = 0;
  for (;;) {
    opener.lastIndex = cursor;
    const hit = opener.exec(source);
    if (!hit) return kept + source.slice(cursor);
    kept += source.slice(cursor, hit.index);
    let depth = 1;
    let index = opener.lastIndex;
    while (index < source.length && depth > 0) {
      if (source[index] === '{') depth += 1;
      else if (source[index] === '}') depth -= 1;
      index += 1;
    }
    cursor = index;
  }
}

/** The text between `open` and the bracket that closes the group it opened. */
function balancedBlock(source: string, open: number): string {
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    const char = source[index];
    if (char === '(' || char === '[' || char === '{') depth += 1;
    else if (char === ')' || char === ']' || char === '}') {
      if (depth === 0) return source.slice(open, index);
      depth -= 1;
    }
  }
  return source.slice(open);
}

/**
 * Read a crate source file. The web tsconfig has no `@types/node`, so `node:fs` is reached
 * through the indirect-specifier trick `src/app/motion.test.ts` already uses; vitest runs from
 * `apps/web`, so the repo root is two levels up.
 */
async function readCrateSource(relative: string): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync(`../../${relative}`, 'utf8');
}

function matchAll(source: string, pattern: RegExp): string[] {
  return [...source.matchAll(pattern)].map((match) => match[1]);
}

describe('dashboardAlertSourceLabel', () => {
  it('renders a known source as source-locale copy, not the wire identifier', () => {
    // The reported defect: `entities.books` is the data scope the check ran over, not an event.
    expect(dashboardAlertSourceLabel('entities.books')).toBe('Livros da entidade');
    expect(dashboardAlertSourceLabel('ledger.verify')).toBe('Verificação da cadeia de registo');
    expect(dashboardAlertSourceLabel('books.termo_abertura')).toBe('Termo de abertura do livro');
    expect(dashboardAlertSourceLabel('registry_extracts.provenance.valid_until')).toBe(
      'Validade da certidão do registo',
    );
  });

  it('names a rule pack across versions, so a /v3 does not silently fall back', () => {
    expect(dashboardAlertSourceLabel('csc-art63/v2')).toBe('Regras do CSC (artigo 63.º)');
    expect(dashboardAlertSourceLabel('csc-art63/v3')).toBe('Regras do CSC (artigo 63.º)');
    expect(dashboardAlertSourceLabel('condominio-dl268/v1')).toBe(
      'Regras de condomínio (DL 268/94)',
    );
  });

  it('falls back to the raw identifier for a source a newer server introduces', () => {
    // Never blank, never "undefined": an unlabelled source still names itself.
    expect(dashboardAlertSourceLabel('quantum.entanglement')).toBe('quantum.entanglement');
    expect(dashboardAlertSourceLabel('unknown-pack/v9')).toBe('unknown-pack/v9');
    expect(dashboardAlertSourceLabel('  entities.books  ')).toBe('Livros da entidade');
  });

  it('returns the input unchanged for an empty or whitespace source', () => {
    expect(dashboardAlertSourceLabel('')).toBe('');
    expect(dashboardAlertSourceLabel('   ')).toBe('   ');
  });

  it('has a catalog entry for every source it claims to label', () => {
    const missing = [...LABELLED_DASHBOARD_ALERT_SOURCES].filter(
      (source) => !(`enum.dashboardAlertSource.${source}` in ptPT),
    );
    expect(missing).toEqual([]);
  });

  it('labels every source the Rust dashboard can emit', async () => {
    // Parity against the source of truth, not the UI: a source added server-side must fail here
    // rather than leak a raw identifier onto the Fonte line.
    const dashboard = await readCrateSource('crates/chancela-api/src/dashboard.rs');
    const rules = await readCrateSource('crates/chancela-core/src/rules.rs');

    const literals = matchAll(dashboard, /^\s*source: Some\("([^"]+)"\.to_owned\(\)\)/gmu);
    // `source: Some(pack.id().to_owned())` — every shipped `RulePack::ID`.
    const rulePackIds = matchAll(rules, /pub const ID: &'static str = "([^"]+)";/gu);
    expect(dashboard).toContain('source: Some(pack.id().to_owned())');
    expect(literals.length).toBeGreaterThan(0);
    expect(rulePackIds.length).toBeGreaterThan(0);

    const unlabelled = [...new Set([...literals, ...rulePackIds])]
      .filter((source) => dashboardAlertSourceLabel(source) === source)
      .sort();
    expect(unlabelled).toEqual([]);
  });
});

describe('dashboardReminderRuleLabel', () => {
  it('renders a known rule as source-locale copy', () => {
    expect(dashboardReminderRuleLabel('act-follow-up')).toBe('Seguimento de deliberação');
    expect(dashboardReminderRuleLabel('act-attendance-missing')).toBe('Presenças em falta na ata');
  });

  it('prefers the authored preset label the payload already carries', () => {
    // Profile-calendar reminders name themselves; that authored pt-PT title wins over any map.
    expect(
      dashboardReminderRuleLabel('csc-art376-annual', 'Assembleia geral anual (CSC art. 376.º)'),
    ).toBe('Assembleia geral anual (CSC art. 376.º)');
    expect(dashboardReminderRuleLabel('act-follow-up', '  ')).toBe('Seguimento de deliberação');
  });

  it('returns undefined for an unmapped rule so the caller keeps the raw rule / profile line', () => {
    expect(dashboardReminderRuleLabel('rule-from-the-future')).toBeUndefined();
    expect(dashboardReminderRuleLabel('')).toBeUndefined();
  });

  it('has a catalog entry for every rule it claims to label', () => {
    const missing = [...LABELLED_DASHBOARD_REMINDER_RULES].filter(
      (rule) => !(`enum.dashboardReminderRule.${rule}` in ptPT),
    );
    expect(missing).toEqual([]);
  });

  it('labels every reminder rule the Rust dashboard can emit, or lets the payload name it', async () => {
    const dashboard = await readCrateSource('crates/chancela-api/src/dashboard.rs');
    const literals = matchAll(dashboard, /^\s*source_rule: "([^"]+)"\.to_owned\(\)/gmu);
    // The privacy generators pass their rule as the first argument of the shared builder.
    const privacy = matchAll(dashboard, /privacy_review_reminder_from_summary\(\s*"([^"]+)"/gu);
    expect(literals.length).toBeGreaterThan(0);
    expect(privacy.length).toBeGreaterThan(0);

    const unlabelled = [...new Set([...literals, ...privacy])]
      .filter((rule) => dashboardReminderRuleLabel(rule) === undefined)
      .sort();
    // `source_rule: preset.id` is deliberately absent: those reminders ship `preset_label`.
    expect(unlabelled).toEqual([]);
  });
});

describe('roleNameLabel', () => {
  /** The u128 literals in `role.rs` rendered as the UUIDs the API puts on the wire. */
  function uuidOf(hex: string): string {
    const h = BigInt(`0x${hex.replace(/_/gu, '')}`)
      .toString(16)
      .padStart(32, '0');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }

  async function seededRoleIdsFromCrate(): Promise<Map<string, string>> {
    const source = await readCrateSource('crates/chancela-authz/src/role.rs');
    const found = new Map<string, string>();
    for (const match of source.matchAll(
      /pub const (\w+_ROLE_ID): RoleId =\s*RoleId\(Uuid::from_u128\(0x([0-9a-f_]+)\)\)/gu,
    )) {
      found.set(match[1], uuidOf(match[2]));
    }
    return found;
  }

  it('names every seeded role the Rust catalog defines, and invents none', async () => {
    // The claim the module docs make: `SEEDED_ROLE_NAMES` mirrors `role.rs`. Assert it against the
    // crate rather than against a copy, so adding or retiring a role server-side fails here instead
    // of silently rendering a bare UUID in the roles table.
    const fromCrate = await seededRoleIdsFromCrate();
    expect(fromCrate.size).toBeGreaterThan(0);

    const crateIds = [...fromCrate.values()].sort();
    const clientIds = Object.keys(SEEDED_ROLE_NAMES).sort();
    expect(clientIds).toEqual(crateIds);
  });

  it('marks exactly the retired ids as retired', async () => {
    const fromCrate = await seededRoleIdsFromCrate();
    const retiredInCrate = [...fromCrate]
      .filter(([name]) => name.startsWith('RETIRED_'))
      .map(([, id]) => id)
      .sort();
    const retiredInClient = Object.entries(SEEDED_ROLE_NAMES)
      .filter(([, entry]) => entry.retired)
      .map(([id]) => id)
      .sort();
    expect(retiredInClient).toEqual(retiredInCrate);
    expect(retiredInClient.length).toBe(2);
  });

  it('has a catalog entry for every seeded role, in every shipped locale', () => {
    // "Resolves to a name in all 14 locales" is the requirement, so assert it over the real
    // catalogs rather than over pt-PT alone — a missing slice would otherwise only surface for that
    // locale's users.
    //
    // The catalogs are imported statically, the same way `i18n/catalogLeakGate.test.ts` does it,
    // NOT awaited through `LOCALE_LOADERS`. An earlier version of this test resolved the 13
    // code-split loaders at runtime; it passed in isolation and timed out at 5s under the full
    // suite, which made a correctness gate into a load-dependent flake. Static imports make it
    // synchronous and deterministic.
    const slugs = Object.values(SEEDED_ROLE_NAMES).map((entry) => entry.slug);
    expect(slugs.length).toBe(Object.keys(SEEDED_ROLE_NAMES).length);
    expect(new Set(slugs).size).toBe(slugs.length);
    // All 14, counted rather than assumed: pt-PT is the eager source catalog and the other 13 are
    // the shipped locales, so a locale added without a role-name slice fails here.
    expect(Object.keys(ALL_CATALOGS).length).toBe(14);

    for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
      for (const slug of slugs) {
        const key = `enum.roleName.${slug}`;
        expect(
          (catalog as Record<string, string>)[key],
          `${locale} is missing ${key}`,
        ).toBeTruthy();
      }
    }
  });

  it('renders a seeded role in the active locale, not the English name the server stores', () => {
    const owner = '6f776e65-7200-0000-0000-000000000001';
    expect(roleNameLabel(owner, 'Owner')).toBe('Proprietário');
    expect(roleNameLabel('7369676e-7472-7900-0000-00000000000e', 'Signatory')).toBe('Signatário');
    expect(roleNameLabel('636f6f77-6e72-0000-0000-00000000000a', 'Company Owner')).toBe(
      'Proprietário da empresa',
    );
  });

  it('leaves an operator-authored role name exactly as authored', () => {
    // A custom role's id is a random UUID and is never in the map, so its name is data. This is the
    // defect the seeded/custom split exists to prevent: translating someone else's words.
    const custom = '9f1d4c7a-2b3e-4f56-8a90-1c2d3e4f5a6b';
    expect(roleNameLabel(custom, 'Gerente da filial')).toBe('Gerente da filial');
    expect(roleNameLabel(custom, 'Owner')).toBe('Owner');
    expect(roleNameLabel(custom, '  Signatory  ')).toBe('Signatory');
  });

  it('lets an operator rename a seeded role and shows their name, not the translation', () => {
    // Otherwise editing a seeded role's name would silently appear to do nothing.
    const signatory = '7369676e-7472-7900-0000-00000000000e';
    expect(roleNameLabel(signatory, 'Assinante-chefe')).toBe('Assinante-chefe');
    expect(roleNameLabel(signatory, 'Signatory')).toBe('Signatário');
  });

  it('still names a retired id, so past ledger events stay readable', () => {
    // The requirement the merge must not break: these ids are gone from the catalog but remain in
    // append-only history, which is never rewritten. Both must render a name, marked retired.
    const gestor = '67657374-6f72-0000-0000-000000000002';
    const signatario = '7369676e-6174-0000-0000-000000000003';
    expect(isRetiredRoleId(gestor)).toBe(true);
    expect(isRetiredRoleId(signatario)).toBe(true);
    expect(roleNameLabel(gestor)).toBe('Gestor (função descontinuada)');
    expect(roleNameLabel(signatario)).toBe('Signatário (função descontinuada)');

    // A retired id resolves even when a stale record still carries its old stored name.
    expect(roleNameLabel(gestor, 'Gestor')).toBe('Gestor (função descontinuada)');
    expect(isRetiredRoleId('6f776e65-7200-0000-0000-000000000001')).toBe(false);
  });

  it('degrades to the raw id for a role it knows nothing about', () => {
    // Never blank, never "undefined" — the id is still a usable handle in a table cell.
    expect(roleNameLabel('7e57r0le-0000-0000-0000-000000000000')).toBe(
      '7e57r0le-0000-0000-0000-000000000000',
    );
    expect(roleNameLabel('  9f1d4c7a-2b3e-4f56-8a90-1c2d3e4f5a6b  ')).toBe(
      '  9f1d4c7a-2b3e-4f56-8a90-1c2d3e4f5a6b  ',
    );
  });
});
