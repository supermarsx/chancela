import { describe, expect, it } from 'vitest';
import {
  dashboardAlertSourceLabel,
  dashboardReminderRuleLabel,
  ledgerEventKindLabel,
} from './labels';
import {
  LABELLED_DASHBOARD_ALERT_SOURCES,
  LABELLED_DASHBOARD_REMINDER_RULES,
  LABELLED_LEDGER_EVENT_KINDS,
} from '../i18n';
import { ptPT } from '../i18n/locales/pt-PT';

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
    // The catalog was seeded from the 125 kinds `crates/` emits; a shrink is a regression.
    expect(LABELLED_LEDGER_EVENT_KINDS.size).toBeGreaterThanOrEqual(125);
  });
});

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
