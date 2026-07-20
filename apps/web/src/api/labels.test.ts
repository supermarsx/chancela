import { describe, expect, it } from 'vitest';
import { ledgerEventKindLabel } from './labels';
import { LABELLED_LEDGER_EVENT_KINDS } from '../i18n';
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
