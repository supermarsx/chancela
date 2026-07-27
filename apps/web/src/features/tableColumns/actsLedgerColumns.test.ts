/**
 * The `acts` and `ledger` table-column declarations (t54-e6). Kept in a file of its own rather
 * than folded into `tableColumns.test.tsx` — that file is mid-rework under a sibling lane (the
 * `<ColumnPicker>` origin display), and this suite only needs the registry, not the picker.
 */
import { describe, expect, it } from 'vitest';
import {
  ACTS_TABLE,
  LEDGER_TABLE,
  assertTableColumnRegistry,
  controlColumns,
  dataColumns,
  storableColumns,
  structuralColumns,
} from './tableColumnRegistry';

describe('ACTS_TABLE', () => {
  it('registers cleanly alongside the other declared tables', () => {
    expect(() => assertTableColumnRegistry()).not.toThrow();
  });

  it('treats the ata number as identity-bearing, not merely displayed first', () => {
    // A draft has no number yet — that is a state, not a missing fact — but a sealed ata's
    // number is what makes the row identifiable, so it is force-kept rather than offered as a
    // toggle (memory: identity-bearing data is `structural`, never `data`).
    expect(structuralColumns(ACTS_TABLE)).toEqual(['Number']);
  });

  it('keeps the row-open action out of the picker and out of the stored preference', () => {
    expect(controlColumns(ACTS_TABLE)).toEqual(['Actions']);
    expect(storableColumns(ACTS_TABLE)).not.toContain('Actions');
  });

  it('shows every storable column by default — five columns never needed hiding', () => {
    expect(dataColumns(ACTS_TABLE)).toEqual(['Title', 'Channel', 'State']);
    expect(ACTS_TABLE.productDefault).toEqual(['Number', 'Title', 'Channel', 'State']);
  });
});

describe('LEDGER_TABLE', () => {
  it('registers cleanly alongside the other declared tables', () => {
    expect(() => assertTableColumnRegistry()).not.toThrow();
  });

  it('force-keeps the sequence and the event kind — a row is not usable without either', () => {
    expect(structuralColumns(LEDGER_TABLE)).toEqual(['Seq', 'Event']);
  });

  it('has no control column — Arquivo renders no row-actions cell', () => {
    expect(controlColumns(LEDGER_TABLE)).toEqual([]);
  });

  it('defaults Chains OFF and Hash ON, replacing the ad-hoc showChains prop', () => {
    // This is the one default the retired `showChains` prop used to encode by hand (`true` on
    // Arquivo, the implicit `false` on the dashboard) — now resolved once, here.
    expect(dataColumns(LEDGER_TABLE)).toEqual(['Scope', 'Chains', 'Actor', 'Date', 'Hash']);
    expect(LEDGER_TABLE.productDefault).toEqual(['Seq', 'Event', 'Scope', 'Actor', 'Date', 'Hash']);
    expect(LEDGER_TABLE.productDefault).not.toContain('Chains');
    expect(LEDGER_TABLE.productDefault).toContain('Hash');
  });
});
