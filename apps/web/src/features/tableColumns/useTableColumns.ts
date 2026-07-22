/**
 * The one shared mechanism behind every configurable table (entities, books, templates — t37).
 *
 * It resolves a table's effective visible columns from the per-user preferences store
 * (`GET /v1/me/preferences`), canonicalizes the selection (drop unknown ids, collapse duplicates,
 * force-keep the structural always-on columns, normalize to the table's own order), and exposes a
 * `toggle` that writes the change back through `PUT /v1/me/preferences`. The resolution follows the
 * table's fallback chain: when the user has no personal override, the caller's `fallback` applies —
 * for entities that is the instance org default (then the product default); for books and templates
 * it is the product default.
 *
 * The persisted array always carries the structural columns (or, for a table whose structural
 * columns live outside its column set, an `anchor` id), so an ordinary toggle never sends an empty
 * list — the server folds `[]` to "no override", which would silently discard a deliberate
 * "hide every optional column" choice.
 */
import { useCallback, useMemo } from 'react';
import { useUpdateTableColumns, useUserPreferences } from '../../api/hooks';
import type { TableColumnPreferences } from '../../api/types';

export interface TableColumnsSpec<C extends string> {
  /** Which table this configures — the key under `table_columns`. */
  table: keyof TableColumnPreferences;
  /** Every column in canonical render order (both hideable and structural). */
  columns: readonly C[];
  /** The subset the picker offers as checkboxes; the rest are structural and always shown. */
  hideable: readonly C[];
  /** The visible set when the user has no stored override (already in canonical order). */
  fallback: readonly C[];
  /**
   * A storage-only id kept at the head of the persisted array so it is never empty. Only needed
   * for a table whose structural columns live OUTSIDE `columns` (templates render `Name`/`Actions`
   * themselves, so a "hide every optional column" choice would otherwise persist as `[]` and fold
   * to "no override"). Must be a valid column id (ASCII-alphanumeric) and must not be a member of
   * `columns` — it is stripped on read.
   */
  anchor?: string;
}

export interface TableColumnsResult<C extends string> {
  /** The resolved, canonicalized visible columns in render order. */
  visible: C[];
  isVisible: (column: C) => boolean;
  toggle: (column: C, checked: boolean) => void;
  /** Persist an arbitrary visible set (used for the one-time templates localStorage migration). */
  set: (columns: readonly C[]) => void;
  /** Whether the user has a personal override (rather than showing the fallback). */
  overridden: boolean;
  /** The preferences query is still loading. */
  loading: boolean;
  /** A write is in flight. */
  pending: boolean;
}

/** The columns that are structural — present in the render order but not offered as toggles. */
function structuralColumns<C extends string>(columns: readonly C[], hideable: readonly C[]): C[] {
  return columns.filter((column) => !hideable.includes(column));
}

/** Intersect an opaque id list with the known columns, force-keep structural, order-normalize. */
function canonicalize<C extends string>(
  columns: readonly C[],
  hideable: readonly C[],
  source: readonly string[],
): C[] {
  const known = new Set<string>(columns);
  const picked = new Set<C>(source.filter((id): id is C => known.has(id)));
  for (const column of structuralColumns(columns, hideable)) picked.add(column);
  return columns.filter((column) => picked.has(column));
}

export function useTableColumns<C extends string>(
  spec: TableColumnsSpec<C>,
): TableColumnsResult<C> {
  const { table, columns, hideable, fallback, anchor } = spec;
  const prefs = useUserPreferences();
  const update = useUpdateTableColumns();

  const raw = prefs.data?.table_columns?.[table];
  const overridden = Array.isArray(raw);

  const visible = useMemo(
    () => canonicalize(columns, hideable, raw ?? fallback),
    [columns, hideable, raw, fallback],
  );

  const isVisible = useCallback((column: C) => visible.includes(column), [visible]);

  // Persist a whole visible set: normalize to canonical order, force-keep the structural columns,
  // and prepend the anchor (if any) so the stored array is never empty.
  const set = useCallback(
    (next: readonly C[]) => {
      const structural = structuralColumns(columns, hideable);
      const nextVisible = columns.filter(
        (candidate) => structural.includes(candidate) || next.includes(candidate),
      );
      const stored = anchor ? [anchor, ...nextVisible] : [...nextVisible];
      update.mutate({ table, columns: stored });
    },
    [table, columns, hideable, anchor, update],
  );

  const toggle = useCallback(
    (column: C, checked: boolean) => {
      const nextHideable = hideable.filter((candidate) =>
        candidate === column ? checked : visible.includes(candidate),
      );
      set(nextHideable);
    },
    [hideable, visible, set],
  );

  return {
    visible,
    isVisible,
    toggle,
    set,
    overridden,
    loading: prefs.isLoading,
    pending: update.isPending,
  };
}
