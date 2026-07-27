/**
 * The inline show/hide column picker shared by every configurable table (t37). A `<details>`
 * disclosure beside the table — not in a distant Settings card — so entities, books and templates
 * present the control identically and in the same place.
 *
 * The body is the shared {@link ColumnToggleGrid}: an aligned Coluna / Visível / Origem grid rather
 * than the wrapping chip cloud this component shipped with (t54). Read that module for why the
 * layout is tabular but the semantics are not.
 *
 * `Origem` is the picker's own addition: it says whether the current selection is the user's, the
 * instance's, or the shipped default — the one thing this control could never answer before. It is
 * derived by {@link resolveColumnOrigin} at the call site, where the org default is known, and is
 * uniform across the rows because a preference is stored and resolved as one array.
 *
 * Presentational only: the visible/toggle state and its persistence live in `useTableColumns`, and
 * every table-specific string (the summary, the hint, the column labels) is passed in.
 */
import type { ReactNode } from 'react';
import { ColumnToggleGrid } from './ColumnToggleGrid';
import type { ColumnOrigin } from './columnOrigin';

export function ColumnPicker<C extends string>({
  columns,
  label,
  hint,
  ariaLabel,
  isVisible,
  onToggle,
  columnLabel,
  origin,
}: {
  /** The hideable columns to offer, in order. */
  columns: readonly C[];
  /** The `<summary>` label that opens the picker. */
  label: string;
  /** Optional hint shown above the grid. */
  hint?: string;
  /** Accessible name for the grouping fieldset (defaults to `label`). */
  ariaLabel?: string;
  isVisible: (column: C) => boolean;
  onToggle: (column: C, checked: boolean) => void;
  /** Renders the visible label for a column. */
  columnLabel: (column: C) => ReactNode;
  /** Where the current selection comes from; omit to drop the `Origem` column. */
  origin?: ColumnOrigin;
}) {
  return (
    // `templates-columns` is kept alongside the new prefix: it is the width clamp this disclosure
    // has always carried, and it is what the catalog page's own test selects on.
    <details className="column-picker templates-columns filter-advanced">
      <summary>{label}</summary>
      <fieldset className="column-picker__body templates-columns__body filter-advanced__body">
        <legend className="sr-only">{ariaLabel ?? label}</legend>
        {hint ? <p className="field__hint">{hint}</p> : null}
        <ColumnToggleGrid
          columns={columns}
          isVisible={isVisible}
          onToggle={onToggle}
          columnLabel={columnLabel}
          origin={origin}
        />
      </fieldset>
    </details>
  );
}
