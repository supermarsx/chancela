/**
 * The inline show/hide column picker shared by every configurable table (t37). It is the exact
 * `<details>` + checkbox-grid pattern the Minutas catalog introduced (`templates-columns` /
 * `filter-advanced`), lifted into one component so entities, books and templates present the
 * control identically and in the same place — beside the table, not in a distant Settings card.
 *
 * Presentational only: the visible/toggle state and its persistence live in `useTableColumns`.
 * Copy (the summary, the hint, the per-column labels) is passed in, so the component carries no
 * strings of its own and stays locale-agnostic.
 */
import type { ReactNode } from 'react';

export function ColumnPicker<C extends string>({
  columns,
  label,
  hint,
  ariaLabel,
  isVisible,
  onToggle,
  columnLabel,
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
}) {
  return (
    <details className="templates-columns filter-advanced">
      <summary>{label}</summary>
      <fieldset className="templates-columns__body filter-advanced__body">
        <legend className="sr-only">{ariaLabel ?? label}</legend>
        {hint ? <p className="field__hint">{hint}</p> : null}
        <div className="row-wrap">
          {columns.map((column) => (
            <label key={column} className="checkline">
              <input
                type="checkbox"
                checked={isVisible(column)}
                onChange={(event) => onToggle(column, event.target.checked)}
              />
              {columnLabel(column)}
            </label>
          ))}
        </div>
      </fieldset>
    </details>
  );
}
