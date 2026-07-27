/**
 * The inline show/hide column picker shared by every configurable table (t37). A `<details>`
 * disclosure beside the table — not in a distant Settings card — so entities, books and templates
 * present the control identically and in the same place.
 *
 * The body is the shared {@link ColumnToggleGrid}: an aligned Coluna / Visível grid rather than the
 * wrapping chip cloud this component shipped with (t54). Read that module for why the layout is
 * tabular but the semantics are not.
 *
 * ## `Origem`, stated once
 *
 * The picker's own addition is that it says whether the current selection is the user's, the
 * instance's, or the shipped default — the one thing this control could never answer before, and
 * therefore the one thing that tells a user which knob changes it. It is derived by
 * `resolveColumnOrigin` at the call site, where the org default is known.
 *
 * It is stated **once, above the grid**, not once per row. The origin is a property of the
 * selection, not of a column: a preference is stored and resolved as one array, so every row would
 * have carried the same value. Repeating it thirteen times is noise on a control whose whole point
 * is regularity, and it would make a screen reader recite the same phrase once per checkbox.
 *
 * Stated once, it is wired as the `<fieldset>`'s `aria-describedby`, so assistive technology
 * announces it on entering the group — after the group's own name, before the controls — which is
 * where a fact *about the group* belongs. Label and value are separate elements rather than one
 * interpolated string: no noun is dropped into a sentence that would have to agree with it.
 *
 * Presentational only: the visible/toggle state and its persistence live in `useTableColumns`, and
 * every table-specific string (the summary, the hint, the column labels) is passed in.
 */
import { useId, type ReactNode } from 'react';
import { useTableColumnsT, type TableColumnsCopyKey } from '../../i18n/tableColumnsFallback';
import { ColumnToggleGrid } from './ColumnToggleGrid';
import type { ColumnOrigin } from './columnOrigin';

const ORIGIN_KEYS: Record<ColumnOrigin, TableColumnsCopyKey> = {
  personal: 'tableColumns.origin.personal',
  org: 'tableColumns.origin.org',
  product: 'tableColumns.origin.product',
};

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
  /** Where the current selection comes from; omit to say nothing about it. */
  origin?: ColumnOrigin;
}) {
  const ct = useTableColumnsT();
  const originId = `${useId()}origin`;

  return (
    // `templates-columns` is kept alongside the new prefix: it is the width clamp this disclosure
    // has always carried, and it is what the catalog page's own test selects on.
    <details className="column-picker templates-columns filter-advanced">
      <summary>{label}</summary>
      <fieldset
        className="column-picker__body templates-columns__body filter-advanced__body"
        aria-describedby={origin === undefined ? undefined : originId}
      >
        <legend className="sr-only">{ariaLabel ?? label}</legend>
        {hint ? <p className="field__hint">{hint}</p> : null}
        {origin === undefined ? null : (
          <p id={originId} className="column-picker__origin">
            <span className="column-picker__origin-label">{ct('tableColumns.origin.label')}</span>
            <span className="column-picker__origin-value">{ct(ORIGIN_KEYS[origin])}</span>
          </p>
        )}
        <ColumnToggleGrid
          columns={columns}
          isVisible={isVisible}
          onToggle={onToggle}
          columnLabel={columnLabel}
        />
      </fieldset>
    </details>
  );
}
