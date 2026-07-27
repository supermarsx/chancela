/**
 * The aligned column-toggle grid (t54) — shared by the per-user picker beside a table and by the
 * org-default card in Configurações, so the same control reads the same way at both scopes.
 *
 * ## What it replaces
 *
 * A wrapping chip cloud (`.row-wrap` of `.checkline` labels) on the picker, and a stack of `Toggle`
 * switches in the settings card. With thirteen entity columns the cloud reflowed into a ragged block
 * with nothing lining up, which is what the request "much more neatly displayed in a table like
 * format" is about.
 *
 * ## It is a control grid, NOT a `<table>`
 *
 * The layout is tabular; the content is not. These are form controls arranged in columns, not rows
 * of data — and announcing them through table semantics (`<table>`/`role="grid"`) would tell a
 * screen-reader user to navigate cells and read row/column headers for what is, in substance, a list
 * of checkboxes each already carrying its own name and state. That is strictly worse than the
 * checkbox list it replaces, and it would be describing the control as something it is not.
 *
 * So: real `<label>`/`<input type="checkbox">` pairs, laid out with CSS grid, wrapped by the
 * caller's `<fieldset>`/`<legend>` or `role="group"`. The header strip is `aria-hidden` — it repeats
 * information every control already conveys (the name is the label, "visible" is the checked state),
 * so to assistive technology it is decoration and to everyone else it is the alignment cue the
 * layout needs.
 *
 * ## Two columns, because the third would have said one thing thirteen times
 *
 * An earlier revision carried a per-row `Origem` cell. It was dropped: the origin is a property of
 * the *selection*, not of a column — a preference is stored and resolved as one array — so the value
 * was identical on every row by construction. A column that repeats itself works against the very
 * regularity this grid exists to provide, and it made a screen reader recite the same phrase once
 * per checkbox. {@link ColumnPicker} now states it once, as the group's accessible description.
 *
 * Presentational only: visibility and persistence live outside. The per-column labels are passed in
 * (they belong to the table), while the grid's own two headers are read from the module this feature
 * owns, since they are identical at every call site.
 */
import { useId, type ReactNode } from 'react';
import { useTableColumnsT } from '../../i18n/tableColumnsFallback';

export function ColumnToggleGrid<C extends string>({
  columns,
  isVisible,
  onToggle,
  columnLabel,
  ariaLabel,
}: {
  /**
   * The toggleable columns, in order. Only `data` columns belong here: a table's controls are not
   * offered, and its structural columns are always shown. Build this with `dataColumns(entry)` —
   * a control id is not even a member of the type a caller can pass it through.
   */
  columns: readonly C[];
  isVisible: (column: C) => boolean;
  onToggle: (column: C, checked: boolean) => void;
  columnLabel: (column: C) => ReactNode;
  /** Names the grid as a group. Omit when the caller already names it (a `<fieldset>`/`<legend>`). */
  ariaLabel?: string;
}) {
  const ct = useTableColumnsT();
  const id = useId();

  return (
    <div
      className="column-picker__grid"
      role={ariaLabel === undefined ? undefined : 'group'}
      aria-label={ariaLabel}
    >
      <div className="column-picker__head" aria-hidden="true">
        <span className="column-picker__cell">{ct('tableColumns.head.column')}</span>
        <span className="column-picker__cell column-picker__cell--center">
          {ct('tableColumns.head.visible')}
        </span>
      </div>
      {columns.map((column) => {
        const inputId = `${id}${column}`;
        return (
          <div key={column} className="column-picker__row">
            <label className="column-picker__cell column-picker__name" htmlFor={inputId}>
              {columnLabel(column)}
            </label>
            <span className="column-picker__cell column-picker__cell--center">
              <input
                id={inputId}
                type="checkbox"
                checked={isVisible(column)}
                onChange={(event) => onToggle(column, event.target.checked)}
              />
            </span>
          </div>
        );
      })}
    </div>
  );
}
