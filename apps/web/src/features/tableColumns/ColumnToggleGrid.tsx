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
 * Presentational only: visibility and persistence live outside. The per-row labels are passed in
 * (they belong to the table), while the grid's own two headers default to the module this feature
 * owns, since they are identical at every *column* call site.
 *
 * ## Not only columns (t54 §6.5)
 *
 * The layout — "a list of named things, each with one checkbox, all lining up" — is not specific to
 * table columns, and the entity-type allowlist card in Configurações is the same control at a
 * different scope. It reuses this grid rather than cloning it, which is why `headers`, `showHead`
 * and `note` exist:
 *
 * - `headers` — a grid of legal types is not a grid of columns, and labelling its tracks
 *   "Coluna / Visível" would be copy that is simply untrue. The default stays the column wording,
 *   so no existing call site changes.
 * - `showHead` — lets a caller stack several grids under ONE header strip (the entity types are
 *   grouped by family). Repeating the strip five times would be five times the noise for the same
 *   two words.
 * - `note` — a per-row aside beside the name (e.g. how many records already carry that type). It
 *   lives inside the row's `<label>` so the grid stays two tracks at every width; a third track
 *   would reintroduce exactly the misalignment this component exists to remove.
 */
import { useId, type ReactNode } from 'react';
import { useTableColumnsT } from '../../i18n/tableColumnsFallback';

export function ColumnToggleGrid<C extends string>({
  columns,
  isVisible,
  onToggle,
  columnLabel,
  ariaLabel,
  headers,
  showHead = true,
  note,
  isDisabled,
}: {
  /**
   * The toggleable rows, in order. For a table's columns only `data` columns belong here: its
   * controls are not offered, and its structural columns are always shown. Build that with
   * `dataColumns(entry)` — a control id is not even a member of the type a caller can pass it
   * through.
   */
  columns: readonly C[];
  isVisible: (column: C) => boolean;
  onToggle: (column: C, checked: boolean) => void;
  columnLabel: (column: C) => ReactNode;
  /** Names the grid as a group. Omit when the caller already names it (a `<fieldset>`/`<legend>`). */
  ariaLabel?: string;
  /** Overrides the two header words. Defaults to the column-picker wording. */
  headers?: { name: ReactNode; toggle: ReactNode };
  /** Draw the header strip. Set false on all but the first of a stack of grouped grids. */
  showHead?: boolean;
  /** A per-row aside rendered after the name (a count, a state). */
  note?: (column: C) => ReactNode;
  /**
   * Refuse a row's checkbox, with the reason. A disabled checkbox is only honest when the caller
   * says why somewhere the operator can read; the callers that use it render that sentence beside
   * the grid.
   */
  isDisabled?: (column: C) => boolean;
}) {
  const ct = useTableColumnsT();
  const id = useId();

  return (
    <div
      className="column-picker__grid"
      role={ariaLabel === undefined ? undefined : 'group'}
      aria-label={ariaLabel}
    >
      {showHead ? (
        <div className="column-picker__head" aria-hidden="true">
          <span className="column-picker__cell">
            {headers?.name ?? ct('tableColumns.head.column')}
          </span>
          <span className="column-picker__cell column-picker__cell--center">
            {headers?.toggle ?? ct('tableColumns.head.visible')}
          </span>
        </div>
      ) : null}
      {columns.map((column) => {
        const inputId = `${id}${column}`;
        return (
          <div key={column} className="column-picker__row">
            <label className="column-picker__cell column-picker__name" htmlFor={inputId}>
              {columnLabel(column)}
              {note ? note(column) : null}
            </label>
            <span className="column-picker__cell column-picker__cell--center">
              <input
                id={inputId}
                type="checkbox"
                checked={isVisible(column)}
                disabled={isDisabled ? isDisabled(column) : undefined}
                onChange={(event) => onToggle(column, event.target.checked)}
              />
            </span>
          </div>
        );
      })}
    </div>
  );
}
