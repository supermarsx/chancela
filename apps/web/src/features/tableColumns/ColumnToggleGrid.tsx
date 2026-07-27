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
 * information every control already conveys (the name is the label, "visible" is the checked state,
 * the origin is the control's description), so to assistive technology it is decoration and to
 * everyone else it is the alignment cue the layout needs.
 *
 * The `Origem` column is wired as each checkbox's `aria-describedby`, which places it after the
 * name, role and state in the announcement — "Nome, caixa de verificação, marcada, Pessoal" — rather
 * than swallowing it into the accessible name.
 *
 * Presentational only: visibility, persistence and the origin derivation all live outside. The
 * per-column labels are still passed in (they belong to the table), while the grid's own chrome —
 * the three headers and the three origin values — is read from the module this feature owns, since
 * it is identical at every call site and duplicating it across them would be nothing but drift.
 */
import { useId, type ReactNode } from 'react';
import { useTableColumnsT, type TableColumnsCopyKey } from '../../i18n/tableColumnsFallback';
import type { ColumnOrigin } from './columnOrigin';

const ORIGIN_KEYS: Record<ColumnOrigin, TableColumnsCopyKey> = {
  personal: 'tableColumns.origin.personal',
  org: 'tableColumns.origin.org',
  product: 'tableColumns.origin.product',
};

export function ColumnToggleGrid<C extends string>({
  columns,
  isVisible,
  onToggle,
  columnLabel,
  origin,
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
  /**
   * Where the current selection comes from. Omitted on a surface that *is* the source — the org
   * default card would otherwise state its own name back to the administrator on every row.
   */
  origin?: ColumnOrigin;
  /** Names the grid as a group. Omit when the caller already names it (a `<fieldset>`/`<legend>`). */
  ariaLabel?: string;
}) {
  const ct = useTableColumnsT();
  const id = useId();
  const showOrigin = origin !== undefined;

  return (
    <div
      className={showOrigin ? 'column-picker__grid column-picker__grid--origin' : 'column-picker__grid'}
      role={ariaLabel === undefined ? undefined : 'group'}
      aria-label={ariaLabel}
    >
      <div className="column-picker__head" aria-hidden="true">
        <span className="column-picker__cell">{ct('tableColumns.head.column')}</span>
        <span className="column-picker__cell column-picker__cell--center">
          {ct('tableColumns.head.visible')}
        </span>
        {showOrigin ? (
          <span className="column-picker__cell column-picker__cell--origin">
            {ct('tableColumns.head.origin')}
          </span>
        ) : null}
      </div>
      {columns.map((column) => {
        const inputId = `${id}${column}`;
        const originId = `${inputId}-origin`;
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
                aria-describedby={showOrigin ? originId : undefined}
                onChange={(event) => onToggle(column, event.target.checked)}
              />
            </span>
            {origin === undefined ? null : (
              <span
                id={originId}
                className="column-picker__cell column-picker__cell--origin column-picker__origin"
              >
                {ct(ORIGIN_KEYS[origin])}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}
