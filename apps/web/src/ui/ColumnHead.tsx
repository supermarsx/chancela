/**
 * `ColumnHead` — a table column header that carries its own explanation (t101).
 *
 * Trust-list, timestamping and signing grids name their columns with terms an operator cannot
 * infer ("Esquema", "Limites", "Política aceite", "Identidade digital"), so the header needs a
 * place to say what the field *means operationally*. This is that place, and it is deliberately
 * built on {@link FieldHelp} — the quiet `Icon.Info` trigger already used beside form labels —
 * rather than a second, table-only help system.
 *
 * Why `FieldHelp` and not a bare `Tooltip`/`TooltipText`:
 *
 * - it renders a real `<button>`, so the indicator is a **tab stop**; a tooltip only a mouse can
 *   reach is decoration. `TooltipText` would have been wrong here — its focusability is driven by
 *   CSS clipping, and a column header is not clipped, so it would render bare;
 * - the sentence reaches assistive tech through the shared `Tooltip`'s generated
 *   `aria-describedby`, whose bubble stays mounted (visibility is CSS-toggled), so the association
 *   never dangles and Escape dismisses it;
 * - `FieldHelp` separates the trigger's accessible NAME from its DESCRIPTION, which is what lets
 *   the name carry the column.
 *
 * ## Why the `<th>` gets an explicit `aria-label`
 *
 * A screen reader re-announces the column header on **every cell** it moves through. Without the
 * label the computed header name would be the column text PLUS the button's — "Estado, Ajuda sobre
 * a coluna Estado" on every row of every column. `aria-label` names the columnheader only; the
 * button remains a separate focusable node in the accessibility tree with its own name and its own
 * description, so nothing is lost, it is just no longer recited per cell.
 *
 * ## Why the separator is a non-breaking space
 *
 * Load-bearing, not typographic fussiness. With an ordinary space the narrowest header — an
 * intrinsically-sized "Ações" column of about 59px — breaks between the word and the glyph,
 * stranding the glyph on a second line and making the whole header band of a seven-column grid
 * 53px instead of 34px. Pinning them together costs ~18px of intrinsic table width, absorbed by
 * slack at every width `.wide-page` covers (measured: identical table widths, no scroll, at
 * 1280 / 1440 / 1920).
 *
 * No CSS of its own: `.field-help-wrap` is `inline-flex`, so the glyph flows after the header text
 * exactly as it does after a `<Toggle>` label, and `.table th` sets neither `white-space: nowrap`
 * nor a width — the header keeps wrapping at its natural min-content.
 */
import { useT } from '../i18n';
import { FieldHelp } from './FieldHelp';
import type { TooltipPlacement } from './Tooltip';

interface ColumnHeadProps {
  /** The visible column name. Also the `<th>`'s accessible name, on its own. */
  label: string;
  /** The explanation, already `t()`-translated. Say what the field MEANS, not what it is called. */
  help: string;
  /** Where the bubble sits. Default `top`; pass `bottom` for a header near the top of a scroller. */
  placement?: TooltipPlacement;
}

export function ColumnHead({ label, help, placement }: ColumnHeadProps) {
  const t = useT();
  return (
    <th aria-label={label}>
      {label}
      {'\u00a0'}
      <FieldHelp
        text={help}
        placement={placement}
        label={t('common.columnHelp', { column: label })}
      />
    </th>
  );
}
