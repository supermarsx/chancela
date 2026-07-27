/**
 * Where a table's current column selection came from (t54).
 *
 * Until now the picker showed *what* is visible and said nothing about *why*: a user looking at a
 * narrow entities list could not tell whether they had chosen it, whether an administrator had, or
 * whether it was simply the shipped default — and therefore could not tell which knob would change
 * it. `useTableColumns` already knows whether a personal override exists; the remaining question is
 * which of the two inherited sources is in force when it does not.
 *
 * ## The three states
 *
 * | origin | meaning | who changes it |
 * |---|---|---|
 * | `personal` | the user has a stored preference for this table | the user, in this picker |
 * | `org` | no personal preference, and an administrator has moved the instance default away from the shipped one | an administrator, in Configurações |
 * | `product` | no personal preference, and nothing has moved the shipped default | nobody — it is what Chancela ships |
 *
 * ## Why `org` is an inequality and not "the settings field exists"
 *
 * Only `entities` has an org-level default, and its settings field is always populated — an instance
 * that has never been configured still serves `DEFAULT_SETTINGS.ui.registered_entity_columns`.
 * Reporting `org` whenever that field is present would tell every untouched deployment that its
 * administrator had made a choice, which is false and is exactly the kind of misstatement about
 * provenance this product does not make elsewhere. So `org` requires the effective fallback to
 * genuinely *differ* from the product default: it means "somebody decided this", which is the only
 * reading that helps a user work out who to ask.
 *
 * The origin is a property of the **selection**, not of an individual column: a preference is stored
 * and resolved as one array, so every column in a table shares one origin. The picker still shows it
 * per row because that is the aligned layout the user asked for, but it is derived once here.
 */
import {
  toStorableColumns,
  type ConfigurableTable,
  type StorableColumnOf,
} from './tableColumnRegistry';

export type ColumnOrigin = 'personal' | 'org' | 'product';

function sameOrder(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((id, index) => id === right[index]);
}

/**
 * Derive the origin of a table's current selection.
 *
 * `fallback` is the resolved fallback the page handed to `useTableColumns` — for entities the org
 * default, for every other table the product default. It is narrowed to the table's storable set
 * before comparison, so an org default that still lists a control id (`Actions`) compares equal to a
 * product default that never could: saying `Actions` expresses nothing, and an inert difference must
 * not be reported as an administrator's decision.
 */
export function resolveColumnOrigin<E extends ConfigurableTable>(
  entry: E,
  selection: { overridden: boolean; fallback: readonly StorableColumnOf<E>[] },
): ColumnOrigin {
  if (selection.overridden) return 'personal';
  if (entry.orgDefaultSource === undefined) return 'product';
  const declared = toStorableColumns(entry, entry.productDefault);
  return sameOrder(selection.fallback, declared) ? 'product' : 'org';
}
