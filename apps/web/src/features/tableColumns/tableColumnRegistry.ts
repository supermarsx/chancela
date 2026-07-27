/**
 * The single declarative source of truth for a table's column model (t54).
 *
 * Before this module the answer to "what are this table's columns, and which of them show by
 * default?" was spread across `api/types.ts` (`REGISTERED_ENTITY_COLUMNS`, `BOOK_COLUMNS`),
 * `features/templates/templateColumns.ts` and a per-page `*_HIDEABLE_COLUMNS` filter that each
 * restated the same rule. A table declares itself here once; every consumer — the picker, the
 * persistence hook, the page's render order — is derived from that one declaration.
 *
 * ## Three roles, not two
 *
 * | role | what it is | offered in the picker? | may appear in the stored preference? |
 * |---|---|---|---|
 * | `control` | a UI *affordance*, not a datum: the row-actions cell, a bulk-selection checkbox | never | **never** |
 * | `structural` | identity-bearing **data** without which a row cannot be identified: `Name`, `Number`, `Seq` | no | yes, force-kept |
 * | `data` | everything else | yes | yes |
 *
 * `hideable` is **derived** (`role === 'data'`), which is what retires the two hand-maintained
 * `.filter()`s the pages used to carry.
 *
 * ### Why `control` is a role rather than a flag on `structural`
 *
 * The shipped code labelled `Actions` *structural*. That is wrong in kind — `Actions` renders
 * controls, not a fact about the row — and the mislabel would have compounded the moment a second
 * control column (bulk selection) arrived under the same name, leaving "structural" meaning two
 * different things.
 *
 * The separation also buys a guarantee that force-keeping could not: **a control column is not
 * representable in the preference payload at all.** {@link storableColumns} omits control ids, and
 * {@link StorableColumnOf} omits them from the type the persistence hook is instantiated with, so
 * `useTableColumns` never sees one — it cannot toggle one, cannot canonicalize one, and cannot
 * write one. No stored document, stale or hostile, can suppress a control: the page renders control
 * columns from the declaration ({@link renderedColumns}), not from the stored preference. An
 * operator can therefore never lose sight of what a row's controls are, or of what is selected.
 *
 * ## What is NOT declared here
 *
 * The per-instance narrowing of *which entity types exist* is a different axis with a different
 * scope (instance, not user), a different store (the settings document) and a different authority
 * (`settings.manage`). It is deliberately not modelled here — column visibility is disposable
 * presentation state that is never ledgered, and an administrative narrowing of the domain must be.
 * One mechanism cannot be both; do not merge them.
 */
import {
  BOOK_COLUMNS,
  REGISTERED_ENTITY_COLUMNS,
  type BookColumn,
  type RegisteredEntityColumn,
  type TableColumnPreferences,
} from '../../api/types';
import { TEMPLATE_COLUMNS, type TemplateColumn } from '../templates/templateColumns';
import type { TableColumnsSpec } from './useTableColumns';

/** See the module note: `control` is an affordance, `structural` is identity, `data` is the rest. */
export type ColumnRole = 'control' | 'structural' | 'data';

export interface TableColumnDef<Id extends string = string> {
  readonly id: Id;
  readonly role: ColumnRole;
}

/**
 * A settings field an instance administrator may use to override the product default for a table.
 * Only `entities` has one: it alone spans 5→14 columns, so it alone benefits. Declared as a field
 * so another table can opt in later without inventing a second mechanism.
 */
export type OrgDefaultSource = 'settings.ui.registered_entity_columns';

interface TableColumnModelBase<Id extends string> {
  /** Every column, in canonical render order — control, structural and data alike. */
  readonly columns: readonly TableColumnDef<Id>[];
  /** The visible set when nothing overrides it. Storable ids only; a control id is meaningless. */
  readonly productDefault: readonly Id[];
}

/** A table that mounts a column picker and persists a per-user choice. */
export interface ConfigurableTable<Id extends string = string> extends TableColumnModelBase<Id> {
  readonly mode: 'configurable';
  /** The `table_columns` key this table persists under. */
  readonly table: keyof TableColumnPreferences;
  readonly orgDefaultSource?: OrgDefaultSource;
}

/**
 * A table whose default is "every column, always": a diagnostic readout, a detail surface or a
 * generated compliance record, none of which the operator gets to narrow. It has a declared model
 * so the registry can answer the defaults question for it, but no picker and no stored preference.
 */
export interface FixedTable<Id extends string = string> extends TableColumnModelBase<Id> {
  readonly mode: 'fixed';
  /** A registry key. NOT a `table_columns` key — a fixed table persists nothing. */
  readonly table: string;
}

export type TableColumnModel<Id extends string = string> = ConfigurableTable<Id> | FixedTable<Id>;

type ColumnDefsOf<E extends TableColumnModel> = E['columns'][number];

/** Every declared column id, control included — the page's render vocabulary. */
export type ColumnOf<E extends TableColumnModel> = ColumnDefsOf<E>['id'];

/**
 * The ids a preference payload may contain. Control ids are absent **from the type**, which is what
 * makes them unwritable rather than merely force-kept (see the module note).
 */
export type StorableColumnOf<E extends TableColumnModel> = Extract<
  ColumnDefsOf<E>,
  { role: 'structural' | 'data' }
>['id'];

/** The ids the picker offers as checkboxes. */
export type DataColumnOf<E extends TableColumnModel> = Extract<
  ColumnDefsOf<E>,
  { role: 'data' }
>['id'];

/**
 * The storage-only sentinel prepended to the persisted array of a table that declares **no**
 * `structural` column. Such a table can have every one of its columns hidden, which would persist
 * as `[]` — and the server folds `[]` to "no override", silently discarding a deliberate choice.
 * The sentinel keeps the array non-empty. It is not a column: it is stripped on read like any
 * unknown id, and {@link assertTableColumnRegistry} refuses a model that declares it as one.
 *
 * A table with a structural column needs none — its structural ids are always present.
 */
export const PREFERENCE_ANCHOR = 'Override';

function idsWithRole<E extends TableColumnModel>(entry: E, ...roles: ColumnRole[]): string[] {
  return entry.columns.filter((column) => roles.includes(column.role)).map((column) => column.id);
}

/** Every column id in canonical render order. */
export function allColumns<E extends TableColumnModel>(entry: E): ColumnOf<E>[] {
  return entry.columns.map((column) => column.id) as ColumnOf<E>[];
}

export function columnRole<E extends TableColumnModel>(
  entry: E,
  id: ColumnOf<E>,
): ColumnRole | undefined {
  return entry.columns.find((column) => column.id === id)?.role;
}

/** The affordance columns: never offered, never stored, always rendered. */
export function controlColumns<E extends TableColumnModel>(entry: E): ColumnOf<E>[] {
  return idsWithRole(entry, 'control') as ColumnOf<E>[];
}

/** The identity-bearing columns: not offered, but stored and force-kept. */
export function structuralColumns<E extends TableColumnModel>(entry: E): StorableColumnOf<E>[] {
  return idsWithRole(entry, 'structural') as StorableColumnOf<E>[];
}

/** The toggleable columns — `hideable`, derived rather than hand-maintained. */
export function dataColumns<E extends TableColumnModel>(entry: E): DataColumnOf<E>[] {
  return idsWithRole(entry, 'data') as DataColumnOf<E>[];
}

/** The ids a stored preference may carry: structural + data, in canonical order. */
export function storableColumns<E extends TableColumnModel>(entry: E): StorableColumnOf<E>[] {
  return idsWithRole(entry, 'structural', 'data') as StorableColumnOf<E>[];
}

/** Whether the picker offers this column. Derived from the role; never restated by a caller. */
export function isHideable<E extends TableColumnModel>(entry: E, id: ColumnOf<E>): boolean {
  return columnRole(entry, id) === 'data';
}

/**
 * The page's render order: the resolved visible storable columns, with every control column woven
 * back into its declared position. Controls come from the declaration, so a stored preference has
 * no say over whether they appear — only over which data columns sit between them.
 */
export function renderedColumns<E extends TableColumnModel>(
  entry: E,
  visible: readonly StorableColumnOf<E>[],
): ColumnOf<E>[] {
  const shown = new Set<string>(visible);
  return entry.columns
    .filter((column) => column.role === 'control' || shown.has(column.id))
    .map((column) => column.id) as ColumnOf<E>[];
}

/**
 * Narrow an arbitrary id list (an org default, a legacy device-local value) to this table's
 * storable columns, in canonical order. Unknown ids and control ids are dropped: an org default
 * that names `Actions` is stating something the payload cannot express, and saying so is inert
 * rather than an error.
 */
export function toStorableColumns<E extends TableColumnModel>(
  entry: E,
  ids: readonly string[],
): StorableColumnOf<E>[] {
  const wanted = new Set(ids);
  return storableColumns(entry).filter((id) => wanted.has(id));
}

/**
 * The spec `useTableColumns` runs on. This is the only supported way to build one for a real
 * table: it is where `hideable` stops being hand-written, and where control ids stop existing.
 *
 * `fallback` accepts opaque ids so a caller can hand over an org default straight from the
 * settings document; it is narrowed to the storable set here.
 */
export function tableColumnsSpec<E extends ConfigurableTable>(
  entry: E,
  options: { fallback?: readonly string[] } = {},
): TableColumnsSpec<StorableColumnOf<E>> {
  const fallback = toStorableColumns(entry, options.fallback ?? entry.productDefault);
  const spec: TableColumnsSpec<StorableColumnOf<E>> = {
    table: entry.table,
    columns: storableColumns(entry),
    hideable: dataColumns(entry) as StorableColumnOf<E>[],
    fallback,
  };
  // Only a table with nothing force-kept can persist an empty array; only it needs the sentinel.
  return structuralColumns(entry).length === 0 ? { ...spec, anchor: PREFERENCE_ANCHOR } : spec;
}

/* ------------------------------------------------------------------------------------------- *
 * The declarations.
 * ------------------------------------------------------------------------------------------- */

/**
 * Registered entities. Fourteen columns, of which thirteen are data — the widest table in the app
 * and the only one with an org-level default (`settings.ui.registered_entity_columns`), because it
 * is the only one whose useful width varies that far by deployment.
 *
 * `Actions` was declared *structural* before t54. It is a `control`: it renders the row's open
 * button, not a fact about the entity.
 */
export const ENTITIES_TABLE = {
  table: 'entities',
  mode: 'configurable',
  orgDefaultSource: 'settings.ui.registered_entity_columns',
  columns: [
    { id: 'Name', role: 'data' },
    { id: 'Nipc', role: 'data' },
    { id: 'Seat', role: 'data' },
    { id: 'Type', role: 'data' },
    { id: 'Matricula', role: 'data' },
    { id: 'Constitution', role: 'data' },
    { id: 'Capital', role: 'data' },
    { id: 'Cae', role: 'data' },
    { id: 'Registry', role: 'data' },
    { id: 'LastRegistryChange', role: 'data' },
    { id: 'FiscalYearEnd', role: 'data' },
    { id: 'LastBook', role: 'data' },
    { id: 'LastActivity', role: 'data' },
    { id: 'Actions', role: 'control' },
  ],
  // The product default behind the org default. `Actions` is not listed: it is a control, so it is
  // shown unconditionally and cannot be part of a default *set*.
  productDefault: ['Name', 'Nipc', 'Type', 'LastActivity'],
} as const satisfies ConfigurableTable<RegisteredEntityColumn>;

/**
 * Livros. Every column shows by default; `Entity` is absent because the all-books list governs it
 * by page context, not by a per-user toggle.
 */
export const BOOKS_TABLE = {
  table: 'books',
  mode: 'configurable',
  columns: [
    { id: 'Kind', role: 'data' },
    { id: 'Purpose', role: 'data' },
    { id: 'State', role: 'data' },
    { id: 'Opening', role: 'data' },
    { id: 'LastAct', role: 'data' },
    { id: 'Actions', role: 'control' },
  ],
  productDefault: ['Kind', 'Purpose', 'State', 'Opening', 'LastAct'],
} as const satisfies ConfigurableTable<BookColumn>;

/** The catalog's full column vocabulary, including the two the table renders for itself. */
export type TemplatesTableColumn = 'Name' | TemplateColumn | 'Actions';

/**
 * Minutas. `Name` is the row's label — identity-bearing data, hence `structural`; `Actions` is a
 * control. Declaring both retires the `anchor` this table used to need: `Name` is force-kept, so a
 * "hide every optional column" choice already persists as a non-empty array.
 *
 * `LawSource` is off by default — it is by far the widest cell (badge, citation, source line and
 * sometimes a pending note) and it crushed the other columns into slivers. Hidden, never dropped:
 * the toggle brings it back and the template's own page shows it either way.
 */
export const TEMPLATES_TABLE = {
  table: 'templates',
  mode: 'configurable',
  columns: [
    { id: 'Name', role: 'structural' },
    { id: 'Family', role: 'data' },
    { id: 'Stage', role: 'data' },
    { id: 'Channels', role: 'data' },
    { id: 'Signature', role: 'data' },
    { id: 'RulePack', role: 'data' },
    { id: 'LawSource', role: 'data' },
    { id: 'Origin', role: 'data' },
    { id: 'Actions', role: 'control' },
  ],
  productDefault: ['Name', 'Family', 'Stage', 'Channels', 'Signature', 'RulePack', 'Origin'],
} as const satisfies ConfigurableTable<TemplatesTableColumn>;

/**
 * Every table with a declared column model. A table joins this map when it is wired, so that a
 * lookup here is always a lookup of something real.
 */
export const TABLE_COLUMN_REGISTRY = {
  entities: ENTITIES_TABLE,
  books: BOOKS_TABLE,
  templates: TEMPLATES_TABLE,
} as const;

/**
 * The registry's own invariants, asserted from the tests rather than at module load so a
 * declaration mistake fails a build rather than a user's page.
 *
 * The render-order cross-checks are the anti-drift guard: they tie each declaration to the array
 * the rest of the app already types itself against, so adding a column in `api/types.ts` without
 * declaring its role here is a test failure rather than a column that silently stops rendering.
 */
export function assertTableColumnRegistry(): void {
  for (const entry of Object.values(TABLE_COLUMN_REGISTRY) as TableColumnModel[]) {
    const ids = allColumns(entry);
    const label = `table "${entry.table}"`;
    if (ids.length === 0) throw new Error(`${label}: declares no columns`);
    if (new Set(ids).size !== ids.length) throw new Error(`${label}: duplicate column id`);
    if (ids.includes(PREFERENCE_ANCHOR)) {
      throw new Error(`${label}: "${PREFERENCE_ANCHOR}" is the storage sentinel, not a column id`);
    }
    const storable = new Set<string>(storableColumns(entry));
    for (const id of entry.productDefault) {
      if (!storable.has(id)) {
        throw new Error(`${label}: productDefault names "${id}", which is not storable`);
      }
    }
    if (entry.mode === 'configurable' && dataColumns(entry).length === 0) {
      throw new Error(`${label}: configurable but offers no toggleable column`);
    }
  }

  const expected: [string, readonly string[]][] = [
    ['entities', REGISTERED_ENTITY_COLUMNS],
    ['books', BOOK_COLUMNS],
    ['templates', ['Name', ...TEMPLATE_COLUMNS, 'Actions']],
  ];
  const declared = new Map<string, string[]>([
    ['entities', allColumns(ENTITIES_TABLE)],
    ['books', allColumns(BOOKS_TABLE)],
    ['templates', allColumns(TEMPLATES_TABLE)],
  ]);
  for (const [table, order] of expected) {
    const actual = declared.get(table) ?? [];
    if (actual.join(',') !== order.join(',')) {
      throw new Error(
        `table "${table}": declared order ${actual.join(',')} does not match ${order.join(',')}`,
      );
    }
  }
}
