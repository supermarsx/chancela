/**
 * Which columns the Minutas catalog table shows — a DEVICE-LOCAL operator preference.
 *
 * The registered-entities list solves the same problem with a server setting
 * (`settings.ui.registered_entity_columns`), but that field is part of the settings contract
 * and there is no template equivalent on the API. Rather than invent one from the web app,
 * this preference lives in `localStorage`: the catalog is read-only browsing, so a per-device
 * choice loses nothing if it does not follow the operator to another machine. If a
 * `registered_template_columns` settings field ever lands, this module is the single place
 * that has to change.
 *
 * `Name` and `Actions` are not listed: the first is the row's label and the second its
 * controls, so neither is ever hideable.
 *
 * `LawSource` ("Fonte legal") is OFF by default. It is the widest cell in the table by far —
 * a badge, a citation, a source line and sometimes a pending note, per reference — and it
 * pushed the other eight columns into unreadable slivers. It is not dropped: the toggle
 * brings it back, and the template's detail page shows it in full either way.
 */

/** A catalog column the operator may show or hide, in table order. */
export const TEMPLATE_COLUMNS = [
  'Family',
  'Stage',
  'Channels',
  'Signature',
  'RulePack',
  'LawSource',
  'Origin',
] as const;

export type TemplateColumn = (typeof TEMPLATE_COLUMNS)[number];

/** The default set: everything except the law source (see the module note). */
export const DEFAULT_TEMPLATE_COLUMNS: readonly TemplateColumn[] = TEMPLATE_COLUMNS.filter(
  (column) => column !== 'LawSource',
);

const STORAGE_KEY = 'chancela.minutas.columns';

const isTemplateColumn = (value: unknown): value is TemplateColumn =>
  typeof value === 'string' && (TEMPLATE_COLUMNS as readonly string[]).includes(value);

/**
 * Canonicalize a stored or in-flight selection: unknown ids dropped, duplicates collapsed,
 * order forced back to the table's own. An empty selection is legitimate (every optional
 * column hidden) — only a non-array falls back to the defaults.
 */
export function normalizeTemplateColumns(value: unknown): TemplateColumn[] {
  if (!Array.isArray(value)) return [...DEFAULT_TEMPLATE_COLUMNS];
  const picked = new Set(value.filter(isTemplateColumn));
  return TEMPLATE_COLUMNS.filter((column) => picked.has(column));
}

/** The stored selection, or the defaults when storage is empty, unreadable or corrupt. */
export function loadTemplateColumns(): TemplateColumn[] {
  let raw: string | null;
  try {
    raw = window.localStorage.getItem(STORAGE_KEY);
  } catch {
    return [...DEFAULT_TEMPLATE_COLUMNS];
  }
  if (raw === null) return [...DEFAULT_TEMPLATE_COLUMNS];
  try {
    return normalizeTemplateColumns(JSON.parse(raw));
  } catch {
    return [...DEFAULT_TEMPLATE_COLUMNS];
  }
}

/** Persist the selection. A browser with storage disabled degrades to "this session only". */
export function saveTemplateColumns(columns: readonly TemplateColumn[]): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(columns));
  } catch {
    /* private mode / quota: the in-memory selection still applies */
  }
}
