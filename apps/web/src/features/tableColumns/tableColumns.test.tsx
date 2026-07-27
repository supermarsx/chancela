/**
 * The shared configurable-table mechanism (t37): `useTableColumns` (resolve → canonicalize →
 * persist) and the presentational `<ColumnPicker>`. Exercised over a books-shaped spec against a
 * stateful `/v1/me/preferences` stub, the same store the three tables use.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { ColumnPicker } from './ColumnPicker';
import {
  BOOKS_TABLE,
  ENTITIES_TABLE,
  PREFERENCE_ANCHOR,
  TEMPLATES_TABLE,
  allColumns,
  assertTableColumnRegistry,
  controlColumns,
  dataColumns,
  renderedColumns,
  storableColumns,
  structuralColumns,
  tableColumnsSpec,
  type ConfigurableTable,
  type StorableColumnOf,
} from './tableColumnRegistry';
import { useTableColumns, type TableColumnsSpec } from './useTableColumns';

type Col = 'Kind' | 'Purpose' | 'State' | 'Opening' | 'LastAct' | 'Actions';

const SPEC: TableColumnsSpec<Col> = {
  table: 'books',
  columns: ['Kind', 'Purpose', 'State', 'Opening', 'LastAct', 'Actions'],
  hideable: ['Kind', 'Purpose', 'State', 'Opening', 'LastAct'],
  fallback: ['Kind', 'Purpose', 'State', 'Opening', 'LastAct', 'Actions'],
};

interface RecordedRequest {
  url: string;
  method: string;
  body?: string;
}

/** A stateful `/v1/me/preferences` stub, recording every request for the persistence assertions. */
function preferencesFetch(initial: unknown = { table_columns: {} }) {
  const calls: RecordedRequest[] = [];
  let stored = initial;
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    calls.push({ url, method, body: init?.body ? String(init.body) : undefined });
    if (url.includes('/v1/me/preferences')) {
      if (method === 'PUT') stored = JSON.parse(String(init?.body ?? '{}'));
      return Promise.resolve(
        new Response(JSON.stringify(stored), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }
    return Promise.reject(new Error(`no stub for ${method} ${url}`));
  }) as typeof fetch;
  return { fn, calls };
}

function Probe({ spec }: { spec: TableColumnsSpec<Col> }) {
  const columns = useTableColumns(spec);
  return (
    <div>
      <span data-testid="visible">{columns.visible.join(',')}</span>
      <span data-testid="overridden">{String(columns.overridden)}</span>
      <ColumnPicker
        columns={spec.hideable}
        label="Colunas"
        isVisible={columns.isVisible}
        onToggle={columns.toggle}
        columnLabel={(column) => column}
      />
    </div>
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('useTableColumns', () => {
  it('falls back to the product default when the user has no override', async () => {
    vi.stubGlobal('fetch', preferencesFetch().fn);
    renderWithProviders(<Probe spec={SPEC} />);
    await waitFor(() =>
      expect(screen.getByTestId('visible').textContent).toBe(
        'Kind,Purpose,State,Opening,LastAct,Actions',
      ),
    );
    expect(screen.getByTestId('overridden').textContent).toBe('false');
  });

  it('canonicalizes a stored override: drops unknown ids, force-keeps Actions, normalizes order', async () => {
    // Out of order, with a bogus id and no Actions — the resolver repairs all three.
    vi.stubGlobal(
      'fetch',
      preferencesFetch({ table_columns: { books: ['State', 'Bogus', 'Kind'] } }).fn,
    );
    renderWithProviders(<Probe spec={SPEC} />);
    await waitFor(() =>
      expect(screen.getByTestId('visible').textContent).toBe('Kind,State,Actions'),
    );
    expect(screen.getByTestId('overridden').textContent).toBe('true');
  });

  it('persists a toggle as the whole visible set, always keeping the structural Actions column', async () => {
    const stub = preferencesFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<Probe spec={SPEC} />);

    await waitFor(() => expect(screen.getByTestId('overridden').textContent).toBe('false'));
    // Hide "Purpose".
    fireEvent.click(screen.getByLabelText('Purpose'));

    await waitFor(() =>
      expect(screen.getByTestId('visible').textContent).toBe('Kind,State,Opening,LastAct,Actions'),
    );
    const put = stub.calls.find((call) => call.method === 'PUT');
    expect(put).toBeTruthy();
    expect(JSON.parse(put?.body ?? '{}')).toEqual({
      table_columns: { books: ['Kind', 'State', 'Opening', 'LastAct', 'Actions'] },
    });
  });
});

describe('ColumnPicker', () => {
  it('reflects visibility and reports a toggle', () => {
    const onToggle = vi.fn();
    renderWithProviders(
      <ColumnPicker
        columns={['Kind', 'Purpose', 'State'] as Col[]}
        label="Colunas"
        hint="Escolha as colunas"
        isVisible={(column) => column !== 'State'}
        onToggle={onToggle}
        columnLabel={(column) => column}
      />,
    );
    const kind = screen.getByLabelText('Kind') as HTMLInputElement;
    const state = screen.getByLabelText('State') as HTMLInputElement;
    expect(kind.checked).toBe(true);
    expect(state.checked).toBe(false);
    fireEvent.click(state);
    expect(onToggle).toHaveBeenCalledWith('State', true);
  });
});

/**
 * A table shaped like the one bulk selection lands on (t56): a control column FIRST, an
 * identity-bearing structural column, two data columns, and a trailing control. It exists to prove
 * the guarantee on a leading control, which none of the three shipped tables can exercise.
 *
 * It borrows the `books` preference key so the assertions run against a real key.
 */
const SELECTION_TABLE = {
  table: 'books',
  mode: 'configurable',
  columns: [
    { id: 'Select', role: 'control' },
    { id: 'Username', role: 'structural' },
    { id: 'State', role: 'data' },
    { id: 'Access', role: 'data' },
    { id: 'Actions', role: 'control' },
  ],
  productDefault: ['Username', 'State', 'Access'],
} as const satisfies ConfigurableTable;

type SelectionColumn = StorableColumnOf<typeof SELECTION_TABLE>;

/** Renders what the page would render: the resolved set with the controls woven back in. */
function SelectionProbe() {
  const columns = useTableColumns(tableColumnsSpec(SELECTION_TABLE));
  return (
    <div>
      <span data-testid="rendered">
        {renderedColumns(SELECTION_TABLE, columns.visible).join(',')}
      </span>
      <ColumnPicker
        columns={dataColumns(SELECTION_TABLE)}
        label="Colunas"
        isVisible={columns.isVisible}
        onToggle={columns.toggle}
        columnLabel={(column) => column}
      />
    </div>
  );
}

describe('tableColumnRegistry', () => {
  it('holds a consistent model for every declared table', () => {
    expect(() => assertTableColumnRegistry()).not.toThrow();
  });

  it('derives hideable from the role instead of restating it per page', () => {
    // `Actions` is a control on all three, so no picker offers it; templates additionally keeps
    // `Name` out of the picker because it is structural.
    expect(dataColumns(ENTITIES_TABLE)).not.toContain('Actions');
    expect(dataColumns(ENTITIES_TABLE)).toHaveLength(13);
    expect(dataColumns(BOOKS_TABLE)).toEqual(['Kind', 'Purpose', 'State', 'Opening', 'LastAct']);
    expect(dataColumns(TEMPLATES_TABLE)).not.toContain('Name');
    expect(dataColumns(TEMPLATES_TABLE)).not.toContain('Actions');
  });

  it('leaves control columns out of the storable set on every table', () => {
    for (const entry of [ENTITIES_TABLE, BOOKS_TABLE, TEMPLATES_TABLE]) {
      for (const control of controlColumns(entry)) {
        expect(storableColumns(entry)).not.toContain(control);
        expect(entry.productDefault).not.toContain(control);
        // Still rendered, though — a control is always shown, it is just never stored.
        expect(allColumns(entry)).toContain(control);
      }
    }
  });

  it('keeps control ids out of the storable column type', () => {
    // @ts-expect-error — `Select` is a control, so it is not a member of the storable union at
    // all. This is the compile-time half of the guarantee: the persistence hook is instantiated
    // over this type, so a control id cannot even be named in a payload.
    const rejected: SelectionColumn = 'Select';
    expect(rejected).toBe('Select');
  });

  it('anchors only the tables that declare no structural column', () => {
    // Entities and books are all data + a control, so hiding everything would persist as `[]`.
    expect(structuralColumns(ENTITIES_TABLE)).toEqual([]);
    expect(tableColumnsSpec(ENTITIES_TABLE).anchor).toBe(PREFERENCE_ANCHOR);
    expect(tableColumnsSpec(BOOKS_TABLE).anchor).toBe(PREFERENCE_ANCHOR);
    // Templates declares `Name` structural, which force-keeps the array non-empty by itself —
    // this is the `anchor` hack retiring.
    expect(structuralColumns(TEMPLATES_TABLE)).toEqual(['Name']);
    expect(tableColumnsSpec(TEMPLATES_TABLE).anchor).toBeUndefined();
  });

  it('narrows an org default to the storable set, dropping the inert control id', () => {
    // `settings.ui.registered_entity_columns` still lists `Actions`; saying so expresses nothing.
    const spec = tableColumnsSpec(ENTITIES_TABLE, {
      fallback: ['LastActivity', 'Actions', 'Name', 'Bogus'],
    });
    expect(spec.fallback).toEqual(['Name', 'LastActivity']);
  });
});

describe('control columns', () => {
  it('renders a control even when the stored preference names only one data column', async () => {
    vi.stubGlobal('fetch', preferencesFetch({ table_columns: { books: ['State'] } }).fn);
    renderWithProviders(<SelectionProbe />);
    // `Select` leads and `Actions` trails regardless of what the document says, and `Username`
    // is force-kept because it is structural.
    await waitFor(() =>
      expect(screen.getByTestId('rendered').textContent).toBe('Select,Username,State,Actions'),
    );
  });

  it('ignores a stored document that tries to speak about controls', async () => {
    // A stale or hostile payload naming the controls changes nothing: they are not in the
    // table's storable set, so they are dropped on read exactly like `Bogus`.
    vi.stubGlobal(
      'fetch',
      preferencesFetch({ table_columns: { books: ['Select', 'Actions', 'Bogus', 'Access'] } }).fn,
    );
    renderWithProviders(<SelectionProbe />);
    await waitFor(() =>
      expect(screen.getByTestId('rendered').textContent).toBe('Select,Username,Access,Actions'),
    );
  });

  it('never writes a control id back, even when every data column is hidden', async () => {
    const stub = preferencesFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<SelectionProbe />);

    await waitFor(() =>
      expect(screen.getByTestId('rendered').textContent).toBe(
        'Select,Username,State,Access,Actions',
      ),
    );
    fireEvent.click(screen.getByLabelText('State'));
    fireEvent.click(await screen.findByLabelText('Access'));

    await waitFor(() =>
      expect(screen.getByTestId('rendered').textContent).toBe('Select,Username,Actions'),
    );
    const puts = stub.calls.filter((call) => call.method === 'PUT');
    for (const put of puts) {
      expect(put.body).not.toContain('Select');
      expect(put.body).not.toContain('Actions');
    }
    // The structural column keeps the array non-empty, so "hide everything" survives a reload.
    expect(JSON.parse(puts.at(-1)?.body ?? '{}')).toEqual({
      table_columns: { books: ['Username'] },
    });
  });
});
