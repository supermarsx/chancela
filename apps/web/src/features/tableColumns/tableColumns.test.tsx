/**
 * The shared configurable-table mechanism (t37): `useTableColumns` (resolve → canonicalize →
 * persist) and the presentational `<ColumnPicker>`. Exercised over a books-shaped spec against a
 * stateful `/v1/me/preferences` stub, the same store the three tables use.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { ColumnPicker } from './ColumnPicker';
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
