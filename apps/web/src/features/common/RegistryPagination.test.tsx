import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_SETTINGS, type BookListItem, type Entity, type UserView } from '../../api/types';
import { collectionPageFixture, renderWithProviders } from '../../test/utils';
import { BooksPage } from '../books/BooksPage';
import { EntitiesPage } from '../entities/EntitiesPage';
import { UsersList } from '../users/UserListPage';

const BOOK: BookListItem = {
  id: 'book-0',
  entity_id: 'entity-0',
  entity_name: 'Entity 0',
  kind: 'AssembleiaGeral',
  state: 'Open',
  purpose: 'Minutes',
  numbering_scheme: 'Sequential',
  opening_date: '2026-01-01',
  closing_date: null,
  closing_reason: null,
  last_ata_number: 1,
  predecessor: null,
  required_signatories_abertura: null,
  required_signatories_encerramento: null,
};

const ENTITY: Entity = {
  id: 'entity-0',
  tenant_id: 'tenant-0',
  group_id: null,
  name: 'Entity 0',
  nipc: '500000000',
  nipc_validated: true,
  seat: 'Lisboa',
  family: 'CommercialCompany',
  kind: 'SociedadePorQuotas',
  profile: {
    family: 'CommercialCompany',
    rule_pack_id: 'company-default',
    allowed_channels: ['Physical'],
    signature_policy: 'QualifiedPreferred',
    template_family: 'company',
    calendar_presets: [],
    attendee_qualities: [],
  },
  statute: null,
  activity_summary: {
    last_book: BOOK,
    book_state_counts: { created: 0, open: 1, closed: 0 },
    last_change: null,
  },
  registry_summary: null,
};

const USER: UserView = {
  id: 'user-0',
  username: 'user.0',
  display_name: 'User 0',
  email: 'user.0@example.test',
  created_at: '2026-01-01T00:00:00Z',
  active: true,
  has_secret: true,
  has_attestation_key: false,
  has_recovery_phrase: false,
  has_totp: false,
  two_factor_required: false,
  language: 'auto',
  role_assignments: [],
};

function pageFetch() {
  const calls: string[] = [];
  const books = Array.from({ length: 75 }, (_, index) => ({
    ...BOOK,
    id: `book-${index}`,
    entity_id: `entity-${index}`,
    entity_name: `Entity ${index}`,
    purpose: `Minutes ${index}`,
  }));
  const entities = Array.from({ length: 75 }, (_, index) => ({
    ...ENTITY,
    id: `entity-${index}`,
    name: `Entity ${index}`,
  }));
  const users = Array.from({ length: 75 }, (_, index) => ({
    ...USER,
    id: `user-${index}`,
    username: `user.${index}`,
    display_name: `User ${index}`,
  }));
  const fn = vi.fn((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    calls.push(url);
    if (url.includes('/v1/settings')) return Promise.resolve(response(DEFAULT_SETTINGS));
    if (url.includes('/v1/roles')) return Promise.resolve(response([]));
    if (url.includes('/v1/books/page'))
      return Promise.resolve(response(collectionPageFixture(url, books)));
    if (url.includes('/v1/entities/page'))
      return Promise.resolve(response(collectionPageFixture(url, entities)));
    if (url.includes('/v1/users/page'))
      return Promise.resolve(response(collectionPageFixture(url, users)));
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as unknown as typeof fetch;
  return { fn, calls };
}

function cursorPageFetch() {
  const calls: string[] = [];
  const users = Array.from({ length: 75 }, (_, index) => ({
    ...USER,
    id: `user-${index}`,
    username: `user.${index}`,
    display_name: `User ${index}`,
  }));
  const fn = vi.fn((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    calls.push(url);
    if (url.includes('/v1/settings')) return Promise.resolve(response(DEFAULT_SETTINGS));
    if (url.includes('/v1/roles')) return Promise.resolve(response([]));
    if (url.includes('/v1/users/page')) {
      const params = new URL(url, 'http://test.invalid').searchParams;
      const start = params.get('cursor') === 'users-after-50' ? 50 : 0;
      const items = users.slice(start, start + 50);
      const hasMore = start + items.length < users.length;
      return Promise.resolve(
        response({
          items,
          offset: start,
          limit: 50,
          has_more: hasMore,
          next_cursor: hasMore ? 'users-after-50' : null,
          // A cursor response intentionally has no usable offset continuation.
          next_offset: null,
        }),
      );
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as unknown as typeof fetch;
  return { fn, calls };
}

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('bounded registry pages', () => {
  it.each([
    ['books', <BooksPage />],
    ['entities', <EntitiesPage />],
    ['users', <UsersList />],
  ] as const)(
    'renders at most 50 %s rows without its legacy array request',
    async (resource, page) => {
      const { fn, calls } = pageFetch();
      vi.stubGlobal('fetch', fn);
      const view = renderWithProviders(page, [`/${resource}`]);

      await waitFor(() => expect(view.container.querySelectorAll('tbody tr')).toHaveLength(50));
      const paths = calls.map((url) => new URL(url, 'http://test.invalid').pathname);
      expect(paths).toContain(`/v1/${resource}/page`);
      expect(paths).not.toContain(`/v1/${resource}`);
    },
  );

  it('uses offset fallback navigation and debounces server search', async () => {
    const { fn, calls } = pageFetch();
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<UsersList />, ['/settings/users']);
    await screen.findByText('user.0');

    fireEvent.click(screen.getByRole('button', { name: 'Página seguinte' }));
    await waitFor(() =>
      expect(calls.some((url) => url.includes('/v1/users/page') && url.includes('offset=50'))).toBe(
        true,
      ),
    );
    expect(await screen.findByText('user.50')).toBeTruthy();

    const beforeSearch = calls.filter((url) => url.includes('/v1/users/page?q=')).length;
    const search = screen.getByLabelText('Pesquisar');
    fireEvent.change(search, { target: { value: 'u' } });
    fireEvent.change(search, { target: { value: 'us' } });
    fireEvent.change(search, { target: { value: 'user.7' } });
    expect(calls.filter((url) => url.includes('/v1/users/page?q=')).length).toBe(beforeSearch);
    await waitFor(() =>
      expect(calls.filter((url) => url.includes('/v1/users/page?q=user.7'))).toHaveLength(1),
    );
  });

  it('wires an opaque cursor without a conflicting offset and announces page context', async () => {
    const { fn, calls } = cursorPageFetch();
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<UsersList />, ['/settings/users']);
    await screen.findByText('user.0');

    expect(screen.getByLabelText('50 itens nesta página')).toBeTruthy();
    expect(screen.getByText('Itens 1–50').getAttribute('aria-live')).toBe('polite');
    fireEvent.click(screen.getByRole('button', { name: 'Página seguinte' }));

    await screen.findByText('user.50');
    const cursorRequest = calls
      .filter((url) => url.includes('/v1/users/page'))
      .map((url) => new URL(url, 'http://test.invalid'))
      .find((url) => url.searchParams.has('cursor'));
    expect(cursorRequest?.searchParams.get('cursor')).toBe('users-after-50');
    expect(cursorRequest?.searchParams.has('offset')).toBe(false);
    expect(screen.getByText('Itens 51–75')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Página anterior' }));
    expect(await screen.findByText('user.0')).toBeTruthy();
    expect(screen.getByText('Itens 1–50')).toBeTruthy();
  });

  it('keeps current-filter controls mounted without showing stale placeholder rows', async () => {
    const { fn: baseFetch } = pageFetch();
    let resolveSearch: ((response: Response) => void) | undefined;
    const pendingSearch = new Promise<Response>((resolve) => {
      resolveSearch = resolve;
    });
    const requests: string[] = [];
    const fn = vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      requests.push(url);
      if (url.includes('/v1/books/page?q=No+match')) return pendingSearch;
      return baseFetch(input);
    }) as unknown as typeof fetch;
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<BooksPage />, ['/books']);
    await screen.findByText('Minutes 0');

    fireEvent.change(screen.getByLabelText('Pesquisar'), { target: { value: 'No match' } });
    await waitFor(() =>
      expect(requests.some((url) => url.includes('/v1/books/page?q=No+match'))).toBe(true),
    );

    expect(screen.getByLabelText('Pesquisar')).toBeTruthy();
    expect(screen.queryByText('Minutes 0')).toBeNull();
    expect(screen.queryByText('Sem resultados')).toBeNull();

    resolveSearch?.(
      response({
        items: [],
        offset: 0,
        limit: 50,
        has_more: false,
        next_offset: null,
      }),
    );
    expect(await screen.findByText('Sem resultados')).toBeTruthy();
  });

  it('applies a server filter before taking the first 50-row page', async () => {
    const { fn, calls } = pageFetch();
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<BooksPage />, ['/books']);
    await screen.findByText('Minutes 0');

    fireEvent.change(screen.getByLabelText('Pesquisar'), {
      target: { value: 'Minutes 74' },
    });

    expect(await screen.findByText('Minutes 74')).toBeTruthy();
    expect(screen.queryByText('Minutes 0')).toBeNull();
    expect(calls.some((url) => url.includes('/v1/books/page?q=Minutes+74'))).toBe(true);
  });
});
