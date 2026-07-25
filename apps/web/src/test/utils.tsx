/**
 * Test helpers: a fresh QueryClient (no retries, so a mocked error surfaces at once)
 * wrapped around a MemoryRouter for rendering feature pages in isolation.
 */
import type { ReactElement, ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  MemoryRouter,
  RouterProvider,
  createMemoryRouter,
  type RouteObject,
} from 'react-router-dom';
import { render } from '@testing-library/react';
import { ToastProvider } from '../ui/toast';
import { ALLOW_ALL_PERMISSIONS, StaticPermissionsProvider } from '../features/session/permissions';

/**
 * Find the element whose themed tooltip reveals exactly `text` — the replacement for
 * `screen.getByTitle(text)`.
 *
 * t31 moved these reveals off the native `title` attribute (which the browser draws itself,
 * unstyleably) onto the shared `Tooltip` primitive, where the value lives in a portaled
 * bubble linked by `aria-describedby`. Asserting through the description rather than the
 * bubble keeps these tests checking what actually matters: that the full value is still
 * announced to assistive tech, not merely present somewhere in the DOM.
 */
export function getByRevealedText(
  text: string | RegExp,
  // Scope for the TRIGGER. The bubble itself is always looked up in the document, because
  // Tooltip portals it to <body> to escape clipping ancestors — so `within(x)` can never
  // contain it.
  container: ParentNode = document,
): HTMLElement {
  const hit = (value: string) => (typeof text === 'string' ? value === text : text.test(value));
  const matches = Array.from(container.querySelectorAll('[aria-describedby]')).filter((el) =>
    (el.getAttribute('aria-describedby') ?? '').split(/\s+/).some((id) => {
      const bubble = document.getElementById(id);
      return bubble ? hit(bubble.textContent ?? '') : false;
    }),
  );
  if (matches.length !== 1) {
    throw new Error(
      `getByRevealedText: expected exactly 1 element revealing ${JSON.stringify(text)}, found ${matches.length}`,
    );
  }
  return matches[0] as HTMLElement;
}

/**
 * The complete value a user can actually obtain from `el`, by whichever route the design
 * system provides it — the contract that outlived the native `title` attribute.
 *
 * t31 gave truncated content two legitimate shapes, and a test should accept either:
 *  - CSS-clipped text is complete in the DOM (the ellipsis is painted, not applied to the
 *    string), so the value is the element's own text and no description is needed;
 *  - genuinely ABBREVIATED text (`a1b2…c3d4`) keeps the full value only in the tooltip, so
 *    it must arrive through `aria-describedby`.
 *
 * Asserting on this rather than on a class name or a `title` attribute keeps these tests
 * checking what matters — that the full value is still reachable — instead of pinning the
 * mechanism that happens to deliver it.
 */
export function revealedValue(el: Element | null | undefined): string | null {
  if (!el) return null;
  const described = (el.getAttribute('aria-describedby') ?? '')
    .split(/\s+/)
    .map((id) => (id ? document.getElementById(id)?.textContent : null))
    .find((text) => text);
  return described ?? el.textContent ?? null;
}

export function makeClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
}

export function Wrapper({
  children,
  initialEntries = ['/'],
}: {
  children: ReactNode;
  initialEntries?: string[];
}) {
  // ToastProvider is required by any component that calls `useToast()` on mutation, so it
  // is part of the standard render context (mirrors app/providers) — omitting it would
  // break every mutation-flow test at once (plan t44 R6).
  // The standard render context grants ALL permissions (an Owner), so existing
  // affordance/mutation tests see enabled controls exactly as before t64-E5. Tests that
  // exercise gating (a Leitor, a scoped Gestor) wrap their subject in their own
  // <StaticPermissionsProvider> with a narrower value.
  return (
    <QueryClientProvider client={makeClient()}>
      <ToastProvider>
        <StaticPermissionsProvider value={ALLOW_ALL_PERMISSIONS}>
          <MemoryRouter initialEntries={initialEntries}>{children}</MemoryRouter>
        </StaticPermissionsProvider>
      </ToastProvider>
    </QueryClientProvider>
  );
}

export function renderWithProviders(ui: ReactElement, initialEntries?: string[]) {
  return render(<Wrapper initialEntries={initialEntries}>{ui}</Wrapper>);
}

/**
 * The same context, but around a DATA router — the kind the app actually ships
 * (`createBrowserRouter`). Needed by anything that reads route `handle` metadata (the shell's
 * route key does, to tell a page change from a sub-tab switch), because `useMatches` is only
 * available under a data router.
 */
export function renderWithDataRouter(routes: RouteObject[], initialEntries: string[] = ['/']) {
  const router = createMemoryRouter(routes, { initialEntries });
  return render(
    <QueryClientProvider client={makeClient()}>
      <ToastProvider>
        <StaticPermissionsProvider value={ALLOW_ALL_PERMISSIONS}>
          <RouterProvider router={router} />
        </StaticPermissionsProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

/**
 * Build a `fetch` stub that resolves each request by matching its URL against the
 * given table (first substring hit wins). Unmatched URLs reject so a test fails loudly
 * rather than hanging.
 */
export function fetchTable(
  table: { match: string; status?: number; body: unknown }[],
): typeof fetch {
  return ((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    const hit = table.find((t) => url.includes(t.match));
    if (!hit) return Promise.reject(new Error(`no stub for ${url}`));
    const status = hit.status ?? 200;
    const body =
      Array.isArray(hit.body) && /^\/v1\/(entities|books|users)\/page(?:\?|$)/.test(url)
        ? collectionPageFixture(url, hit.body)
        : hit.body;
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
  }) as typeof fetch;
}

function folded(value: unknown): string {
  return String(value ?? '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

/** Server-like filtering for list-page fixtures. Production behavior remains covered in Rust. */
/* eslint-disable @typescript-eslint/no-explicit-any -- heterogeneous wire fixtures are inspected dynamically */
export function collectionPageFixture(url: string, input: unknown[]) {
  const parsed = new URL(url, 'http://test.invalid');
  const p = parsed.searchParams;
  const resource = parsed.pathname.split('/')[2];
  let items = [...input] as Record<string, any>[];
  const q = folded(p.get('q'));
  if (q) items = items.filter((item) => folded(JSON.stringify(item)).includes(q));

  if (resource === 'books') {
    if (p.has('state')) items = items.filter((item) => item.state === p.get('state'));
    if (p.has('kind')) items = items.filter((item) => item.kind === p.get('kind'));
    if (p.get('activity') === 'has-acts') items = items.filter((item) => item.last_ata_number > 0);
    if (p.get('activity') === 'no-acts') items = items.filter((item) => item.last_ata_number <= 0);
    if (p.get('lineage') === 'successor') items = items.filter((item) => !!item.predecessor);
    if (p.get('lineage') === 'origin') items = items.filter((item) => !item.predecessor);
    if (p.has('opened_from'))
      items = items.filter(
        (item) => !!item.opening_date && item.opening_date >= p.get('opened_from')!,
      );
    if (p.has('opened_to'))
      items = items.filter(
        (item) => !!item.opening_date && item.opening_date <= p.get('opened_to')!,
      );
  } else if (resource === 'entities') {
    if (p.has('family')) items = items.filter((item) => item.family === p.get('family'));
    if (p.has('kind')) items = items.filter((item) => item.kind === p.get('kind'));
    if (p.has('nipc_validated'))
      items = items.filter((item) => String(item.nipc_validated) === p.get('nipc_validated'));
    if (p.has('registry_import'))
      items = items.filter((item) =>
        p.get('registry_import') === 'imported' ? !!item.registry_summary : !item.registry_summary,
      );
    if (p.has('registry_freshness'))
      items = items.filter((item) => {
        const registry = item.registry_summary;
        if (p.get('registry_freshness') === 'fresh') return registry?.expired === false;
        if (p.get('registry_freshness') === 'expired') return registry?.expired === true;
        return !registry || registry.valid_until == null || registry.expired == null;
      });
    const summary = (item: Record<string, any>) => item.activity_summary;
    if (p.has('books'))
      items = items.filter((item) => {
        const counts = summary(item)?.book_state_counts ?? { created: 0, open: 0, closed: 0 };
        if (p.get('books') === 'none') return counts.created + counts.open + counts.closed === 0;
        if (p.get('books') === 'no-open') return counts.open === 0;
        return counts[p.get('books')!] > 0;
      });
    if (p.has('book_kind'))
      items = items.filter((item) =>
        (item._test_book_kinds ?? [summary(item)?.last_book?.kind]).includes(p.get('book_kind')),
      );
    if (p.has('last_book'))
      items = items.filter((item) =>
        p.get('last_book') === 'none'
          ? !summary(item)?.last_book
          : summary(item)?.last_book?.state === p.get('last_book'),
      );
    if (p.has('activity_kind'))
      items = items.filter((item) =>
        p.get('activity_kind') === 'none'
          ? !summary(item)?.last_change
          : summary(item)?.last_change?.kind === p.get('activity_kind'),
      );
    if (p.has('activity'))
      items = items.filter((item) => {
        const kind = summary(item)?.last_change?.kind;
        const filter = p.get('activity');
        if (filter === 'none') return !kind;
        if (!kind) return false;
        if (filter === 'registry') return kind === 'registry.imported';
        if (filter === 'act') return kind.startsWith('act.') || kind.startsWith('convening.');
        if (filter === 'document')
          return kind.startsWith('document.') || kind.startsWith('signature.');
        return kind.startsWith(`${filter}.`);
      });
  } else if (resource === 'users') {
    if (p.has('active')) items = items.filter((item) => String(item.active) === p.get('active'));
    if (p.has('role_id'))
      items = items.filter((item) =>
        item.role_assignments?.some(
          (assignment: Record<string, any>) => assignment.role_id === p.get('role_id'),
        ),
      );
    if (p.get('roleless') === 'true')
      items = items.filter((item) => item.role_assignments?.length === 0);
    if (p.has('access'))
      items = items.filter((item) => {
        if (p.get('access') === 'key') return item.has_attestation_key;
        if (p.get('access') === 'no-key') return !item.has_attestation_key;
        if (p.get('access') === 'no-password') return !item.has_secret;
        return item.has_recovery_phrase;
      });
    if (p.has('scope'))
      items = items.filter((item) => {
        const assignments = item.role_assignments ?? [];
        const global = assignments.some(
          (assignment: Record<string, any>) => assignment.scope?.kind === 'global',
        );
        return p.get('scope') === 'global' ? global : !global && assignments.length > 0;
      });
    if (p.has('email'))
      items = items.filter((item) =>
        p.get('email') === 'with' ? !!item.email?.trim() : !item.email?.trim(),
      );
    if (p.has('created_days')) {
      const cutoff = Date.now() - Number(p.get('created_days')) * 86_400_000;
      items = items.filter((item) => Date.parse(item.created_at) >= cutoff);
    }
  }

  const offset = Number(p.get('offset') ?? 0);
  const limit = Number(p.get('limit') ?? 50);
  const pageItems = items.slice(offset, offset + limit);
  const hasMore = offset + pageItems.length < items.length;
  return {
    items: pageItems,
    offset,
    limit,
    has_more: hasMore,
    next_offset: hasMore ? offset + pageItems.length : null,
  };
}
/* eslint-enable @typescript-eslint/no-explicit-any */
