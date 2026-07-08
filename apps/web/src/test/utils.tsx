/**
 * Test helpers: a fresh QueryClient (no retries, so a mocked error surfaces at once)
 * wrapped around a MemoryRouter for rendering feature pages in isolation.
 */
import type { ReactElement, ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { render } from '@testing-library/react';
import { ToastProvider } from '../ui/toast';
import { ALLOW_ALL_PERMISSIONS, StaticPermissionsProvider } from '../features/session/permissions';

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
    return Promise.resolve(
      new Response(JSON.stringify(hit.body), {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
  }) as typeof fetch;
}
