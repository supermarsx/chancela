/**
 * Test helpers: a fresh QueryClient (no retries, so a mocked error surfaces at once)
 * wrapped around a MemoryRouter for rendering feature pages in isolation.
 */
import type { ReactElement, ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { render } from '@testing-library/react';

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
  return (
    <QueryClientProvider client={makeClient()}>
      <MemoryRouter initialEntries={initialEntries}>{children}</MemoryRouter>
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
