/**
 * App-wide providers. A single QueryClient wraps the router so every route shares
 * one cache (mutations in one page invalidate queries in another — e.g. sealing an
 * act refreshes the dashboard). Retries are disabled: API errors here are
 * deterministic domain responses (422/409), not transient faults, so retrying only
 * delays surfacing the real message.
 *
 * Cache tuning (t19-e2 item c) — snappy revisits without staleness:
 *  - `staleTime: 30s` — navigating back to a page within the window renders straight
 *    from cache with no refetch (instant, no spinner/skeleton); after it, the cached
 *    data still shows immediately while a background revalidation runs (silent refresh).
 *  - `gcTime: 10min` — caches survive long enough that moving across the app and back
 *    keeps everything warm rather than re-fetching from cold.
 *  - Correctness is preserved because every mutation invalidates the queries it affects
 *    (see `api/hooks`), so a real change refetches immediately regardless of staleTime.
 */
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      refetchOnWindowFocus: false,
      staleTime: 30_000,
      gcTime: 10 * 60_000,
    },
    mutations: { retry: false },
  },
});

export function Providers({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}
