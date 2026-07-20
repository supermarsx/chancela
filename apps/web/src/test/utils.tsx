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
    (el.getAttribute('aria-describedby') ?? '')
      .split(/\s+/)
      .some((id) => {
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
