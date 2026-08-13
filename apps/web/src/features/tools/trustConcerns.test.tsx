/**
 * The consolidated trust-concern treatment: an icon in the status line, one banner below the
 * lists (t114 — "the cert verify warning should go after the lists and you should only provide a
 * exclamation icon in the item as for alert and a banner in the end of the lists concern alerts").
 *
 * ## What these are actually guarding
 *
 * Three markers — a permitted broken algorithm, a verdict served out of the durable cache, and a
 * Trusted List fetched over an unauthenticated transport — used to render a labelled status-line
 * cell each plus a full banner each, stacked above the fact tables. Collapsing that into one icon
 * per concern and one shared banner is a layout change with three ways to silently cost the
 * operator something real, and there is a test here for each:
 *
 * 1. **Losing copy.** The status-line cell's label and badge had nowhere obvious to go, and a
 *    banner is easy to write as a summary. {@link everySentence} enumerates every sentence the
 *    three old banners rendered plus the six strings the three cells rendered, and asserts each is
 *    on screen — so a future edit that trims one fails here rather than in review.
 * 2. **Losing the link between an icon and its detail.** An icon that says only "something is
 *    wrong here" is worse than the cell it replaced. The association is asserted end to end: the
 *    marker's `href` resolves to an element that exists and is the entry for that same concern.
 * 3. **Flattening severity.** A stale cached list and an informational transport note must not
 *    read alike. The mixed-severity case asserts both are present, that they are ordered warning
 *    first, and that the entries carry different severities.
 *
 * ## Why almost nothing here is a text query
 *
 * Each concern's heading is deliberately three things at once: the entry's heading, the marker's
 * accessible name, and the marker's tooltip. A `getByText` would match all three and cannot say
 * which it found, so structure (ids, roles, `data-trust-concern`) does the locating and text
 * assertions are scoped inside an element already located structurally. Expected copy is read out
 * of the pt-PT catalog by key rather than typed in, so a copy revision moves the test with the
 * product instead of pinning a rendered substring.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { ptPT } from '../../i18n/locales/pt-PT';
import { TrustCatalogPage } from './TrustCatalogPage';
import { TSL_LEGACY_ALGORITHMS } from '../../api/types';
import type {
  TslCacheFallbackView,
  TslCatalogView,
  TslSummaryView,
  TslUnverifiedTransportView,
  WeakAlgorithmUse,
} from '../../api/types';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const CLEAN_SUMMARY: TslSummaryView = {
  source: { kind: 'Fixture', path: null, note: '' },
  last_refresh: null,
  scheme_operator_name: 'Gabinete Nacional de Segurança',
  scheme_name: 'Lista de Confiança de Portugal',
  scheme_territory: 'PT',
  sequence_number: 42,
  issue_date_time: '2026-07-08T00:00:00Z',
  next_update: '2026-08-08T00:00:00Z',
  stale: false,
  validation: { checked_at: '2026-07-09T00:00:00Z', signature: 'Valid', error: null },
  providers: 0,
  services: 0,
  ca_qc_services: 0,
  qualified_esignature_services: 0,
  trusted_esignature_services: 0,
};

const WEAK_USES: WeakAlgorithmUse[] = [
  {
    code: 'tsl_weak_signature_method_permitted',
    algorithm: TSL_LEGACY_ALGORITHMS[1],
    site: 'signature_method',
  },
];

/** Past its own `NextUpdate` — the loud arm, where a withdrawn service still reads as granted. */
const STALE_CACHE: TslCacheFallbackView = {
  code: 'tsl_served_from_stale_cache',
  stale: true,
  fetched_at: '2026-06-01T00:00:00Z',
  expires_at: '2026-06-30T00:00:00Z',
  served_at: '2026-07-09T00:00:00Z',
  fetch_error: 'connection timed out after 30s',
};

/** Inside its validity — ordinary, and the reason the cache marker is not always a warning. */
const FRESH_CACHE: TslCacheFallbackView = {
  ...STALE_CACHE,
  code: 'tsl_served_from_cache',
  stale: false,
  expires_at: '2026-08-30T00:00:00Z',
};

const TRANSPORT: TslUnverifiedTransportView = {
  code: 'tsl_transport_not_verified',
  source_id: 'pt-gns',
  url: 'https://lists.example.pt/tsl.xml',
};

function summaryWith(validation: Partial<TslSummaryView['validation']>): TslSummaryView {
  return { ...CLEAN_SUMMARY, validation: { ...CLEAN_SUMMARY.validation, ...validation } };
}

/** Only the two endpoints the Trusted List sub-tab reads; everything else 404s loudly. */
function stubFetch(summary: TslSummaryView): void {
  const catalog: TslCatalogView = { summary, providers: [] };
  vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
    const parsed = new URL(String(input), 'http://localhost');
    if (parsed.pathname === '/v1/trust/status') return Promise.resolve(jsonResponse(summary));
    if (parsed.pathname === '/v1/trust/catalog') return Promise.resolve(jsonResponse(catalog));
    return Promise.resolve(jsonResponse({}, 404));
  }) as typeof fetch);
}

function entryId(slug: string): string {
  return `trust-concern-tsl-status-${slug}`;
}

async function waitForEntry(slug: string): Promise<HTMLElement> {
  return (await waitFor(() => {
    const found = document.getElementById(entryId(slug));
    expect(found).not.toBeNull();
    return found;
  })) as HTMLElement;
}

function markers(): HTMLAnchorElement[] {
  return Array.from(
    document.querySelectorAll<HTMLAnchorElement>('.trust-statusline__item--concerns a'),
  );
}

function banner(): HTMLElement | null {
  return document.querySelector('.inline-warning:has(.trust-concerns)');
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('Ferramentas — trust concerns: icon in the item, banner after the lists', () => {
  it('renders no icon, no banner and no empty container on a clean verdict', async () => {
    // The whole design intent. An install that never permitted a broken algorithm, never fell back
    // to the cache and authenticates its transport must see exactly the screen it saw before any
    // of these markers existed — not a green "all clear" chip, and not an empty cell holding a gap
    // in the status line's flex row.
    stubFetch(CLEAN_SUMMARY);
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);

    await screen.findByText(CLEAN_SUMMARY.scheme_operator_name);
    expect(markers()).toHaveLength(0);
    expect(banner()).toBeNull();
    expect(document.querySelector('.trust-statusline__item--concerns')).toBeNull();
    expect(document.querySelector('.trust-concern-markers')).toBeNull();
    expect(document.querySelector('.trust-concerns')).toBeNull();
    expect(document.querySelector('[data-trust-concerns]')).toBeNull();
  });

  it('raises exactly the concerns the verdict carries, and no icon for the ones it does not', async () => {
    stubFetch(summaryWith({ unverified_transport: TRANSPORT }));
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);

    await waitForEntry('unverified-transport');
    // One concern in, one icon out — the other two are not merely quiet, they are absent.
    expect(markers().map((marker) => marker.dataset.trustConcern)).toEqual([
      'unverified-transport',
    ]);
    expect(document.getElementById(entryId('weak-algorithms'))).toBeNull();
    expect(document.getElementById(entryId('cache-fallback'))).toBeNull();
  });

  it('gives each icon an accessible name and an association with its own banner entry that resolves', async () => {
    stubFetch(
      summaryWith({
        weak_algorithms: WEAK_USES,
        cache_fallback: STALE_CACHE,
        unverified_transport: TRANSPORT,
      }),
    );
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);
    await waitForEntry('weak-algorithms');

    const links = screen.getAllByRole('link').filter((link) => link.dataset.trustConcern);
    expect(links).toHaveLength(3);

    for (const link of links) {
      const slug = link.dataset.trustConcern as string;
      const name = link.getAttribute('aria-label') ?? '';
      // A name, and a name that says what KIND of concern this is rather than "warning".
      expect(name.length).toBeGreaterThan(0);

      // The association, end to end: the href is a fragment, the fragment resolves to a real
      // element, and that element is this concern's entry — not merely the banner.
      const href = link.getAttribute('href') ?? '';
      expect(href.startsWith('#')).toBe(true);
      const target = document.getElementById(href.slice(1));
      expect(target).not.toBeNull();
      expect(target?.dataset.trustConcern).toBe(slug);
      // Focusable as a link target, so following the icon lands a keyboard user ON the detail
      // rather than at the top of a banner counting entries.
      expect(target?.getAttribute('tabindex')).toBe('-1');
      // The link's name is its target's heading, which is what lets a screen-reader user tell
      // which item is affected without reading the banner first.
      expect(target?.querySelector('.trust-concern__heading')?.textContent).toBe(name);
    }
  });

  it('names every affected source in the banner and keeps their severities apart', async () => {
    stubFetch(
      summaryWith({
        weak_algorithms: WEAK_USES,
        cache_fallback: STALE_CACHE,
        unverified_transport: TRANSPORT,
      }),
    );
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);
    await waitForEntry('weak-algorithms');

    const entries = Array.from(
      (banner() as HTMLElement).querySelectorAll<HTMLElement>('.trust-concern'),
    );
    // Warnings first, informational last: a mixed banner read top-down is ordered by severity, so
    // it can never be an undifferentiated pile of "concerns".
    expect(entries.map((entry) => entry.dataset.severity)).toEqual(['warn', 'warn', 'info']);
    // Every source names itself. A banner that said "some lists have concerns" would pass a naive
    // presence check and be useless.
    expect(entries.map((entry) => entry.dataset.trustConcern)).toEqual([
      'weak-algorithms',
      'cache-fallback',
      'unverified-transport',
    ]);
    // Three kinds in, three kinds out — nothing collapsed into a neighbour.
    expect(new Set(entries.map((entry) => entry.dataset.trustConcern)).size).toBe(3);
    // The box takes the loudest severity it holds, and the informational entry inside it is still
    // marked informational.
    expect((banner() as HTMLElement).className).toContain('inline-warning--warn');
  });

  it('lets a purely informational set stay informational, in the banner and in the glyph', async () => {
    // The counterpart to the mixed case: severity is derived, not hard-coded to "warn" the moment
    // anything at all is raised. An unverified transport sits beside a Valid verdict routinely,
    // and shouting about it is how true warnings get ignored.
    stubFetch(summaryWith({ cache_fallback: FRESH_CACHE, unverified_transport: TRANSPORT }));
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);
    await waitForEntry('unverified-transport');

    expect((banner() as HTMLElement).className).toContain('inline-warning--info');
    expect(markers().map((marker) => marker.dataset.severity)).toEqual(['info', 'info']);
    // …and the same cache marker turns into a warning purely on the backend's `stale` flag.
    cleanup();
    vi.unstubAllGlobals();
    stubFetch(summaryWith({ cache_fallback: STALE_CACHE }));
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);
    const stale = await waitForEntry('cache-fallback');
    expect(stale.dataset.severity).toBe('warn');
  });

  it('puts the banner after the lists, not between the status line and them', async () => {
    // The complaint this change answers. `Node.compareDocumentPosition` reads document order,
    // which is what a screen reader and a scrolling operator both follow, and — unlike anything
    // measured in pixels — it is real under jsdom.
    stubFetch(summaryWith({ unverified_transport: TRANSPORT }));
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);
    await waitForEntry('unverified-transport');

    const statusline = document.querySelector('.trust-statusline') as HTMLElement;
    const lists = document.querySelector('.trust-diagnostics-grid') as HTMLElement;
    const bannerEl = banner() as HTMLElement;

    const follows = (node: HTMLElement, other: HTMLElement) =>
      Boolean(node.compareDocumentPosition(other) & Node.DOCUMENT_POSITION_FOLLOWING);

    // The predicate red-proofed on a synthetic pair before it is trusted on the real one: a
    // `follows` that returned `true` for everything would pass the three assertions below while
    // proving nothing, and mutating the page to prove it would mean editing a tree other lanes
    // are working in.
    const probe = document.createElement('div');
    probe.innerHTML = '<i></i><b></b>';
    const [first, second] = Array.from(probe.children) as HTMLElement[];
    expect(follows(first, second)).toBe(true);
    expect(follows(second, first)).toBe(false);

    expect(follows(statusline, lists)).toBe(true);
    expect(follows(lists, bannerEl)).toBe(true);
    // Stated in both directions, so "the banner is after the lists" cannot pass by the banner and
    // the lists being the same element or by the comparison collapsing.
    expect(follows(bannerEl, lists)).toBe(false);
    // …and the icon is still up in the status line, where the operator scans.
    expect(statusline.contains(markers()[0])).toBe(true);
  });

  /**
   * Every sentence the three separate banners rendered, plus the six strings their three
   * status-line cells rendered. Asserted as a set, because "we moved the copy" is exactly the
   * change during which a paragraph quietly fails to make the trip.
   */
  const everySentence = [
    // The status-line cells' label + badge, which no longer have a cell of their own.
    ptPT['trust.weakAlgorithms.label'],
    ptPT['trust.weakAlgorithms.badge'],
    ptPT['trust.cacheFallback.label'],
    ptPT['trust.cacheFallback.badge.stale'],
    ptPT['trust.unverifiedTransport.label'],
    ptPT['trust.unverifiedTransport.badge'],
    // The three banners' titles.
    ptPT['trust.weakAlgorithms.title'],
    ptPT['trust.cacheFallback.title.stale'],
    ptPT['trust.unverifiedTransport.title'],
    // The three banners' prose.
    ptPT['trust.weakAlgorithms.intro'],
    ptPT['trust.weakAlgorithms.signatureMethod'],
    ptPT['trust.cacheFallback.pastValidity'],
    ptPT['trust.cacheFallback.fetchedAt'],
    ptPT['trust.cacheFallback.expiresAt'],
    ptPT['trust.cacheFallback.servedAt'],
    ptPT['trust.cacheFallback.reason'],
    ptPT['trust.unverifiedTransport.body'],
    ptPT['trust.unverifiedTransport.stillAuthenticated'],
    ptPT['trust.unverifiedTransport.residualRisk'],
    ptPT['trust.unverifiedTransport.remedy'],
  ];

  it('still renders every sentence the three separate banners did, none behind a hover', async () => {
    stubFetch(
      summaryWith({
        weak_algorithms: WEAK_USES,
        cache_fallback: STALE_CACHE,
        unverified_transport: TRANSPORT,
      }),
    );
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);
    await waitForEntry('weak-algorithms');

    // Read out of the banner alone, so a sentence that survives only as a tooltip bubble (which
    // is portaled to <body>, outside this element) counts as lost.
    const text = (banner() as HTMLElement).textContent ?? '';
    const missing = everySentence.filter((sentence) => !text.includes(sentence));
    expect(missing).toEqual([]);

    // The wire values too: the algorithm URI, the transport diagnostic, and the source and host,
    // each of which reaches every locale verbatim because translating it removes its only use.
    for (const verbatim of [
      WEAK_USES[0].algorithm,
      STALE_CACHE.fetch_error,
      TRANSPORT.source_id,
      TRANSPORT.url,
    ]) {
      expect(text).toContain(verbatim);
    }
  });

  it('keeps the last import’s concerns in their own group rather than merging them upward', async () => {
    // The import and the current status are two verdicts, and the settings can change between
    // them. Merging them into one banner would assert something false about whichever is cleaner.
    stubFetch({
      ...summaryWith({ unverified_transport: TRANSPORT }),
      last_refresh: {
        attempted_at: '2026-07-09T10:00:00Z',
        outcome: 'Success',
        source_kind: 'Url',
        source_url: 'https://lists.example.pt/tsl.xml',
        source_path: null,
        target_path: null,
        providers: 2,
        services: 3,
        ca_qc_services: 1,
        qualified_esignature_services: 1,
        trusted_esignature_services: 2,
        error: null,
        validation: {
          checked_at: '2026-07-09T10:00:00Z',
          signature: 'Valid',
          error: null,
          weak_algorithms: WEAK_USES,
        },
      },
    });
    renderWithProviders(<TrustCatalogPage />, ['/tools/trust']);

    const importEntry = (await waitFor(() => {
      const found = document.getElementById('trust-concern-tsl-import-weak-algorithms');
      expect(found).not.toBeNull();
      return found;
    })) as HTMLElement;

    // Two banners, each holding only its own verdict's concerns.
    const banners = Array.from(document.querySelectorAll('.inline-warning:has(.trust-concerns)'));
    expect(banners).toHaveLength(2);
    expect(document.getElementById(entryId('weak-algorithms'))).toBeNull();
    expect(document.getElementById('trust-concern-tsl-import-unverified-transport')).toBeNull();

    // The import's icon points at the import's entry, not at the status one.
    const importMarker = document.querySelector<HTMLAnchorElement>(
      '.trust-fact-cell--marked a[data-trust-concern="weak-algorithms"]',
    );
    expect(importMarker?.getAttribute('href')).toBe(`#${importEntry.id}`);
  });
});
