/**
 * Ferramentas' tool strip, after it stopped being a fork.
 *
 * The strip was hand-rolled (`.tools-subnav`) before the shared `<SubNav>` primitive existed,
 * and never picked up what the primitive grew afterwards — the horizontal scroller, the edge
 * fades and the scroll arrows. With seven tools it is the LONGEST strip in the product, so it
 * was the one place where sub-tabs could run off the shell with no way to reach them. These
 * assert the properties the migration had to carry across, and the one it had to add.
 *
 * ## Two kinds of assertion here, and why
 *
 * Everything about which tabs exist, which is pressed, what a deep link resolves to and what a
 * denied permission hides is a DOM fact and is asserted as one. The overflow scroller is a CSS
 * fact, and jsdom does not apply stylesheets to `getComputedStyle`: a test that mounts the strip
 * and reads `overflow-x` passes whether or not the rule exists. Those assertions read `theme.css`
 * itself and each carries a red-proof against an in-memory copy with the rule removed, the same
 * way `ui/subNavRhythmGuards.test.ts` does.
 *
 * ## No translated copy in the assertions
 *
 * Tabs are identified by their POSITION in the fixed `SECTIONS` order, not by their pt-PT labels,
 * so a copy revision cannot turn these red and a label swap cannot turn them green.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { permissionsValue, StaticPermissionsProvider } from '../session/permissions';
import { ToolsPage } from './ToolsPage';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Enough of a backend for any tool to mount; none of these tests read a tool's contents. */
function toolsFetch(): typeof fetch {
  return ((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.includes('/v1/search/status')) {
      return Promise.resolve(jsonResponse({ enabled: false, execution_mode: 'embedded' }));
    }
    if (url.includes('/v1/external-validator-reports')) {
      return Promise.resolve(jsonResponse({ storage: 'durable', count: 0, reports: [] }));
    }
    return Promise.resolve(jsonResponse({}));
  }) as typeof fetch;
}

/**
 * The TOOL strip specifically — the one in the page header. Scoping matters: the Validador PDF
 * tool renders a second `<SubNav>` of its own inside the content region, and an unscoped lookup
 * would silently pick whichever came first.
 */
function toolStrip(): HTMLElement {
  const el = document.querySelector('.page-header .subnav');
  if (!(el instanceof HTMLElement)) throw new Error('the tool strip is not rendered');
  return el;
}

/** The tool strip's buttons, in `SECTIONS` order (the scroll arrows sit OUTSIDE `.subnav`). */
function toolTabs(): HTMLButtonElement[] {
  return Array.from(toolStrip().querySelectorAll('button'));
}

/** Index of the pressed tab, or -1 — position rather than label, so copy revisions are inert. */
function pressedTab(): number {
  return toolTabs().findIndex((b) => b.getAttribute('aria-pressed') === 'true');
}

/** `SECTIONS` order in ToolsPage. Positions, not labels, are what these tests assert on. */
const SEARCH = 0;
const CAE = 1;
const CERTIDAO = 2;
const PDF = 4;

describe('Ferramentas tool strip — the shared primitive', () => {
  it('renders through <SubNav>: the rail, the scrolling wrap and the strip as the scroller', () => {
    vi.stubGlobal('fetch', toolsFetch());
    renderWithProviders(<ToolsPage />, ['/tools/certidao']);

    // The exact nesting `<SubNav>` produces. A hand-rolled strip has the group but neither box,
    // and it is the wrap that owns the fades and hosts the arrows.
    const strip = toolStrip();
    const wrap = strip.parentElement;
    expect(wrap?.className).toBe('subnav-wrap');
    expect(wrap?.parentElement?.className).toBe('subnav-rail');
    expect(strip.getAttribute('role')).toBe('group');
  });

  it('keeps a decorative glyph on every tool tab', () => {
    vi.stubGlobal('fetch', toolsFetch());
    renderWithProviders(<ToolsPage />, ['/tools/certidao']);

    const tabs = toolTabs();
    expect(tabs).toHaveLength(7);
    for (const tab of tabs) {
      const glyph = tab.querySelector('.subnav__icon');
      expect(glyph, `tool tab ${tab.textContent} lost its glyph`).toBeTruthy();
      // Decorative: the label alone is the accessible name.
      expect(glyph?.getAttribute('aria-hidden')).toBe('true');
    }
  });

  it('keeps the gliding indicator behind the active tab', () => {
    vi.stubGlobal('fetch', toolsFetch());
    renderWithProviders(<ToolsPage />, ['/tools/certidao']);

    const indicator = toolStrip().querySelector('.subnav__indicator');
    expect(indicator).toBeTruthy();
    expect(indicator?.getAttribute('aria-hidden')).toBe('true');
  });
});

describe('Ferramentas tool strip — overflow', () => {
  /**
   * The defect the migration fixes: with the strip wider than the shell, a scroll arrow must
   * appear for the edge that has more tabs behind it. The hand-rolled strip had no scroller at
   * all, so this could not be satisfied by any amount of scrolling.
   */
  it('offers a scroll arrow for whichever edge currently hides tabs', () => {
    vi.stubGlobal('fetch', toolsFetch());
    renderWithProviders(<ToolsPage />, ['/tools/certidao']);
    const strip = toolStrip();

    const arrows = () =>
      Array.from(document.querySelectorAll('.subnav__scroll')).map((el) =>
        el.className.includes('subnav__scroll--start') ? 'start' : 'end',
      );

    // Fits: no arrows.
    Object.defineProperties(strip, {
      scrollLeft: { configurable: true, writable: true, value: 0 },
      clientWidth: { configurable: true, writable: true, value: 900 },
      scrollWidth: { configurable: true, writable: true, value: 900 },
    });
    fireEvent.scroll(strip);
    expect(arrows()).toEqual([]);

    // Overflows to the right only.
    Object.defineProperty(strip, 'clientWidth', { configurable: true, value: 300 });
    Object.defineProperty(strip, 'scrollWidth', { configurable: true, value: 900 });
    fireEvent.scroll(strip);
    expect(arrows()).toEqual(['end']);

    // Scrolled to the far end: the hidden tabs are now behind, so the arrow flips sides.
    strip.scrollLeft = 600;
    fireEvent.scroll(strip);
    expect(arrows()).toEqual(['start']);

    // Every arrow carries an accessible name rather than being an unlabelled glyph.
    for (const arrow of document.querySelectorAll('.subnav__scroll')) {
      expect(arrow.getAttribute('aria-label')?.length).toBeGreaterThan(0);
    }
  });
});

describe('Ferramentas tool strip — deep links', () => {
  it('the default tool owns the bare /tools address', () => {
    vi.stubGlobal('fetch', toolsFetch());
    renderWithProviders(<ToolsPage />, ['/tools']);
    expect(pressedTab()).toBe(SEARCH);
  });

  it('a path segment selects its tool', () => {
    vi.stubGlobal('fetch', toolsFetch());
    renderWithProviders(<ToolsPage />, ['/tools/certidao']);
    expect(pressedTab()).toBe(CERTIDAO);
    expect(document.getElementById('certidao-lookup-code')).not.toBeNull();
  });

  it('an unknown segment falls back to the default rather than blanking the surface', () => {
    vi.stubGlobal('fetch', toolsFetch());
    renderWithProviders(<ToolsPage />, ['/tools/nao-existe']);
    expect(pressedTab()).toBe(SEARCH);
  });

  it('both navigation levels resolve from one deep link', () => {
    vi.stubGlobal('fetch', toolsFetch());
    renderWithProviders(<ToolsPage />, ['/tools/pdf/asic']);

    // Level 1: the tool.
    expect(pressedTab()).toBe(PDF);

    // Level 2: the validator's own strip, which is a `<SubNav>` too and is NOT the tool strip.
    const strips = Array.from(document.querySelectorAll('.subnav'));
    expect(strips).toHaveLength(2);
    const inner = strips.find((el) => el !== toolStrip());
    const innerTabs = Array.from(inner?.querySelectorAll('button') ?? []);
    expect(innerTabs.map((b) => b.getAttribute('aria-pressed'))).toEqual([
      'false',
      'true',
      'false',
    ]);
  });

  it('clicking a tool moves the pressed tab', () => {
    vi.stubGlobal('fetch', toolsFetch());
    renderWithProviders(<ToolsPage />, ['/tools/certidao']);
    expect(pressedTab()).toBe(CERTIDAO);

    fireEvent.click(toolTabs()[CAE]);
    expect(pressedTab()).toBe(CAE);
  });
});

describe('Ferramentas tool strip — permission gating', () => {
  /** An Owner minus the one verb the certidão lookup is gated on. */
  const withoutRegistryLookup = permissionsValue((p) => p !== 'entity.registry.lookup');

  it('hides the certidão tab from a principal without entity.registry.lookup', () => {
    vi.stubGlobal('fetch', toolsFetch());
    renderWithProviders(
      <StaticPermissionsProvider value={withoutRegistryLookup}>
        <ToolsPage />
      </StaticPermissionsProvider>,
      ['/tools'],
    );

    expect(toolTabs()).toHaveLength(6);
    expect(pressedTab()).toBe(SEARCH);
  });

  it('does not let a deep link reach the gated-out tool', () => {
    const fetchMock = vi.fn(toolsFetch());
    vi.stubGlobal('fetch', fetchMock);
    renderWithProviders(
      <StaticPermissionsProvider value={withoutRegistryLookup}>
        <ToolsPage />
      </StaticPermissionsProvider>,
      ['/tools/certidao'],
    );

    // The tab is absent AND the tool did not mount behind it.
    expect(toolTabs()).toHaveLength(6);
    expect(document.getElementById('certidao-lookup-code')).toBeNull();
    expect(pressedTab()).toBe(SEARCH);
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes('/v1/registry'))).toBe(false);
  });
});

/**
 * Source assertions on `theme.css`. jsdom applies no stylesheet, so these read the sheet text;
 * each has a red-proof against an in-memory copy with the rule removed.
 */
describe('Ferramentas tool strip — the sheet backing the scroller', () => {
  let THEME = '';

  beforeAll(async () => {
    // The app project has no `@types/node`; this indirection is the suite's existing idiom.
    const nodeFs = 'node:fs';
    const { readFileSync } = (await import(nodeFs)) as {
      readFileSync(path: string, encoding: 'utf8'): string;
    };
    THEME = readFileSync('src/theme.css', 'utf8').replace(/\r\n/gu, '\n');
  });

  /** The base strip rule, which must itself be the scroller now that there is only one. */
  const SUBNAV_RULE = /\n\.subnav\s*\{([^}]*)\}/;

  it('makes the one sub-nav rule scroll horizontally', () => {
    const block = THEME.match(SUBNAV_RULE);
    expect(block, 'the .subnav rule must exist').not.toBeNull();
    expect(block![1]).toMatch(/overflow-x:\s*auto/);
    expect(block![1]).toMatch(/max-width:\s*100%/);
  });

  it('fails against a sheet whose sub-nav rule cannot scroll', () => {
    // Red-proof, in memory: strip `overflow-x` out of the rule and the assertion above must go red.
    const stripped = THEME.replace(SUBNAV_RULE, (rule) => rule.replace(/overflow-x:\s*auto;/, ''));
    expect(stripped).not.toBe(THEME);
    expect(stripped.match(SUBNAV_RULE)![1]).not.toMatch(/overflow-x:\s*auto/);
  });

  it('keeps the edge fades and the scroll arrows keyed to the overflow flags', () => {
    expect(THEME).toMatch(/\.subnav-wrap\[data-overflow-start\]::before/);
    expect(THEME).toMatch(/\.subnav-wrap\[data-overflow-end\]::after/);
    expect(THEME).toMatch(/\.subnav__scroll--start\s*\{/);
    expect(THEME).toMatch(/\.subnav__scroll--end\s*\{/);
  });

  /**
   * The fork is gone from the sheet as well as from the markup. Left behind, `.tools-subnav*`
   * would be dead rules that still look like a supported alternative to the shared primitive —
   * which is how the divergence happened the first time.
   */
  it('carries no .tools-subnav rules, because nothing renders that class any more', () => {
    const rules = THEME.replace(/\/\*[\s\S]*?\*\//gu, '');
    expect(rules).not.toMatch(/\.tools-subnav/);
  });
});
