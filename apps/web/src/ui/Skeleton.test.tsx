import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import {
  Skeleton,
  SkeletonCards,
  SkeletonChips,
  SkeletonDeflist,
  SkeletonForm,
  SkeletonList,
  SkeletonRegion,
  SkeletonTable,
} from './Skeleton';

afterEach(cleanup);

describe('Skeleton', () => {
  it('renders an aria-hidden shimmer block honouring width/height', () => {
    const { container } = render(<Skeleton width="8rem" height="1.2rem" />);
    const block = container.querySelector('.skeleton') as HTMLElement;
    expect(block).toBeTruthy();
    // Decorative: hidden from assistive tech so the busy region's status text speaks.
    expect(block.getAttribute('aria-hidden')).toBe('true');
    expect(block.style.width).toBe('8rem');
    expect(block.style.height).toBe('1.2rem');
  });

  it('SkeletonTable mirrors the requested rows and columns', () => {
    const { container } = render(<SkeletonTable rows={3} cols={4} />);
    // A head row plus three body rows.
    expect(container.querySelectorAll('.skeleton-table__row').length).toBe(4);
    expect(container.querySelector('.skeleton-table__row--head')).toBeTruthy();
    // Each body row has one shimmer per column.
    const bodyRow = container.querySelectorAll(
      '.skeleton-table__row:not(.skeleton-table__row--head)',
    )[0];
    expect(bodyRow.querySelectorAll('.skeleton').length).toBe(4);
  });

  it('SkeletonCards renders the requested number of metric cards', () => {
    const { container } = render(<SkeletonCards count={5} />);
    expect(container.querySelectorAll('.card').length).toBe(5);
  });

  it('SkeletonList mirrors the dashboard list item box (head + meta rows)', () => {
    const { container } = render(<SkeletonList items={3} />);
    expect(container.querySelectorAll('.dashboard-list__item').length).toBe(3);
    // Same class names as the real list, so the swap keeps the box model identical.
    expect(container.querySelectorAll('.dashboard-list__head').length).toBe(3);
    expect(container.querySelectorAll('.dashboard-list__meta').length).toBe(3);
  });

  it('SkeletonForm reserves label + control pairs on the real form boxes', () => {
    const { container } = render(<SkeletonForm fields={3} className="settings-rows" />);
    expect(container.querySelector('.form.settings-rows')).toBeTruthy();
    expect(container.querySelectorAll('.field').length).toBe(3);
    // Label over control, so a form waiting on its seed data holds its real height.
    expect(container.querySelectorAll('.field')[0].querySelectorAll('.skeleton').length).toBe(2);
  });

  it('SkeletonDeflist adopts the grid class it stands in for', () => {
    // The operations metric strip is the same dt/dd shape under another name; a `.deflist`
    // placeholder in front of it would lay out at the wrong width.
    const { container } = render(<SkeletonDeflist rows={4} className="operations-metrics" />);
    expect(container.querySelector('.operations-metrics')).toBeTruthy();
    expect(container.querySelector('.deflist')).toBeNull();
  });

  it('SkeletonChips renders a wrapping band of pills', () => {
    const { container } = render(<SkeletonChips count={3} />);
    expect(container.querySelectorAll('.skeleton-chips > .skeleton').length).toBe(3);
  });
});

describe('SkeletonRegion', () => {
  it('announces loading politely while marking the subtree busy', () => {
    render(
      <SkeletonRegion>
        <SkeletonTable rows={2} cols={2} />
      </SkeletonRegion>,
    );
    const region = screen.getByRole('status');
    expect(region.getAttribute('aria-busy')).toBe('true');
    // The blocks themselves are aria-hidden, so this text is the only thing a screen
    // reader gets during load — without it the surface is silent.
    expect(region.querySelector('.sr-only')?.textContent).toBe('A carregar…');
  });

  it('accepts a surface-specific label', () => {
    render(
      <SkeletonRegion label="A carregar livros…">
        <Skeleton />
      </SkeletonRegion>,
    );
    expect(screen.getByRole('status').querySelector('.sr-only')?.textContent).toBe(
      'A carregar livros…',
    );
  });

  it('does not expose the decorative blocks to assistive tech', () => {
    const { container } = render(
      <SkeletonRegion>
        <SkeletonList items={2} />
      </SkeletonRegion>,
    );
    // Every skeleton subtree root hides itself; nothing below it is reachable.
    expect(container.querySelector('.dashboard-list')?.getAttribute('aria-hidden')).toBe('true');
  });
});

// Matches the convention in LedgerPage.test.tsx: an indirect dynamic import, since the
// web tsconfig carries no @types/node.
async function themeCss(): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8');
}

describe('will-change budget', () => {
  /** Selectors allowed a permanent promotion hint: small, few, animated on later input. */
  const ALLOWED = ['.ferramentas-subnav__indicator', '.subnav__indicator'];

  async function willChangeSelectors(): Promise<string[]> {
    const css = (await themeCss()).replace(/\/\*[\s\S]*?\*\//g, '');
    return css
      .split('}')
      .filter((block) => /will-change\s*:/.test(block))
      .map((block) => block.slice(0, block.indexOf('{')).trim().replace(/\s+/g, ' '));
  }

  it('keeps will-change off large or heavily repeated elements', async () => {
    const selectors = await willChangeSelectors();
    // Firefox's budget is document surface x 3; once exceeded it ignores every further
    // declaration, so hints on full-bleed or repeated elements disable the whole feature.
    // `.route-transition` nests three deep, `.leather-bg::after` is the full viewport, and
    // `.skeleton` matches dozens of blocks at once.
    for (const banned of ['.route-transition', '.leather-bg::after', '.skeleton']) {
      expect(selectors.some((sel) => sel.includes(banned))).toBe(false);
    }
  });

  it('only the tightly-scoped subnav indicator keeps a hint, and not for width', async () => {
    const selectors = await willChangeSelectors();
    for (const sel of selectors) {
      expect(ALLOWED.some((allowed) => sel.includes(allowed))).toBe(true);
    }
    const css = (await themeCss()).replace(/\/\*[\s\S]*?\*\//g, '');
    // `width` is a layout property and cannot be composited; hinting it promotes for nothing.
    expect(css).not.toMatch(/will-change:[^;]*width/);
  });
});

describe('appear delay', () => {
  it('blocks hold at opacity 0 for ~180ms so a fast load never flashes a skeleton', async () => {
    const css = (await themeCss()).replace(/\/\*[\s\S]*?\*\//g, '');
    const block = /\.skeleton\s*\{([\s\S]*?)\}/.exec(css)?.[1] ?? '';
    // The same `skeleton-appear` hold the indeterminate bar uses. `both` is load-bearing:
    // without it the from-frame is not held through the delay and the hold does nothing.
    const appear = /skeleton-appear\s+\d+ms\s+[\w-]+\s+(\d+)ms\s+both/.exec(block);
    expect(appear, 'no delayed skeleton-appear on .skeleton').toBeTruthy();
    const delay = Number(appear?.[1]);
    expect(delay).toBeGreaterThanOrEqual(150);
    expect(delay).toBeLessThanOrEqual(200);
  });

  it('the table head rule holds too, so it cannot draw alone before the blocks', async () => {
    const css = (await themeCss()).replace(/\/\*[\s\S]*?\*\//g, '');
    const head = /\.skeleton-table__row--head\s*\{([\s\S]*?)\}/.exec(css)?.[1] ?? '';
    expect(head).toMatch(/skeleton-appear/);
  });

  it('no skeleton keyframe animates width — a placeholder must not imply progress', async () => {
    const css = (await themeCss()).replace(/\/\*[\s\S]*?\*\//g, '');
    const frames = /@keyframes\s+skeleton-sweep\s*\{([\s\S]*?)\n\}/.exec(css)?.[1] ?? '';
    expect(frames).toMatch(/background-position/);
    // A block that grew would read as a determinate bar. These waits have no numerator.
    expect(frames).not.toMatch(/width/);
  });
});

describe('reduced motion', () => {
  it('theme.css disables the shimmer sweep under prefers-reduced-motion', async () => {
    // jsdom has no cascade, so assert the stylesheet rule itself: the animated
    // background-image is removed, leaving a static tint.
    const css = await themeCss();
    const block = css.slice(css.indexOf('/* --- Skeleton loaders'));
    const reduced = block.slice(block.indexOf('@media (prefers-reduced-motion: reduce)'));
    expect(reduced).toMatch(/\.skeleton\s*\{[^}]*background-image:\s*none/);
  });
});
