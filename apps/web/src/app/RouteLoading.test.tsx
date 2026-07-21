/**
 * The route/boot wait, after the indeterminate bar was removed (t81).
 *
 * These are the contracts the deleted `ui/Loading.test.tsx` held, repointed onto the
 * skeleton that replaced the bar. They are asserted here rather than in `ui/` because the
 * bar was a shared primitive and its replacement is not: each surface now skeletons its own
 * shape, and the route fallback is the one every operator sees most often.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { RouteLoading } from './RouteLoading';
import { AuthGate } from '../features/session/AuthGate';
import { Wrapper } from '../test/utils';

afterEach(cleanup);

async function themeCss(): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8').replace(/\r\n/g, '\n');
}

/** The declaration block of the first rule whose selector matches, comments stripped. */
function block(css: string, selector: RegExp): string {
  return (css.replace(/\/\*[\s\S]*?\*\//g, '').match(selector)?.[1] ?? '').trim();
}

describe('RouteLoading', () => {
  it('announces the wait as a polite busy region without a visible caption', () => {
    render(
      <Wrapper>
        <RouteLoading />
      </Wrapper>,
    );
    const region = screen.getByRole('status');
    expect(region.getAttribute('aria-busy')).toBe('true');
    // The announcement survives the bar's removal — but only as visually-hidden text. A
    // skeleton that needs a caption explaining it is loading has failed at its one job.
    const announcement = region.querySelector('.sr-only');
    expect(announcement?.textContent).toBe('A carregar…');
    expect(region.textContent).toBe('A carregar…');
  });

  it('skeletons the page frame every route shares, not a generic box', () => {
    const { container } = render(
      <Wrapper>
        <RouteLoading />
      </Wrapper>,
    );
    // Header block (crumb, title, lede) over a real `.panel` — the shape the resolved page
    // will occupy, so the content does not jump when the chunk lands.
    expect(container.querySelector('.panel')).toBeTruthy();
    expect(container.querySelectorAll('.skeleton').length).toBeGreaterThan(4);
  });

  it('hides the placeholder blocks from assistive tech', () => {
    const { container } = render(
      <Wrapper>
        <RouteLoading />
      </Wrapper>,
    );
    for (const el of Array.from(container.querySelectorAll('.skeleton'))) {
      // Decorative by design: the region's status text is the announcement, not the blocks.
      expect(el.getAttribute('aria-hidden')).toBe('true');
    }
  });

  it('claims no progress it cannot substantiate', async () => {
    render(
      <Wrapper>
        <RouteLoading />
      </Wrapper>,
    );
    // A determinate indicator would need a genuine numerator; we have none for these waits.
    expect(screen.queryByRole('progressbar')).toBeNull();
    const region = screen.getByRole('status');
    for (const attr of ['aria-valuenow', 'aria-valuemin', 'aria-valuemax']) {
      expect(region.querySelector(`[${attr}]`)).toBeNull();
    }
    const css = await themeCss();
    // The shimmer moves a gradient; it never grows a box, which is what fake progress does.
    const sweep = block(css, /@keyframes skeleton-sweep\s*\{([\s\S]*?)\n\}/);
    expect(sweep).toContain('background-position');
    expect(sweep).not.toContain('width');
  });

  it('styles the placeholders from theme tokens only — no literal colours or pixel sizes', async () => {
    const css = await themeCss();
    const rules = [
      block(css, /\n\.skeleton \{([^}]*)\}/),
      block(css, /\n\.skeleton-table__row \{([^}]*)\}/),
      block(css, /\n\.skeleton-table__row--head \{([^}]*)\}/),
      block(css, /\n\.skeleton-chips \{([^}]*)\}/),
    ].join('\n');
    expect(rules).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(rules).not.toMatch(/\brgba?\(/);
    // Sizes must be relative. `border-width` is exempt and only that: a hairline rule is a
    // device pixel by intent, and the table head's 2px matches the real `<Table>` head.
    expect(rules.replace(/border[^;]*;/g, '')).not.toMatch(/\d+px/);
    expect(rules).toContain('var(--accent)');
  });

  it('leaves no rule behind for the removed bar', async () => {
    const css = await themeCss();
    // Dead CSS describing a component that no longer exists is exactly the artifact this
    // change set out to remove; assert it cannot creep back.
    for (const gone of ['.loading', '.route-loading', 'loading-sweep']) {
      expect(css).not.toContain(gone);
    }
  });
});

describe('AuthGate boot', () => {
  it('skeletons the boot panel and announces it exactly once', () => {
    render(
      <Wrapper>
        <AuthGate>
          <p>app</p>
        </AuthGate>
      </Wrapper>,
    );
    // One live region, not two: the boot panel IS the region, so nothing nested inside it
    // may announce the same wait a second time. (This is the contract the removed
    // `region={false}` prop used to carry.)
    const regions = screen.getAllByRole('status');
    expect(regions.length).toBe(1);
    expect(regions[0].getAttribute('aria-busy')).toBe('true');
    expect(regions[0].querySelector('.skeleton')).toBeTruthy();
  });
});
