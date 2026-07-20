import { describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach } from 'vitest';
import { Loading } from './index';
import { Wrapper } from '../test/utils';

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

function renderLoading(ui: React.ReactElement) {
  return render(<Wrapper>{ui}</Wrapper>);
}

afterEach(cleanup);

describe('Loading', () => {
  it('announces the wait as a polite status region carrying real label text', () => {
    renderLoading(<Loading />);

    const region = screen.getByRole('status');
    expect(region.classList.contains('loading')).toBe(true);
    expect(region.getAttribute('aria-busy')).toBe('true');
    // The label is real text, not a title attribute: a purely visual bar is not a loading
    // state for a screen-reader user.
    expect(region.textContent).toContain('A carregar…');
  });

  it('keeps a caller-supplied label instead of the generic one', () => {
    renderLoading(<Loading label="A pesquisar…" />);
    expect(screen.getByRole('status').textContent).toContain('A pesquisar…');
    expect(screen.queryByText('A carregar…')).toBeNull();
  });

  it('hides the bar itself from assistive tech — it decorates the label', () => {
    renderLoading(<Loading />);
    const track = document.querySelector('.loading__track');
    expect(track?.getAttribute('aria-hidden')).toBe('true');
    expect(track?.querySelector('.loading__indicator')).toBeTruthy();
  });

  it('drops its own live region when the caller already is one', () => {
    // Nesting two role="status" elements announces the same wait twice; the auth gate's
    // boot panel is the real caller that needs this.
    renderLoading(<Loading region={false} />);
    expect(screen.queryByRole('status')).toBeNull();
    expect(document.querySelector('.loading')?.hasAttribute('aria-busy')).toBe(false);
    // …but the bar and its label are still rendered.
    expect(document.querySelector('.loading__indicator')).toBeTruthy();
    expect(document.body.textContent).toContain('A carregar…');
  });

  it('is indeterminate: no ARIA progress semantics and no percentage anywhere', async () => {
    renderLoading(<Loading />);
    // A determinate bar would need a genuine numerator. We do not have one for these
    // waits, so the markup must not claim progress it cannot substantiate.
    expect(screen.queryByRole('progressbar')).toBeNull();
    const region = screen.getByRole('status');
    for (const attr of ['aria-valuenow', 'aria-valuemin', 'aria-valuemax']) {
      expect(region.querySelector(`[${attr}]`)).toBeNull();
    }

    const css = await themeCss();
    // The sweep animates transform between two off-track positions; it never animates a
    // width, which is what a fake-progress bar would do.
    const sweep = block(css, /@keyframes loading-sweep\s*\{([\s\S]*?)\n\}/);
    expect(sweep).toContain('translateX');
    expect(sweep).not.toContain('width');
  });

  it('delays its appearance so a fast response never flashes a bar', async () => {
    const css = await themeCss();
    const rule = block(css, /\n\.loading \{([^}]*)\}/);
    // `both` fill mode holds the from-frame (opacity 0) through the delay.
    expect(rule).toContain('animation: loading-appear 140ms ease-out 180ms both;');
    expect(block(css, /@keyframes loading-appear\s*\{([\s\S]*?)\n\}/)).toContain('opacity: 0');
  });

  it('degrades to a static filled track under prefers-reduced-motion', async () => {
    const css = await themeCss();
    // The global reduced-motion block zeroes animation-duration, which would freeze the
    // sweep at its first frame — an indicator parked off the left edge, i.e. an empty
    // track. The override must therefore re-lay-out the indicator, not merely stop it.
    const reduced = block(
      css,
      /@media \(prefers-reduced-motion: reduce\) \{\s*\.loading__indicator \{([^}]*)\}/,
    );
    expect(reduced).toContain('animation: none;');
    expect(reduced).toContain('position: static;');
    expect(reduced).toContain('width: 100%;');
    // Regression: dropping `position: absolute` returns the span to `display: inline`,
    // where `width` does not apply. Without this the reduced-motion bar measured 0px wide
    // and the track rendered empty — caught in a real browser, not in jsdom.
    expect(reduced).toContain('display: block;');
  });

  it('styles the bar from theme tokens only — no literal colours, no pixel sizes', async () => {
    const css = await themeCss();
    const rules = [
      block(css, /\n\.loading \{([^}]*)\}/),
      block(css, /\n\.loading__track \{([^}]*)\}/),
      block(css, /\n\.loading__indicator \{([^}]*)\}/),
      block(css, /\n\.route-loading \{([^}]*)\}/),
    ].join('\n');
    expect(rules).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(rules).not.toMatch(/\brgba?\(/);
    expect(rules).not.toMatch(/\d+px/);
    expect(rules).toContain('var(--accent)');
  });
});
