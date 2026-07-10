import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { SubNav, type SubNavItem } from './SubNav';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const ITEMS: SubNavItem<'a' | 'b' | 'c'>[] = [
  { id: 'a', label: 'Alpha' },
  { id: 'b', label: 'Beta' },
  { id: 'c', label: 'Gamma' },
];

/** Fresh-identity items each call, to churn props in the regression test. */
const mk = (n: number): SubNavItem<'a' | 'b'>[] => [
  { id: 'a', label: `Alpha ${n}` },
  { id: 'b', label: 'Beta' },
];

function setScrollMetrics(
  el: HTMLElement,
  metrics: { scrollLeft: number; clientWidth: number; scrollWidth: number },
) {
  Object.defineProperties(el, {
    scrollLeft: { configurable: true, writable: true, value: metrics.scrollLeft },
    clientWidth: { configurable: true, value: metrics.clientWidth },
    scrollWidth: { configurable: true, value: metrics.scrollWidth },
  });
}

function expectTooltip(control: HTMLElement, label: string) {
  const tooltipIds = (control.getAttribute('aria-describedby') ?? '')
    .split(/\s+/)
    .filter(Boolean);
  const tooltip = tooltipIds
    .map((id) => document.getElementById(id))
    .find((node) => node?.getAttribute('role') === 'tooltip' && node.textContent === label);

  expect(tooltip?.textContent).toBe(label);
}

describe('SubNav', () => {
  it('renders one pressed button per item and reports the selection', () => {
    const onSelect = vi.fn();
    render(<SubNav items={ITEMS} active="b" onSelect={onSelect} ariaLabel="Secções" />);

    expect(screen.getByRole('group', { name: 'Secções' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Beta' }).getAttribute('aria-pressed')).toBe('true');
    expect(screen.getByRole('button', { name: 'Alpha' }).getAttribute('aria-pressed')).toBe(
      'false',
    );

    fireEvent.click(screen.getByRole('button', { name: 'Gamma' }));
    expect(onSelect).toHaveBeenCalledWith('c');
  });

  it('renders a decorative leading icon only for items that carry one (backward-compat)', () => {
    const items: SubNavItem<'a' | 'b'>[] = [
      { id: 'a', label: 'Alpha', icon: <svg data-testid="glyph" /> },
      { id: 'b', label: 'Beta' },
    ];
    render(<SubNav items={items} active="a" onSelect={() => {}} ariaLabel="Secções" />);

    // The label is unchanged and the button still resolves by its accessible name.
    const withIcon = screen.getByRole('button', { name: 'Alpha' });
    const iconSpan = withIcon.querySelector('.subnav__icon');
    expect(iconSpan).toBeTruthy();
    expect(iconSpan?.getAttribute('aria-hidden')).toBe('true');

    // An item without an icon renders exactly as before — no decorative span.
    const withoutIcon = screen.getByRole('button', { name: 'Beta' });
    expect(withoutIcon.querySelector('.subnav__icon')).toBeNull();
  });

  it('can render an icon-only item with an accessible name and tooltip', () => {
    const onSelect = vi.fn();
    const items: SubNavItem<'a' | 'b'>[] = [
      {
        id: 'a',
        label: 'Alpha',
        tooltipLabel: 'Alpha',
        iconOnly: true,
        icon: <svg data-testid="glyph" />,
      },
      { id: 'b', label: 'Beta' },
    ];
    render(<SubNav items={items} active="a" onSelect={onSelect} ariaLabel="Secções" />);

    const iconOnly = screen.getByRole('button', { name: 'Alpha' });
    expect(iconOnly.className).toContain('subnav__btn--iconOnly');
    expect(iconOnly.textContent).not.toContain('Alpha');
    expect(iconOnly.querySelector('.subnav__icon')?.getAttribute('aria-hidden')).toBe('true');

    const tooltipIds = (iconOnly.getAttribute('aria-describedby') ?? '')
      .split(/\s+/)
      .filter(Boolean);
    const tooltip = tooltipIds
      .map((id) => document.getElementById(id))
      .find((node) => node?.getAttribute('role') === 'tooltip' && node.textContent === 'Alpha');
    expect(tooltip?.textContent).toBe('Alpha');

    fireEvent.click(iconOnly);
    expect(onSelect).toHaveBeenCalledWith('a');
  });

  it('renders the gliding indicator element', () => {
    const { container } = render(
      <SubNav items={ITEMS} active="a" onSelect={() => {}} ariaLabel="Secções" />,
    );
    expect(container.querySelector('.subnav__indicator')).toBeTruthy();
  });

  it('exposes only usable scroll arrows for the current overflow edge', () => {
    render(<SubNav items={ITEMS} active="a" onSelect={() => {}} ariaLabel="Secções" />);
    const strip = screen.getByRole('group', { name: 'Secções' });

    expect(screen.queryByRole('button', { name: 'Secções: scroll left' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Secções: scroll right' })).toBeNull();

    setScrollMetrics(strip, { scrollLeft: 0, clientWidth: 100, scrollWidth: 300 });
    fireEvent.scroll(strip);

    expect(screen.queryByRole('button', { name: 'Secções: scroll left' })).toBeNull();
    const right = screen.getByRole('button', { name: 'Secções: scroll right' });
    expect(right).toBeTruthy();
    expectTooltip(right, 'Secções: scroll right');

    strip.scrollLeft = 200;
    fireEvent.scroll(strip);

    const left = screen.getByRole('button', { name: 'Secções: scroll left' });
    expect(left).toBeTruthy();
    expectTooltip(left, 'Secções: scroll left');
    expect(screen.queryByRole('button', { name: 'Secções: scroll right' })).toBeNull();
  });

  it('auto-scrolls smoothly while scroll arrows are hovered, focused, or pressed', () => {
    let nextFrame: FrameRequestCallback | null = null;
    let frameId = 0;
    vi.spyOn(window, 'requestAnimationFrame').mockImplementation((cb) => {
      nextFrame = cb;
      frameId += 1;
      return frameId;
    });
    vi.spyOn(window, 'cancelAnimationFrame').mockImplementation(() => {});

    render(<SubNav items={ITEMS} active="a" onSelect={() => {}} ariaLabel="Secções" />);
    const strip = screen.getByRole('group', { name: 'Secções' });
    setScrollMetrics(strip, { scrollLeft: 0, clientWidth: 100, scrollWidth: 300 });
    fireEvent.scroll(strip);

    const runFrame = (time: number) => {
      const frame = nextFrame;
      nextFrame = null;
      expect(frame).toBeTruthy();
      act(() => {
        frame?.(time);
      });
    };
    const rightArrow = () => screen.getByRole('button', { name: 'Secções: scroll right' });
    const stopAndAssertStill = (event: () => void, time: number) => {
      event();
      const stoppedAt = strip.scrollLeft;
      runFrame(time);
      expect(strip.scrollLeft).toBe(stoppedAt);
    };

    fireEvent.mouseEnter(rightArrow());
    runFrame(16);
    expect(strip.scrollLeft).toBeGreaterThan(0);
    stopAndAssertStill(() => fireEvent.mouseLeave(rightArrow()), 32);

    strip.scrollLeft = 0;
    fireEvent.scroll(strip);
    fireEvent.focus(rightArrow());
    runFrame(48);
    expect(strip.scrollLeft).toBeGreaterThan(0);
    stopAndAssertStill(() => fireEvent.blur(rightArrow()), 64);

    strip.scrollLeft = 0;
    fireEvent.scroll(strip);
    fireEvent.pointerDown(rightArrow());
    runFrame(80);
    expect(strip.scrollLeft).toBeGreaterThan(0);
    stopAndAssertStill(() => fireEvent.pointerUp(rightArrow()), 96);
  });

  it('cancels hover autoscroll and hides arrows when overflow disappears', () => {
    let nextFrame: FrameRequestCallback | null = null;
    vi.spyOn(window, 'requestAnimationFrame').mockImplementation((cb) => {
      nextFrame = cb;
      return 1;
    });
    const cancel = vi.spyOn(window, 'cancelAnimationFrame').mockImplementation(() => {});

    render(<SubNav items={ITEMS} active="a" onSelect={() => {}} ariaLabel="Secções" />);
    const strip = screen.getByRole('group', { name: 'Secções' });
    setScrollMetrics(strip, { scrollLeft: 0, clientWidth: 100, scrollWidth: 300 });
    fireEvent.scroll(strip);

    fireEvent.mouseEnter(screen.getByRole('button', { name: 'Secções: scroll right' }));
    expect(nextFrame).toBeTruthy();

    setScrollMetrics(strip, { scrollLeft: 0, clientWidth: 300, scrollWidth: 300 });
    fireEvent.scroll(strip);

    expect(screen.queryByRole('button', { name: 'Secções: scroll left' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Secções: scroll right' })).toBeNull();
    expect(cancel).toHaveBeenCalledWith(1);

    const frame = nextFrame as unknown as FrameRequestCallback | null;
    nextFrame = null;
    act(() => {
      if (frame) frame(16);
    });
    expect(strip.scrollLeft).toBe(0);
  });

  // Regression for the user-reported "Maximum update depth exceeded" crash: the segmented
  // pill's indicator effect must depend only on stable values (active + locale, never the
  // per-render `t`) and guard setState by geometry. The buggy pattern loops on mount /
  // re-render and React throws here. Churning `items`/handler identity must be inert.
  it('does not enter an infinite update loop as props churn on re-render', () => {
    const { rerender } = render(
      <SubNav items={mk(0)} active="a" onSelect={() => {}} ariaLabel="Secções" />,
    );
    expect(() => {
      for (let i = 1; i <= 30; i++) {
        rerender(<SubNav items={mk(i)} active="a" onSelect={() => {}} ariaLabel="Secções" />);
      }
    }).not.toThrow();
    expect(screen.getByRole('button', { name: 'Beta' })).toBeTruthy();
  });
});
