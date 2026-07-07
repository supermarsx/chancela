import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { SubNav, type SubNavItem } from './SubNav';

afterEach(cleanup);

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

  it('renders the gliding indicator element', () => {
    const { container } = render(
      <SubNav items={ITEMS} active="a" onSelect={() => {}} ariaLabel="Secções" />,
    );
    expect(container.querySelector('.subnav__indicator')).toBeTruthy();
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
