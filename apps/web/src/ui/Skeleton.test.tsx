import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import { Skeleton, SkeletonCards, SkeletonTable } from './Skeleton';

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
});
