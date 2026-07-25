import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { useCollectionNavigation } from './CollectionPager';

afterEach(cleanup);

function Harness({ filter = 'all' }: { filter?: string }) {
  const navigation = useCollectionNavigation(filter);
  return (
    <>
      <output aria-label="request">{JSON.stringify(navigation.position)}</output>
      <output aria-label="range-offset">{navigation.displayOffset}</output>
      <button onClick={() => navigation.next(50, 'opaque-cursor', navigation.displayOffset + 50)}>
        cursor
      </button>
      <button onClick={() => navigation.next(50, undefined, navigation.displayOffset + 50)}>
        offset
      </button>
    </>
  );
}

describe('useCollectionNavigation', () => {
  it('uses an opaque cursor without a conflicting offset while advancing the display range', () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole('button', { name: 'cursor' }));

    expect(JSON.parse(screen.getByLabelText('request').textContent ?? '{}')).toEqual({
      cursor: 'opaque-cursor',
    });
    expect(screen.getByLabelText('range-offset').textContent).toBe('50');
  });

  it('falls back to an offset and resets request/range state when filters change', () => {
    const view = render(<Harness />);
    fireEvent.click(screen.getByRole('button', { name: 'offset' }));
    expect(JSON.parse(screen.getByLabelText('request').textContent ?? '{}')).toEqual({
      offset: 50,
    });
    expect(screen.getByLabelText('range-offset').textContent).toBe('50');

    view.rerender(<Harness filter="active" />);
    expect(JSON.parse(screen.getByLabelText('request').textContent ?? '{}')).toEqual({
      offset: 0,
    });
    expect(screen.getByLabelText('range-offset').textContent).toBe('0');
  });

  it('does not resurrect a previous cursor after an A → B → A filter sequence', async () => {
    const view = render(<Harness filter="a" />);
    fireEvent.click(screen.getByRole('button', { name: 'cursor' }));
    expect(JSON.parse(screen.getByLabelText('request').textContent ?? '{}')).toEqual({
      cursor: 'opaque-cursor',
    });

    view.rerender(<Harness filter="b" />);
    await waitFor(() =>
      expect(JSON.parse(screen.getByLabelText('request').textContent ?? '{}')).toEqual({
        offset: 0,
      }),
    );
    view.rerender(<Harness filter="a" />);

    expect(JSON.parse(screen.getByLabelText('request').textContent ?? '{}')).toEqual({
      offset: 0,
    });
    expect(screen.getByLabelText('range-offset').textContent).toBe('0');
  });
});
