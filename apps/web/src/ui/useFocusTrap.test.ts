import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render } from '@testing-library/react';
import { createElement, useRef, type ReactNode } from 'react';
import { useFocusTrap } from './useFocusTrap';

afterEach(cleanup);

/** A minimal dialog that attaches the trap to its container and renders N buttons. */
function TrapDialog({ active, labels }: { active: boolean; labels: string[] }) {
  const ref = useFocusTrap<HTMLDivElement>(active);
  return createElement(
    'div',
    { ref, 'data-testid': 'container' },
    ...labels.map((label): ReactNode => createElement('button', { key: label }, label)),
  );
}

/** Wraps the dialog with an outside button that owns focus before the trap engages. */
function Harness({ open, labels }: { open: boolean; labels: string[] }) {
  const outsideRef = useRef<HTMLButtonElement>(null);
  return createElement(
    'div',
    null,
    createElement('button', { ref: outsideRef, 'data-testid': 'outside' }, 'outside'),
    open ? createElement(TrapDialog, { active: true, labels }) : null,
  );
}

describe('useFocusTrap', () => {
  it('moves focus into the container on activation', () => {
    const { getByText } = render(
      createElement(TrapDialog, { active: true, labels: ['First', 'Second'] }),
    );
    expect(document.activeElement).toBe(getByText('First'));
  });

  it('restores focus to the pre-open element when the trap unmounts', () => {
    const { getByTestId, getByText, rerender } = render(
      createElement(Harness, { open: false, labels: ['First', 'Second'] }),
    );

    // Focus an element outside the (not-yet-open) dialog.
    const outside = getByTestId('outside') as HTMLButtonElement;
    outside.focus();
    expect(document.activeElement).toBe(outside);

    // Opening the dialog pulls focus inside…
    rerender(createElement(Harness, { open: true, labels: ['First', 'Second'] }));
    expect(document.activeElement).toBe(getByText('First'));

    // …and closing it (unmount) restores focus to where it was.
    rerender(createElement(Harness, { open: false, labels: ['First', 'Second'] }));
    expect(document.activeElement).toBe(outside);
  });

  it('wraps Tab from the last focusable to the first', () => {
    const { getByText, getByTestId } = render(
      createElement(TrapDialog, { active: true, labels: ['First', 'Second', 'Third'] }),
    );
    const first = getByText('First');
    const last = getByText('Third');

    last.focus();
    fireEvent.keyDown(getByTestId('container'), { key: 'Tab' });
    expect(document.activeElement).toBe(first);
  });

  it('wraps Shift+Tab from the first focusable to the last', () => {
    const { getByText, getByTestId } = render(
      createElement(TrapDialog, { active: true, labels: ['First', 'Second', 'Third'] }),
    );
    const first = getByText('First');
    const last = getByText('Third');

    first.focus();
    fireEvent.keyDown(getByTestId('container'), { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(last);
  });
});
