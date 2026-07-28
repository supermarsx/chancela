/**
 * `SidePanel` behaviour (t88).
 *
 * The three things that make a floating detail pane usable rather than a modal wearing a
 * different shape: it opens onto its own content, Escape gives the keyboard back to the row that
 * opened it, and — unlike `ConfirmActionModal` — it never claims to be a dialog or traps Tab, so
 * the list underneath stays operable while the detail is up.
 *
 * Nothing here asserts on rendered Portuguese: the panel takes its copy as props, so these drive
 * it with fixed English test labels and assert on roles, focus, and structure.
 */
import { describe, expect, it, vi, afterEach } from 'vitest';
import { useState } from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { SidePanel } from './SidePanel';

const LABEL = 'Detail panel';
const CLOSE = 'Close the detail';

afterEach(cleanup);

/**
 * A list of opener rows plus the panel, wired the way the trust catalog wires it: the row sets the
 * selection, the panel is open while a selection exists, and closing clears it.
 */
function Harness({ onClose }: { onClose?: () => void } = {}) {
  const [selected, setSelected] = useState<string | null>(null);
  return (
    <div>
      <button type="button" data-testid="row-a" onClick={() => setSelected('a')}>
        Row A
      </button>
      <button type="button" data-testid="row-b" onClick={() => setSelected('b')}>
        Row B
      </button>
      <SidePanel
        open={selected !== null}
        label={LABEL}
        closeLabel={CLOSE}
        onClose={() => {
          onClose?.();
          setSelected(null);
        }}
      >
        <p data-testid="detail">Detail for {selected}</p>
        <button type="button" data-testid="inside">
          Inside
        </button>
      </SidePanel>
    </div>
  );
}

/** Click a row the way a browser does — pointer interaction focuses the button first. */
function pick(testId: string): HTMLElement {
  const row = screen.getByTestId(testId);
  row.focus();
  fireEvent.click(row);
  return row;
}

describe('SidePanel', () => {
  it('renders nothing at all while closed', () => {
    render(
      <SidePanel open={false} label={LABEL} closeLabel={CLOSE} onClose={() => {}}>
        <p data-testid="detail">Detail</p>
      </SidePanel>,
    );
    expect(screen.queryByRole('complementary')).toBeNull();
    // Closed means the children are not rendered either, so a detail query never fires.
    expect(screen.queryByTestId('detail')).toBeNull();
  });

  it('opens as a named complementary region and moves focus into the panel', () => {
    render(<Harness />);
    const row = pick('row-a');

    const panel = screen.getByRole('complementary', { name: LABEL });
    expect(panel.contains(screen.getByTestId('detail'))).toBe(true);
    expect(document.activeElement).toBe(panel);
    expect(document.activeElement).not.toBe(row);
  });

  it('is a panel, not a dialog: no dialog role, no aria-modal, no trapped Tab', () => {
    render(<Harness />);
    pick('row-a');

    const panel = screen.getByRole('complementary', { name: LABEL });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(panel.getAttribute('aria-modal')).toBeNull();
    expect(document.querySelector('.modal-backdrop')).toBeNull();
    // A focus trap would swallow Tab from the last focusable descendant. Nothing here listens for
    // it, so the key event reaches the panel undefended and the list stays reachable.
    screen.getByTestId('inside').focus();
    const tab = fireEvent.keyDown(screen.getByTestId('inside'), { key: 'Tab' });
    expect(tab).toBe(true);
    expect(document.activeElement).toBe(screen.getByTestId('inside'));
    // And the rows behind it are still in the document, interactive, and outside the panel.
    expect(panel.contains(screen.getByTestId('row-b'))).toBe(false);
  });

  it('closes on Escape and returns focus to the row that opened it', () => {
    const onClose = vi.fn();
    render(<Harness onClose={onClose} />);
    const row = pick('row-a');
    expect(screen.getByRole('complementary', { name: LABEL })).toBeTruthy();

    fireEvent.keyDown(document, { key: 'Escape' });

    expect(onClose).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('complementary')).toBeNull();
    expect(document.activeElement).toBe(row);
  });

  it('closes from the close control and returns focus to the opener', () => {
    render(<Harness />);
    const row = pick('row-a');

    fireEvent.click(screen.getByRole('button', { name: CLOSE }));

    expect(screen.queryByRole('complementary')).toBeNull();
    expect(document.activeElement).toBe(row);
  });

  it('follows the selection: picking a second row keeps the panel open and re-aims Escape', () => {
    render(<Harness />);
    pick('row-a');
    // The list stays operable while the panel is up — no close needed to pick again.
    const rowB = pick('row-b');
    expect(screen.getByRole('complementary', { name: LABEL })).toBeTruthy();
    expect(screen.getByTestId('detail').textContent).toBe('Detail for b');

    fireEvent.keyDown(document, { key: 'Escape' });

    // Focus goes back to the row the operator last used, not to the one that first opened it.
    expect(document.activeElement).toBe(rowB);
  });

  it('ignores other keys and survives an opener that has gone away', () => {
    const onClose = vi.fn();
    const { unmount } = render(<Harness onClose={onClose} />);
    pick('row-a');

    fireEvent.keyDown(document, { key: 'Enter' });
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole('complementary', { name: LABEL })).toBeTruthy();

    // Unmounting the whole surface disconnects the opener; restoring focus must not throw.
    expect(() => unmount()).not.toThrow();
    expect(document.querySelector('.side-panel')).toBeNull();
  });
});
