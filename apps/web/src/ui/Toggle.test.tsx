import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Toggle } from './index';

afterEach(cleanup);

describe('Toggle', () => {
  it('exposes a labelled switch reflecting the checked state', () => {
    render(<Toggle label="Textura de couro nos botões" checked onChange={() => {}} />);
    const sw = screen.getByRole('switch', { name: 'Textura de couro nos botões' });
    expect((sw as HTMLInputElement).checked).toBe(true);
  });

  it('reports the next value on toggle', () => {
    const onChange = vi.fn();
    render(<Toggle label="Textura de couro nos botões" checked={false} onChange={onChange} />);
    fireEvent.click(screen.getByRole('switch'));
    expect(onChange).toHaveBeenCalledWith(true);
  });

  it('marks the switch disabled so the control is inert', () => {
    render(<Toggle label="Exigir" checked={false} disabled onChange={() => {}} />);
    const sw = screen.getByRole('switch') as HTMLInputElement;
    expect(sw.disabled).toBe(true);
    // The label carries the disabled affordance for styling.
    expect(sw.closest('.toggle')?.className).toContain('toggle--disabled');
  });

  /**
   * t90 puts a settings-row toggle's text in the grid's label column and its switch in the
   * control column. That is done entirely with grid tracks precisely so this stays true: the
   * `<label>` still WRAPS the input, so the accessible name survives without an `htmlFor`.
   * Splitting the text out into a sibling element would render identically and silently leave
   * an unnamed switch, so the association is asserted rather than eyeballed.
   */
  it('keeps its accessible name when laid out as a settings row', () => {
    render(
      <div className="form settings-rows">
        <Toggle label="Textura de couro no fundo" checked={false} onChange={() => {}} />
      </div>,
    );
    const sw = screen.getByRole('switch', { name: 'Textura de couro no fundo' });
    // The wrapping label — not a detached sibling — is what names it.
    expect(sw.closest('label')?.className).toContain('toggle');
    expect(screen.getByLabelText('Textura de couro no fundo')).toBe(sw);
  });
});
