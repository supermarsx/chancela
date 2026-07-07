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
});
