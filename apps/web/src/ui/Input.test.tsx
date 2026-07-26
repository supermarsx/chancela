import { useState } from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Input } from './index';

function ControlledDate(props: {
  min?: string;
  max?: string;
  disabled?: boolean;
  readOnly?: boolean;
}) {
  const [value, setValue] = useState('');
  return (
    <Input
      aria-label="Data"
      type="date"
      value={value}
      min={props.min}
      max={props.max}
      disabled={props.disabled}
      readOnly={props.readOnly}
      onChange={(event) => setValue(event.target.value)}
    />
  );
}

describe('Input date action', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(2026, 6, 26, 12, 0, 0));
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it('sets a controlled civil-date input to the local current day', () => {
    render(<ControlledDate />);

    fireEvent.click(screen.getByRole('button', { name: 'Definir para hoje' }));

    expect((screen.getByLabelText('Data') as HTMLInputElement).value).toBe('2026-07-26');
    expect(document.activeElement).toBe(screen.getByLabelText('Data'));
  });

  it('keeps the action adjacent, keyboard-operable and disabled with the input', () => {
    const { container, rerender } = render(<ControlledDate disabled />);
    const button = screen.getByRole('button', { name: 'Definir para hoje' });

    expect(container.querySelector('.date-input > input + .tooltip .date-input__today')).toBe(
      button,
    );
    expect((button as HTMLButtonElement).disabled).toBe(true);

    rerender(<ControlledDate readOnly />);
    expect(
      (screen.getByRole('button', { name: 'Definir para hoje' }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it('disables today when it falls outside the native min/max interval', () => {
    const { rerender } = render(<ControlledDate min="2026-07-27" />);
    expect(
      (screen.getByRole('button', { name: 'Definir para hoje' }) as HTMLButtonElement).disabled,
    ).toBe(true);

    rerender(<ControlledDate max="2026-07-25" />);
    expect(
      (screen.getByRole('button', { name: 'Definir para hoje' }) as HTMLButtonElement).disabled,
    ).toBe(true);

    rerender(<ControlledDate min="2026-07-01" max="2026-07-31" />);
    expect(
      (screen.getByRole('button', { name: 'Definir para hoje' }) as HTMLButtonElement).disabled,
    ).toBe(false);
  });

  it('does not add an action to non-date inputs', () => {
    render(<Input aria-label="Nome" value="" onChange={() => undefined} />);

    expect(screen.queryByRole('button', { name: 'Definir para hoje' })).toBeNull();
    expect(screen.getByLabelText('Nome').classList.contains('control')).toBe(true);
  });
});
