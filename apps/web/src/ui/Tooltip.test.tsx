import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Tooltip, IconButton } from './Tooltip';
import { Pencil } from './icons';

afterEach(cleanup);

describe('Tooltip', () => {
  it('wires aria-describedby from the trigger to the bubble', () => {
    render(
      <Tooltip label="Editar">
        <button type="button">alvo</button>
      </Tooltip>,
    );
    const trigger = screen.getByRole('button', { name: 'alvo' });
    const bubble = screen.getByRole('tooltip');
    expect(bubble.textContent).toBe('Editar');
    expect(trigger.getAttribute('aria-describedby')).toBe(bubble.id);
  });

  it('shows on keyboard focus and hides on blur', () => {
    render(
      <Tooltip label="Editar">
        <button type="button">alvo</button>
      </Tooltip>,
    );
    const trigger = screen.getByRole('button');
    const bubble = screen.getByRole('tooltip');
    expect(bubble.className).not.toContain('is-open');
    fireEvent.focus(trigger);
    expect(bubble.className).toContain('is-open');
    fireEvent.blur(trigger);
    expect(bubble.className).not.toContain('is-open');
  });

  it('shows on hover and hides on pointer-leave', () => {
    render(
      <Tooltip label="Editar">
        <button type="button">alvo</button>
      </Tooltip>,
    );
    const trigger = screen.getByRole('button');
    const bubble = screen.getByRole('tooltip');
    fireEvent.mouseEnter(trigger);
    expect(bubble.className).toContain('is-open');
    fireEvent.mouseLeave(trigger);
    expect(bubble.className).not.toContain('is-open');
  });

  it('dismisses on Escape', () => {
    render(
      <Tooltip label="Editar">
        <button type="button">alvo</button>
      </Tooltip>,
    );
    const trigger = screen.getByRole('button');
    const bubble = screen.getByRole('tooltip');
    fireEvent.focus(trigger);
    expect(bubble.className).toContain('is-open');
    fireEvent.keyDown(trigger, { key: 'Escape' });
    expect(bubble.className).not.toContain('is-open');
  });

  it("preserves the child's own handlers", () => {
    const onFocus = vi.fn();
    render(
      <Tooltip label="Editar">
        <button type="button" onFocus={onFocus}>
          alvo
        </button>
      </Tooltip>,
    );
    fireEvent.focus(screen.getByRole('button'));
    expect(onFocus).toHaveBeenCalledTimes(1);
  });

  it('honours the placement modifier', () => {
    render(
      <Tooltip label="Editar" placement="right">
        <button type="button">alvo</button>
      </Tooltip>,
    );
    expect(screen.getByRole('tooltip').className).toContain('tooltip__bubble--right');
  });
});

describe('IconButton', () => {
  it('exposes its label as the accessible name', () => {
    render(<IconButton icon={<Pencil />} label="Editar" />);
    expect(screen.getByRole('button', { name: 'Editar' })).toBeTruthy();
  });

  it('forwards onClick to the underlying button', () => {
    const onClick = vi.fn();
    render(<IconButton icon={<Pencil />} label="Editar" onClick={onClick} />);
    fireEvent.click(screen.getByRole('button', { name: 'Editar' }));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it('is inert and swallows clicks when disabled', () => {
    const onClick = vi.fn();
    render(<IconButton icon={<Pencil />} label="Editar" disabled onClick={onClick} />);
    const btn = screen.getByRole('button', { name: 'Editar' }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    fireEvent.click(btn);
    expect(onClick).not.toHaveBeenCalled();
  });

  it('defaults to type=button and carries its own tooltip', () => {
    render(<IconButton icon={<Pencil />} label="Editar" />);
    const btn = screen.getByRole('button', { name: 'Editar' });
    expect(btn.getAttribute('type')).toBe('button');
    const bubble = screen.getByRole('tooltip');
    expect(bubble.textContent).toBe('Editar');
    expect(btn.getAttribute('aria-describedby')).toBe(bubble.id);
  });
});
