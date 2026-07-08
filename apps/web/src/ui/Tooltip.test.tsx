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

  it('portals the bubble to document.body so no ancestor can clip or under-stack it', () => {
    // A clipping/stacking ancestor like the real `.route-transition` container.
    render(
      <div className="route-transition" style={{ overflow: 'hidden', transform: 'translateZ(0)' }}>
        <Tooltip label="Editar">
          <button type="button">alvo</button>
        </Tooltip>
      </div>,
    );
    const bubble = screen.getByRole('tooltip');
    // The bubble is a direct child of <body> (portaled out), NOT nested under the trigger's
    // `.tooltip` wrapper nor the clipping container.
    expect(bubble.parentElement).toBe(document.body);
    expect(document.querySelector('.tooltip')?.contains(bubble)).toBe(false);
    expect(document.querySelector('.route-transition')?.contains(bubble)).toBe(false);
    // It still carries the tooltip class the top-of-scale z-index is bound to in the theme.
    expect(bubble.className).toContain('tooltip__bubble');
    // …and the aria-describedby association survives the portal (IDs are document-global).
    expect(screen.getByRole('button', { name: 'alvo' }).getAttribute('aria-describedby')).toBe(
      bubble.id,
    );
  });

  it('clamps a wide wrapped bubble so its centred edge stays within the viewport', () => {
    render(
      <Tooltip label="Uma etiqueta muito comprida que deveria quebrar em várias linhas">
        <button type="button">alvo</button>
      </Tooltip>,
    );
    const trigger = screen.getByRole('button');
    const bubble = screen.getByRole('tooltip');
    const wrapper = document.querySelector('.tooltip') as HTMLElement;

    const origWidth = window.innerWidth;
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 1000 });
    const rect = (r: Partial<DOMRect>) => () => ({ toJSON: () => ({}), ...r }) as DOMRect;
    // Trigger hugging the right edge; its centre is at 1000 (980 + 40/2). A 320px-wide
    // wrapped bubble centred there would spill off-screen (right edge at 1160).
    wrapper.getBoundingClientRect = rect({
      left: 980,
      right: 1020,
      width: 40,
      top: 40,
      height: 20,
    });
    bubble.getBoundingClientRect = rect({ left: 0, right: 320, width: 320, top: 0, height: 40 });

    fireEvent.focus(trigger);

    // Clamped to innerWidth - margin(8) - halfWidth(160) = 832, so the box's right edge lands
    // at 992 (< 1000) — fully visible instead of overflowing.
    expect(bubble.style.left).toBe('832px');
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: origWidth });
  });

  it('adds the prose modifier for the wrapping-sentence variant (FieldHelp)', () => {
    render(
      <Tooltip label="Explicação longa" variant="prose">
        <button type="button">alvo</button>
      </Tooltip>,
    );
    expect(screen.getByRole('tooltip').className).toContain('tooltip__bubble--prose');
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
