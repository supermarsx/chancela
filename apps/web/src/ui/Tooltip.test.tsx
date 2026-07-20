import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Tooltip, IconButton, TooltipText } from './Tooltip';
import { Pencil } from './icons';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

// Same indirect dynamic import as Stepper.test.tsx / Skeleton.test.tsx: the web tsconfig
// carries no @types/node.
async function themeCss(): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8').replace(/\r\n/g, '\n');
}

/** Every `.tooltip*` rule body in theme.css, with comments stripped. */
function tooltipRules(css: string): string {
  const withoutComments = css.replace(/\/\*[\s\S]*?\*\//g, '');
  return (withoutComments.match(/^\.tooltip[^{}]*\{[^}]*\}/gm) ?? []).join('\n');
}

/** Force the overflow probe in `useIsClipped` to report an ellipsised box (jsdom is 0×0). */
function mockClipped() {
  vi.spyOn(HTMLElement.prototype, 'scrollWidth', 'get').mockReturnValue(400);
  vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(120);
}

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

  it('keeps focus on the trigger when Escape dismisses, and does not re-open by itself', () => {
    render(
      <Tooltip label="Editar">
        <button type="button">alvo</button>
      </Tooltip>,
    );
    const trigger = screen.getByRole('button');
    const bubble = screen.getByRole('tooltip');
    trigger.focus();
    fireEvent.focus(trigger);
    expect(bubble.className).toContain('is-open');

    fireEvent.keyDown(trigger, { key: 'Escape' });
    expect(bubble.className).not.toContain('is-open');
    // Escape dismisses the bubble, NOT the focus. A keyboard operator who reads a hint and
    // presses Escape must still be on the control they were about to activate — otherwise
    // dismissing a passive hint silently throws them back to the top of the document.
    expect(document.activeElement).toBe(trigger);
    // …and the still-focused trigger must not re-announce it on the next tick, or Escape
    // would be a no-op for anyone navigating by keyboard.
    fireEvent.mouseLeave(trigger);
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

  it('flips to the opposite side when the requested one has no room', () => {
    render(
      <Tooltip label="Editar" placement="top">
        <button type="button">alvo</button>
      </Tooltip>,
    );
    const trigger = screen.getByRole('button');
    const bubble = screen.getByRole('tooltip');
    const wrapper = document.querySelector('.tooltip') as HTMLElement;
    const rect = (r: Partial<DOMRect>) => () => ({ toJSON: () => ({}), ...r }) as DOMRect;

    Object.defineProperty(window, 'innerHeight', { configurable: true, value: 800 });
    // Trigger pinned to the very top: only 4px above it, but plenty below.
    wrapper.getBoundingClientRect = rect({ left: 100, right: 140, width: 40, top: 4, bottom: 24 });
    bubble.getBoundingClientRect = rect({ width: 120, height: 40 });

    fireEvent.focus(trigger);

    // A `top` bubble would hang off the viewport, so it renders below instead.
    expect(bubble.className).toContain('tooltip__bubble--bottom');
    expect(bubble.className).not.toContain('tooltip__bubble--top');
  });

  it('keeps the requested side when it fits', () => {
    render(
      <Tooltip label="Editar" placement="top">
        <button type="button">alvo</button>
      </Tooltip>,
    );
    const trigger = screen.getByRole('button');
    const bubble = screen.getByRole('tooltip');
    const wrapper = document.querySelector('.tooltip') as HTMLElement;
    const rect = (r: Partial<DOMRect>) => () => ({ toJSON: () => ({}), ...r }) as DOMRect;

    Object.defineProperty(window, 'innerHeight', { configurable: true, value: 800 });
    wrapper.getBoundingClientRect = rect({ left: 100, right: 140, width: 40, top: 400, bottom: 420 });
    bubble.getBoundingClientRect = rect({ width: 120, height: 40 });

    fireEvent.focus(trigger);
    expect(bubble.className).toContain('tooltip__bubble--top');
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

describe('Tooltip theming', () => {
  it('drives every colour from a token — no hex/rgb()/hsl() literals in the tooltip CSS', async () => {
    const rules = tooltipRules(await themeCss());
    // Guard the guard: if the selector match ever silently returns nothing, the assertions
    // below would pass vacuously.
    expect(rules).toContain('.tooltip__bubble');
    expect(rules).toContain('var(--');

    expect(rules).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(rules).not.toMatch(/\brgba?\(/);
    expect(rules).not.toMatch(/\bhsla?\(/);
    // A themed bubble must survive a theme swap: colour comes only from custom properties.
    for (const decl of rules.match(/^\s*(background|color|border|box-shadow):[^;]+;/gm) ?? []) {
      expect(decl).toContain('var(--');
    }
  });
});

describe('TooltipText', () => {
  it('reveals an abbreviated value: focusable, described, escapable', () => {
    render(
      <TooltipText label="a1b2c3d4e5f6" as="code">
        a1b2…e5f6
      </TooltipText>,
    );
    const trigger = screen.getByText('a1b2…e5f6');
    const bubble = screen.getByRole('tooltip');
    expect(trigger.tagName).toBe('CODE');
    expect(bubble.textContent).toBe('a1b2c3d4e5f6');
    expect(trigger.getAttribute('aria-describedby')).toBe(bubble.id);
    // The full value exists ONLY in the bubble, so keyboard users must be able to reach it.
    expect(trigger.getAttribute('tabindex')).toBe('0');
    fireEvent.focus(trigger);
    expect(bubble.className).toContain('is-open');
    // Dismissible while the trigger keeps focus (WCAG 1.4.13).
    fireEvent.keyDown(trigger, { key: 'Escape' });
    expect(bubble.className).not.toContain('is-open');
  });

  it('stays bare when clipped-only content is not actually clipped', () => {
    render(
      <TooltipText label="Assembleia Geral Ordinária" onlyWhenClipped>
        Assembleia Geral Ordinária
      </TooltipText>,
    );
    // Nothing is hidden, so there is no bubble and no aria-describedby repeating the text.
    expect(screen.queryByRole('tooltip')).toBeNull();
    const trigger = screen.getByText('Assembleia Geral Ordinária');
    expect(trigger.getAttribute('aria-describedby')).toBeNull();
    expect(trigger.getAttribute('tabindex')).toBeNull();
  });

  it('attaches the reveal once the text is actually clipped, without a tab stop', () => {
    mockClipped();
    render(
      <TooltipText label="Assembleia Geral Ordinária" onlyWhenClipped className="cell">
        Assembleia Geral Ordinária
      </TooltipText>,
    );
    const trigger = document.querySelector('.cell') as HTMLElement;
    const bubble = document.querySelector('.tooltip__bubble') as HTMLElement;
    expect(bubble.textContent).toBe('Assembleia Geral Ordinária');
    fireEvent.mouseEnter(trigger);
    expect(bubble.className).toContain('is-open');

    // Clipped text is complete in the DOM, so assistive tech already reads all of it. The
    // bubble is therefore a purely visual affordance: kept OUT of the accessibility tree
    // rather than announced as a description duplicating the text the user just heard.
    expect(bubble.getAttribute('aria-hidden')).toBe('true');
    expect(bubble.getAttribute('role')).toBeNull();
    expect(trigger.getAttribute('aria-describedby')).toBeNull();
    expect(trigger.getAttribute('tabindex')).toBeNull();
  });

  it('drops the bubble when the label merely repeats the visible text', () => {
    // The commonest shape of the native `title` this replaced: `title` set to the exact
    // string already rendered. It revealed nothing then and must not be reinstated now.
    const { container } = render(<TooltipText label="Selado">Selado</TooltipText>);
    expect(screen.queryByRole('tooltip')).toBeNull();
    expect(container.querySelector('.tooltip__bubble')).toBeNull();
    expect(screen.getByText('Selado').getAttribute('aria-describedby')).toBeNull();
  });

  it('adds no wrapper box, so it cannot disturb the layout it is dropped into', () => {
    const { container } = render(
      <TooltipText label="valor completo" className="cell">
        valor
      </TooltipText>,
    );
    // The default Tooltip wraps its trigger in an inline-flex `.tooltip` span; TooltipText
    // anchors against the trigger itself instead, so grid/flex sizing is untouched.
    expect(container.querySelector('.tooltip')).toBeNull();
    expect(container.childElementCount).toBe(1);
    expect((container.firstElementChild as HTMLElement).className).toBe('cell');
  });

  it('never renders a native title, which is what made these unstyleable', () => {
    mockClipped();
    const { container } = render(
      <TooltipText label="valor completo" onlyWhenClipped className="cell">
        valor
      </TooltipText>,
    );
    expect(container.querySelector('[title]')).toBeNull();
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
