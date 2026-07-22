import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { ColorPicker } from './ColorPicker';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

// The suite runs without a QueryClient/i18n provider, so `useT` renders the pt-PT source
// catalog by default (see i18n/store.ts) — the labels asserted below are the pt-PT strings.

// Same indirect dynamic import as the sibling theme/ui tests: the web tsconfig carries no
// @types/node, so `node:fs` is reached through an untyped dynamic import.
async function themeCss(): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8').replace(/\r\n/g, '\n');
}

/** Render with sensible defaults; override per test. */
function setup(props: Partial<Parameters<typeof ColorPicker>[0]> = {}) {
  const onChange = vi.fn();
  const onClear = vi.fn();
  render(
    <ColorPicker
      value="#b8963e"
      label="Primária"
      onChange={onChange}
      onClear={onClear}
      {...props}
    />,
  );
  return { onChange, onClear };
}

function trigger(): HTMLElement {
  return screen.getByRole('button', { name: 'Escolher cor: Primária' });
}

function openPanel(): HTMLElement {
  fireEvent.click(trigger());
  return screen.getByRole('dialog', { name: /Primária/ });
}

describe('ColorPicker', () => {
  it('shows the current value on a collapsed trigger', () => {
    setup();
    expect(trigger().getAttribute('aria-expanded')).toBe('false');
    expect(trigger().textContent).toContain('#b8963e');
    // The panel is portaled+mounted but not open.
    expect(screen.getByRole('dialog', { name: /Primária/ }).className).not.toContain('is-open');
  });

  it('opens the popover on trigger click and exposes the controls', () => {
    setup();
    openPanel();
    expect(trigger().getAttribute('aria-expanded')).toBe('true');
    const panel = screen.getByRole('dialog', { name: /Primária/ });
    expect(panel.className).toContain('is-open');
    // S/V area + hue slider (two sliders), the hex field, and the preset group.
    expect(screen.getByRole('slider', { name: 'Saturação e brilho' })).toBeTruthy();
    expect(screen.getByRole('slider', { name: 'Matiz' })).toBeTruthy();
    expect(screen.getByLabelText('Código hexadecimal')).toBeTruthy();
    expect(screen.getByRole('group', { name: 'Predefinições' })).toBeTruthy();
  });

  it('commits a valid hex typed into the field and ignores an invalid one', () => {
    const { onChange } = setup();
    openPanel();
    const hex = screen.getByLabelText('Código hexadecimal');

    fireEvent.change(hex, { target: { value: '#123456' } });
    expect(onChange).toHaveBeenLastCalledWith('#123456');

    onChange.mockClear();
    fireEvent.change(hex, { target: { value: '#12' } });
    expect(onChange).not.toHaveBeenCalled();
    expect(hex.getAttribute('aria-invalid')).toBe('true');
  });

  it('applies a preset swatch on click', () => {
    const { onChange } = setup();
    openPanel();
    // Preset aria-label interpolates the hex: 'Aplicar a cor {color}'.
    fireEvent.click(screen.getByRole('button', { name: 'Aplicar a cor #1f6f4a' }));
    expect(onChange).toHaveBeenLastCalledWith('#1f6f4a');
  });

  it('nudges saturation/brightness with the arrow keys', () => {
    const { onChange } = setup();
    openPanel();
    const area = screen.getByRole('slider', { name: 'Saturação e brilho' });
    fireEvent.keyDown(area, { key: 'ArrowRight' });
    expect(onChange).toHaveBeenCalled();
    // The emitted value is a normalised 6-digit hex.
    expect(onChange.mock.calls.at(-1)?.[0]).toMatch(/^#[0-9a-f]{6}$/);
  });

  it('nudges the hue with the arrow keys', () => {
    const { onChange } = setup();
    openPanel();
    const hue = screen.getByRole('slider', { name: 'Matiz' });
    const before = hue.getAttribute('aria-valuenow');
    fireEvent.keyDown(hue, { key: 'ArrowRight' });
    expect(onChange).toHaveBeenCalled();
    expect(hue.getAttribute('aria-valuenow')).not.toBe(before);
  });

  it('closes on Escape and returns focus to the trigger', () => {
    setup();
    const btn = trigger();
    openPanel();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.getByRole('dialog', { name: /Primária/ }).className).not.toContain('is-open');
    expect(btn.getAttribute('aria-expanded')).toBe('false');
    expect(document.activeElement).toBe(btn);
  });

  it('closes on an outside pointer-down', () => {
    setup();
    openPanel();
    fireEvent.pointerDown(document.body);
    expect(screen.getByRole('dialog', { name: /Primária/ }).className).not.toContain('is-open');
  });

  it('offers a clear action only when a value is set, and fires onClear', () => {
    const { onClear } = setup({ isSet: true });
    openPanel();
    const clear = screen.getByRole('button', { name: 'Repor esta cor' });
    fireEvent.click(clear);
    expect(onClear).toHaveBeenCalledTimes(1);
    // Clearing is terminal for the field: the panel closes.
    expect(screen.getByRole('dialog', { name: /Primária/ }).className).not.toContain('is-open');
  });

  it('hides the clear action when nothing is overridden', () => {
    setup({ isSet: false });
    const panel = openPanel();
    expect(within(panel).queryByRole('button', { name: 'Repor esta cor' })).toBeNull();
  });

  it('retires the native colour-input swatch rules but keeps the group shell', async () => {
    const css = await themeCss();
    // The old native `<input type="color">` chrome is gone …
    expect(css).not.toContain('.color-customizer__swatch');
    // … the reused group shell (field grid, reset row) stays …
    expect(css).toContain('.color-customizer__grid');
    expect(css).toContain('.color-customizer > .form__actions');
    // … and the new themed picker block is present.
    expect(css).toContain('.color-picker__panel');
    expect(css).toContain('.color-picker__area');
  });
});
