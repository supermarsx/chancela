import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';


// A plain left-click on an external link routes through openExternal (which opens the
// OS browser under the desktop shell); stub it so we can assert the interception.
const openExternal = vi.fn();
vi.mock('../desktop/openExternal', () => ({ openExternal: (url: string) => openExternal(url) }));

import { Truncate } from './Truncate';

afterEach(() => {
  cleanup();
  openExternal.mockClear();
  // The overflow-probe spies below are per-test; restore so they cannot leak.
  vi.restoreAllMocks();
});

const LONG = 'https://registo.example.pt/consulta/certidao/permanente/12045-20200115?token=abcdef';

describe('Truncate', () => {
  it('renders a span carrying the full value as text, with the truncate class', () => {
    render(<Truncate text={LONG} />);
    const el = screen.getByText(LONG);
    expect(el.tagName).toBe('SPAN');
    expect(el.className).toContain('truncate');
    // t31: the unstyleable native tooltip is gone. Nothing is lost — CSS ellipsis clips the
    // value visually but leaves it complete in the DOM, so assistive tech still reads it all.
    expect(el.getAttribute('title')).toBeNull();
  });

  it('reveals the full value in the themed tooltip once the ellipsis actually engages', () => {
    // jsdom reports every box as 0×0, so the overflow probe never fires on its own; emulate a
    // span whose content is wider than its box (the real ellipsised case).
    vi.spyOn(HTMLElement.prototype, 'scrollWidth', 'get').mockReturnValue(400);
    vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(120);
    const { container } = render(<Truncate text={LONG} />);
    const el = container.querySelector('.truncate') as HTMLElement;
    const bubble = document.querySelector('.tooltip__bubble') as HTMLElement;
    expect(bubble.textContent).toBe(LONG);
    fireEvent.mouseEnter(el);
    expect(bubble.className).toContain('is-open');
    fireEvent.mouseLeave(el);
    expect(bubble.className).not.toContain('is-open');

    // Deliberately neither a tab stop nor a description: the value is CSS-clipped, not
    // abbreviated, so it is complete in the DOM and already announced in full. Making every
    // clipped table cell focusable would bury the page's real controls, and describing it
    // would make a screen reader read the same string twice.
    expect(el.getAttribute('tabindex')).toBeNull();
    expect(el.getAttribute('aria-describedby')).toBeNull();
    expect(bubble.getAttribute('aria-hidden')).toBe('true');
  });

  it('renders a clickable external link that opens in a new tab', () => {
    render(<Truncate text={LONG} href={LONG} mono />);
    const link = screen.getByRole('link');
    expect(link.getAttribute('href')).toBe(LONG);
    // The link text still carries the full value (t31 replaced the native title).
    expect(link.textContent).toBe(LONG);
    expect(link.getAttribute('title')).toBeNull();
    expect(link.getAttribute('target')).toBe('_blank');
    expect(link.getAttribute('rel')).toContain('noopener');
    expect(link.className).toContain('truncate');
    expect(link.className).toContain('mono');
  });

  it('adds no wrapper element, so the ellipsis sizing of .truncate is untouched', () => {
    // The tooltip anchors against the trigger itself rather than wrapping it in the
    // `.tooltip` inline-flex box, which would otherwise resize a `display: block` .truncate.
    vi.spyOn(HTMLElement.prototype, 'scrollWidth', 'get').mockReturnValue(400);
    vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(120);
    const { container } = render(<Truncate text={LONG} />);
    expect(container.querySelector('.tooltip')).toBeNull();
    expect((container.firstElementChild as HTMLElement).className).toContain('truncate');
  });

  it('does not add target/rel for a relative href', () => {
    render(<Truncate text="/entities/ent-1" href="/entities/ent-1" />);
    const link = screen.getByRole('link');
    expect(link.getAttribute('target')).toBeNull();
  });

  it('routes a plain external click through openExternal (opens outside the app)', () => {
    render(<Truncate text={LONG} href={LONG} />);
    const link = screen.getByRole('link');
    // A plain left-click is intercepted and handed to openExternal.
    fireEvent.click(link);
    expect(openExternal).toHaveBeenCalledWith(LONG);
  });

  it('leaves modified clicks (ctrl/⌘) to native behaviour', () => {
    render(<Truncate text={LONG} href={LONG} />);
    const link = screen.getByRole('link');
    fireEvent.click(link, { ctrlKey: true });
    expect(openExternal).not.toHaveBeenCalled();
  });

  it('does not intercept a relative (in-app) href', () => {
    render(<Truncate text="/entities/ent-1" href="/entities/ent-1" />);
    fireEvent.click(screen.getByRole('link'));
    expect(openExternal).not.toHaveBeenCalled();
  });
});
