import { afterEach, describe, expect, it } from 'vitest';
import { act, cleanup, render, screen } from '@testing-library/react';
import { DateOnly, DateTime, RelativeDateTime } from './DateTime';
import { i18nStore } from '../i18n';

afterEach(() => {
  cleanup();
  i18nStore.setActiveLocale('pt-PT');
});

// The instant the user reported seeing raw in the UI: RFC 3339 straight off the wire, with
// NANOSECOND precision. It must never be the text a human reads, and must always survive
// intact in the `datetime` attribute.
const NANOS = '2026-07-20T22:41:06.589989639Z';

function timeElement(): HTMLTimeElement {
  const element = document.querySelector('time');
  if (!element) throw new Error('expected a <time> element');
  return element;
}

describe('DateOnly', () => {
  it('renders a calendar day with no time component', () => {
    render(<DateOnly value="2026-07-20" />);
    expect(timeElement().textContent).not.toContain(':');
  });
});

describe('DateTime', () => {
  it('shows a legible local time while keeping the exact instant machine-readable', () => {
    render(<DateTime value={NANOS} />);
    const element = timeElement();

    // The whole point: the attribute keeps every nanosecond, the text shows none of them.
    expect(element.getAttribute('datetime')).toBe(NANOS);
    expect(element.textContent).not.toContain('589989639');
    expect(element.textContent).not.toContain('T');
    expect(element.textContent).toMatch(/\d{1,2}:\d{2}/);
  });

  it('adds seconds and a time zone in the evidentiary variant', () => {
    render(<DateTime value={NANOS} evidentiary />);
    const element = timeElement();

    expect(element.getAttribute('datetime')).toBe(NANOS);
    expect(element.textContent).toMatch(/\d{1,2}:\d{2}:\d{2}/);
    expect(element.textContent).not.toContain('589989639');
  });

  it('passes the class through for dense monospaced tables', () => {
    render(<DateTime value={NANOS} className="mono" />);
    expect(timeElement().className).toBe('mono');
  });
});

describe('RelativeDateTime', () => {
  it('leads with the relative form but keeps the absolute value reachable', () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
    render(<RelativeDateTime value={twoHoursAgo} />);
    const element = timeElement();

    expect(element.textContent).toBe('há 2 horas');
    expect(element.getAttribute('datetime')).toBe(twoHoursAgo);
    // "há 2 horas" alone is useless in a record, so the exact instant must be announced
    // to a screen reader and reachable by keyboard, not mouse-only.
    expect(element.getAttribute('aria-label')).toMatch(/\d{1,2}:\d{2}:\d{2}/);
    expect(element.tabIndex).toBe(0);
  });
});

describe('missing and invalid values', () => {
  const rejected: [string, unknown][] = [
    ['null', null],
    ['undefined', undefined],
    ['empty', ''],
    ['unparseable', 'not-a-date'],
  ];

  for (const [label, value] of rejected) {
    it(`renders the placeholder for ${label}, never "Invalid Date" or the raw string`, () => {
      render(
        <>
          <DateOnly value={value as string} />
          <DateTime value={value as string} />
          <RelativeDateTime value={value as string} />
        </>,
      );

      expect(screen.getAllByText('—')).toHaveLength(3);
      // No `<time>` at all: an empty or invalid `datetime` attribute would claim a
      // machine-readability the value does not have.
      expect(document.querySelector('time')).toBeNull();
    });
  }
});

describe('the active locale drives the rendering', () => {
  it('re-renders LIVE when the locale flips, with no re-render from the parent', () => {
    render(<DateOnly value="2026-07-20T10:00:00Z" />);
    expect(timeElement().textContent).toContain('julho');

    // A settings change flips the locale app-wide; dates must follow the copy around them
    // rather than sitting stale until something else happens to re-render the page.
    act(() => {
      i18nStore.setActiveLocale('en-US');
    });
    expect(timeElement().textContent).toContain('July');
  });
});
