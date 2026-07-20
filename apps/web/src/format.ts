/**
 * Presentation helpers for the Chancela shell.
 *
 * `formatAtaNumber` renders the sequential ata number that the domain core assigns
 * when an act is sealed within its book (WFL-12). Numbering is per-book and never
 * reused; here we only format an already-assigned value for display in the active locale.
 *
 * The date/time family below is the ONE place the app turns an instant into text. The
 * core emits RFC 3339 with nanosecond precision (`2026-07-20T22:41:06.589989639Z`); that
 * is a wire format, never a thing to show a human, and before t66 roughly eight different
 * ad-hoc renderings (bare `toLocaleString`, four different `Intl` option sets, two
 * hard-coded `pt-PT` call sites, `.slice(0, 10)` truncation, and raw interpolation) each
 * bypassed the others. Use these helpers — or the {@link ../ui/DateTime} components that
 * wrap them — instead of reaching for `Intl` at a call site.
 */
import { t, i18nStore } from './i18n';

export function formatAtaNumber(sequence: number, year: number): string {
  if (!Number.isInteger(sequence) || sequence < 1) {
    throw new RangeError('Ata number must be a positive integer');
  }
  if (!Number.isInteger(year) || year < 1) {
    throw new RangeError('Year must be a positive integer');
  }
  const padded = String(sequence).padStart(4, '0');
  return t('format.ataNumber', { padded, year });
}

// --- Dates and timestamps ---------------------------------------------------------

/**
 * What a date field renders when there is nothing to render, or when the value cannot be
 * parsed. An em dash reads as "no value" in every shipped locale and, crucially, is not
 * `Invalid Date`, `NaN`, or the raw wire string leaking into the page.
 */
export const NO_DATE = '—';

/** An instant as it arrives from the core, or from a form: RFC 3339, epoch millis, or Date. */
export type DateInput = string | number | Date | null | undefined;

/**
 * Parse an instant, or `null` if there is nothing sensible to show. Nanosecond-precision
 * RFC 3339 parses natively — `Date` truncates the sub-millisecond digits, which is why the
 * full original string is what goes into the `datetime` attribute rather than a re-emitted one.
 */
function parseInstant(value: DateInput): Date | null {
  if (value === null || value === undefined || value === '') return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function activeLocale(locale?: string): string {
  return locale ?? i18nStore.getActiveLocale();
}

/**
 * A calendar date with no time component — an opening date, a meeting date, a due date.
 * These are days, not instants; rendering `00:00` beside them is noise that invites the
 * reader to believe a time was recorded when none was.
 */
export function formatDate(value: DateInput, locale?: string): string {
  const date = parseInstant(value);
  if (!date) return NO_DATE;
  return new Intl.DateTimeFormat(activeLocale(locale), { dateStyle: 'long' }).format(date);
}

/**
 * A date and a time to the MINUTE — the everyday form for "when did this happen": a
 * notification, an API key expiry, a job run. Seconds are below the resolution anyone
 * reads at a glance; for evidence use {@link formatTimestamp} instead.
 */
export function formatDateTime(value: DateInput, locale?: string): string {
  const date = parseInstant(value);
  if (!date) return NO_DATE;
  return new Intl.DateTimeFormat(activeLocale(locale), {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date);
}

/**
 * An EVIDENTIARY timestamp: a ledger event, a signature time, a seal time, an audit entry.
 *
 * Time zone (t66 decision): every rendering in this app is in the VIEWER'S local zone, since
 * that is the zone a reader reasons in. For evidence that is not enough on its own — a local
 * wall-clock time with no zone is ambiguous the moment the record crosses a border or a DST
 * boundary — so this variant carries seconds AND the zone abbreviation (`WEST`, `UTC+1`).
 * The unrounded original, nanoseconds included, stays machine-readable in the `datetime`
 * attribute of the {@link ../ui/DateTime} `<time>` element; nothing a verifier needs is lost,
 * it simply stops being the thing a human is asked to read.
 */
export function formatTimestamp(value: DateInput, locale?: string): string {
  const date = parseInstant(value);
  if (!date) return NO_DATE;
  return new Intl.DateTimeFormat(activeLocale(locale), {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short',
  }).format(date);
}

/** Descending thresholds for {@link formatRelative}, in seconds per unit. */
const RELATIVE_UNITS: readonly [Intl.RelativeTimeFormatUnit, number][] = [
  ['year', 365 * 24 * 60 * 60],
  ['month', 30 * 24 * 60 * 60],
  ['day', 24 * 60 * 60],
  ['hour', 60 * 60],
  ['minute', 60],
  ['second', 1],
];

/**
 * A relative form — "há 3 minutos", "ontem" — for surfaces where RECENCY is the whole point
 * (the dashboard activity feed, "last checked"). Never use it alone on an evidentiary
 * surface: "há 2 dias" is worthless in a record someone has to verify, which is why the
 * {@link ../ui/RelativeDateTime} component always pairs it with the absolute value on hover.
 */
export function formatRelative(
  value: DateInput,
  now: DateInput = new Date(),
  locale?: string,
): string {
  const date = parseInstant(value);
  const reference = parseInstant(now) ?? new Date();
  if (!date) return NO_DATE;
  const deltaSeconds = (date.getTime() - reference.getTime()) / 1000;
  const formatter = new Intl.RelativeTimeFormat(activeLocale(locale), { numeric: 'auto' });
  for (const [unit, seconds] of RELATIVE_UNITS) {
    if (Math.abs(deltaSeconds) >= seconds) {
      return formatter.format(Math.round(deltaSeconds / seconds), unit);
    }
  }
  // Inside a second either way: `0 seconds` reads as "agora"/"now" under `numeric: 'auto'`.
  return formatter.format(0, 'second');
}

/**
 * The value for a `<time datetime="…">` attribute: the ORIGINAL string when the core gave us
 * one, so the full nanosecond precision survives into the DOM untouched, and a derived ISO
 * string otherwise. `undefined` for an unparseable value — an unparseable `datetime` is worse
 * than none, since it claims machine-readability it does not have.
 */
export function isoAttribute(value: DateInput): string | undefined {
  const date = parseInstant(value);
  if (!date) return undefined;
  return typeof value === 'string' ? value : date.toISOString();
}
