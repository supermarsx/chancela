/**
 * Render an instant as a semantic `<time>` element: human-readable text in the active
 * locale, with the UNROUNDED original value (nanoseconds and all) preserved in the
 * `datetime` attribute for machines and verifiers.
 *
 * This is the component half of the date family in {@link ../format}; prefer it over
 * calling the formatters by hand wherever the value lands in the DOM, because the
 * `datetime` attribute is what keeps an evidentiary surface honest — the reader sees a
 * legible local time, and the exact instant the core recorded is still one "view source"
 * or one copy away.
 *
 * Three variants, matching the three genuinely different cases:
 *   `<DateOnly>`        — a calendar day (opening date, meeting date); no time shown.
 *   `<DateTime>`        — an everyday instant to the minute; `evidentiary` adds seconds
 *                         and the zone abbreviation for ledger/signature/seal times.
 *   `<RelativeDateTime>` — "há 3 minutos", with the absolute value always on hover.
 */
import { useActiveLocale } from '../i18n';
import {
  NO_DATE,
  formatDate,
  formatDateTime,
  formatRelative,
  formatTimestamp,
  isoAttribute,
  type DateInput,
} from '../format';
import { Tooltip } from './Tooltip';

interface DateProps {
  value: DateInput;
  /** Extra classes for the `<time>` element (e.g. `mono` in a dense evidence table). */
  className?: string;
}

/**
 * The shared shell. A value we cannot parse renders the {@link NO_DATE} placeholder in a
 * plain `<span>` rather than a `<time>`: an empty or invalid `datetime` attribute would be
 * a lie about machine-readability, and the em dash is not a time.
 */
function TimeElement({
  value,
  text,
  title,
  className,
}: DateProps & { text: string; title?: string }) {
  const iso = isoAttribute(value);
  if (!iso) return <span className={className}>{NO_DATE}</span>;
  return (
    <time dateTime={iso} className={className} title={title}>
      {text}
    </time>
  );
}

/**
 * A calendar day with no time component.
 *
 * Each component reads the locale through {@link useActiveLocale} rather than letting the
 * formatter fall back to the store: the hook SUBSCRIBES, so a settings change that flips the
 * locale re-renders every date on screen live, exactly as the translated copy around it does.
 */
export function DateOnly({ value, className }: DateProps) {
  const locale = useActiveLocale();
  return <TimeElement value={value} className={className} text={formatDate(value, locale)} />;
}

/**
 * An instant. `evidentiary` switches from "to the minute" to the audit rendering —
 * seconds plus the time-zone abbreviation, so a local time is never mistaken for UTC.
 */
export function DateTime({
  value,
  className,
  evidentiary = false,
}: DateProps & { evidentiary?: boolean }) {
  const locale = useActiveLocale();
  const text = evidentiary ? formatTimestamp(value, locale) : formatDateTime(value, locale);
  return <TimeElement value={value} className={className} text={text} />;
}

/**
 * Recency-first: relative text, absolute evidentiary value in the themed tooltip. The
 * tooltip is not decoration — "há 2 dias" alone is unusable in a record, so the exact
 * instant has to stay reachable by hover AND by keyboard, and the `aria-label` makes it
 * what a screen reader announces rather than the vague relative phrase.
 */
export function RelativeDateTime({ value, className }: DateProps) {
  const locale = useActiveLocale();
  const iso = isoAttribute(value);
  if (!iso) return <span className={className}>{NO_DATE}</span>;
  const absolute = formatTimestamp(value, locale);
  return (
    <Tooltip label={absolute}>
      <time dateTime={iso} className={className} tabIndex={0} aria-label={absolute}>
        {formatRelative(value, undefined, locale)}
      </time>
    </Tooltip>
  );
}
