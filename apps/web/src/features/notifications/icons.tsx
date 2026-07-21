/**
 * Semantic type glyphs for a notification row's leading icon, in the same single-stroke
 * `currentColor` idiom as `ui/icons` but kept local: the shared app set (named by action)
 * has no alert-triangle, shield-alert or activity glyph, and this feature does not own
 * `ui/icons.tsx`. Reminder rows reuse `Icon.Calendar` and accent alert rows reuse
 * `Icon.Bell` from the app set — they share the exact geometry, so the row reads as one
 * consistent line style. Every glyph is decorative (`aria-hidden`); the row's accessible
 * name still comes from its badge + title text, so the a11y/name assertions stay intact.
 */
import type { ReactNode, SVGProps } from 'react';
import { Icon } from '../../ui';
import type { NotificationItem } from './notifications';

function Glyph({ children, ...props }: SVGProps<SVGSVGElement>) {
  return (
    <svg
      className="icon"
      viewBox="0 0 24 24"
      width="1em"
      height="1em"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...props}
    >
      {children}
    </svg>
  );
}

/** critical / integrity — an exclamation inside a triangle (the strongest, error tone). */
export function AlertTriangleGlyph(props: SVGProps<SVGSVGElement>) {
  return (
    <Glyph {...props}>
      <path d="M12 4.5 21 19.5H3z" />
      <path d="M12 10v4" />
      <path d="M12 16.6h.01" />
    </Glyph>
  );
}

/** review-required / overdue — a shield with an exclamation (warn tone, distinct from error). */
export function ShieldAlertGlyph(props: SVGProps<SVGSVGElement>) {
  return (
    <Glyph {...props}>
      <path d="M12 3.5 19 6v5c0 4.4-3 7.6-7 9.5-4-1.9-7-5.1-7-9.5V6z" />
      <path d="M12 8.5v4" />
      <path d="M12 15.4h.01" />
    </Glyph>
  );
}

/** operation log — a ledger-pulse line (lowest emphasis, neutral tone). */
export function ActivityGlyph(props: SVGProps<SVGSVGElement>) {
  return (
    <Glyph {...props}>
      <path d="M3.5 12h3.5L9.5 6l4 12 2.5-6h4" />
    </Glyph>
  );
}

/**
 * "Marcar como lida" — an opened envelope. The row is **seen but still open**: `read` is the
 * only non-terminal triage status, so the row stays in the list (merely de-emphasised) and the
 * glyph has to say *opened*, not *finished*. An envelope carries that on its own; a tick does
 * not, which is why this and `ShieldCheckGlyph` deliberately share no geometry.
 */
export function MailOpenGlyph(props: SVGProps<SVGSVGElement>) {
  return (
    <Glyph {...props}>
      <path d="M3.5 10.5 12 4.5l8.5 6v8a1.5 1.5 0 0 1-1.5 1.5H5a1.5 1.5 0 0 1-1.5-1.5z" />
      <path d="M3.5 10.5 12 16l8.5-5.5" />
    </Glyph>
  );
}

/**
 * "Reconhecer" — a shield with a check. Acknowledging is terminal and is offered only on rows
 * that represent work (never on the operation log): the operator is taking the item on, not
 * just noting it. The shield is the **same outline as `ShieldAlertGlyph`**, on purpose — the
 * row raising a warning and the control that resolves it read as one pair.
 */
export function ShieldCheckGlyph(props: SVGProps<SVGSVGElement>) {
  return (
    <Glyph {...props}>
      <path d="M12 3.5 19 6v5c0 4.4-3 7.6-7 9.5-4-1.9-7-5.1-7-9.5V6z" />
      <path d="m9 11.5 2.2 2.2 4-4.2" />
    </Glyph>
  );
}

/**
 * The distinct type of a row's leading chip, keyed by kind + tone. The chip's colour is
 * driven by `item.tone` (see `notifications-list__icon--*` in theme.css); this only picks
 * the glyph and a stable `name` used both as the chip's `data-notification-icon`
 * scan/test hook and to make the choice legible at the call site.
 *
 * Precedence: the two attention tones (error → warn) win first so an integrity failure or
 * an overdue/compliance item always reads as an alarm; then reminders (calendar) and
 * operation-log rows (activity); the remainder is an actionable accent alert
 * (advance / signing-ready), which carries a bell.
 */
export function notificationTypeGlyph(item: Pick<NotificationItem, 'kind' | 'tone'>): {
  icon: ReactNode;
  name: string;
} {
  if (item.tone === 'error') return { icon: <AlertTriangleGlyph />, name: 'alert' };
  if (item.tone === 'warn') return { icon: <ShieldAlertGlyph />, name: 'warn' };
  if (item.kind === 'reminder') return { icon: <Icon.Calendar />, name: 'reminder' };
  if (item.kind === 'operation') return { icon: <ActivityGlyph />, name: 'operation' };
  return { icon: <Icon.Bell />, name: 'accent' };
}
