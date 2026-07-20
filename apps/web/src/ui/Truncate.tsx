/**
 * Render a long value on a single line, abbreviated with an ellipsis when it overflows
 * its container (t13 item 4). The full value is always available through the shared themed
 * {@link Tooltip} — which replaced the unstyleable native `title` in t31 — so nothing is
 * lost; the text merely shrinks to fit. The bubble is attached only while the ellipsis is
 * actually engaged, so an unclipped value stays a plain element with no redundant
 * description. When `href` is given it renders a clickable link (external URLs open in a
 * new tab) that stays clickable across its whole visible span; otherwise a plain span.
 *
 * Truncation is pure CSS (`text-overflow: ellipsis`) so it reflows with the container
 * and needs no measurement. In a flex/grid parent the ellipsis only engages when the
 * item may shrink, which is why `.truncate` sets `min-width: 0`.
 *
 * External links are routed through {@link openExternal} on a plain left-click so they
 * open in the user's default browser under the desktop shell (and a new tab in the
 * browser) instead of navigating the app's own WebView. Modified clicks (new-tab /
 * middle-click / copy-link) keep the native anchor behaviour, which is why the `href`
 * and `target="_blank"` attributes are retained.
 */
import { useRef, type AnchorHTMLAttributes, type MouseEvent } from 'react';
import { openExternal } from '../desktop/openExternal';
import { Tooltip, TooltipText, useIsClipped } from './Tooltip';

interface TruncateProps {
  /** The full value; shown verbatim in the tooltip and abbreviated visually. */
  text: string;
  /** When set, renders an anchor to this href instead of a span. */
  href?: string;
  /** Render in the monospace face (URLs, identifiers). */
  mono?: boolean;
  /** Extra classes appended to `.truncate`. */
  className?: string;
}

/**
 * Scheme allowlist for rendered `href`s. A `javascript:`/`data:` URL reaching the
 * renderer would execute in the app origin, so any absolute scheme other than
 * http(s)/mailto/tel is treated as untrusted text (rendered as a plain span, no
 * `href`). Relative URLs (no scheme, e.g. `/entidades/ent-1`) resolve against the
 * app origin and are always safe.
 */
function isSafeUrl(url: string): boolean {
  const trimmed = url.trim();
  if (/^(https?|mailto|tel):/i.test(trimmed)) return true;
  // Any other `scheme:` (javascript:, data:, vbscript:, …) is unsafe.
  if (/^[\w+.-]+:/i.test(trimmed)) return false;
  // No scheme → relative/app-origin URL; safe.
  return true;
}

export function Truncate({ text, href, mono, className }: TruncateProps) {
  const cls = `truncate ${mono ? 'mono' : ''} ${className ?? ''}`.trim().replace(/\s+/g, ' ');
  const safeHref = href && isSafeUrl(href) ? href : undefined;
  const anchorRef = useRef<HTMLAnchorElement>(null);
  // Only reveal the full value when the ellipsis has actually engaged; an unclipped link
  // already shows everything, and a bubble repeating it would be noise (and a redundant
  // `aria-describedby`). The anchor is focusable in its own right, so no tabIndex is needed.
  const anchorClipped = useIsClipped(anchorRef, Boolean(safeHref));
  if (safeHref) {
    const external = /^https?:\/\//i.test(safeHref);
    const extra: AnchorHTMLAttributes<HTMLAnchorElement> = external
      ? {
          target: '_blank',
          rel: 'noreferrer noopener',
          onClick: (e: MouseEvent<HTMLAnchorElement>) => {
            // Let modified clicks (new tab/window, middle-click) use native behaviour;
            // route a plain click to the OS browser / a new tab via openExternal.
            if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
            e.preventDefault();
            void openExternal(safeHref);
          },
        }
      : {};
    const anchor = (
      <a ref={anchorRef} className={cls} href={safeHref} {...extra}>
        {text}
      </a>
    );
    // `anchorRef` keeps the tooltip layout-transparent: `.truncate` is `display: block` and
    // is routinely sized as a flex/grid child, so the default `.tooltip` inline-flex wrapper
    // would change how the link sizes and where the ellipsis falls.
    return anchorClipped ? (
      <Tooltip label={text} variant="prose" anchorRef={anchorRef}>
        {anchor}
      </Tooltip>
    ) : (
      anchor
    );
  }
  return (
    <TooltipText className={cls} label={text} onlyWhenClipped>
      {text}
    </TooltipText>
  );
}
