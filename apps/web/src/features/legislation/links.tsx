/**
 * Shared safe external-link helper for the Legislação surface (the curated shelf + the
 * full-text corpus reader). An external (official) link opens in the OS browser (desktop) or a
 * new tab (browser) via {@link openExternal} on a plain left-click, while modified/middle clicks
 * keep the native anchor behaviour. An unsafe scheme (e.g. `javascript:`/`data:`) — which would
 * execute in the app origin — is rendered as plain text with no anchor, so it can never navigate.
 */
import type { MouseEvent, ReactNode } from 'react';
import { openExternal } from '../../desktop/openExternal';

/**
 * Scheme allowlist for external links. Any absolute scheme other than http(s)/mailto/tel is
 * rejected; a relative URL (no scheme) is safe (it resolves against the app origin).
 */
export function isSafeUrl(url: string): boolean {
  const trimmed = url.trim();
  if (/^(https?|mailto|tel):/i.test(trimmed)) return true;
  if (/^[\w+.-]+:/i.test(trimmed)) return false;
  return true;
}

export function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  if (!isSafeUrl(href)) {
    return <span className="leg-link leg-link--text">{children}</span>;
  }
  return (
    <a
      className="leg-link"
      href={href}
      target="_blank"
      rel="noreferrer noopener"
      onClick={(e: MouseEvent<HTMLAnchorElement>) => {
        if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
        e.preventDefault();
        void openExternal(href);
      }}
    >
      {children}
    </a>
  );
}
