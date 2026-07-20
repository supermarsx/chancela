/**
 * Present a hex fingerprint (a SHA-256 digest or a ledger hash) in an abbreviated,
 * tamper-legible form: the first and last eight hex characters joined by an ellipsis
 * (`a1b2c3d4…e5f6a7b8`), with the FULL value in the shared themed {@link Tooltip} — which
 * replaced the unstyleable native `title` in t31 — and an optional click-to-copy control
 * (t13 item 5). Short values are shown whole. The abbreviation is display-only — the
 * complete value is always one hover, one Tab, or one copy away, so none of the evidence
 * is hidden.
 */
import { useState } from 'react';
import { Check, Copy } from './icons';
import { Tooltip, TooltipText } from './Tooltip';
import { useT } from '../i18n';

interface DigestProps {
  /** The full hex digest/hash. */
  value: string;
  /** Characters kept at each end (default 8 → `8…8`). */
  edge?: number;
  /** Show the copy control (default true). Disable it in dense tables if desired. */
  copyable?: boolean;
}

/**
 * Abbreviate a hex value to `<edge>…<edge>`, keeping short values whole. Never returns
 * a string longer than the input, so a value that is already compact is untouched.
 */
export function abbreviateDigest(value: string, edge = 8): string {
  if (value.length <= edge * 2 + 1) return value;
  return `${value.slice(0, edge)}…${value.slice(-edge)}`;
}

export function Digest({ value, edge = 8, copyable = true }: DigestProps) {
  const t = useT();
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard access can be unavailable or denied; the full value is still on the
      // title tooltip, so copy is a convenience rather than the only path to it.
    }
  }

  return (
    <span className="digest">
      {/* Focusable (TooltipText's default for abbreviated content): the full digest lives
          ONLY in the bubble, so a keyboard user with no mouse would otherwise have no way
          to read it. */}
      <TooltipText as="code" className="mono digest__value" label={value}>
        {abbreviateDigest(value, edge)}
      </TooltipText>
      {copyable ? (
        // Wrapped in Tooltip rather than swapped for `IconButton`: this control is
        // deliberately bare (a 1.4rem borderless glyph that sits inline inside a dense
        // table cell), and `IconButton` would layer the full `.btn` chrome onto it.
        <Tooltip label={copied ? t('common.copied') : t('ui.digest.copy')}>
          <button
            type="button"
            className="digest__copy"
            onClick={copy}
            aria-label={copied ? t('common.copied') : t('ui.digest.copy')}
          >
            {copied ? <Check /> : <Copy />}
          </button>
        </Tooltip>
      ) : null}
    </span>
  );
}
