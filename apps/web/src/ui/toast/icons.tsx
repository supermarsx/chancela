/**
 * Variant glyphs for the toast viewport, in the same single-stroke `currentColor`
 * idiom as `ui/icons` but kept local: the shared set (named by app action) has no
 * check-circle / alert / info glyph, and this slice does not own `ui/icons.tsx`. Each
 * is decorative (`aria-hidden`), so it never contributes to the toast's accessible name.
 */
import type { SVGProps } from 'react';

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

/** success — a check inside a circle. */
export function SuccessGlyph(props: SVGProps<SVGSVGElement>) {
  return (
    <Glyph {...props}>
      <circle cx="12" cy="12" r="9" />
      <path d="M8 12.5l2.5 2.5L16 9" />
    </Glyph>
  );
}

/** error — an exclamation inside a triangle. */
export function ErrorGlyph(props: SVGProps<SVGSVGElement>) {
  return (
    <Glyph {...props}>
      <path d="M12 4.5 21 19.5H3z" />
      <path d="M12 10v4" />
      <path d="M12 16.6h.01" />
    </Glyph>
  );
}

/** info — an "i" inside a circle. */
export function InfoGlyph(props: SVGProps<SVGSVGElement>) {
  return (
    <Glyph {...props}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5" />
      <path d="M12 8h.01" />
    </Glyph>
  );
}
