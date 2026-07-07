/**
 * A single-stroke, currentColor inline-SVG icon set (t19-e2 item g). One consistent
 * editorial line style across the whole app — no icon font, no runtime dependency.
 *
 * Every icon is a 24×24 line drawing that inherits its colour from `currentColor` and
 * sizes to the surrounding text (`1em`), so an icon inside a `.btn` scales with the
 * button label and picks up the button's ink in either theme. Icons are decorative:
 * they carry `aria-hidden` and `focusable="false"`, so a button's accessible name comes
 * from its text label alone (the accessible-name assertions in the specs stay intact).
 *
 * Naming is by ACTION, not by shape, so call sites read semantically:
 *   create = Plus · import = Tray · seal = Seal · print = Printer · refresh = Refresh ·
 *   close-book = BookClosed · sign-out = SignOut · copy = Copy · save = Check/Save ·
 *   delete = Trash · external = ExternalLink · cancel = Close · search = Search …
 */
import type { SVGProps } from 'react';

type IconProps = SVGProps<SVGSVGElement>;

/**
 * Shared chrome for every glyph: the 24×24 viewBox, the single round stroke, and the
 * `1em` sizing + a11y attributes. Individual icons only supply their path geometry.
 */
function Icon({ children, ...props }: IconProps) {
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

/** create — a plus. */
export function Plus(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 5v14M5 12h14" />
    </Icon>
  );
}

/** open a new book — a book with a plus. */
export function BookPlus(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M5 4.5A1.5 1.5 0 0 1 6.5 3H19v14H6.5A1.5 1.5 0 0 0 5 18.5z" />
      <path d="M5 18.5A1.5 1.5 0 0 0 6.5 20H19" />
      <path d="M13.5 8.5h3M15 7v3" />
    </Icon>
  );
}

/** import — a tray receiving a downward arrow. */
export function Tray(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 4v9m0 0 3.5-3.5M12 13 8.5 9.5" />
      <path d="M4 15v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3" />
    </Icon>
  );
}

/** seal / stamp — a wax-seal stamp motif. */
export function Seal(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="9" r="5" />
      <path d="M9.5 9.2l1.6 1.6L14.6 7" />
      <path d="M9.7 13.6 9 20l3-1.6L15 20l-.7-6.4" />
    </Icon>
  );
}

/** print — a printer. */
export function Printer(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M7 8V3.5h10V8" />
      <path d="M7 17H5.5A1.5 1.5 0 0 1 4 15.5v-5A1.5 1.5 0 0 1 5.5 9h13a1.5 1.5 0 0 1 1.5 1.5v5a1.5 1.5 0 0 1-1.5 1.5H17" />
      <rect x="7" y="14" width="10" height="6.5" rx="0.5" />
      <path d="M16.5 11.5h.5" />
    </Icon>
  );
}

/** refresh / update — two arrows in a cycle. */
export function Refresh(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4.5 9a7.5 7.5 0 0 1 12.9-3.2L20 8" />
      <path d="M19.5 15a7.5 7.5 0 0 1-12.9 3.2L4 16" />
      <path d="M20 4v4h-4M4 20v-4h4" />
    </Icon>
  );
}

/** regenerate / re-roll — a shuffle/dice motif reusing the cycle idiom. */
export function Shuffle(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4 7h3.5l9 10H20M4 17h3.5l3-3.3M13.5 8.3l3-3.3H20" />
      <path d="M17.5 3.5 20 5l-2.5 1.5M17.5 15.5 20 17l-2.5 1.5" />
    </Icon>
  );
}

/** close / encerrar a book — a closed book with a lock clasp. */
export function BookClosed(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M6 4.5A1.5 1.5 0 0 1 7.5 3H18v18H7.5A1.5 1.5 0 0 1 6 19.5z" />
      <path d="M9 3v18" />
      <path d="M13 10.5v-1a1.5 1.5 0 0 1 3 0v1M12.7 10.5h3.6v3h-3.6z" />
    </Icon>
  );
}

/** sign out — a door with an exit arrow. */
export function SignOut(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M14 4.5H6.5A1.5 1.5 0 0 0 5 6v12a1.5 1.5 0 0 0 1.5 1.5H14" />
      <path d="M11 12h9m0 0-3-3m3 3-3 3" />
    </Icon>
  );
}

/** copy — two stacked sheets. */
export function Copy(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x="8" y="8" width="11" height="12" rx="1.5" />
      <path d="M16 8V5.5A1.5 1.5 0 0 0 14.5 4h-8A1.5 1.5 0 0 0 5 5.5v9A1.5 1.5 0 0 0 6.5 16H8" />
    </Icon>
  );
}

/** save / confirm — a check mark. */
export function Check(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M5 12.5 10 17.5 19 6.5" />
    </Icon>
  );
}

/** save — a floppy-disk motif (for explicit "guardar"). */
export function Save(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M5 5.5A1.5 1.5 0 0 1 6.5 4h9L20 8.5v10a1.5 1.5 0 0 1-1.5 1.5h-12A1.5 1.5 0 0 1 5 18.5z" />
      <path d="M8 4v4h6V4" />
      <rect x="8" y="12" width="8" height="6" rx="0.5" />
    </Icon>
  );
}

/** delete — a waste bin. */
export function Trash(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4.5 6.5h15M9 6.5V5a1.5 1.5 0 0 1 1.5-1.5h3A1.5 1.5 0 0 1 15 5v1.5" />
      <path d="M6.5 6.5 7.3 19a1.5 1.5 0 0 0 1.5 1.4h6.4a1.5 1.5 0 0 0 1.5-1.4l.8-12.5" />
      <path d="M10 10v6M14 10v6" />
    </Icon>
  );
}

/** external link — a box with an out-arrow. */
export function ExternalLink(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M13 5h6v6" />
      <path d="M19 5l-8 8" />
      <path d="M18 13.5v4A1.5 1.5 0 0 1 16.5 19h-10A1.5 1.5 0 0 1 5 17.5v-10A1.5 1.5 0 0 1 6.5 6h4" />
    </Icon>
  );
}

/** cancel / close — an X. */
export function Close(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M6 6l12 12M18 6 6 18" />
    </Icon>
  );
}

/** search — a magnifier. */
export function Search(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="10.5" cy="10.5" r="6" />
      <path d="M15 15l4.5 4.5" />
    </Icon>
  );
}

/** advance / next — a right chevron. */
export function ArrowRight(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M5 12h13m0 0-5-5m5 5-5 5" />
    </Icon>
  );
}

/** users / people. */
export function Users(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="9" cy="8" r="3" />
      <path d="M3.5 19a5.5 5.5 0 0 1 11 0" />
      <path d="M15.5 5.5a3 3 0 0 1 0 5.5M17 13.5a5.5 5.5 0 0 1 3.5 5.5" />
    </Icon>
  );
}

/** archive — a storage box with a lid. */
export function Archive(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x="4" y="4.5" width="16" height="4" rx="0.5" />
      <path d="M5.5 8.5V18a1.5 1.5 0 0 0 1.5 1.5h10a1.5 1.5 0 0 0 1.5-1.5V8.5" />
      <path d="M10 12h4" />
    </Icon>
  );
}

/** tools / wrench (Ferramentas). */
export function Wrench(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M15.5 4a4.5 4.5 0 0 0-4.2 6.1L4 17.4a1.8 1.8 0 0 0 2.6 2.6l7.3-7.3A4.5 4.5 0 0 0 20 8.5l-2.6 2.6-2.5-2.5L17.5 6A4.5 4.5 0 0 0 15.5 4z" />
    </Icon>
  );
}
