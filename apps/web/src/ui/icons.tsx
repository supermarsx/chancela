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
 *   delete = Trash · external = ExternalLink · cancel = Close · search = Search ·
 *   clear filters = FilterClear …
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

/** clear filters — a funnel with a small clearing mark. */
export function FilterClear(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4.5 5.5h15l-6 7v5l-3 1.5v-6.5z" />
      <path d="M16.5 15.5l3 3M19.5 15.5l-3 3" />
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

/** step back / revert — a left arrow, the mirror of {@link ArrowRight}. */
export function ArrowLeft(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M19 12H6m0 0 5-5m-5 5 5 5" />
    </Icon>
  );
}

/** move up / reorder — an up chevron. */
export function ArrowUp(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 19V6m0 0-5 5m5-5 5 5" />
    </Icon>
  );
}

/** move down / reorder — a down chevron. */
export function ArrowDown(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 5v13m0 0 5-5m-5 5-5-5" />
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

/** notifications — a bell. */
export function Bell(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M6.5 10a5.5 5.5 0 0 1 11 0c0 4 1.5 5.2 2.2 6H4.3c.7-.8 2.2-2 2.2-6" />
      <path d="M9.5 18.5a2.7 2.7 0 0 0 5 0" />
      <path d="M10 5.1a2 2 0 0 1 4 0" />
    </Icon>
  );
}

/** reminders — a calendar page. */
export function Calendar(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x="4.5" y="5.5" width="15" height="14" rx="1.5" />
      <path d="M8 3.5v4M16 3.5v4M4.5 10h15" />
      <path d="M8.5 13.5h2M13.5 13.5h2M8.5 16.5h2" />
    </Icon>
  );
}

/**
 * settings / Configurações — a cog wheel (t103).
 *
 * Deliberately a **cog**, not {@link Sliders}: the app already uses `Sliders` for filter and
 * preference controls *inside* pages, and the top bar needed a glyph that reads as "the settings
 * surface" at a glance beside the tools wrench. Two teeth-rings plus a hub, drawn in the same
 * single-stroke 24×24 style as the rest of the set, so it inherits the stroke, sizing and
 * `aria-hidden` chrome from {@link Icon} and cannot drift from the house line weight.
 */
export function Cog(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="3.2" />
      <path d="M12 3.5v2.2M12 18.3v2.2M20.5 12h-2.2M5.7 12H3.5" />
      <path d="M18.01 5.99l-1.56 1.56M7.55 16.45l-1.56 1.56M18.01 18.01l-1.56-1.56M7.55 7.55L5.99 5.99" />
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

/** edit — a pencil. */
export function Pencil(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4 20l.8-3.5L15 6.3a1.9 1.9 0 0 1 2.7 0l.7.7a1.9 1.9 0 0 1 0 2.7L8.5 20z" />
      <path d="M13.8 7.5l2.7 2.7" />
    </Icon>
  );
}

/** activate / deactivate — a power symbol. */
export function Power(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 4v7.5" />
      <path d="M7.5 7.3a7 7 0 1 0 9 0" />
    </Icon>
  );
}

/** appearance / Aparência — an artist's palette. */
export function Palette(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 4a8 8 0 0 0-.5 16c.9.05 1.5-.9 1.1-1.75-.4-.9.2-1.9 1.2-1.9H16a4 4 0 0 0 4-4c0-4.5-3.6-8.35-8-8.35z" />
      <circle cx="8.5" cy="10.5" r="1" />
      <circle cx="12" cy="8" r="1" />
      <circle cx="15.5" cy="10.5" r="1" />
    </Icon>
  );
}

/** identity / Identidade — an ID card with a portrait. */
export function IdCard(props: IconProps) {
  return (
    <Icon {...props}>
      <rect x="3.5" y="6" width="17" height="12" rx="1.5" />
      <circle cx="8.5" cy="11" r="1.8" />
      <path d="M5.8 15.6a2.8 2.8 0 0 1 5.4 0" />
      <path d="M14 10.5h4M14 13.5h4" />
    </Icon>
  );
}

/** document / Documentos — a page with text lines. */
export function FileText(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M6.5 3.5h6.5L18 8.5V19a1.5 1.5 0 0 1-1.5 1.5h-10A1.5 1.5 0 0 1 5 19V5A1.5 1.5 0 0 1 6.5 3.5z" />
      <path d="M12.5 3.5V9h5" />
      <path d="M8.5 13h7M8.5 16h7" />
    </Icon>
  );
}

/** signatures / Assinaturas — a fountain-pen nib. */
export function PenNib(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4.5 19.5 6.5 13 13 6.5l4.5 4.5L11 17.5z" />
      <path d="M13 6.5 15 4.5a1.4 1.4 0 0 1 2 0l.5.5a1.4 1.4 0 0 1 0 2L15.5 9" />
      <circle cx="9.7" cy="14.3" r="1.5" />
    </Icon>
  );
}

/** management / Gestão — adjustment sliders. */
export function Sliders(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4 8h9M17 8h3" />
      <path d="M4 16h3M11 16h9" />
      <circle cx="15" cy="8" r="2" />
      <circle cx="9" cy="16" r="2" />
    </Icon>
  );
}

/** information / Sobre — an "i" in a circle. */
export function Info(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="8" />
      <path d="M12 11v5" />
      <path d="M12 8h.01" />
    </Icon>
  );
}

/** catalogue / Catálogo — stacked layers. */
export function Layers(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 4 20 8l-8 4-8-4z" />
      <path d="M4 12l8 4 8-4" />
      <path d="M4 16l8 4 8-4" />
    </Icon>
  );
}

/** legislation / Legislação — a balance scale. */
export function Scale(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 4.5v15" />
      <path d="M7.5 19.5h9" />
      <path d="M4.5 7h15" />
      <path d="M4.5 7 2 12.5a2.5 2.5 0 0 0 5 0z" />
      <path d="M19.5 7 17 12.5a2.5 2.5 0 0 0 5 0z" />
    </Icon>
  );
}

/**
 * security / Segurança — a shield with a check (t103).
 *
 * The user-facing security tab needed a glyph distinct from `Seal` (the attestation key) and
 * `Cog` (settings): a shield reads as "account protection" at a glance. Single-stroke, in the
 * house 24×24 style, so it inherits the shared `Icon` chrome and cannot drift from the line
 * weight — the same discipline the `Cog` addition followed.
 */
export function Shield(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 3.5 5 6.2v5c0 4.3 2.9 7.4 7 8.8 4.1-1.4 7-4.5 7-8.8v-5z" />
      <path d="M9 11.7l2.2 2.2L15 8.6" />
    </Icon>
  );
}

/**
 * menu / collapse — a three-line "hamburger" (t42).
 *
 * The trigger the top bar shows when the primary tab row no longer fits and reflows into a
 * dropdown. It is icon-only, so the button that carries it supplies the accessible name; the
 * glyph stays decorative like every other in the set, inheriting the shared 24×24 chrome.
 */
export function Menu(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4 7h16M4 12h16M4 17h16" />
    </Icon>
  );
}

/**
 * overflow / more — three horizontal dots (t42).
 *
 * Distinct from {@link Menu}: this fronts the *utility* overflow (the archive/tools/settings
 * glyphs, and any icon added to the bar later) when the bar is too narrow to show them inline,
 * so it reads as "more of these controls" rather than "the site navigation". Filled dots, since a
 * 1.5px ring reads as noise at this size.
 */
export function MoreHorizontal(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="5" cy="12" r="1.5" fill="currentColor" stroke="none" />
      <circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none" />
      <circle cx="19" cy="12" r="1.5" fill="currentColor" stroke="none" />
    </Icon>
  );
}
