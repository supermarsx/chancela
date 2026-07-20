/**
 * Applies the settings-driven appearance to the document, end to end.
 *
 * These are pure DOM side-effects (no React), so they can be unit-tested directly
 * and reused by both the global {@link AppearanceEffects} layer and the live preview
 * on the Configurações page.
 *
 * - **Theme mode**: `light`/`dark` stamp a `data-theme` attribute on the root that
 *   `theme.css` honours (forcing the palette regardless of `prefers-color-scheme`);
 *   `system` removes the attribute so the OS preference wins again. Because the whole
 *   palette — including `--leather-base` and the titlebar tokens — is derived from
 *   these custom properties, one attribute switches the entire app and its chrome.
 * - **Texture intensity**: published as `--leather-grain-opacity` (0..1); the grain
 *   layer's opacity reads it, so the slider scales grain strength live. (The
 *   texture on/off toggle is handled in {@link LeatherBackground}, which stops
 *   rendering the layer entirely when off — per the "hide the background layer" spec.)
 * - **Button texture**: stamps `data-button-texture="on"|"off"` on the root; `theme.css`
 *   paints (or drops) the leather grain layer behind every button accordingly, exactly
 *   like the background texture but on the button chrome (contract F1 default `true`).
 * - **Locale**: reflected onto `document.documentElement.lang` (minimal-viable i18n;
 *   full translation is deferred — no framework is introduced here).
 */
import type { AppearanceSettings, Locale, ThemeMode } from '../api/types';

/** Apply the theme mode: `data-theme` for light/dark, removed for system. */
export function applyThemeMode(
  theme: ThemeMode,
  root: HTMLElement = document.documentElement,
): void {
  if (theme === 'system') {
    root.removeAttribute('data-theme');
  } else {
    root.setAttribute('data-theme', theme);
  }
}

/** Publish the grain opacity (0..1) from the 0..100 intensity. */
export function applyTextureIntensity(
  intensity: number,
  root: HTMLElement = document.documentElement,
): void {
  const clamped = Math.min(100, Math.max(0, intensity)) / 100;
  root.style.setProperty('--leather-grain-opacity', String(clamped));
}

/** Reflect the locale onto the document lang (minimal-viable). */
export function applyLocale(locale: Locale, root: HTMLElement = document.documentElement): void {
  root.lang = locale;
}

/** Stamp the button-texture flag (`on`/`off`) that gates the leather grain on buttons. */
export function applyButtonTexture(
  on: boolean,
  root: HTMLElement = document.documentElement,
): void {
  root.setAttribute('data-button-texture', on ? 'on' : 'off');
}

/**
 * Operator-chosen colour overrides (client-only, persisted in {@link colorStore}).
 *
 * Every field is optional: an unset field means "use the theme default from theme.css".
 * The values are `#rgb`/`#rrggbb` hex strings. These are cosmetic, per-operator
 * preferences — deliberately NOT part of the persisted §2.8 settings document (whose
 * `appearance` block is a fixed 4-key contract), exactly like the leather grain.
 */
export interface ColorOverrides {
  /** Primary brand colour → `--accent-strong` (primary button fill, current step). */
  primary?: string;
  /** Secondary/accent colour → `--accent` (links, focus ring, badges). */
  secondary?: string;
  /** Main app background → `--bg` + `--leather-base` (the page ground). */
  background?: string;
  /** Card/panel surface → `--surface`. */
  surface?: string;
}

/** The set of override fields, in a stable order. */
export const COLOR_OVERRIDE_FIELDS = ['primary', 'secondary', 'background', 'surface'] as const;
export type ColorOverrideField = (typeof COLOR_OVERRIDE_FIELDS)[number];

const HEX_COLOR = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;

/** True for a syntactically valid `#rgb` / `#rrggbb` colour string. */
export function isHexColor(value: unknown): value is string {
  return typeof value === 'string' && HEX_COLOR.test(value);
}

/** Parse a `#rgb`/`#rrggbb` hex to `[r, g, b]` (0..255), or `null` if malformed. */
export function parseHexColor(hex: string): [number, number, number] | null {
  if (!isHexColor(hex)) return null;
  let body = hex.slice(1);
  if (body.length === 3) body = body[0]! + body[0]! + body[1]! + body[1]! + body[2]! + body[2]!;
  const n = Number.parseInt(body, 16);
  return [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
}

/** WCAG relative luminance (0..1) of a hex colour, or `null` when unparseable. */
export function relativeLuminance(hex: string): number | null {
  const rgb = parseHexColor(hex);
  if (!rgb) return null;
  const [r, g, b] = rgb.map((c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** Near-black ink and near-parchment ink — the two theme extremes for legible text. */
const INK_DARK = '#10241b';
const INK_LIGHT = '#f7f3ea';

/**
 * A legible text ink for content placed ON `background` — near-black over a light
 * colour, near-parchment over a dark one. This is the readability guard: whatever
 * background/surface an operator picks, body text keeps contrast rather than vanishing.
 */
export function readableInk(background: string): string {
  const lum = relativeLuminance(background);
  // Fall back to the dark ink for an unparseable value (matches the light default).
  return lum !== null && lum < 0.42 ? INK_LIGHT : INK_DARK;
}

/**
 * Apply the operator colour overrides as inline custom properties on the root. Inline
 * styles out-specify every `theme.css` rule (including the `[data-theme]` blocks), so a
 * set field wins in both light and dark; an UNSET field is removed, handing the property
 * back to the stylesheet default. Derived tokens are kept in step for readability:
 *   - a primary fill derives `--on-accent` (the label sitting on it) from its luminance;
 *   - a custom ground derives `--text`/`--text-muted` so page + card copy stays legible.
 */
export function applyColorOverrides(
  overrides: ColorOverrides,
  root: HTMLElement = document.documentElement,
): void {
  const style = root.style;
  const setOrClear = (prop: string, value: string | undefined): void => {
    if (isHexColor(value)) style.setProperty(prop, value);
    else style.removeProperty(prop);
  };

  // Primary → the strong accent (primary buttons, current stepper), with a readable label.
  setOrClear('--accent-strong', overrides.primary);
  if (isHexColor(overrides.primary))
    style.setProperty('--on-accent', readableInk(overrides.primary));
  else style.removeProperty('--on-accent');

  // Secondary → the accent used for links, focus ring and badges.
  setOrClear('--accent', overrides.secondary);

  // Surface → card/panel ground.
  setOrClear('--surface', overrides.surface);

  // Background → both the flat page ground (`--bg`) and the leather base under the grain.
  setOrClear('--bg', overrides.background);
  setOrClear('--leather-base', overrides.background);

  // Readability guard: derive the ink from whichever ground is set (surface preferred,
  // since most copy sits on cards). If neither is customised, the theme ink is kept.
  const ground = isHexColor(overrides.surface)
    ? overrides.surface
    : isHexColor(overrides.background)
      ? overrides.background
      : undefined;
  if (ground) {
    const ink = readableInk(ground);
    style.setProperty('--text', ink);
    // A muted variant that keeps contrast: the ink softened toward the ground.
    style.setProperty('--text-muted', `color-mix(in srgb, ${ink} 62%, ${ground})`);
  } else {
    style.removeProperty('--text');
    style.removeProperty('--text-muted');
  }
}

/** Apply the full appearance block (theme + intensity + button texture) in one call. */
export function applyAppearance(
  appearance: AppearanceSettings,
  root: HTMLElement = document.documentElement,
): void {
  applyThemeMode(appearance.theme, root);
  applyTextureIntensity(appearance.texture_intensity, root);
  applyButtonTexture(appearance.button_texture, root);
}
