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

/** Apply the full appearance block (theme + intensity + button texture) in one call. */
export function applyAppearance(
  appearance: AppearanceSettings,
  root: HTMLElement = document.documentElement,
): void {
  applyThemeMode(appearance.theme, root);
  applyTextureIntensity(appearance.texture_intensity, root);
  applyButtonTexture(appearance.button_texture, root);
}
