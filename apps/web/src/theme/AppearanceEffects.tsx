/**
 * Applies the persisted appearance + locale to the document, app-wide.
 *
 * Mounted once high in the tree (inside {@link Layout}). It reads the shared settings
 * query and, whenever the persisted appearance changes (including the optimistic
 * cache update on save), re-applies the theme, grain intensity and document lang.
 * Renders nothing. The Configurações page layers a live *preview* on top of this for
 * unsaved edits; this component is the source of truth for the committed settings.
 */
import { useEffect, useSyncExternalStore } from 'react';
import { useSession, useSettings } from '../api/hooks';
import { DEFAULT_SETTINGS, LANGUAGE_AUTO } from '../api/types';
import type { Locale, UserLanguage } from '../api/types';
import { grainStore } from './grainStore';
import { colorStore } from './colorStore';
import { applyAppearance, applyColorOverrides, applyLocale } from './appearance';
import { i18nStore } from '../i18n';
import { browserLanguages, negotiateLocale } from '../i18n/negotiate';

/**
 * Which locale the interface renders in (t71).
 *
 * @param preference the signed-in user's stored preference, or `null` when signed out
 * @param documentLocale the instance's `settings.documents.locale` — the floor, and the language
 *   generated legal instruments are written in. Read only; never written back to.
 */
export function resolveUiLocale(preference: UserLanguage | null, documentLocale: Locale): Locale {
  if (preference === null) return documentLocale;
  if (preference === LANGUAGE_AUTO) return negotiateLocale(browserLanguages(), documentLocale);
  return preference;
}

export function AppearanceEffects() {
  const { data } = useSettings();
  const appearance = data?.appearance ?? DEFAULT_SETTINGS.appearance;
  // The DOCUMENT locale — the language generated legal instruments are written in. It is the
  // instance's setting, it is the floor for UI negotiation below, and a user's UI preference must
  // NEVER propagate back into it: a Portuguese company's atas stay pt-PT however its operator
  // reads the interface.
  const documentLocale = data?.documents?.locale ?? DEFAULT_SETTINGS.documents.locale;

  // The UI locale (t71). A pinned preference wins; `auto` negotiates against the browser and falls
  // back to the document locale.
  //
  // Detection applies ONLY to a signed-in user. `auto` is a *user's* standing instruction, and
  // signed out there is no user to have given one — so the instance's configured language governs
  // the sign-in screen, as it always has. Detecting there would let a visitor's browser headers
  // override a language the instance operator deliberately chose, for someone who has expressed no
  // preference at all.
  const session = useSession();
  const user = session.data?.user ?? null;
  const uiLocale = resolveUiLocale(user?.language ?? null, documentLocale);

  // Publish the per-session leather grain onto the root so BOTH the fixed background
  // layer and the button-texture layer read the same hide. Kept here (not only in
  // LeatherBackground) because button texture can be on while the background layer is
  // off, so the grain var must exist independently of the background element.
  const grain = useSyncExternalStore(grainStore.subscribe, grainStore.get, grainStore.get);
  useEffect(() => {
    document.documentElement.style.setProperty('--leather-grain', `url("${grain}")`);
  }, [grain]);

  useEffect(() => {
    applyAppearance(appearance);
  }, [appearance]);

  // Operator colour overrides (primary/secondary/background/surface). Client-only and
  // localStorage-backed (see colorStore), so they persist without touching the settings
  // wire contract. Each set field wins over theme.css via an inline custom property; an
  // empty store clears them all and the theme defaults govern again. Because this whole
  // component is unmounted in safe mode, custom colours are automatically bypassed there.
  const colors = useSyncExternalStore(colorStore.subscribe, colorStore.get, colorStore.get);
  useEffect(() => {
    applyColorOverrides(colors);
  }, [colors]);

  useEffect(() => {
    applyLocale(uiLocale);
    // Keep the i18n store's active locale in sync so the non-React `t()` (API client, enum-label
    // shim) and the live catalog swap agree.
    i18nStore.setActiveLocale(uiLocale);
  }, [uiLocale]);

  return null;
}
