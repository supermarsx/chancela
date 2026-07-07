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
import { useSettings } from '../api/hooks';
import { DEFAULT_SETTINGS } from '../api/types';
import { grainStore } from './grainStore';
import { applyAppearance, applyLocale } from './appearance';
import { i18nStore } from '../i18n';

export function AppearanceEffects() {
  const { data } = useSettings();
  const appearance = data?.appearance ?? DEFAULT_SETTINGS.appearance;
  const locale = data?.documents?.locale ?? DEFAULT_SETTINGS.documents.locale;

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

  useEffect(() => {
    applyLocale(locale);
    // Keep the i18n store's active locale in sync with the committed settings so the
    // non-React `t()` (API client, enum-label shim) and the live catalog swap agree.
    i18nStore.setActiveLocale(locale);
  }, [locale]);

  return null;
}
