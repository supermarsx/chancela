/**
 * The fixed, full-viewport leather layer. Its grain comes from {@link grainStore}
 * (randomized once per session, re-rollable from Configurações) via
 * `useSyncExternalStore`, so a re-roll repaints instantly. Everything else — base
 * colour, vignette, highlight, blend, and the grain's opacity (the texture-intensity
 * slider) — is theme/settings-driven in `theme.css`, so the layer looks right in both
 * light and dark without any per-theme logic here.
 *
 * When `appearance.leather_texture` is off the layer is not rendered at all (the spec
 * is "hide the background layer"); the flat `--leather-base` colour on `html` remains
 * as the page ground.
 */
import { useSyncExternalStore } from 'react';
import { grainStore } from './grainStore';
import { useSettings } from '../api/hooks';
import type { CSSProperties } from 'react';

export function LeatherBackground() {
  const grain = useSyncExternalStore(grainStore.subscribe, grainStore.get, grainStore.get);
  const { data } = useSettings();

  // Default to on until settings load (matches the server default), so there is no
  // flash of a missing background on first paint.
  const textureOn = data?.appearance.leather_texture ?? true;
  if (!textureOn) return null;

  // The grain travels as a CSS custom property; `.leather-bg::after` composites it.
  // Typed loosely because custom properties aren't in CSSProperties.
  const style = { '--leather-grain': `url("${grain}")` } as CSSProperties;

  return <div className="leather-bg" aria-hidden="true" data-testid="leather-bg" style={style} />;
}
