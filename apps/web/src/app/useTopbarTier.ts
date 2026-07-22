/**
 * Which reflow tier the fixed top bar is in (t42).
 *
 * The bar carries three clusters — the brand, the centred primary tabs, and the right-hand
 * utility/session controls. On a wide window all three lay out inline; as the window narrows they
 * stop fitting and must collapse *before* they would paint over one another. This hook measures the
 * viewport (the bar is `position: fixed; left: 0; right: 0`, so its width IS the viewport width) and
 * reports one of three tiers; the shell renders a single representation for the current tier, so the
 * DOM never carries a hidden duplicate of a control.
 *
 *   - `wide`   — everything inline: brand · centred tabs · icon-nav · bell · picker.
 *   - `medium` — the tab row is over budget: tabs fold into a burger; brand + icon-nav stay.
 *   - `narrow` — the utilities are over budget too: icon-nav folds into a "more" menu, the brand
 *                is dropped, and the user picker shows avatar-only.
 *
 * The two breakpoints are deliberately generous: the tabs collapse at 960px (comfortably before the
 * eight-tab row would meet the session cluster in the longest locales — grid centring keeps them
 * from overlapping down to ~950px, and the burger takes over below that), and the utilities collapse
 * at 600px. `matchMedia` drives it, with `change` listeners so a live resize reflows without a
 * reload. Where `matchMedia` is unavailable (jsdom under test, or any non-DOM host) it fails OPEN to
 * `wide` — the same fail-safe stance the app's other `matchMedia` reads take — so the full inline
 * layout, and the tests that assert it, are the default.
 */
import { useEffect, useState } from 'react';

export type TopbarTier = 'wide' | 'medium' | 'narrow';

/** ≤ this width, the primary tab row folds into the burger. */
export const TOPBAR_NAV_COLLAPSE = '(max-width: 960px)';
/** ≤ this width, the utility glyphs fold into the "more" menu and the brand is dropped. */
export const TOPBAR_UTILITY_COLLAPSE = '(max-width: 600px)';

function readTier(): TopbarTier {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return 'wide';
  if (window.matchMedia(TOPBAR_UTILITY_COLLAPSE).matches) return 'narrow';
  if (window.matchMedia(TOPBAR_NAV_COLLAPSE).matches) return 'medium';
  return 'wide';
}

export function useTopbarTier(): TopbarTier {
  // Read synchronously on first render (no matchMedia ⇒ 'wide') so a narrow window paints collapsed
  // immediately rather than flashing the inline layout and snapping.
  const [tier, setTier] = useState<TopbarTier>(readTier);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
    const nav = window.matchMedia(TOPBAR_NAV_COLLAPSE);
    const utility = window.matchMedia(TOPBAR_UTILITY_COLLAPSE);
    const update = () => setTier(readTier());
    // Re-read on the first render after mount too, in case the environment gained matchMedia (or
    // the width changed) between the initial state read and the effect running.
    update();
    nav.addEventListener('change', update);
    utility.addEventListener('change', update);
    return () => {
      nav.removeEventListener('change', update);
      utility.removeEventListener('change', update);
    };
  }, []);

  return tier;
}
