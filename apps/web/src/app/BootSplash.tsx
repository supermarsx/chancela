/**
 * Startup fade-in splash (plan t50 W4, item 1).
 *
 * A brief, decorative app-boot overlay: the gilt crest + wordmark fade/rise in over the
 * leather ground, then the whole layer fades out and unmounts on a short timer. It is an
 * OVERLAY, never a gate — the router, the {@link AuthGate}, and the safe-mode banner all
 * render and become interactive UNDERNEATH it (the splash is `pointer-events: none`, is
 * never awaited for data/readiness, and unmounts itself). It shows once per app load,
 * mounted above the router in `main.tsx`.
 *
 * ## Gating (the hard rule)
 * The splash is SKIPPED ENTIRELY under BOTH kill-switches — it renders nothing, sets no
 * timers, and plays no motion:
 *   - `prefers-reduced-motion: reduce` (checked live via `matchMedia`), and
 *   - safe mode (`isSafeMode()`).
 * The decision is made once, synchronously, before first paint. This is belt-and-braces
 * with the two global CSS kill-switches in `theme.css` (which already zero every
 * animation/transition on `*`): even if it mounted, the `.boot-splash` motion would
 * collapse — but under either signal it never mounts in the first place.
 */
import { useEffect, useState } from 'react';
import { isSafeMode } from './safeMode';
import { useT } from '../i18n';

/** How long the crest is held before the overlay begins fading out (ms). */
const HOLD_MS = 560;
/** Fade-out duration — MUST match the `.boot-splash` opacity transition in theme.css (ms). */
const FADE_MS = 320;

/**
 * Whether the splash may play at all. Decided once, synchronously: safe mode or a
 * reduced-motion preference (or an environment without `matchMedia`) all mean "no motion".
 */
function splashAllowed(): boolean {
  if (isSafeMode()) return false;
  try {
    return !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch {
    // No matchMedia (or it threw) — err on the side of no motion.
    return false;
  }
}

export function BootSplash() {
  const t = useT();
  // Seed the visibility from the synchronous gate so a skipped splash never mounts a DOM
  // node, never schedules a timer, and never flashes.
  const [visible, setVisible] = useState(splashAllowed);
  const [leaving, setLeaving] = useState(false);

  useEffect(() => {
    if (!visible) return;
    const toLeave = window.setTimeout(() => setLeaving(true), HOLD_MS);
    const toHide = window.setTimeout(() => setVisible(false), HOLD_MS + FADE_MS);
    return () => {
      window.clearTimeout(toLeave);
      window.clearTimeout(toHide);
    };
  }, [visible]);

  if (!visible) return null;

  return (
    <div
      className={leaving ? 'boot-splash is-leaving' : 'boot-splash'}
      role="status"
      aria-label={t('splash.aria')}
      data-testid="boot-splash"
    >
      <div className="boot-splash__mark" aria-hidden="true">
        <svg className="boot-splash__crest" viewBox="0 0 48 48" width="48" height="48">
          <circle cx="24" cy="24" r="21" />
          <text x="24" y="31" textAnchor="middle">
            C
          </text>
        </svg>
        <span className="boot-splash__word">{t('common.brand')}</span>
      </div>
    </div>
  );
}
