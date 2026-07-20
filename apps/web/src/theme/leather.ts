/**
 * Procedural leather-grain background (UX-01/UX-03).
 *
 * The texture is a self-contained inline SVG — an `feTurbulence` fractalNoise
 * field rendered to an opaque grayscale tile — encoded as a `data:` URI. There
 * is NO external image and NO network fetch, so the offline/CSP parity the rest
 * of the app relies on is preserved. `theme.css` composites this grain over the
 * theme's deep-green (dark) / warm parchment (light) base with a soft-light
 * blend plus radial highlight + vignette, giving the leathery depth.
 *
 * The turbulence seed (and a small base-frequency jitter) are randomized per
 * load, so every session gets a subtly different hide. The texture is static —
 * nothing animates — so `prefers-reduced-motion` needs no special handling.
 */

// A single seamless tile; `stitchTiles="stitch"` lets the browser repeat it
// across any viewport without visible seams. Kept modest so the data URI stays
// small.
const TILE = 520;

/** A fresh turbulence seed in a stable, reasonable integer range. */
export function randomSeed(): number {
  return Math.floor(Math.random() * 100_000);
}

/**
 * Build the leather-grain tile as an `data:image/svg+xml` URI.
 *
 * `seed` picks the noise field; `frequency` is the fractalNoise base frequency
 * (higher = finer grain). Both default to randomized values so callers get a
 * different hide each time, but they are injectable to keep tests deterministic.
 */
export function leatherGrainDataUri(
  seed: number = randomSeed(),
  frequency: number = 0.62 + Math.random() * 0.14,
): string {
  // Two slightly different x/y frequencies avoid an obviously uniform weave.
  const fx = frequency.toFixed(4);
  const fy = (frequency * 1.06).toFixed(4);

  // feTurbulence emits noise in all four channels; the feColorMatrix collapses
  // RGB to a grayscale value (row-averaged) and forces alpha to 1, yielding an
  // OPAQUE gray field. theme.css then soft-light-blends it so the grain both
  // lightens and darkens the base colour — the look of tanned hide.
  const svg =
    `<svg xmlns='http://www.w3.org/2000/svg' width='${TILE}' height='${TILE}'>` +
    `<filter id='l' x='0' y='0' width='100%' height='100%'>` +
    `<feTurbulence type='fractalNoise' baseFrequency='${fx} ${fy}' numOctaves='5' seed='${seed}' stitchTiles='stitch' result='n'/>` +
    `<feColorMatrix in='n' type='matrix' values='0.33 0.33 0.33 0 0 0.33 0.33 0.33 0 0 0.33 0.33 0.33 0 0 0 0 0 0 1'/>` +
    `</filter>` +
    `<rect width='100%' height='100%' filter='url(#l)'/>` +
    `</svg>`;

  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

/**
 * Randomize the leather grain for this load and publish it to CSS as the
 * `--leather-grain` custom property. `theme.css`'s `.leather-bg` layer reads it;
 * the base colour, vignette and blend all live in CSS so both themes stay in
 * sync via `prefers-color-scheme`.
 */
export function applyLeatherTexture(root: HTMLElement = document.documentElement): void {
  root.style.setProperty('--leather-grain', `url("${leatherGrainDataUri()}")`);
}
