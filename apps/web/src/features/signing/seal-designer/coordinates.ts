/**
 * Canvas <-> PDF user-space coordinate mapping for the visual seal designer (t67-e12).
 *
 * This is the single load-bearing correctness surface of the designer: the on-screen seal
 * box (CSS pixels, origin top-left, y increasing DOWN) has to become the backend seal DTO
 * rectangle in **unrotated PDF user space** (points, origin bottom-left, y increasing UP,
 * `x`/`y` = the LOWER-LEFT corner) — the convention frozen by the e3 backend
 * (`SealPlacement`) and the plan's §0.3 binding coordinate spec:
 *
 *   - page is 0-based; units are PDF points;
 *   - origin is the page's bottom-left, y-UP; x/y are the seal rectangle's lower-left corner;
 *   - the backend emits `/Rect = [x, y, x + w, y + h]`;
 *   - a `/Rotate`d page is placed in **unrotated user space** (the page's own coordinate
 *     system, before display rotation) — so the mapping must undo both the render scale and
 *     the display rotation.
 *
 * The transform matrix here is the exact one pdf.js builds for a page viewport
 * (`PageViewport`, scale + rotation, MediaBox origin at 0,0 — the sealed PDF/A pages the app
 * renders). Replicating it (rather than only calling `viewport.convertToPdfPoint` at runtime)
 * lets the mapping be unit-tested to the point without a live pdf.js render, and keeps the
 * on-screen overlay (forward map) and the emitted DTO (inverse map) provably reciprocal.
 */

/** A page's display rotation, normalized to one of the four right angles. */
export type Rotation = 0 | 90 | 180 | 270;

/** The rendered PDF page's geometry needed to map between canvas and PDF space. */
export interface PageGeometry {
  /** Unrotated PDF page width in points (MediaBox width, before any `/Rotate`). */
  widthPt: number;
  /** Unrotated PDF page height in points (MediaBox height, before any `/Rotate`). */
  heightPt: number;
  /** Effective display rotation of the page (`/Rotate` normalized to 0|90|180|270). */
  rotation: Rotation;
  /** Uniform render scale — CSS pixels per PDF point — the page was rasterized at. */
  scale: number;
}

/** A rectangle in the rendered canvas: CSS pixels, origin top-left, y increasing DOWN. */
export interface CanvasBox {
  left: number;
  top: number;
  width: number;
  height: number;
}

/** A seal rectangle in PDF user space: points, origin bottom-left, y-UP, lower-left corner. */
export interface PdfRect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** A 2-D affine transform `[a, b, c, d, e, f]` (pdf.js / PDF matrix order). */
export type Matrix = [number, number, number, number, number, number];

/** Normalize any integer degree (incl. negatives / >=360) to a {@link Rotation}. */
export function normalizeRotation(deg: number): Rotation {
  const r = (((Math.round(deg / 90) * 90) % 360) + 360) % 360;
  return r as Rotation;
}

/**
 * The CSS-pixel size of the rendered page. When the page is rotated by a quarter turn the
 * on-screen width/height swap relative to the unrotated MediaBox.
 */
export function renderedSize(geo: PageGeometry): { width: number; height: number } {
  const quarterTurned = geo.rotation === 90 || geo.rotation === 270;
  const w = (quarterTurned ? geo.heightPt : geo.widthPt) * geo.scale;
  const h = (quarterTurned ? geo.widthPt : geo.heightPt) * geo.scale;
  return { width: w, height: h };
}

/**
 * The exact pdf.js page-viewport transform for a MediaBox anchored at the origin
 * (`viewBox = [0, 0, widthPt, heightPt]`, no offset). Maps an unrotated PDF user-space point
 * (origin bottom-left, y-UP) to a rendered canvas point (origin top-left, y-DOWN).
 */
export function viewportTransform(geo: PageGeometry): Matrix {
  const { widthPt: W, heightPt: H, scale: s } = geo;
  const rotation = normalizeRotation(geo.rotation);

  // Rotation sub-matrix (pdf.js PageViewport), with the y-flip baked into the 0/180 rows.
  let rotateA: number;
  let rotateB: number;
  let rotateC: number;
  let rotateD: number;
  switch (rotation) {
    case 90:
      rotateA = 0;
      rotateB = 1;
      rotateC = 1;
      rotateD = 0;
      break;
    case 180:
      rotateA = -1;
      rotateB = 0;
      rotateC = 0;
      rotateD = 1;
      break;
    case 270:
      rotateA = 0;
      rotateB = -1;
      rotateC = -1;
      rotateD = 0;
      break;
    default:
      rotateA = 1;
      rotateB = 0;
      rotateC = 0;
      rotateD = -1;
      break;
  }

  const centerX = W / 2;
  const centerY = H / 2;

  let offsetCanvasX: number;
  let offsetCanvasY: number;
  if (rotateA === 0) {
    offsetCanvasX = Math.abs(centerY) * s;
    offsetCanvasY = Math.abs(centerX) * s;
  } else {
    offsetCanvasX = Math.abs(centerX) * s;
    offsetCanvasY = Math.abs(centerY) * s;
  }

  return [
    rotateA * s,
    rotateB * s,
    rotateC * s,
    rotateD * s,
    offsetCanvasX - rotateA * s * centerX - rotateC * s * centerY,
    offsetCanvasY - rotateB * s * centerX - rotateD * s * centerY,
  ];
}

/** Apply an affine transform to a point (forward: PDF point -> canvas point). */
export function applyMatrix(m: Matrix, x: number, y: number): [number, number] {
  return [m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]];
}

/** Apply the inverse of an affine transform to a point (canvas point -> PDF point). */
export function applyInverseMatrix(m: Matrix, x: number, y: number): [number, number] {
  const [a, b, c, d, e, f] = m;
  const det = a * d - b * c;
  if (det === 0) {
    // A degenerate (zero-scale) viewport never occurs for a real render; fail safe at origin.
    return [0, 0];
  }
  const px = (d * (x - e) - c * (y - f)) / det;
  const py = (-b * (x - e) + a * (y - f)) / det;
  return [px, py];
}

/** Round a point value to 2 decimals (sub-point precision the backend accepts as `f32`). */
function round2(v: number): number {
  return Math.round(v * 100) / 100;
}

/**
 * Map an on-screen seal box (CSS px, top-left origin, y-DOWN) to the backend seal rectangle
 * in unrotated PDF user space (points, bottom-left origin, y-UP, lower-left corner).
 *
 * Both opposite corners of the box are converted, then min/max-reduced: this is what makes
 * the result correct under the y-flip (the box's TOP edge becomes the rectangle's HIGHER `y`)
 * and under any quarter-turn rotation (where on-screen width and height swap axes). `x`/`y`
 * are clamped to non-negative (the backend rejects negatives) and every value is rounded to
 * sub-point precision.
 */
export function canvasBoxToPdfRect(box: CanvasBox, geo: PageGeometry): PdfRect {
  const m = viewportTransform(geo);
  const [x1, y1] = applyInverseMatrix(m, box.left, box.top);
  const [x2, y2] = applyInverseMatrix(m, box.left + box.width, box.top + box.height);
  const x = Math.max(0, Math.min(x1, x2));
  const y = Math.max(0, Math.min(y1, y2));
  const w = Math.abs(x1 - x2);
  const h = Math.abs(y1 - y2);
  return { x: round2(x), y: round2(y), w: round2(w), h: round2(h) };
}

/**
 * The inverse of {@link canvasBoxToPdfRect}: place a stored PDF-space seal rectangle back onto
 * the rendered canvas as a CSS-pixel box. Drives the live "this is where it will appear"
 * overlay so the preview is the exact reciprocal of what will be sent.
 */
export function pdfRectToCanvasBox(rect: PdfRect, geo: PageGeometry): CanvasBox {
  const m = viewportTransform(geo);
  const [cx1, cy1] = applyMatrix(m, rect.x, rect.y);
  const [cx2, cy2] = applyMatrix(m, rect.x + rect.w, rect.y + rect.h);
  const left = Math.min(cx1, cx2);
  const top = Math.min(cy1, cy2);
  return {
    left,
    top,
    width: Math.abs(cx1 - cx2),
    height: Math.abs(cy1 - cy2),
  };
}

/** Clamp a canvas box so it stays fully inside the rendered page (used while dragging). */
export function clampBoxToPage(box: CanvasBox, geo: PageGeometry): CanvasBox {
  const { width: pageW, height: pageH } = renderedSize(geo);
  const width = Math.min(box.width, pageW);
  const height = Math.min(box.height, pageH);
  const left = Math.min(Math.max(0, box.left), Math.max(0, pageW - width));
  const top = Math.min(Math.max(0, box.top), Math.max(0, pageH - height));
  return { left, top, width, height };
}
