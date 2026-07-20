/**
 * Inline-SVG QR renderer (wp27-e5) over the zero-dep {@link ./qr} encoder.
 *
 * The matrix is drawn as a single SVG `<path>` (one `M…h…v…` sub-path per dark module) so
 * the whole code is one vector node — crisp at any size, no raster, no dependency. A
 * 4-module quiet zone is added around the matrix (mandatory for scanners). Colours are
 * fixed dark-on-light regardless of the app theme: a scanner needs the canonical contrast,
 * and a theme-inverted (light-on-dark) code is unreliable to read.
 */
import { useMemo } from 'react';
import { encodeQr } from './qr';

/** Modules of quiet zone the spec requires around the symbol. */
const QUIET_ZONE = 4;

export interface QrCodeProps {
  /** The payload to encode (the pairing deep-link). */
  value: string;
  /** Rendered pixel size of the square (including quiet zone). */
  size?: number;
  /** Accessible name for the image. */
  title: string;
}

/**
 * Render `value` as a scannable QR image. Returns `null` when the value is empty or exceeds
 * the encoder's capacity — the caller always pairs this with a copyable deep-link fallback,
 * so a missing QR never blocks enrollment.
 */
export function QrCode({ value, size = 240, title }: QrCodeProps) {
  const drawing = useMemo(() => {
    if (!value) return null;
    try {
      const { matrix, size: modules } = encodeQr(value);
      const dimension = modules + QUIET_ZONE * 2;
      let path = '';
      for (let r = 0; r < modules; r += 1) {
        for (let c = 0; c < modules; c += 1) {
          if (matrix[r][c]) {
            path += `M${c + QUIET_ZONE} ${r + QUIET_ZONE}h1v1h-1z`;
          }
        }
      }
      return { path, dimension };
    } catch {
      // Over-capacity payload — the panel shows the copyable deep-link instead.
      return null;
    }
  }, [value]);

  if (!drawing) return null;

  return (
    <svg
      className="qr-code"
      role="img"
      aria-label={title}
      width={size}
      height={size}
      viewBox={`0 0 ${drawing.dimension} ${drawing.dimension}`}
      shapeRendering="crispEdges"
      xmlns="http://www.w3.org/2000/svg"
    >
      <rect width={drawing.dimension} height={drawing.dimension} fill="#ffffff" />
      <path d={drawing.path} fill="#0b0b0b" />
    </svg>
  );
}
