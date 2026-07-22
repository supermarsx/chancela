/**
 * The app-themed colour picker — a self-built replacement for the raw OS-native
 * `<input type="color">` in Configurações › Aparência › Cores personalizadas.
 *
 * A swatch trigger opens an interactive popover styled entirely with the app's own design
 * tokens (gilt / green / parchment), so it is light- and dark-correct for free: the palette
 * flips via `[data-theme]` / `prefers-color-scheme`, and this component only ever reads those
 * tokens. The popover carries a 2D saturation/brightness area, a hue slider, a hex text field,
 * and a row of on-brand preset swatches. It is a **controlled** component — `value` (hex) in,
 * `onChange(hex)` out — and changes NOTHING about the colour model: the caller keeps writing
 * the existing `colorStore` and applying live through `applyColorOverrides`. This swaps the
 * input control, not the behaviour.
 *
 * ## Why not a dependency
 * No colour-picker library is present, and one would ship its own CSS-var-blind chrome that
 * fights the gilt theme and the light/dark token flip. The only colour maths not already in
 * {@link ./appearance} is hex↔HSV, which lives in {@link ./colorConversion}; everything here is
 * presentation and interaction.
 *
 * ## Rendering above everything + dismissal (mirrors {@link ../ui/Tooltip})
 * The panel is **portaled to `document.body`** and positioned `fixed` against the trigger's
 * `getBoundingClientRect()`, so it escapes every `overflow: hidden` / transform ancestor that
 * would clip it, and it re-pins on scroll (capture) and resize. Unlike the `pointer-events:none`
 * Tooltip, this popover is INTERACTIVE: it owns its own open state, closes on outside
 * pointer-down / `Escape` / focus leaving the panel, and returns focus to the trigger. Its
 * entrance transition lives on `.color-picker__panel` and so collapses under BOTH
 * `prefers-reduced-motion` and `:root[data-safe-mode='on']` (each zeroes transition on `*`),
 * exactly like `.tooltip*`.
 *
 * ## HSV is the interactive source of truth
 * The 2D area and hue slider work in HSV, which hex cannot round-trip losslessly (a colour at
 * `v = 0` is black regardless of hue). So while the panel is open the live HSV is held in local
 * state, seeded from `value` on each open and reconciled only when the operator commits via the
 * hex field or a preset — never re-derived from `value` mid-drag, which would snap hue/sat back.
 */
import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
  type PointerEvent as ReactPointerEvent,
} from 'react';
import { createPortal } from 'react-dom';
import { isHexColor } from './appearance';
import { hexToHsv, hsvToHex, type Hsv } from './colorConversion';
import { useT } from '../i18n';

/**
 * On-brand preset swatches — the gilt/green/parchment identity constants from `theme.css`
 * (`--gold*`, `--green*`, `--paper`, the light surface). These are brand hexes, not operator
 * copy, so they are literals rather than tokens: a preset must resolve to a fixed colour, not
 * to whatever the *current* theme has bound the token to. Keeping the row on-brand nudges
 * operators toward a coherent palette.
 */
const PRESETS: readonly string[] = [
  '#b8963e', // --gold
  '#d8b55a', // --gold-bright
  '#6b4d12', // --gold-deep
  '#1f6f4a', // --green-accent
  '#10241b', // --green-ink
  '#0b1a13', // --green-deep
  '#f7f3ea', // --paper
  '#fffdf8', // light surface
];

/** A fallback HSV for the rare unparseable `value` (keeps the controls operable). */
const FALLBACK_HSV: Hsv = { h: 0, s: 0, v: 0 };

export interface ColorPickerProps {
  /** The current colour as a `#rgb`/`#rrggbb` hex (an override, or the field's seed). */
  value: string;
  /** Called with a normalised `#rrggbb` hex whenever the operator commits a new colour. */
  onChange: (hex: string) => void;
  /** Clear this field back to the theme default. Shown only when {@link isSet} is true. */
  onClear?: () => void;
  /** Whether an override is actually set (vs. showing the seed) — gates the clear affordance. */
  isSet?: boolean;
  /** The field's human label (e.g. "Cor primária") — names the trigger and the dialog. */
  label: string;
}

/** How far one arrow-key press nudges saturation/value (fraction) and hue (degrees). */
const SV_STEP = 0.02;
const HUE_STEP = 2;

export function ColorPicker({ value, onChange, onClear, isSet = false, label }: ColorPickerProps) {
  const t = useT();
  const dialogId = useId();

  const [open, setOpen] = useState(false);
  // The live HSV while the panel is open — seeded from `value` on open, then owned by the
  // interactive controls (see the file header on why hex cannot be the source of truth).
  const [hsv, setHsv] = useState<Hsv>(() => hexToHsv(value) ?? FALLBACK_HSV);
  // The hex field's editable buffer — kept separate so partial/invalid typing is not clobbered.
  const [hexDraft, setHexDraft] = useState(value);

  const triggerRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const areaRef = useRef<HTMLDivElement>(null);
  const hueRef = useRef<HTMLDivElement>(null);
  const [coords, setCoords] = useState<{ left: number; top: number; placement: 'top' | 'bottom' }>({
    left: 0,
    top: 0,
    placement: 'bottom',
  });

  const currentHex = hsvToHex(hsv);
  const draftValid = isHexColor(hexDraft);

  // --- Commit helpers --------------------------------------------------------------------
  // Every path that changes the colour funnels through one of these two, so the local HSV,
  // the hex draft, and the parent stay in lockstep.

  /** Apply an HSV change (2D area / hue slider): derive the hex, sync the draft, notify. */
  const applyHsv = useCallback(
    (next: Hsv): void => {
      setHsv(next);
      const hex = hsvToHex(next);
      setHexDraft(hex);
      onChange(hex);
    },
    [onChange],
  );

  /** Apply a known-valid hex (hex field / preset): back-derive HSV so the area/hue follow. */
  const applyHex = useCallback(
    (hex: string): void => {
      const next = hexToHsv(hex);
      if (next) setHsv(next);
      setHexDraft(hex);
      onChange(hex);
    },
    [onChange],
  );

  // --- Open / close ----------------------------------------------------------------------

  const openPanel = useCallback((): void => {
    // Re-seed from the current value so the panel always opens on what is applied now.
    setHsv(hexToHsv(value) ?? FALLBACK_HSV);
    setHexDraft(value);
    setOpen(true);
  }, [value]);

  const closePanel = useCallback((returnFocus = true): void => {
    setOpen(false);
    if (returnFocus) triggerRef.current?.focus();
  }, []);

  // --- Popover positioning (technique from Tooltip: fixed, anchored, flip + clamp) --------
  const reposition = useCallback((): void => {
    const trigger = triggerRef.current;
    if (!trigger) return;
    const rect = trigger.getBoundingClientRect();
    const panel = panelRef.current?.getBoundingClientRect() ?? null;
    const gap = 6;
    const panelH = panel?.height ?? 0;
    const panelW = panel?.width ?? 0;

    // Prefer below; flip above when the panel would fall off the bottom but fits above.
    const roomBelow = window.innerHeight - rect.bottom;
    const roomAbove = rect.top;
    const placement: 'top' | 'bottom' =
      roomBelow >= panelH + gap || roomBelow >= roomAbove ? 'bottom' : 'top';
    const top =
      placement === 'bottom' ? rect.bottom + gap : Math.max(gap, rect.top - panelH - gap);

    // Left-align to the trigger, then clamp so a wide panel near the right edge stays on screen.
    const margin = 8;
    let left = rect.left;
    const maxLeft = window.innerWidth - margin - panelW;
    if (maxLeft >= margin) left = Math.min(Math.max(left, margin), maxLeft);

    setCoords((prev) =>
      prev.left === left && prev.top === top && prev.placement === placement
        ? prev
        : { left, top, placement },
    );
  }, []);

  // Position synchronously before paint, and keep pinned while open. Focus the S/V area on open.
  useLayoutEffect(() => {
    if (!open) return;
    reposition();
    areaRef.current?.focus();
    window.addEventListener('scroll', reposition, true);
    window.addEventListener('resize', reposition);
    return () => {
      window.removeEventListener('scroll', reposition, true);
      window.removeEventListener('resize', reposition);
    };
  }, [open, reposition]);

  // Dismiss on outside pointer-down and on Escape (capture Escape anywhere while open).
  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent): void => {
      const target = event.target as Node | null;
      if (panelRef.current?.contains(target) || triggerRef.current?.contains(target)) return;
      closePanel(false);
    };
    const onKeyDown = (event: globalThis.KeyboardEvent): void => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        closePanel();
      }
    };
    document.addEventListener('pointerdown', onPointerDown, true);
    document.addEventListener('keydown', onKeyDown, true);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown, true);
      document.removeEventListener('keydown', onKeyDown, true);
    };
  }, [open, closePanel]);

  // --- 2D saturation/brightness area -----------------------------------------------------

  /** Map a pointer position within the area to saturation/value and commit. */
  const areaFromPointer = useCallback(
    (clientX: number, clientY: number): void => {
      const el = areaRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      // A zero-sized box (jsdom) yields NaN → clamp01 folds to 0; harmless in tests.
      const s = (clientX - rect.left) / rect.width;
      const v = 1 - (clientY - rect.top) / rect.height;
      applyHsv({ h: hsv.h, s: clamp01(s), v: clamp01(v) });
    },
    [applyHsv, hsv.h],
  );

  const onAreaPointerDown = (event: ReactPointerEvent<HTMLDivElement>): void => {
    event.preventDefault();
    areaRef.current?.focus();
    const el = event.currentTarget;
    if (typeof el.setPointerCapture === 'function') {
      try {
        el.setPointerCapture(event.pointerId);
      } catch {
        // jsdom / unsupported — dragging still works via the move listener.
      }
    }
    areaFromPointer(event.clientX, event.clientY);
  };

  const onAreaPointerMove = (event: ReactPointerEvent<HTMLDivElement>): void => {
    const el = event.currentTarget;
    if (typeof el.hasPointerCapture === 'function' && !el.hasPointerCapture(event.pointerId)) return;
    if (event.buttons === 0) return;
    areaFromPointer(event.clientX, event.clientY);
  };

  const onAreaKeyDown = (event: KeyboardEvent<HTMLDivElement>): void => {
    let { s, v } = hsv;
    switch (event.key) {
      case 'ArrowLeft':
        s -= SV_STEP;
        break;
      case 'ArrowRight':
        s += SV_STEP;
        break;
      case 'ArrowUp':
        v += SV_STEP;
        break;
      case 'ArrowDown':
        v -= SV_STEP;
        break;
      default:
        return;
    }
    event.preventDefault();
    applyHsv({ h: hsv.h, s: clamp01(s), v: clamp01(v) });
  };

  // --- Hue slider ------------------------------------------------------------------------

  const hueFromPointer = useCallback(
    (clientX: number): void => {
      const el = hueRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const ratio = (clientX - rect.left) / rect.width;
      applyHsv({ ...hsv, h: clamp01(ratio) * 360 });
    },
    [applyHsv, hsv],
  );

  const onHuePointerDown = (event: ReactPointerEvent<HTMLDivElement>): void => {
    event.preventDefault();
    hueRef.current?.focus();
    const el = event.currentTarget;
    if (typeof el.setPointerCapture === 'function') {
      try {
        el.setPointerCapture(event.pointerId);
      } catch {
        // ignore — move listener still tracks the drag.
      }
    }
    hueFromPointer(event.clientX);
  };

  const onHuePointerMove = (event: ReactPointerEvent<HTMLDivElement>): void => {
    const el = event.currentTarget;
    if (typeof el.hasPointerCapture === 'function' && !el.hasPointerCapture(event.pointerId)) return;
    if (event.buttons === 0) return;
    hueFromPointer(event.clientX);
  };

  const onHueKeyDown = (event: KeyboardEvent<HTMLDivElement>): void => {
    let h = hsv.h;
    if (event.key === 'ArrowLeft' || event.key === 'ArrowDown') h -= HUE_STEP;
    else if (event.key === 'ArrowRight' || event.key === 'ArrowUp') h += HUE_STEP;
    else return;
    event.preventDefault();
    applyHsv({ ...hsv, h: ((h % 360) + 360) % 360 });
  };

  // --- Render ----------------------------------------------------------------------------

  const hueHex = hsvToHex({ h: hsv.h, s: 1, v: 1 });
  const areaStyle: CSSProperties = {
    // Layered: value darkens toward the bottom, saturation toward the left, over the pure hue.
    backgroundImage: `linear-gradient(to top, #000, transparent), linear-gradient(to right, #fff, transparent)`,
    backgroundColor: hueHex,
  };
  const thumbStyle: CSSProperties = { left: `${hsv.s * 100}%`, top: `${(1 - hsv.v) * 100}%` };
  const hueThumbStyle: CSSProperties = { left: `${(hsv.h / 360) * 100}%` };

  const panel = (
    <div
      ref={panelRef}
      id={dialogId}
      role="dialog"
      aria-label={`${label} — ${t('settings.appearance.colors.picker.dialog')}`}
      className={`color-picker__panel${open ? ' is-open' : ''} color-picker__panel--${coords.placement}`}
      style={{ left: coords.left, top: coords.top }}
    >
      <div
        ref={areaRef}
        role="slider"
        tabIndex={0}
        aria-label={t('settings.appearance.colors.picker.saturation')}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(hsv.s * 100)}
        aria-valuetext={currentHex}
        className="color-picker__area"
        style={areaStyle}
        onPointerDown={onAreaPointerDown}
        onPointerMove={onAreaPointerMove}
        onKeyDown={onAreaKeyDown}
      >
        <span className="color-picker__area-thumb" style={thumbStyle} aria-hidden />
      </div>

      <div
        ref={hueRef}
        role="slider"
        tabIndex={0}
        aria-label={t('settings.appearance.colors.picker.hue')}
        aria-valuemin={0}
        aria-valuemax={360}
        aria-valuenow={Math.round(hsv.h)}
        className="color-picker__hue"
        onPointerDown={onHuePointerDown}
        onPointerMove={onHuePointerMove}
        onKeyDown={onHueKeyDown}
      >
        <span className="color-picker__hue-thumb" style={hueThumbStyle} aria-hidden />
      </div>

      <div className="color-picker__hexrow">
        <label className="color-picker__hexlabel" htmlFor={`${dialogId}-hex`}>
          {t('settings.appearance.colors.picker.hex')}
        </label>
        <input
          id={`${dialogId}-hex`}
          className="color-picker__hexinput"
          type="text"
          inputMode="text"
          spellCheck={false}
          autoComplete="off"
          value={hexDraft}
          aria-invalid={hexDraft.length > 0 && !draftValid}
          onChange={(event) => {
            const raw = event.target.value;
            setHexDraft(raw);
            if (isHexColor(raw)) applyHex(raw);
          }}
          onBlur={() => setHexDraft(currentHex)}
        />
      </div>

      <div
        role="group"
        aria-label={t('settings.appearance.colors.picker.presets')}
        className="color-picker__presets"
      >
        {PRESETS.map((preset) => (
          <button
            key={preset}
            type="button"
            className="color-picker__preset"
            style={{ backgroundColor: preset }}
            aria-label={t('settings.appearance.colors.picker.preset', { color: preset })}
            onClick={() => applyHex(preset)}
          />
        ))}
      </div>

      {onClear && isSet ? (
        <div className="color-picker__footer">
          <button
            type="button"
            className="btn btn--ghost color-picker__clear"
            onClick={() => {
              onClear();
              closePanel();
            }}
          >
            {t('settings.appearance.colors.clearField')}
          </button>
        </div>
      ) : null}
    </div>
  );

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        className="color-picker__trigger"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={open ? dialogId : undefined}
        aria-label={`${t('settings.appearance.colors.picker.open')}: ${label}`}
        onClick={() => (open ? closePanel() : openPanel())}
      >
        <span className="color-picker__chip" style={{ backgroundColor: value }} aria-hidden />
        <span className="color-picker__triggerhex">{value}</span>
      </button>
      {typeof document !== 'undefined' ? createPortal(panel, document.body) : panel}
    </>
  );
}

/** Clamp a number to `[0, 1]` (NaN → 0), mirroring `colorConversion`'s own guard. */
function clamp01(n: number): number {
  if (Number.isNaN(n)) return 0;
  return Math.min(1, Math.max(0, n));
}
