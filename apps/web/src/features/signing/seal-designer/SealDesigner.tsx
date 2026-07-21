/**
 * The visual seal designer (t67-e12) — the marquee feature of the web signing tier.
 *
 * Renders the sealed act's PDF page to a canvas (via {@link usePdfPage}) and lets the user place
 * a draggable/resizable seal box over it, pick a predefined text template or upload a raster
 * image, and select the target page. The single source of truth is the seal rectangle in PDF
 * user space ({@link PdfRect}, points, bottom-left origin); the on-screen overlay is its exact
 * reciprocal (`pdfRectToCanvasBox`) and every gesture converts back through `canvasBoxToPdfRect`,
 * so the "this is where it will appear" preview and the emitted DTO can never diverge. On apply it
 * builds the backend {@link SealAppearanceBody} the sign request carries.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { Button, Field, Input, Select, Skeleton, SkeletonRegion } from '../../../ui';
import { useT } from '../../../i18n';
import type { SealAppearanceBody } from '../../../api/types';
import {
  canvasBoxToPdfRect,
  clampBoxToPage,
  pdfRectToCanvasBox,
  renderedSize,
  type CanvasBox,
  type PageGeometry,
  type PdfRect,
} from './coordinates';
import {
  buildSealBody,
  imageContentFromSeal,
  nameDateTemplate,
  readSealImage,
  signedByTemplate,
  type SealContent,
  type SealImageError,
} from './sealSpec';
import { usePdfPage } from './usePdfPage';

/** The CSS width the page is fit into (the container's inner width caps the actual render). */
const DEFAULT_FIT_WIDTH = 560;
/** Stable fallback while pdf.js is still loading the real page geometry (US Letter portrait). */
const FALLBACK_RENDERED_SIZE = {
  width: DEFAULT_FIT_WIDTH,
  height: Math.round(DEFAULT_FIT_WIDTH * (11 / 8.5)),
};
/** A sensible starting seal rectangle (points) when the user opts in without drawing first. */
const DEFAULT_RECT: PdfRect = { x: 72, y: 72, w: 200, h: 80 };
const MIN_CANVAS_BOX_SIZE = 8;
const KEYBOARD_STEP_PT = 1;
const KEYBOARD_FAST_STEP_PT = 10;
const ARIA_KEY_SHORTCUTS =
  'ArrowUp ArrowDown ArrowLeft ArrowRight Shift+ArrowUp Shift+ArrowDown Shift+ArrowLeft Shift+ArrowRight';

type ContentKind = 'name_date' | 'signed_by' | 'image';

export interface SealDesignerProps {
  /** Loads the target (sealed, pre-signature) PDF bytes to render. */
  loadPdf: () => Promise<ArrayBuffer>;
  /** A previously applied seal to re-open for editing, if any. */
  initialSeal?: SealAppearanceBody | null;
  /** Prefill for the text templates (the signer's name and the signing date). */
  defaultName?: string;
  defaultDate?: string;
  /** Apply the built seal appearance back to the signing flow. */
  onApply: (seal: SealAppearanceBody) => void;
  /** Close without applying. */
  onCancel: () => void;
}

type DragMode = 'draw' | 'move' | 'resize';
interface DragState {
  mode: DragMode;
  originX: number;
  originY: number;
  startBox: CanvasBox;
}

export function SealDesigner({
  loadPdf,
  initialSeal,
  defaultName = '',
  defaultDate = '',
  onApply,
  onCancel,
}: SealDesignerProps) {
  const t = useT();
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const surfaceRef = useRef<HTMLDivElement | null>(null);
  const dragRef = useRef<DragState | null>(null);

  const [data, setData] = useState<ArrayBuffer | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [pageIndex, setPageIndex] = useState(initialSeal?.page ?? 0);

  // The seal rectangle in PDF user space — the single source of truth (see file header).
  const [rect, setRect] = useState<PdfRect | null>(
    initialSeal && initialSeal.invisible === false && initialSeal.w && initialSeal.h
      ? {
          x: initialSeal.x ?? 0,
          y: initialSeal.y ?? 0,
          w: initialSeal.w,
          h: initialSeal.h,
        }
      : null,
  );

  const initialKind: ContentKind = initialSeal?.image_base64
    ? 'image'
    : initialSeal?.template?.kind === 'signed_by'
      ? 'signed_by'
      : 'name_date';
  const [contentKind, setContentKind] = useState<ContentKind>(initialKind);
  const [name, setName] = useState(
    initialSeal?.template?.kind === 'name_date' || initialSeal?.template?.kind === 'signed_by'
      ? initialSeal.template.name
      : defaultName,
  );
  const [date, setDate] = useState(
    initialSeal?.template?.kind === 'name_date' || initialSeal?.template?.kind === 'signed_by'
      ? initialSeal.template.date
      : defaultDate,
  );
  const [heading, setHeading] = useState(
    initialSeal?.template?.kind === 'signed_by' ? initialSeal.template.heading : '',
  );
  const [image, setImage] = useState<Extract<SealContent, { kind: 'image' }> | null>(() =>
    imageContentFromSeal(initialSeal),
  );
  const [imageError, setImageError] = useState<SealImageError | null>(null);

  // Load the PDF bytes once.
  useEffect(() => {
    let cancelled = false;
    loadPdf()
      .then((buf) => {
        if (!cancelled) setData(buf);
      })
      .catch((err) => {
        if (!cancelled) setLoadError(err);
      });
    return () => {
      cancelled = true;
    };
  }, [loadPdf]);

  const { status, pageCount, geometry, error } = usePdfPage({
    data,
    pageIndex,
    targetWidth: DEFAULT_FIT_WIDTH,
    canvasRef,
  });

  // Revoke an image preview URL when it is replaced or the designer unmounts.
  useEffect(() => {
    return () => {
      if (image?.revokePreview) URL.revokeObjectURL(image.previewUrl);
    };
  }, [image]);

  /** The pointer position in canvas CSS coordinates (origin = top-left of the render surface). */
  function toCanvasPoint(e: { clientX: number; clientY: number }): { x: number; y: number } {
    const surface = surfaceRef.current;
    if (!surface) return { x: 0, y: 0 };
    const box = surface.getBoundingClientRect();
    return { x: e.clientX - box.left, y: e.clientY - box.top };
  }

  const overlayBox: CanvasBox | null = rect && geometry ? pdfRectToCanvasBox(rect, geometry) : null;

  const commitBox = useCallback((box: CanvasBox, geo: PageGeometry) => {
    setRect(canvasBoxToPdfRect(clampBoxToPage(box, geo), geo));
  }, []);

  function keyboardStepPx(e: React.KeyboardEvent): number {
    return (e.shiftKey ? KEYBOARD_FAST_STEP_PT : KEYBOARD_STEP_PT) * (geometry?.scale ?? 1);
  }

  function moveBoxWithKeyboard(e: React.KeyboardEvent) {
    if (!geometry || !overlayBox) return;
    const step = keyboardStepPx(e);
    let dx = 0;
    let dy = 0;
    switch (e.key) {
      case 'ArrowLeft':
        dx = -step;
        break;
      case 'ArrowRight':
        dx = step;
        break;
      case 'ArrowUp':
        dy = -step;
        break;
      case 'ArrowDown':
        dy = step;
        break;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
    commitBox({ ...overlayBox, left: overlayBox.left + dx, top: overlayBox.top + dy }, geometry);
  }

  function resizeBoxWithKeyboard(e: React.KeyboardEvent) {
    if (!geometry || !overlayBox) return;
    const step = keyboardStepPx(e);
    let dw = 0;
    let dh = 0;
    switch (e.key) {
      case 'ArrowLeft':
        dw = -step;
        break;
      case 'ArrowRight':
        dw = step;
        break;
      case 'ArrowUp':
        dh = -step;
        break;
      case 'ArrowDown':
        dh = step;
        break;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
    commitBox(
      {
        ...overlayBox,
        width: Math.max(MIN_CANVAS_BOX_SIZE, overlayBox.width + dw),
        height: Math.max(MIN_CANVAS_BOX_SIZE, overlayBox.height + dh),
      },
      geometry,
    );
  }

  // Window-level drag: track move/up on the document so a fast drag that leaves the surface still
  // updates and releases cleanly.
  useEffect(() => {
    function onMove(e: MouseEvent) {
      const drag = dragRef.current;
      const geo = geometry;
      if (!drag || !geo) return;
      const p = toCanvasPoint(e);
      if (drag.mode === 'draw') {
        const left = Math.min(drag.originX, p.x);
        const top = Math.min(drag.originY, p.y);
        commitBox(
          { left, top, width: Math.abs(p.x - drag.originX), height: Math.abs(p.y - drag.originY) },
          geo,
        );
      } else if (drag.mode === 'move') {
        const dx = p.x - drag.originX;
        const dy = p.y - drag.originY;
        commitBox(
          {
            left: drag.startBox.left + dx,
            top: drag.startBox.top + dy,
            width: drag.startBox.width,
            height: drag.startBox.height,
          },
          geo,
        );
      } else {
        const width = Math.max(MIN_CANVAS_BOX_SIZE, drag.startBox.width + (p.x - drag.originX));
        const height = Math.max(MIN_CANVAS_BOX_SIZE, drag.startBox.height + (p.y - drag.originY));
        commitBox({ left: drag.startBox.left, top: drag.startBox.top, width, height }, geo);
      }
    }
    function onUp() {
      dragRef.current = null;
    }
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [geometry, commitBox]);

  function startDraw(e: React.MouseEvent) {
    if (!geometry) return;
    e.preventDefault();
    const p = toCanvasPoint(e);
    dragRef.current = {
      mode: 'draw',
      originX: p.x,
      originY: p.y,
      startBox: { left: p.x, top: p.y, width: 0, height: 0 },
    };
    commitBox({ left: p.x, top: p.y, width: 0, height: 0 }, geometry);
  }

  function startMove(e: React.MouseEvent) {
    if (!geometry || !overlayBox) return;
    e.preventDefault();
    e.stopPropagation();
    const p = toCanvasPoint(e);
    dragRef.current = { mode: 'move', originX: p.x, originY: p.y, startBox: overlayBox };
  }

  function startResize(e: React.MouseEvent) {
    if (!geometry || !overlayBox) return;
    e.preventDefault();
    e.stopPropagation();
    const p = toCanvasPoint(e);
    dragRef.current = { mode: 'resize', originX: p.x, originY: p.y, startBox: overlayBox };
  }

  async function onImageChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setImageError(null);
    const result = await readSealImage(file);
    if (!result.ok) {
      setImage((prev) => {
        if (prev?.revokePreview) URL.revokeObjectURL(prev.previewUrl);
        return null;
      });
      setImageError(result.error);
      return;
    }
    setImage((prev) => {
      if (prev?.revokePreview) URL.revokeObjectURL(prev.previewUrl);
      return result.content;
    });
  }

  /** Edit one PDF-point coordinate directly (precise placement fallback). */
  function editRectField(field: keyof PdfRect, value: number) {
    setRect((prev) => {
      const base = prev ?? DEFAULT_RECT;
      const next = { ...base, [field]: Number.isFinite(value) ? Math.max(0, value) : base[field] };
      return next;
    });
  }

  function currentContent(): SealContent | null {
    if (contentKind === 'image') {
      return image;
    }
    if (contentKind === 'signed_by') {
      return signedByTemplate(heading, name, date);
    }
    return nameDateTemplate(name, date);
  }

  const content = currentContent();
  const canApply = rect != null && rect.w > 0 && rect.h > 0 && content != null;

  function handleApply() {
    if (!rect || !content) return;
    onApply(buildSealBody(pageIndex, rect, content));
  }

  const rendered = geometry ? renderedSize(geometry) : FALLBACK_RENDERED_SIZE;
  const placementText = rect
    ? t('signing.seal.designer.placement.summary', {
        page: String(pageIndex + 1),
        w: String(Math.round(rect.w)),
        h: String(Math.round(rect.h)),
        x: String(Math.round(rect.x)),
        y: String(Math.round(rect.y)),
      })
    : t('signing.seal.designer.placement.hint');
  const moveControlLabel = `${t('signing.seal.designer.position.legend')}: ${placementText}`;
  const resizeControlLabel = `${t('signing.seal.designer.position.w')} / ${t(
    'signing.seal.designer.position.h',
  )}: ${placementText}`;

  return (
    <section className="seal-designer" aria-label={t('signing.seal.designer.title')}>
      <header className="seal-designer__head">
        <p className="signing-kicker">{t('signing.seal.designer.kicker')}</p>
        <p className="seal-designer__title">{t('signing.seal.designer.title')}</p>
        <p className="seal-designer__intro">{t('signing.seal.designer.intro')}</p>
      </header>

      <div className="seal-designer__body">
        <div className="seal-designer__stage">
          {pageCount > 1 ? (
            <div className="seal-designer__pager">
              <Button
                variant="ghost"
                onClick={() => setPageIndex((i) => Math.max(0, i - 1))}
                disabled={pageIndex <= 0}
                aria-label={t('signing.seal.designer.page.prev')}
              >
                ‹
              </Button>
              <span className="seal-designer__page-label">
                {t('signing.seal.designer.page.of', {
                  current: String(pageIndex + 1),
                  total: String(pageCount),
                })}
              </span>
              <Button
                variant="ghost"
                onClick={() => setPageIndex((i) => Math.min(pageCount - 1, i + 1))}
                disabled={pageIndex >= pageCount - 1}
                aria-label={t('signing.seal.designer.page.next')}
              >
                ›
              </Button>
            </div>
          ) : null}

          <div
            ref={surfaceRef}
            className="seal-designer__surface"
            style={{
              position: 'relative',
              width: rendered.width,
              height: rendered.height,
              minHeight: rendered.height,
              aspectRatio: `${rendered.width} / ${rendered.height}`,
            }}
            onMouseDown={startDraw}
            role="application"
            aria-label={t('signing.seal.designer.surface.aria')}
          >
            <canvas ref={canvasRef} className="seal-designer__canvas" />
            {/* The surface already reserves the page's exact box (width/height/aspect are
                set above), so there is no layout shift to fix here — what the shimmer buys
                is that the wait reads as a page rendering rather than as a line of prose
                floating over an empty rectangle. The overlay rule is unchanged. */}
            {status === 'loading' ? (
              <SkeletonRegion
                className="seal-designer__hint"
                label={t('signing.seal.designer.loading')}
              >
                <Skeleton height="100%" />
              </SkeletonRegion>
            ) : null}
            {overlayBox ? (
              <div
                className="seal-designer__box"
                data-testid="seal-box"
                style={{
                  position: 'absolute',
                  left: overlayBox.left,
                  top: overlayBox.top,
                  width: overlayBox.width,
                  height: overlayBox.height,
                }}
              >
                <button
                  type="button"
                  className="seal-designer__move-control"
                  data-testid="seal-move-control"
                  onMouseDown={startMove}
                  onKeyDown={moveBoxWithKeyboard}
                  aria-label={moveControlLabel}
                  aria-keyshortcuts={ARIA_KEY_SHORTCUTS}
                >
                  {contentKind === 'image' && image ? (
                    <img
                      src={image.previewUrl}
                      alt=""
                      className="seal-designer__box-image"
                      style={{ width: '100%', height: '100%', objectFit: 'contain' }}
                    />
                  ) : (
                    <span className="seal-designer__box-label">
                      {name || t('signing.seal.designer.box.placeholder')}
                    </span>
                  )}
                </button>
                <button
                  type="button"
                  className="seal-designer__handle"
                  data-testid="seal-resize-handle"
                  onMouseDown={startResize}
                  onKeyDown={resizeBoxWithKeyboard}
                  aria-label={resizeControlLabel}
                  aria-keyshortcuts={ARIA_KEY_SHORTCUTS}
                />
              </div>
            ) : null}
          </div>

          {status === 'error' || loadError ? (
            <p className="seal-designer__error" role="alert">
              {t('signing.seal.designer.error')}
            </p>
          ) : (
            <p className="seal-designer__hint">{placementText}</p>
          )}
          {error ? <span hidden>{String(error)}</span> : null}
        </div>

        <div className="seal-designer__controls">
          <fieldset className="seal-designer__content">
            <legend>{t('signing.seal.designer.content.legend')}</legend>
            <Select
              aria-label={t('signing.seal.designer.content.legend')}
              value={contentKind}
              onChange={(e) => setContentKind(e.target.value as ContentKind)}
              options={[
                { value: 'name_date', label: t('signing.seal.designer.template.nameDate') },
                { value: 'signed_by', label: t('signing.seal.designer.template.signedBy') },
                { value: 'image', label: t('signing.seal.designer.content.image') },
              ]}
            />

            {contentKind === 'image' ? (
              <div className="seal-designer__image">
                <Field
                  label={t('signing.seal.designer.image.upload')}
                  htmlFor="seal-image"
                  hint={t('signing.seal.designer.image.hint')}
                >
                  <input
                    id="seal-image"
                    type="file"
                    accept="image/png,image/jpeg"
                    onChange={onImageChange}
                  />
                </Field>
                {imageError ? (
                  <p className="seal-designer__error" role="alert">
                    {imageError.code === 'too_large'
                      ? t('signing.seal.designer.image.error.tooLarge')
                      : imageError.code === 'empty'
                        ? t('signing.seal.designer.image.error.empty')
                        : t('signing.seal.designer.image.error.unsupported')}
                  </p>
                ) : image ? (
                  <p className="seal-designer__hint">
                    {t('signing.seal.designer.image.selected', {
                      kb: String(Math.max(1, Math.round(image.byteSize / 1024))),
                    })}
                  </p>
                ) : null}
              </div>
            ) : (
              <>
                <Field label={t('signing.seal.designer.template.name.label')} htmlFor="seal-name">
                  <Input id="seal-name" value={name} onChange={(e) => setName(e.target.value)} />
                </Field>
                {contentKind === 'signed_by' ? (
                  <Field
                    label={t('signing.seal.designer.template.heading.label')}
                    htmlFor="seal-heading"
                  >
                    <Input
                      id="seal-heading"
                      value={heading}
                      onChange={(e) => setHeading(e.target.value)}
                    />
                  </Field>
                ) : null}
                <Field label={t('signing.seal.designer.template.date.label')} htmlFor="seal-date">
                  <Input id="seal-date" value={date} onChange={(e) => setDate(e.target.value)} />
                </Field>
              </>
            )}
          </fieldset>

          <fieldset className="seal-designer__position">
            <legend>{t('signing.seal.designer.position.legend')}</legend>
            <div className="seal-designer__coords">
              <Field label={t('signing.seal.designer.position.x')} htmlFor="seal-x">
                <Input
                  id="seal-x"
                  type="number"
                  value={rect ? String(Math.round(rect.x)) : ''}
                  onChange={(e) => editRectField('x', Number(e.target.value))}
                />
              </Field>
              <Field label={t('signing.seal.designer.position.y')} htmlFor="seal-y">
                <Input
                  id="seal-y"
                  type="number"
                  value={rect ? String(Math.round(rect.y)) : ''}
                  onChange={(e) => editRectField('y', Number(e.target.value))}
                />
              </Field>
              <Field label={t('signing.seal.designer.position.w')} htmlFor="seal-w">
                <Input
                  id="seal-w"
                  type="number"
                  value={rect ? String(Math.round(rect.w)) : ''}
                  onChange={(e) => editRectField('w', Number(e.target.value))}
                />
              </Field>
              <Field label={t('signing.seal.designer.position.h')} htmlFor="seal-h">
                <Input
                  id="seal-h"
                  type="number"
                  value={rect ? String(Math.round(rect.h)) : ''}
                  onChange={(e) => editRectField('h', Number(e.target.value))}
                />
              </Field>
            </div>
            <p className="seal-designer__note">{t('signing.seal.designer.position.note')}</p>
          </fieldset>

          <div className="seal-designer__actions">
            <Button onClick={handleApply} disabled={!canApply}>
              {t('signing.seal.designer.apply')}
            </Button>
            <Button variant="ghost" onClick={onCancel}>
              {t('signing.seal.designer.cancel')}
            </Button>
          </div>
        </div>
      </div>
    </section>
  );
}
