/**
 * Visual seal designer (t67-e12): a PDF-page renderer + draggable/resizable seal overlay whose
 * on-screen box maps to the backend seal DTO in unrotated PDF user space. Mounted from the
 * signing flow to position a visible signature seal before signing.
 */
export { SealDesigner, type SealDesignerProps } from './SealDesigner';
export {
  canvasBoxToPdfRect,
  pdfRectToCanvasBox,
  type PageGeometry,
  type PdfRect,
  type CanvasBox,
} from './coordinates';
export { buildSealBody, readSealImage, type SealContent } from './sealSpec';
