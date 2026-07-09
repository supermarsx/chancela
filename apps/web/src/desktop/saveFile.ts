/**
 * Save/download helper for generated exports.
 *
 * Desktop/Tauri can ask the user for an exact save path and write the bytes there.
 * Browsers cannot reliably choose an arbitrary path from JavaScript, so the fallback
 * starts a normal browser download and reports that honestly to the caller.
 */
import { isTauri } from './tauri';

export interface SaveDialogFilter {
  name: string;
  extensions: string[];
}

export interface SaveBlobOptions {
  blob: Blob;
  filename: string;
  contentType?: string;
  filters?: SaveDialogFilter[];
}

interface SaveResultBase {
  filename: string;
  contentType: string;
  bytes: number;
}

export type SaveBlobResult =
  | (SaveResultBase & { kind: 'desktop-save'; path: string })
  | (SaveResultBase & { kind: 'browser-download' })
  | (SaveResultBase & { kind: 'cancelled' });

function extensionFromFilename(filename: string): string | null {
  const basename = filename.split(/[\\/]/).pop() ?? filename;
  const match = /\.([a-z0-9]+)$/i.exec(basename);
  return match ? match[1].toLowerCase() : null;
}

function filterName(extension: string, contentType: string): string {
  if (extension === 'pdf') return 'PDF';
  if (extension === 'zip') return 'ZIP';
  if (extension === 'md') return 'Markdown';
  if (extension === 'docx') return 'Word';
  return contentType || extension.toUpperCase();
}

function filtersFor(filename: string, contentType: string): SaveDialogFilter[] | undefined {
  const extension = extensionFromFilename(filename);
  if (!extension) return undefined;
  return [{ name: filterName(extension, contentType), extensions: [extension] }];
}

function browserDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function blobArrayBuffer(blob: Blob): Promise<ArrayBuffer> {
  if (typeof blob.arrayBuffer === 'function') return blob.arrayBuffer();

  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (reader.result instanceof ArrayBuffer) {
        resolve(reader.result);
        return;
      }
      reject(new Error('Não foi possível ler os bytes do ficheiro a guardar.'));
    };
    reader.onerror = () =>
      reject(reader.error ?? new Error('Não foi possível ler o ficheiro a guardar.'));
    reader.readAsArrayBuffer(blob);
  });
}

async function tryDesktopSave({
  blob,
  filename,
  contentType,
  filters,
}: Required<Pick<SaveBlobOptions, 'blob' | 'filename'>> &
  Pick<SaveBlobOptions, 'contentType' | 'filters'>): Promise<SaveBlobResult | null> {
  let dialog: typeof import('@tauri-apps/plugin-dialog');
  let fs: typeof import('@tauri-apps/plugin-fs');
  try {
    [dialog, fs] = await Promise.all([
      import('@tauri-apps/plugin-dialog'),
      import('@tauri-apps/plugin-fs'),
    ]);
  } catch (err) {
    console.error('saveFile: Tauri save APIs unavailable, falling back to browser download', err);
    return null;
  }

  let path: string | null;
  try {
    path = await dialog.save({
      defaultPath: filename,
      filters: filters ?? filtersFor(filename, contentType ?? blob.type),
    });
  } catch (err) {
    console.error('saveFile: native save dialog failed, falling back to browser download', err);
    return null;
  }

  const resolvedContentType = contentType ?? blob.type;
  if (!path) {
    return {
      kind: 'cancelled',
      filename,
      contentType: resolvedContentType,
      bytes: blob.size,
    };
  }

  const bytes = new Uint8Array(await blobArrayBuffer(blob));
  await fs.writeFile(path, bytes);
  return {
    kind: 'desktop-save',
    filename,
    contentType: resolvedContentType,
    bytes: blob.size,
    path,
  };
}

export async function saveBlobAs(options: SaveBlobOptions): Promise<SaveBlobResult> {
  const contentType = options.contentType ?? options.blob.type;
  if (isTauri()) {
    const desktopResult = await tryDesktopSave({ ...options, contentType });
    if (desktopResult) return desktopResult;
  }

  browserDownload(options.blob, options.filename);
  return {
    kind: 'browser-download',
    filename: options.filename,
    contentType,
    bytes: options.blob.size,
  };
}

export function saveBlobResultMessage(result: SaveBlobResult): string {
  if (result.kind === 'desktop-save') return `Ficheiro guardado: ${result.filename}.`;
  if (result.kind === 'cancelled') return `Guardar cancelado: ${result.filename}.`;
  return `Transferência iniciada pelo navegador: ${result.filename}. A pasta é definida pelo browser.`;
}
