/**
 * Save/download helper for generated exports.
 *
 * Desktop/Tauri can ask the user for an exact save path and write the bytes there.
 * Browsers with the File System Access API can ask for a save location; other browsers
 * start a normal browser download and report that honestly to the caller.
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
  preferBrowserSavePicker?: boolean;
}

interface SaveResultBase {
  filename: string;
  contentType: string;
  bytes: number;
}

export type SaveBlobResult =
  | (SaveResultBase & { kind: 'desktop-save'; path: string })
  | (SaveResultBase & { kind: 'browser-save' })
  | (SaveResultBase & { kind: 'browser-download' })
  | (SaveResultBase & { kind: 'cancelled' });

interface BrowserSaveFilePickerOptions {
  suggestedName?: string;
  types?: {
    description?: string;
    accept: Record<string, string[]>;
  }[];
}

interface BrowserFileHandle {
  name?: string;
  createWritable: () => Promise<{
    write: (data: Blob) => Promise<void> | void;
    close: () => Promise<void> | void;
  }>;
}

interface BrowserWindowWithSavePicker extends Window {
  showSaveFilePicker?: (options?: BrowserSaveFilePickerOptions) => Promise<BrowserFileHandle>;
}

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

function pickerMime(contentType: string): string | null {
  const mime = contentType.split(';', 1)[0]?.trim() ?? '';
  return /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i.test(mime) ? mime : null;
}

function pickerTypesFor(
  filename: string,
  contentType: string,
  filters?: SaveDialogFilter[],
): BrowserSaveFilePickerOptions['types'] {
  const mime = pickerMime(contentType);
  const pickerFilters = filters ?? filtersFor(filename, contentType);
  if (!mime || !pickerFilters?.length) return undefined;

  return pickerFilters.map((filter) => ({
    description: filter.name,
    accept: {
      [mime]: filter.extensions.map((extension) =>
        extension.startsWith('.') ? extension : `.${extension}`,
      ),
    },
  }));
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

function isAbortError(error: unknown): boolean {
  return (
    error instanceof DOMException &&
    (error.name === 'AbortError' || error.name === 'NotAllowedError')
  );
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

async function tryBrowserSavePicker({
  blob,
  filename,
  contentType,
  filters,
}: Required<Pick<SaveBlobOptions, 'blob' | 'filename' | 'contentType'>> &
  Pick<SaveBlobOptions, 'filters'>): Promise<SaveBlobResult | null> {
  if (typeof window === 'undefined') return null;

  const browserWindow = window as BrowserWindowWithSavePicker;
  if (typeof browserWindow.showSaveFilePicker !== 'function') return null;

  let handle: BrowserFileHandle;
  try {
    handle = await browserWindow.showSaveFilePicker({
      suggestedName: filename,
      types: pickerTypesFor(filename, contentType, filters),
    });
  } catch (err) {
    if (isAbortError(err)) {
      return {
        kind: 'cancelled',
        filename,
        contentType,
        bytes: blob.size,
      };
    }
    console.error('saveFile: browser save picker failed, falling back to browser download', err);
    return null;
  }

  try {
    const writable = await handle.createWritable();
    await writable.write(blob);
    await writable.close();
  } catch (err) {
    console.error('saveFile: browser file write failed, falling back to browser download', err);
    return null;
  }

  return {
    kind: 'browser-save',
    filename: handle.name ?? filename,
    contentType,
    bytes: blob.size,
  };
}

export async function saveBlobAs(options: SaveBlobOptions): Promise<SaveBlobResult> {
  const contentType = options.contentType ?? options.blob.type;
  if (isTauri()) {
    const desktopResult = await tryDesktopSave({ ...options, contentType });
    if (desktopResult) return desktopResult;
  }

  if (options.preferBrowserSavePicker) {
    const browserResult = await tryBrowserSavePicker({ ...options, contentType });
    if (browserResult) return browserResult;
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
  if (result.kind === 'desktop-save' || result.kind === 'browser-save') {
    return `Ficheiro guardado: ${result.filename}.`;
  }
  if (result.kind === 'cancelled') return `Guardar cancelado: ${result.filename}.`;
  return `Transferência iniciada pelo navegador: ${result.filename}. A pasta é definida pelo browser.`;
}
