import { afterEach, describe, expect, it, vi } from 'vitest';
import { saveBlobAs, saveBlobResultMessage } from './saveFile';

const tauriMocks = vi.hoisted(() => ({
  save: vi.fn(),
  writeFile: vi.fn(),
}));

vi.mock('@tauri-apps/plugin-dialog', () => ({ save: tauriMocks.save }));
vi.mock('@tauri-apps/plugin-fs', () => ({ writeFile: tauriMocks.writeFile }));

const asRecord = window as unknown as Record<string, unknown>;

afterEach(() => {
  delete asRecord.__TAURI_INTERNALS__;
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  tauriMocks.save.mockReset();
  tauriMocks.writeFile.mockReset();
});

describe('saveBlobAs', () => {
  it('uses the native save dialog in Tauri and writes the exact bytes with name/type metadata', async () => {
    asRecord.__TAURI_INTERNALS__ = {};
    tauriMocks.save.mockResolvedValue('C:\\exports\\ata.pdf');
    tauriMocks.writeFile.mockResolvedValue(undefined);
    const blob = new Blob([new Uint8Array([0, 255, 65])], { type: 'application/pdf' });

    const result = await saveBlobAs({ blob, filename: 'ata.pdf' });

    expect(tauriMocks.save).toHaveBeenCalledWith({
      defaultPath: 'ata.pdf',
      filters: [{ name: 'PDF', extensions: ['pdf'] }],
    });
    expect(tauriMocks.writeFile).toHaveBeenCalledTimes(1);
    expect(tauriMocks.writeFile.mock.calls[0][0]).toBe('C:\\exports\\ata.pdf');
    expect(tauriMocks.writeFile.mock.calls[0][1]).toEqual(new Uint8Array([0, 255, 65]));
    expect(result).toEqual({
      kind: 'desktop-save',
      filename: 'ata.pdf',
      contentType: 'application/pdf',
      bytes: 3,
      path: 'C:\\exports\\ata.pdf',
    });
    expect(saveBlobResultMessage(result)).toBe('Ficheiro guardado: ata.pdf.');
  });

  it('reports a cancelled desktop save without writing or starting a fake browser download', async () => {
    asRecord.__TAURI_INTERNALS__ = {};
    tauriMocks.save.mockResolvedValue(null);
    const createUrl = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl });

    const result = await saveBlobAs({
      blob: new Blob(['cancel'], { type: 'text/markdown' }),
      filename: 'working-copy.md',
    });

    expect(tauriMocks.writeFile).not.toHaveBeenCalled();
    expect(createUrl).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      kind: 'cancelled',
      filename: 'working-copy.md',
      contentType: 'text/markdown',
    });
    expect(saveBlobResultMessage(result)).toBe('Guardar cancelado: working-copy.md.');
  });

  it('uses the browser save picker when requested and writes the selected file', async () => {
    const blob = new Blob(['%PDF'], { type: 'application/pdf' });
    const writable = {
      write: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
    };
    const createWritable = vi.fn().mockResolvedValue(writable);
    const showSaveFilePicker = vi.fn().mockResolvedValue({
      name: 'arquivo-filtrado.pdf',
      createWritable,
    });
    const createUrl = vi.fn();
    vi.stubGlobal('showSaveFilePicker', showSaveFilePicker);
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl });

    const result = await saveBlobAs({
      blob,
      filename: 'arquivo-filtrado.pdf',
      preferBrowserSavePicker: true,
    });

    expect(showSaveFilePicker).toHaveBeenCalledWith({
      suggestedName: 'arquivo-filtrado.pdf',
      types: [{ description: 'PDF', accept: { 'application/pdf': ['.pdf'] } }],
    });
    expect(createWritable).toHaveBeenCalledTimes(1);
    expect(writable.write).toHaveBeenCalledWith(blob);
    expect(writable.close).toHaveBeenCalledTimes(1);
    expect(createUrl).not.toHaveBeenCalled();
    expect(result).toEqual({
      kind: 'browser-save',
      filename: 'arquivo-filtrado.pdf',
      contentType: 'application/pdf',
      bytes: 4,
    });
    expect(saveBlobResultMessage(result)).toBe('Ficheiro guardado: arquivo-filtrado.pdf.');
  });

  it('reports a cancelled browser save picker without falling back to a download', async () => {
    const showSaveFilePicker = vi
      .fn()
      .mockRejectedValue(new DOMException('cancelled', 'AbortError'));
    const createUrl = vi.fn();
    vi.stubGlobal('showSaveFilePicker', showSaveFilePicker);
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl });

    const result = await saveBlobAs({
      blob: new Blob(['cancel'], { type: 'application/pdf' }),
      filename: 'arquivo.pdf',
      preferBrowserSavePicker: true,
    });

    expect(createUrl).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      kind: 'cancelled',
      filename: 'arquivo.pdf',
      contentType: 'application/pdf',
    });
  });

  it('falls back to a browser blob download when a requested save picker is unavailable', async () => {
    const blob = new Blob(['zipbytes'], { type: 'application/zip' });
    const createUrl = vi.fn().mockReturnValue('blob:bundle');
    const revokeUrl = vi.fn();
    vi.stubGlobal('showSaveFilePicker', undefined);
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl, revokeObjectURL: revokeUrl });
    const clickedDownloads: string[] = [];
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clickedDownloads.push(this.download);
    });

    const result = await saveBlobAs({
      blob,
      filename: 'book-1.zip',
      preferBrowserSavePicker: true,
    });

    expect(tauriMocks.save).not.toHaveBeenCalled();
    expect(tauriMocks.writeFile).not.toHaveBeenCalled();
    expect(createUrl).toHaveBeenCalledWith(blob);
    expect(clickSpy).toHaveBeenCalled();
    expect(clickedDownloads).toEqual(['book-1.zip']);
    expect(revokeUrl).toHaveBeenCalledWith('blob:bundle');
    expect(result).toEqual({
      kind: 'browser-download',
      filename: 'book-1.zip',
      contentType: 'application/zip',
      bytes: 8,
    });
    expect(saveBlobResultMessage(result)).toBe(
      'Transferência iniciada pelo navegador: book-1.zip. A pasta é definida pelo browser.',
    );
  });

  it('falls back to a browser blob download when the requested save picker write fails', async () => {
    const blob = new Blob(['%PDF'], { type: 'application/pdf' });
    const writable = {
      write: vi.fn().mockRejectedValue(new Error('disk write failed')),
      close: vi.fn().mockResolvedValue(undefined),
    };
    const showSaveFilePicker = vi.fn().mockResolvedValue({
      name: 'arquivo.pdf',
      createWritable: vi.fn().mockResolvedValue(writable),
    });
    const createUrl = vi.fn().mockReturnValue('blob:pdf');
    const revokeUrl = vi.fn();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.stubGlobal('showSaveFilePicker', showSaveFilePicker);
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl, revokeObjectURL: revokeUrl });
    const clickedDownloads: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clickedDownloads.push(this.download);
    });

    const result = await saveBlobAs({
      blob,
      filename: 'arquivo.pdf',
      preferBrowserSavePicker: true,
    });

    expect(showSaveFilePicker).toHaveBeenCalledWith({
      suggestedName: 'arquivo.pdf',
      types: [{ description: 'PDF', accept: { 'application/pdf': ['.pdf'] } }],
    });
    expect(writable.write).toHaveBeenCalledWith(blob);
    expect(writable.close).not.toHaveBeenCalled();
    expect(createUrl).toHaveBeenCalledWith(blob);
    expect(clickedDownloads).toEqual(['arquivo.pdf']);
    expect(revokeUrl).toHaveBeenCalledWith('blob:pdf');
    expect(result).toEqual({
      kind: 'browser-download',
      filename: 'arquivo.pdf',
      contentType: 'application/pdf',
      bytes: 4,
    });
  });

  it('falls back to a browser blob download and describes the browser-managed save location', async () => {
    const blob = new Blob(['zipbytes'], { type: 'application/zip' });
    const createUrl = vi.fn().mockReturnValue('blob:bundle');
    const revokeUrl = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl, revokeObjectURL: revokeUrl });
    const clickedDownloads: string[] = [];
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clickedDownloads.push(this.download);
    });

    const result = await saveBlobAs({ blob, filename: 'book-1.zip' });

    expect(tauriMocks.save).not.toHaveBeenCalled();
    expect(tauriMocks.writeFile).not.toHaveBeenCalled();
    expect(createUrl).toHaveBeenCalledWith(blob);
    expect(clickSpy).toHaveBeenCalled();
    expect(clickedDownloads).toEqual(['book-1.zip']);
    expect(revokeUrl).toHaveBeenCalledWith('blob:bundle');
    expect(result).toEqual({
      kind: 'browser-download',
      filename: 'book-1.zip',
      contentType: 'application/zip',
      bytes: 8,
    });
    expect(saveBlobResultMessage(result)).toBe(
      'Transferência iniciada pelo navegador: book-1.zip. A pasta é definida pelo browser.',
    );
  });
});
