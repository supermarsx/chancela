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

  it('falls back to a browser download when the native save dialog itself fails', async () => {
    // A broken or ACL-denied native dialog must not cost the operator their export. This is the
    // only path where the desktop shell produces nothing at all unless the fallback fires.
    asRecord.__TAURI_INTERNALS__ = {};
    tauriMocks.save.mockRejectedValue(new Error('dialog plugin not in the ACL'));
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    const createUrl = vi.fn().mockReturnValue('blob:fallback');
    const revokeUrl = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl, revokeObjectURL: revokeUrl });
    const clickedDownloads: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clickedDownloads.push(this.download);
    });

    const result = await saveBlobAs({
      blob: new Blob(['%PDF'], { type: 'application/pdf' }),
      filename: 'ata.pdf',
    });

    expect(tauriMocks.writeFile).not.toHaveBeenCalled();
    expect(clickedDownloads).toEqual(['ata.pdf']);
    expect(result.kind).toBe('browser-download');
    // Reported, not swallowed: a silent downgrade hides a broken desktop install.
    expect(logged).toHaveBeenCalled();
  });

  it('falls back to a browser download when the save picker fails for a reason other than cancelling', async () => {
    // A cancel is the operator's decision and must be reported as `cancelled` (asserted above);
    // any other rejection is a broken picker, and the file must still arrive.
    const showSaveFilePicker = vi.fn().mockRejectedValue(new TypeError('picker unavailable'));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const createUrl = vi.fn().mockReturnValue('blob:pdf');
    vi.stubGlobal('showSaveFilePicker', showSaveFilePicker);
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl, revokeObjectURL: vi.fn() });
    const clickedDownloads: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clickedDownloads.push(this.download);
    });

    const result = await saveBlobAs({
      blob: new Blob(['%PDF'], { type: 'application/pdf' }),
      filename: 'arquivo.pdf',
      preferBrowserSavePicker: true,
    });

    expect(result.kind).toBe('browser-download');
    expect(clickedDownloads).toEqual(['arquivo.pdf']);
  });

  it('reads the bytes through FileReader when the blob has no arrayBuffer()', async () => {
    // Older WebViews hand back a Blob without `arrayBuffer`. The bytes written must be the same
    // ones either way — a truncated or reordered read would corrupt a signed export silently.
    asRecord.__TAURI_INTERNALS__ = {};
    tauriMocks.save.mockResolvedValue('C:\\exports\\legado.pdf');
    tauriMocks.writeFile.mockResolvedValue(undefined);
    const blob = new Blob([new Uint8Array([1, 2, 250])], { type: 'application/pdf' });
    Object.defineProperty(blob, 'arrayBuffer', { value: undefined, configurable: true });

    const result = await saveBlobAs({ blob, filename: 'legado.pdf' });

    expect(tauriMocks.writeFile.mock.calls[0][1]).toEqual(new Uint8Array([1, 2, 250]));
    expect(result).toMatchObject({ kind: 'desktop-save', path: 'C:\\exports\\legado.pdf' });
  });

  it('names the dialog filter after the format and offers none when the filename has no extension', async () => {
    // The filter is what makes the native dialog default to the right folder and extension; a
    // wrong one silently saves an .md as a .pdf.
    asRecord.__TAURI_INTERNALS__ = {};
    tauriMocks.save.mockResolvedValue(null);

    await saveBlobAs({
      blob: new Blob(['#'], { type: 'text/markdown; charset=utf-8' }),
      filename: 'copia-de-trabalho.md',
    });
    expect(tauriMocks.save.mock.calls[0][0].filters).toEqual([
      { name: 'Markdown', extensions: ['md'] },
    ]);

    await saveBlobAs({
      blob: new Blob(['x'], { type: 'application/octet-stream' }),
      filename: 'sem-extensao',
    });
    expect(tauriMocks.save.mock.calls[1][0].filters).toBeUndefined();
  });

  it('omits picker types when the content type is not a usable MIME type', async () => {
    // `showSaveFilePicker` throws on a malformed `accept` key, which would turn a save into an
    // exception rather than a file. Offering no types is the honest degradation.
    const writable = {
      write: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
    };
    const showSaveFilePicker = vi.fn().mockResolvedValue({
      name: 'export.zip',
      createWritable: vi.fn().mockResolvedValue(writable),
    });
    vi.stubGlobal('showSaveFilePicker', showSaveFilePicker);
    vi.stubGlobal('URL', { ...URL, createObjectURL: vi.fn(), revokeObjectURL: vi.fn() });

    const result = await saveBlobAs({
      blob: new Blob(['zip'], { type: '' }),
      filename: 'export.zip',
      contentType: 'not a mime type',
      preferBrowserSavePicker: true,
    });

    expect(showSaveFilePicker).toHaveBeenCalledWith({
      suggestedName: 'export.zip',
      types: undefined,
    });
    expect(result).toMatchObject({ kind: 'browser-save', filename: 'export.zip' });
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
