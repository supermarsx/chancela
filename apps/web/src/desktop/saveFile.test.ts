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
