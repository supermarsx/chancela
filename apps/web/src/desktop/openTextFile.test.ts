/**
 * The refusal surface of the open-a-text-file helper.
 *
 * Every branch here exists so a caller can SHOW why no text arrived rather than swallow it, so
 * the assertions are on the discriminated `kind` — never on a message. What matters is that the
 * four failure modes stay distinguishable (`cancelled` vs `unavailable` vs `too-large` vs
 * `unreadable`), and that the size ceiling is enforced BEFORE any bytes are read: a picker can
 * hand back a multi-gigabyte file, and `readTextFile` on it would freeze the shell.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

const tauri = vi.hoisted(() => ({
  open: vi.fn(),
  stat: vi.fn(),
  readTextFile: vi.fn(),
  /** Flipped by the one test that proves a missing plugin degrades instead of throwing. */
  dialogImportFails: false,
}));

vi.mock('@tauri-apps/plugin-dialog', () => {
  if (tauri.dialogImportFails) throw new Error('plugin-dialog is not bundled');
  return { open: tauri.open };
});
vi.mock('@tauri-apps/plugin-fs', () => ({
  stat: tauri.stat,
  readTextFile: tauri.readTextFile,
}));

const asRecord = window as unknown as Record<string, unknown>;

/** A fresh module graph per test, so the plugin-import failure is not served from cache. */
async function loadModule() {
  vi.resetModules();
  return import('./openTextFile');
}

function inTauri() {
  asRecord.__TAURI_INTERNALS__ = {};
}

const PEM_OPTIONS = {
  filterName: 'Certificado',
  extensions: ['pem', 'crt', 'cer'],
  maxBytes: 64 * 1024,
};

afterEach(() => {
  delete asRecord.__TAURI_INTERNALS__;
  tauri.dialogImportFails = false;
  tauri.open.mockReset();
  tauri.stat.mockReset();
  tauri.readTextFile.mockReset();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('acceptAttribute', () => {
  it('prefixes each extension with a dot so an <input accept> matches the dialog filter', async () => {
    const { acceptAttribute } = await loadModule();
    expect(acceptAttribute(PEM_OPTIONS.extensions)).toBe('.pem,.crt,.cer');
  });
});

describe('readPickedTextFile', () => {
  it('refuses an oversized file by its declared size, without reading a byte of it', async () => {
    const { readPickedTextFile } = await loadModule();
    const text = vi.fn();
    const file = { name: 'huge.pem', size: 5_000_000, text } as unknown as File;

    const result = await readPickedTextFile(file, 64 * 1024);

    expect(result).toEqual({ kind: 'too-large', name: 'huge.pem', bytes: 5_000_000 });
    expect(text).not.toHaveBeenCalled();
  });

  it('accepts a file exactly at the ceiling — the bound is inclusive', async () => {
    const { readPickedTextFile } = await loadModule();
    const file = {
      name: 'exact.pem',
      size: 1024,
      text: () => Promise.resolve('-----BEGIN CERTIFICATE-----'),
    } as unknown as File;

    expect(await readPickedTextFile(file, 1024)).toEqual({
      kind: 'opened',
      name: 'exact.pem',
      text: '-----BEGIN CERTIFICATE-----',
    });
  });

  it('reports an unreadable file instead of propagating the read error', async () => {
    const { readPickedTextFile } = await loadModule();
    const file = {
      name: 'locked.pem',
      size: 10,
      text: () => Promise.reject(new Error('NotReadableError')),
    } as unknown as File;

    expect(await readPickedTextFile(file, 64 * 1024)).toEqual({
      kind: 'unreadable',
      name: 'locked.pem',
    });
  });
});

describe('openTextFileNative', () => {
  it('is unavailable outside the desktop shell, so the caller can use the browser input', async () => {
    const { openTextFileNative } = await loadModule();
    expect(await openTextFileNative(PEM_OPTIONS)).toEqual({ kind: 'unavailable' });
    expect(tauri.open).not.toHaveBeenCalled();
  });

  it('degrades to unavailable when the Tauri plugins cannot be imported', async () => {
    inTauri();
    tauri.dialogImportFails = true;
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
    const { openTextFileNative } = await loadModule();

    expect(await openTextFileNative(PEM_OPTIONS)).toEqual({ kind: 'unavailable' });
    expect(errors).toHaveBeenCalled();
  });

  it('degrades to unavailable when the native dialog itself throws', async () => {
    inTauri();
    tauri.open.mockRejectedValue(new Error('no display'));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const { openTextFileNative } = await loadModule();

    expect(await openTextFileNative(PEM_OPTIONS)).toEqual({ kind: 'unavailable' });
  });

  it('passes the caller filter to the dialog and reads the chosen file as text', async () => {
    inTauri();
    tauri.open.mockResolvedValue('C:\\certs\\ama.pem');
    tauri.stat.mockResolvedValue({ size: 2048 });
    tauri.readTextFile.mockResolvedValue('-----BEGIN CERTIFICATE-----\nabc\n');
    const { openTextFileNative } = await loadModule();

    const result = await openTextFileNative(PEM_OPTIONS);

    expect(tauri.open).toHaveBeenCalledWith({
      multiple: false,
      directory: false,
      filters: [{ name: 'Certificado', extensions: ['pem', 'crt', 'cer'] }],
    });
    expect(result).toEqual({
      kind: 'opened',
      name: 'ama.pem',
      text: '-----BEGIN CERTIFICATE-----\nabc\n',
    });
  });

  it('returns the file NAME only — never the path the picker handed back', async () => {
    inTauri();
    tauri.open.mockResolvedValue('/home/amelia.marques/secrets/ama.pem');
    tauri.stat.mockResolvedValue({ size: 12 });
    tauri.readTextFile.mockResolvedValue('pem');
    const { openTextFileNative } = await loadModule();

    const result = await openTextFileNative(PEM_OPTIONS);

    expect(result).toEqual({ kind: 'opened', name: 'ama.pem', text: 'pem' });
    expect(JSON.stringify(result)).not.toContain('/home/amelia.marques');
  });

  it('treats a dismissed dialog as cancelled, distinct from unavailable', async () => {
    inTauri();
    tauri.open.mockResolvedValue(null);
    const { openTextFileNative } = await loadModule();

    expect(await openTextFileNative(PEM_OPTIONS)).toEqual({ kind: 'cancelled' });
    expect(tauri.stat).not.toHaveBeenCalled();
  });

  it('treats an empty-string selection as cancelled rather than opening ""', async () => {
    inTauri();
    tauri.open.mockResolvedValue('');
    const { openTextFileNative } = await loadModule();

    expect(await openTextFileNative(PEM_OPTIONS)).toEqual({ kind: 'cancelled' });
    expect(tauri.readTextFile).not.toHaveBeenCalled();
  });

  it('takes the first entry when the dialog returns an array', async () => {
    inTauri();
    tauri.open.mockResolvedValue(['C:\\certs\\first.pem', 'C:\\certs\\second.pem']);
    tauri.stat.mockResolvedValue({ size: 4 });
    tauri.readTextFile.mockResolvedValue('one');
    const { openTextFileNative } = await loadModule();

    expect(await openTextFileNative(PEM_OPTIONS)).toEqual({
      kind: 'opened',
      name: 'first.pem',
      text: 'one',
    });
    expect(tauri.readTextFile).toHaveBeenCalledWith('C:\\certs\\first.pem');
  });

  it('refuses an oversized file on the stat, before readTextFile is ever called', async () => {
    inTauri();
    tauri.open.mockResolvedValue('C:\\certs\\huge.pem');
    tauri.stat.mockResolvedValue({ size: 900_000_000 });
    const { openTextFileNative } = await loadModule();

    expect(await openTextFileNative(PEM_OPTIONS)).toEqual({
      kind: 'too-large',
      name: 'huge.pem',
      bytes: 900_000_000,
    });
    expect(tauri.readTextFile).not.toHaveBeenCalled();
  });

  it('still reads when stat reports no numeric size — an unknown size is not a refusal', async () => {
    inTauri();
    tauri.open.mockResolvedValue('C:\\certs\\pipe.pem');
    tauri.stat.mockResolvedValue({ size: undefined });
    tauri.readTextFile.mockResolvedValue('pem');
    const { openTextFileNative } = await loadModule();

    expect(await openTextFileNative(PEM_OPTIONS)).toMatchObject({ kind: 'opened' });
  });

  it('reports unreadable when the file cannot be stat-ed', async () => {
    inTauri();
    tauri.open.mockResolvedValue('C:\\certs\\gone.pem');
    tauri.stat.mockRejectedValue(new Error('ENOENT'));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const { openTextFileNative } = await loadModule();

    expect(await openTextFileNative(PEM_OPTIONS)).toEqual({
      kind: 'unreadable',
      name: 'gone.pem',
    });
    expect(tauri.readTextFile).not.toHaveBeenCalled();
  });

  it('reports unreadable when the read fails after a successful stat', async () => {
    inTauri();
    tauri.open.mockResolvedValue('C:\\certs\\denied.pem');
    tauri.stat.mockResolvedValue({ size: 10 });
    tauri.readTextFile.mockRejectedValue(new Error('EACCES'));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const { openTextFileNative } = await loadModule();

    expect(await openTextFileNative(PEM_OPTIONS)).toEqual({
      kind: 'unreadable',
      name: 'denied.pem',
    });
  });
});

describe('readClipboardText', () => {
  it('reports unavailable when the clipboard read API is absent (insecure context)', async () => {
    vi.stubGlobal('navigator', {});
    const { readClipboardText } = await loadModule();
    expect(await readClipboardText()).toEqual({ kind: 'unavailable' });
  });

  it('reports denied — not empty — when the permission is refused', async () => {
    vi.stubGlobal('navigator', {
      clipboard: { readText: () => Promise.reject(new Error('NotAllowedError')) },
    });
    const { readClipboardText } = await loadModule();
    expect(await readClipboardText()).toEqual({ kind: 'denied' });
  });

  it('distinguishes a whitespace-only clipboard from a denied one', async () => {
    vi.stubGlobal('navigator', { clipboard: { readText: () => Promise.resolve('  \n\t ') } });
    const { readClipboardText } = await loadModule();
    expect(await readClipboardText()).toEqual({ kind: 'empty' });
  });

  it('returns the text untrimmed when there is any', async () => {
    vi.stubGlobal('navigator', {
      clipboard: { readText: () => Promise.resolve(' -----BEGIN CERTIFICATE----- ') },
    });
    const { readClipboardText } = await loadModule();
    expect(await readClipboardText()).toEqual({
      kind: 'read',
      text: ' -----BEGIN CERTIFICATE----- ',
    });
  });
});
