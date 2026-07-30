/**
 * Open-a-text-file helper — the read-side mirror of {@link ./saveFile saveBlobAs} (t112).
 *
 * The app runs both as a browser SPA and inside the Tauri WebView, and the two need different
 * paths, so this follows the same shape `saveFile.ts` already established: branch on
 * {@link isTauri}, `import()` the Tauri plugins **dynamically** so the browser bundle and vitest
 * stay Tauri-free, and degrade to the browser route when the native call is unavailable or fails.
 *
 * ## Content, never a path
 *
 * Every caller here wants the **text inside** the file. `ama_cert_pem` stores the certificate
 * itself; the `CHANCELA_CMD_AMA_CERT_PEM` environment variable is the one that names a *path* for
 * the server to read. Returning a path from this module would make that confusion easy to write, so
 * it does not return one — {@link OpenedTextFile} carries `text` and a display-only `name`.
 *
 * ## The size bound is not advisory
 *
 * A picker will happily hand back a multi-gigabyte file, and reading it into a `string` freezes the
 * tab before any validation runs. So the size is checked **before** the bytes are read (browser:
 * `File.size`; Tauri: `stat`), and the caller gets a typed `too-large` result rather than an
 * exception to guess at.
 */
import { isTauri } from './tauri';

export interface OpenTextFileOptions {
  /** Dialog filter name, already translated. */
  filterName: string;
  /** Extensions WITHOUT the leading dot, e.g. `['pem', 'crt', 'cer']`. */
  extensions: string[];
  /** Hard ceiling in bytes. Anything larger is refused unread. */
  maxBytes: number;
}

export type OpenTextFileResult =
  | { kind: 'opened'; name: string; text: string }
  | { kind: 'cancelled' }
  /** The picker itself could not run (no native dialog, and the browser route was not used). */
  | { kind: 'unavailable' }
  | { kind: 'too-large'; name: string; bytes: number }
  | { kind: 'unreadable'; name: string };

/** `accept` for a browser `<input type="file">`, from the same extension list. */
export function acceptAttribute(extensions: string[]): string {
  return extensions.map((extension) => `.${extension}`).join(',');
}

/**
 * Read one already-picked browser `File`, refusing an implausibly large one before touching it.
 *
 * Split out from the Tauri path because in the browser the file arrives from an `<input>` change
 * event, which is a genuinely different flow from "open a dialog and wait".
 */
export async function readPickedTextFile(
  file: File,
  maxBytes: number,
): Promise<OpenTextFileResult> {
  if (file.size > maxBytes) {
    return { kind: 'too-large', name: file.name, bytes: file.size };
  }
  try {
    return { kind: 'opened', name: file.name, text: await file.text() };
  } catch {
    return { kind: 'unreadable', name: file.name };
  }
}

/**
 * Open a native file dialog and read the chosen file as text. Tauri only.
 *
 * Returns `unavailable` (never throws) when the plugins cannot be imported or the dialog fails, so
 * the caller can fall back to the browser `<input type="file">` in the same render.
 */
export async function openTextFileNative(
  options: OpenTextFileOptions,
): Promise<OpenTextFileResult> {
  if (!isTauri()) return { kind: 'unavailable' };

  let dialog: typeof import('@tauri-apps/plugin-dialog');
  let fs: typeof import('@tauri-apps/plugin-fs');
  try {
    [dialog, fs] = await Promise.all([
      import('@tauri-apps/plugin-dialog'),
      import('@tauri-apps/plugin-fs'),
    ]);
  } catch (err) {
    console.error('openTextFile: Tauri open APIs unavailable', err);
    return { kind: 'unavailable' };
  }

  let selected: string | string[] | null;
  try {
    selected = await dialog.open({
      multiple: false,
      directory: false,
      filters: [{ name: options.filterName, extensions: options.extensions }],
    });
  } catch (err) {
    console.error('openTextFile: native open dialog failed', err);
    return { kind: 'unavailable' };
  }
  if (selected === null) return { kind: 'cancelled' };
  const path = Array.isArray(selected) ? selected[0] : selected;
  if (typeof path !== 'string' || path.length === 0) return { kind: 'cancelled' };
  const name = path.split(/[\\/]/).pop() ?? path;

  // Size BEFORE bytes: `readTextFile` on a huge file would be read fully into memory first.
  try {
    const info = await fs.stat(path);
    if (typeof info.size === 'number' && info.size > options.maxBytes) {
      return { kind: 'too-large', name, bytes: info.size };
    }
  } catch (err) {
    console.error('openTextFile: could not stat the chosen file', err);
    return { kind: 'unreadable', name };
  }

  try {
    return { kind: 'opened', name, text: await fs.readTextFile(path) };
  } catch (err) {
    console.error('openTextFile: could not read the chosen file', err);
    return { kind: 'unreadable', name };
  }
}

/** Why {@link readClipboardText} could not produce text. */
export type ClipboardReadResult =
  | { kind: 'read'; text: string }
  /** No `navigator.clipboard.readText` at all: an insecure context, or a blocking permissions policy. */
  | { kind: 'unavailable' }
  /** The API exists and refused — permission denied, or the user dismissed the prompt. */
  | { kind: 'denied' }
  | { kind: 'empty' };

/**
 * Read the clipboard, reporting every failure the caller must SHOW rather than swallow.
 *
 * `DiagnosticsSection.copyReport` established the rule for the write direction — an insecure
 * context or a permissions policy is surfaced, never a silent no-op, because the operator needs to
 * know to select the text by hand instead. This is the same rule in the read direction, and the
 * result is a discriminated union rather than `string | null` so a caller cannot accidentally
 * collapse "denied" and "empty" into one message.
 */
export async function readClipboardText(): Promise<ClipboardReadResult> {
  if (typeof navigator === 'undefined' || !navigator.clipboard?.readText) {
    return { kind: 'unavailable' };
  }
  let text: string;
  try {
    text = await navigator.clipboard.readText();
  } catch {
    return { kind: 'denied' };
  }
  return text.trim().length === 0 ? { kind: 'empty' } : { kind: 'read', text };
}
