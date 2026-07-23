/**
 * Shared types and pure helpers for the ata body editor (t74-e6).
 *
 * Kept out of the editor module so the public wrapper can name its props without pulling
 * ProseMirror into the eager bundle — importing a type from a module also imports the module
 * unless the type lives somewhere weightless.
 *
 * This module has ALSO now survived one whole editor replacement (CodeMirror → ProseMirror) and
 * two working-tree deletions, which is the argument for keeping it separate: the byte-offset
 * conversion below is the most valuable thing in the tranche and it must not be hostage to
 * whichever editing surface is current.
 */

/**
 * A construct the server compiler refused, as reported by `MarkdownError::Unsupported`.
 *
 * With a schema-restricted editor this should be rare — the surface cannot produce most of what the
 * compiler rejects — but it stays because the source is markdown text: an operator can paste, type
 * or receive markdown whose meaning the server reads differently, and the server is the authority.
 *
 * `construct` is the server's own token (`table`, `image`, `html`, …), rendered verbatim rather
 * than translated: it is a protocol value and the operator may need to quote it. `offset` is a
 * **byte** offset into the UTF-8 source — see {@link charIndexForByteOffset}.
 */
export interface MarkdownDiagnostic {
  construct: string;
  offset: number;
}

/** What a paste could not keep. Surfaced to the operator; never silently applied. */
export interface PasteReport {
  changes: { construct: string; kind: 'downgraded' | 'removed'; count: number }[];
}

/**
 * Copy for the optional visible formatting toolbar.
 *
 * The editor engine is shared by several surfaces, but each feature owns its translated chrome.
 * Passing the labels opts into the toolbar without pulling feature copy into the lazy ProseMirror
 * chunk or forcing every existing caller to grow a toolbar at once.
 */
export interface MarkdownBodyToolbarLabels {
  ariaLabel: string;
  editor: string;
  paragraph: string;
  headings: readonly [string, string, string, string, string, string];
  bold: string;
  italic: string;
  horizontalRule: string;
  undo: string;
  redo: string;
}

export interface MarkdownBodyEditorProps {
  /** The markdown source — the stored, sealed, compiled artifact. */
  value: string;
  /** Receives markdown re-serialized from the document on every change. */
  onChange: (next: string) => void;
  disabled?: boolean;
  /** The server's rejection, if the last save or preview produced one. Never computed here. */
  diagnostic?: MarkdownDiagnostic | null;
  /** Byte ceiling for the body (t74 §9.6). Displayed; nothing is ever truncated to fit it. */
  maxBytes?: number;
  /** DOM id applied to the editable surface. */
  id?: string;
  /** Accessible name for the `role="textbox"` editing surface. */
  ariaLabel?: string;
  /** Supplying translated labels opts this instance into the visible formatting toolbar. */
  toolbarLabels?: MarkdownBodyToolbarLabels;
}

/** UTF-8 byte length — what the server's cap is expressed in, not `String.length`. */
export function byteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

/**
 * Convert a **UTF-8 byte** offset (what Rust reports) into a JavaScript string index.
 *
 * These differ the moment the text is not pure ASCII, which for Portuguese prose is immediately:
 * `deliberação` is 11 characters and 13 bytes. Using the byte offset directly as a string index
 * would put the diagnostic under the wrong word, drifting further with every accent before it.
 * Astral characters are 4 bytes and 2 UTF-16 units, so this counts code points rather than units.
 */
export function charIndexForByteOffset(text: string, byteOffset: number): number {
  if (byteOffset <= 0) return 0;
  const encoder = new TextEncoder();
  let bytes = 0;
  let index = 0;
  for (const codePoint of text) {
    if (bytes >= byteOffset) return index;
    bytes += encoder.encode(codePoint).length;
    index += codePoint.length;
  }
  return Math.min(index, text.length);
}

/** 1-based line and column of a string index, for a human-readable diagnostic. */
export function locateIndex(text: string, index: number): { line: number; column: number } {
  const clamped = Math.max(0, Math.min(index, text.length));
  const before = text.slice(0, clamped);
  const lines = before.split('\n');
  return { line: lines.length, column: (lines[lines.length - 1]?.length ?? 0) + 1 };
}
