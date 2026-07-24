/**
 * The ata body editor's engine (t74-e6) — a WYSIWYG surface whose schema *is* the frozen block set.
 *
 * ## Why a restricted schema rather than validation
 *
 * The plan originally argued for a source editor on the grounds that a rich editor lets an operator
 * build constructs the server compiler rejects. The user overruled it, and the reframe is the right
 * one: **make the constructs unrepresentable instead of rejecting them afterwards.** ProseMirror's
 * schema is declarative and authoritative — a node type that is not declared cannot exist in the
 * document, at any point, by any route. Tables, images, code blocks, lists, block quotes and raw
 * HTML are therefore not "discouraged"; there is nowhere in the document for them to be.
 *
 * The declared set maps 1:1 onto `chancela-core::Block`:
 *
 * | schema | Block |
 * | --- | --- |
 * | `paragraph` | `Paragraph { runs }` |
 * | `heading` (level 1–6) | `Heading { level, text }` |
 * | `horizontal_rule` | `Rule` |
 * | `strong` / `em` marks | `Run { bold, italic }` |
 *
 * `KeyValue`, `VoteTable` and `SignatureBlock` are deliberately absent: they are produced by the
 * template from structured fields, never authored as prose (t74 §3, disjoint ownership).
 *
 * ## Markdown is the stored source of truth, not ProseMirror JSON
 *
 * The document is saved, sealed and compiled as **markdown text**. This module parses markdown to
 * populate the editor and serializes back to markdown on every change; the ProseMirror document is
 * a transient view of it that never leaves the browser.
 *
 * ## …and this is NOT a document compiler
 *
 * The distinction that matters, because it looks superficially like the thing the codebase forbids:
 * markdown here is parsed to build an *editing view*. It is never turned into `Block[]`, never
 * turned into HTML for display, and never sent anywhere. `Block[]` comes from the server's
 * `POST /v1/acts/{id}/body/preview`, running the same function that runs at content freeze. If this
 * module's reading of a document ever disagrees with the server's, the server is right and the
 * operator sees the server's answer in the preview — which is why the preview is not optional.
 *
 * The bound on that divergence is the round-trip property (see the tests): text this editor cannot
 * represent survives as literal prose and is escaped on the way out, so serializing can only ever
 * emit constructs from the accept set above.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { Schema } from 'prosemirror-model';
import type { Node as PmNode } from 'prosemirror-model';
import { EditorState, Plugin, type Command } from 'prosemirror-state';
import { Decoration, DecorationSet, EditorView } from 'prosemirror-view';
import { MarkdownParser, MarkdownSerializer } from 'prosemirror-markdown';
import { baseKeymap, setBlockType, toggleMark } from 'prosemirror-commands';
import { keymap } from 'prosemirror-keymap';
import { history, redo, undo } from 'prosemirror-history';
import MarkdownIt from 'markdown-it';
import { useT } from '../../i18n';
import { InlineWarning } from '../../ui';
import type { MarkdownBodyEditorProps } from './markdownBodyTypes';
import { byteLength, charIndexForByteOffset, locateIndex } from './markdownBodyTypes';

// --- The schema: the frozen block set, and nothing else ---------------------------

export const ataBodySchema = new Schema({
  nodes: {
    doc: { content: 'block+' },
    paragraph: {
      content: 'inline*',
      group: 'block',
      parseDOM: [{ tag: 'p' }],
      toDOM: () => ['p', 0],
    },
    heading: {
      attrs: { level: { default: 1 } },
      content: 'inline*',
      group: 'block',
      defining: true,
      parseDOM: [1, 2, 3, 4, 5, 6].map((level) => ({ tag: `h${level}`, attrs: { level } })),
      toDOM: (node) => [`h${node.attrs.level as number}`, 0],
    },
    horizontal_rule: {
      group: 'block',
      parseDOM: [{ tag: 'hr' }],
      toDOM: () => ['hr'],
    },
    text: { group: 'inline' },
  },
  marks: {
    strong: {
      parseDOM: [{ tag: 'strong' }, { tag: 'b' }],
      toDOM: () => ['strong', 0],
    },
    em: {
      parseDOM: [{ tag: 'em' }, { tag: 'i' }],
      toDOM: () => ['em', 0],
    },
  },
});

// --- Markdown in ------------------------------------------------------------------

/**
 * markdown-it restricted to the accept set.
 *
 * Starting from the `zero` preset and enabling only what the schema can hold means an unsupported
 * construct is not *dropped* — it stays literal text in a paragraph. `- item` reads as the
 * characters `- item`, which is exactly what the server will also do once the serializer escapes
 * it on the way out. `html: false` keeps raw HTML from ever being interpreted.
 */
const tokenizer = MarkdownIt('zero', { html: false }).enable([
  'heading',
  'lheading',
  'hr',
  'emphasis',
  'newline',
  'escape',
  'entity',
]);

export const markdownParser = new MarkdownParser(ataBodySchema, tokenizer, {
  paragraph: { block: 'paragraph' },
  heading: {
    block: 'heading',
    getAttrs: (token) => ({ level: Number(token.tag.slice(1)) || 1 }),
  },
  hr: { node: 'horizontal_rule' },
  em: { mark: 'em' },
  strong: { mark: 'strong' },
});

// --- Markdown out -----------------------------------------------------------------

export const markdownSerializer = new MarkdownSerializer(
  {
    paragraph(state, node) {
      state.renderInline(node);
      state.closeBlock(node);
    },
    heading(state, node) {
      state.write(`${state.repeat('#', node.attrs.level as number)} `);
      state.renderInline(node);
      state.closeBlock(node);
    },
    horizontal_rule(state, node) {
      state.write('---');
      state.closeBlock(node);
    },
    text(state, node) {
      state.text(node.text ?? '');
    },
  },
  {
    em: { open: '*', close: '*', mixable: true, expelEnclosingWhitespace: true },
    strong: { open: '**', close: '**', mixable: true, expelEnclosingWhitespace: true },
  },
  {
    // Escape angle brackets on the way out as well as the usual markdown punctuation.
    //
    // Found by probing the round trip rather than by reasoning: `<script>alert(1)</script>` typed
    // as literal text survived serialization *unescaped*, because prosemirror-markdown's default
    // escape set does not include `<`. Nothing would have executed — the schema has no HTML node,
    // React escapes text, and the server rejects `Event::Html` outright — but the saved markdown
    // would have contained raw HTML that the server then refuses, so the operator would meet a
    // rejection for text the editor had shown as perfectly ordinary.
    //
    // With this, the serializer's output is provably inside the accept set: there is no input to
    // this editor that produces markdown containing an HTML tag.
    //
    // `<` ONLY, not `>`. Escaping both broke round-trip stability, which the corpus test caught:
    // prosemirror-markdown already escapes a leading `>` as the blockquote character, so adding it
    // here escaped the backslash of the first escape and `> citação` grew a backslash on every
    // pass. A `>` that is not opening a quote is ordinary punctuation and needs no escape; `<` is
    // the character that starts a tag, and it is the one that matters.
    escapeExtraCharacters: /</g,
  },
);

/** markdown → document. Total: anything unrepresentable arrives as literal text. */
export function parseMarkdown(source: string): PmNode {
  return markdownParser.parse(source) ?? ataBodySchema.topNodeType.createAndFill()!;
}

/**
 * `1)` at the start of a line, which prosemirror-markdown does not escape and the server rejects.
 *
 * CommonMark accepts **both** `.` and `)` as ordered-list delimiters. prosemirror-markdown's
 * built-in start-of-line escaping covers `1.` and misses `1)`, so an operator typing
 * `1) Deliberou-se…` — ordinary Portuguese legal prose — had it saved unescaped, and the server
 * compiler (which rejects lists outright) answered `422 Unsupported { construct: "list" }` on the
 * very next save. Text that looked perfectly fine in the editor, refused on save: a round-trip bug
 * rather than operator error, arriving through the one construct a restricted schema cannot
 * prevent, because it is just characters inside a paragraph.
 *
 * Confirmed against the real compiler by t74-e5 rather than inferred from either escape list, and
 * pinned there by `which_line_leading_characters_are_structure_to_this_compiler`.
 *
 * Applied to the serialized output rather than through `escapeExtraCharacters`, which has no
 * notion of line position and would escape every `)` in the document. Idempotent: in `1\)` the
 * character after the digits is a backslash, so the pattern no longer matches.
 *
 * NOT extended to `=` or `|`, both of which were also checked and are deliberately left alone:
 * - `|` is not structure to that compiler at all (`Options::empty()`, table extension off).
 *   Escaping it would re-create the `>` double-escape bug in a new character.
 * - `=` is a paragraph on its own but **does** form a setext heading directly under a paragraph
 *   line. We are safe only because this serializer puts a blank line between every block — that
 *   is a property of the spacing, not of the character. **If block separation ever changes, `=`
 *   becomes live and nothing will announce it.**
 */
function escapeLeadingOrderedParen(markdown: string): string {
  return markdown.replace(/^(\s*\d+)\)/gm, '$1\\)');
}

/** document → markdown. This output is what gets saved, sealed and compiled. */
export function serializeMarkdown(doc: PmNode): string {
  return escapeLeadingOrderedParen(markdownSerializer.serialize(doc));
}

// --- Visible toolbar commands ------------------------------------------------------

const paragraphCommand = setBlockType(ataBodySchema.nodes.paragraph);
const headingCommands = [1, 2, 3, 4, 5, 6].map((level) =>
  setBlockType(ataBodySchema.nodes.heading, { level }),
);
const boldCommand = toggleMark(ataBodySchema.marks.strong);
const italicCommand = toggleMark(ataBodySchema.marks.em);

/** Insert the one non-text block admitted by the prose schema. */
const horizontalRuleCommand: Command = (state, dispatch) => {
  if (dispatch) {
    dispatch(
      state.tr.replaceSelectionWith(ataBodySchema.nodes.horizontal_rule.create()).scrollIntoView(),
    );
  }
  return true;
};

function blockIsActive(view: EditorView | null, type: 'paragraph' | 'heading', level?: number) {
  if (!view) return false;
  const parent = view.state.selection.$from.parent;
  if (parent.type !== ataBodySchema.nodes[type]) return false;
  return level === undefined || parent.attrs.level === level;
}

function markIsActive(view: EditorView | null, type: 'strong' | 'em') {
  if (!view) return false;
  const { from, to, empty, $from } = view.state.selection;
  const mark = ataBodySchema.marks[type];
  if (empty) {
    return mark.isInSet(view.state.storedMarks ?? $from.marks()) !== undefined;
  }
  return view.state.doc.rangeHasMark(from, to, mark);
}

// --- Paste: downgrade loudly, never strip silently ---------------------------------

/**
 * What a paste lost, so the operator can be told rather than left to notice.
 *
 * A restricted schema's natural behaviour on paste is to *silently discard* what it cannot hold —
 * someone pastes a table out of Word, it vanishes, and they may not see it go. That is the same
 * "content disappeared without telling anyone" failure this whole tranche exists to prevent,
 * arriving through a different door. So the paste is pre-processed here: everything that cannot be
 * represented is either downgraded to something that can be, or removed, and **either way it is
 * reported**.
 */
export interface PasteChange {
  /** The HTML construct encountered: `table`, `image`, `list`, `code`, `quote`, `link`. */
  construct: string;
  /** `downgraded` — the text survives in a different shape; `removed` — nothing survives. */
  kind: 'downgraded' | 'removed';
  count: number;
}

/**
 * Block containers that become paragraphs, and the name the operator is told.
 *
 * One map rather than a set plus a lookup: with two structures a tag could be listed for
 * downgrading and have no name, and the report would say `undefined`. Here that cannot happen.
 */
const DOWNGRADE_TO_PARAGRAPHS: Record<string, string> = {
  UL: 'list',
  OL: 'list',
  BLOCKQUOTE: 'quote',
  PRE: 'code',
  TABLE: 'table',
};
const IMAGE_CONSTRUCT = 'image';
const LINK_CONSTRUCT = 'link';

/**
 * Rewrite pasted HTML into something the schema can hold, recording every change.
 *
 * Pure and exported so the reporting can be tested directly — this is the function whose behaviour
 * the operator actually experiences on a hostile paste.
 */
export function sanitizePastedHtml(html: string): { html: string; changes: PasteChange[] } {
  const counts = new Map<string, PasteChange>();
  const note = (construct: string, kind: PasteChange['kind']) => {
    const key = `${construct}:${kind}`;
    const existing = counts.get(key);
    if (existing) existing.count += 1;
    else counts.set(key, { construct, kind, count: 1 });
  };

  const doc = new window.DOMParser().parseFromString(`<body>${html}</body>`, 'text/html');

  // Images carry no text, so there is nothing to downgrade to: they are removed, and that is the
  // loudest case to report because the operator loses content outright.
  for (const img of Array.from(doc.querySelectorAll('img'))) {
    note(IMAGE_CONSTRUCT, 'removed');
    img.remove();
  }

  // Links keep their text and lose their target — no Block variant carries a link, so a surviving
  // href would render as clickable on screen and as bare text in the PDF: two different documents.
  for (const anchor of Array.from(doc.querySelectorAll('a'))) {
    note(LINK_CONSTRUCT, 'downgraded');
    anchor.replaceWith(...Array.from(anchor.childNodes));
  }

  // Block containers we cannot represent become paragraphs, one per row/item/line, so the words
  // survive even though the structure does not.
  let guard = 0;
  for (;;) {
    const found = Array.from(doc.body.querySelectorAll('*')).find(
      (el) => el.tagName in DOWNGRADE_TO_PARAGRAPHS,
    );
    if (!found || guard++ > 500) break;
    note(DOWNGRADE_TO_PARAGRAPHS[found.tagName], 'downgraded');
    const parts =
      found.tagName === 'TABLE'
        ? Array.from(found.querySelectorAll('tr')).map((row) =>
            Array.from(row.querySelectorAll('th,td'))
              .map((cell) => cell.textContent?.trim() ?? '')
              .filter(Boolean)
              .join(' · '),
          )
        : found.tagName === 'UL' || found.tagName === 'OL'
          ? Array.from(found.querySelectorAll('li')).map((li) => li.textContent?.trim() ?? '')
          : [found.textContent ?? ''];

    const replacements = parts
      .filter((text) => text.trim() !== '')
      .map((text) => {
        const p = doc.createElement('p');
        p.textContent = text;
        return p;
      });
    found.replaceWith(...replacements);
  }

  return { html: doc.body.innerHTML, changes: [...counts.values()] };
}

// --- Placeholders: styled, never locked -------------------------------------------

const PLACEHOLDER_PATTERN = /\{\{[^\n}]*\}\}|\{%[^\n%]*%\}/g;

/**
 * Decorate minijinja spans.
 *
 * `Decoration.inline` is presentational only: the range stays ordinary text that can be selected,
 * split, deleted or retyped character by character. "Always editable in full" is the explicit
 * requirement, so nothing here may become a node view, an atom, or a widget. Partially typing one
 * simply matches nothing until it closes.
 */
export function placeholderDecorations(doc: PmNode): DecorationSet {
  const decorations: Decoration[] = [];
  doc.descendants((node, pos) => {
    if (!node.isText || !node.text) return;
    for (const match of node.text.matchAll(PLACEHOLDER_PATTERN)) {
      if (match.index === undefined) continue;
      decorations.push(
        Decoration.inline(pos + match.index, pos + match.index + match[0].length, {
          class: 'md-placeholder',
        }),
      );
    }
  });
  return DecorationSet.create(doc, decorations);
}

const placeholderPlugin = new Plugin({
  props: {
    decorations: (state) => placeholderDecorations(state.doc),
  },
});

// --- The component ----------------------------------------------------------------

export default function MarkdownBodyEditorInner({
  value,
  onChange,
  disabled = false,
  diagnostic = null,
  maxBytes,
  id = 'ata-body-editor',
  ariaLabel,
  toolbarLabels,
}: MarkdownBodyEditorProps) {
  const t = useT();
  const host = useRef<HTMLDivElement | null>(null);
  const viewRef = useRef<EditorView | null>(null);
  const [paste, setPaste] = useState<PasteChange[]>([]);
  // Selection-only transactions do not change the markdown value, but they do change which
  // toolbar controls are active. This revision makes that state visible to React.
  const [, setEditorRevision] = useState(0);

  const onChangeRef = useRef(onChange);
  useEffect(() => {
    onChangeRef.current = onChange;
  }, [onChange]);

  useEffect(() => {
    if (!host.current) return;

    const view = new EditorView(host.current, {
      state: EditorState.create({
        doc: parseMarkdown(value),
        plugins: [
          history(),
          keymap({
            'Mod-z': undo,
            'Mod-y': redo,
            'Mod-Shift-z': redo,
            'Mod-b': toggleMark(ataBodySchema.marks.strong),
            'Mod-i': toggleMark(ataBodySchema.marks.em),
          }),
          keymap(baseKeymap),
          placeholderPlugin,
        ],
      }),
      editable: () => !disabled,
      attributes: {
        id,
        class: 'markdown-body-editor__surface',
        role: 'textbox',
        'aria-multiline': 'true',
        ...(ariaLabel || toolbarLabels?.editor
          ? { 'aria-label': ariaLabel ?? toolbarLabels?.editor ?? '' }
          : {}),
      },
      transformPastedHTML: (html) => {
        const { html: clean, changes } = sanitizePastedHtml(html);
        if (changes.length > 0) setPaste(changes);
        return clean;
      },
      dispatchTransaction(transaction) {
        const next = view.state.apply(transaction);
        view.updateState(next);
        setEditorRevision((current) => current + 1);
        if (transaction.docChanged) onChangeRef.current(serializeMarkdown(next.doc));
      },
    });
    viewRef.current = view;
    setEditorRevision((current) => current + 1);

    return () => {
      view.destroy();
      viewRef.current = null;
    };
    // Built once; `value` and `disabled` are synchronised below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Adopt an external change (a reset, a discard, a load) without disturbing the caret while the
  // operator is typing — their own keystroke comes back down as a new `value`.
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    if (serializeMarkdown(view.state.doc) === value) return;
    // A whole new state rather than a replace transaction. An external change is a reset, a
    // discard or a reload — not an edit — so it should not be undoable back into the operator's
    // typing, and rebuilding cannot produce the invalid slice that a range replacement can.
    view.updateState(
      EditorState.create({ doc: parseMarkdown(value), plugins: view.state.plugins }),
    );
    setEditorRevision((current) => current + 1);
  }, [value]);

  useEffect(() => {
    viewRef.current?.setProps({ editable: () => !disabled });
    setEditorRevision((current) => current + 1);
  }, [disabled]);

  const commandEnabled = (command: Command) => {
    const view = viewRef.current;
    return !disabled && view !== null && command(view.state);
  };
  const runCommand = (command: Command) => {
    const view = viewRef.current;
    if (!view || disabled) return;
    view.focus();
    command(view.state, view.dispatch, view);
    setEditorRevision((current) => current + 1);
  };

  const toolbarButton = (
    label: string,
    visibleLabel: string,
    command: Command,
    pressed?: boolean,
  ) => (
    <button
      key={label}
      type="button"
      className="markdown-body-editor__tool"
      aria-label={label}
      aria-pressed={pressed}
      title={label}
      disabled={!commandEnabled(command)}
      onMouseDown={(event) => event.preventDefault()}
      onClick={() => runCommand(command)}
    >
      {visibleLabel}
    </button>
  );

  const used = useMemo(() => byteLength(value), [value]);
  const over = maxBytes !== undefined && used > maxBytes;

  const position = useMemo(() => {
    if (!diagnostic) return null;
    return locateIndex(value, charIndexForByteOffset(value, diagnostic.offset));
  }, [diagnostic, value]);

  return (
    <div className="markdown-body-editor">
      {diagnostic && position ? (
        <InlineWarning tone="error" title={t('acts.body.rejected.title')}>
          <p>
            <code>{diagnostic.construct}</code>{' '}
            {t('acts.body.rejected.at', {
              line: String(position.line),
              column: String(position.column),
            })}
          </p>
          <p>{t('acts.body.rejected.remedy')}</p>
        </InlineWarning>
      ) : null}

      {/* A paste that lost something says so, in place, and does not disappear on its own —
          dismissing it is the operator's decision, not a timeout's. */}
      {paste.length > 0 ? (
        <InlineWarning tone="warn" title={t('acts.body.paste.title')}>
          <ul className="markdown-body-editor__paste-list">
            {paste.map((change) => (
              <li key={`${change.construct}:${change.kind}`}>
                {t(
                  change.kind === 'removed'
                    ? 'acts.body.paste.removed'
                    : 'acts.body.paste.downgraded',
                  {
                    construct: t(`acts.body.construct.${change.construct}` as never),
                    count: String(change.count),
                  },
                )}
              </li>
            ))}
          </ul>
          <p>{t('acts.body.paste.why')}</p>
          <button type="button" className="btn btn--ghost" onClick={() => setPaste([])}>
            {t('acts.body.paste.dismiss')}
          </button>
        </InlineWarning>
      ) : null}

      {toolbarLabels ? (
        <div
          className="markdown-body-editor__toolbar"
          role="toolbar"
          aria-label={toolbarLabels.ariaLabel}
          aria-controls={id}
        >
          <span className="markdown-body-editor__tool-group">
            {toolbarButton(
              toolbarLabels.paragraph,
              'P',
              paragraphCommand,
              blockIsActive(viewRef.current, 'paragraph'),
            )}
            {toolbarLabels.headings.map((label, index) =>
              toolbarButton(
                label,
                `H${index + 1}`,
                headingCommands[index],
                blockIsActive(viewRef.current, 'heading', index + 1),
              ),
            )}
          </span>
          <span className="markdown-body-editor__tool-group">
            {toolbarButton(
              toolbarLabels.bold,
              toolbarLabels.bold,
              boldCommand,
              markIsActive(viewRef.current, 'strong'),
            )}
            {toolbarButton(
              toolbarLabels.italic,
              toolbarLabels.italic,
              italicCommand,
              markIsActive(viewRef.current, 'em'),
            )}
            {toolbarButton(toolbarLabels.horizontalRule, '—', horizontalRuleCommand)}
          </span>
          <span className="markdown-body-editor__tool-group">
            {toolbarButton(toolbarLabels.undo, toolbarLabels.undo, undo)}
            {toolbarButton(toolbarLabels.redo, toolbarLabels.redo, redo)}
          </span>
        </div>
      ) : null}

      <div ref={host} className="markdown-body-editor__host" data-testid="markdown-editor-host" />

      <p className="field__hint">{t('acts.body.editor.subset')}</p>
      <p className="field__hint">{t('acts.body.editor.placeholders')}</p>

      {maxBytes !== undefined ? (
        <p className={over ? 'field__error' : 'field__hint'}>
          {t(over ? 'acts.body.editor.bytesOver' : 'acts.body.editor.bytes', {
            used: String(used),
            max: String(maxBytes),
          })}
        </p>
      ) : null}
    </div>
  );
}
