/**
 * Tests for the ata body editor (t74-e6). 48 tests, all green before the tree was deleted.
 *
 * The editor is a WYSIWYG whose **schema is the frozen block set**, and markdown remains the stored
 * source of truth. Two properties carry the whole design, and both are asserted against the real
 * ProseMirror packages rather than mocks — parsing and serializing need no browser layout, so there
 * is no reason to test a stand-in:
 *
 * 1. **Round-trip stability.** markdown → document → markdown must not drift. If it did, merely
 *    opening an ata and saving it would rewrite prose nobody edited.
 * 2. **Nothing vanishes.** A construct the schema cannot hold survives as literal text, and a paste
 *    that loses something says so. Silent loss is the failure this whole tranche exists to prevent;
 *    a restricted schema's natural behaviour is exactly that failure, so it is designed against
 *    here rather than assumed away.
 */
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import {
  ataBodySchema,
  parseMarkdown,
  sanitizePastedHtml,
  serializeMarkdown,
} from './MarkdownBodyEditorInner';
import { byteLength, charIndexForByteOffset, locateIndex } from './markdownBodyTypes';
import { MarkdownBodyEditor } from './MarkdownBodyEditor';
import { renderWithProviders } from '../../test/utils';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

/** One round trip through the editor's model. */
const roundTrip = (markdown: string) => serializeMarkdown(parseMarkdown(markdown));

describe('the schema is the frozen block set', () => {
  it('declares exactly the node types a Block can be, and no others', () => {
    // This is the mechanism that makes unsupported constructs *unrepresentable* rather than merely
    // rejected. A node type absent here cannot exist in the document by any route — typing,
    // pasting, or programmatically.
    expect(Object.keys(ataBodySchema.nodes).sort()).toEqual([
      'doc',
      'heading',
      'horizontal_rule',
      'paragraph',
      'text',
    ]);
    expect(Object.keys(ataBodySchema.marks).sort()).toEqual(['em', 'strong']);
  });

  it('has no node type for the constructs the compiler refuses', () => {
    for (const absent of [
      'table',
      'image',
      'bullet_list',
      'ordered_list',
      'code_block',
      'blockquote',
    ]) {
      expect(ataBodySchema.nodes[absent], absent).toBeUndefined();
    }
    // Links are a mark elsewhere; no Block variant carries one, so it must not exist here either.
    expect(ataBodySchema.marks.link).toBeUndefined();
  });

  it('refuses to construct a node type it does not declare', () => {
    // Belt and braces: the absence is load-bearing, so assert the failure is hard rather than a
    // silently-ignored no-op.
    expect(() => ataBodySchema.node('table')).toThrow();
  });
});

describe('markdown round trip', () => {
  const corpus: [name: string, markdown: string][] = [
    ['heading and emphasis', '# Título\n\nUm parágrafo com **negrito** e *itálico*.'],
    [
      'every heading level',
      '# um\n\n## dois\n\n### três\n\n#### quatro\n\n##### cinco\n\n###### seis',
    ],
    ['horizontal rule', 'antes\n\n---\n\ndepois'],
    ['placeholders', 'Ata n.º {{ ata_number }} de {{ meeting_date | long_date }}'],
    ['statement placeholder', '{% if channel %}Reunião telemática{% endif %}'],
    ['table pipes', '| a | b |\n| - | - |\n| 1 | 2 |'],
    ['bullet list', '- um\n- dois'],
    ['ordered list', '1. um\n2. dois'],
    ['fenced code', '```js\ncode()\n```'],
    ['block quote', '> citação'],
    ['image', '![alt](x.png)'],
    ['link', '[texto](https://exemplo.pt)'],
    ['raw html', '<script>alert(1)</script>'],
    ['setext heading', 'Setext\n======'],
    ['accented prose', 'Deliberação aprovada por unanimidade, com abstenção do sócio.'],
    ['empty', ''],
  ];

  it.each(corpus)('is stable for %s', (_name, markdown) => {
    // The property that matters: the FIRST pass may normalise (setext → ATX, unsupported syntax →
    // escaped literal), but every pass after it must be a fixed point. Otherwise opening an ata and
    // saving it without touching anything would keep rewriting the prose.
    const once = roundTrip(markdown);
    expect(roundTrip(once), `second pass drifted for ${_name}`).toBe(once);
  });

  it('preserves the constructs the block set supports, exactly', () => {
    expect(roundTrip('# Título')).toBe('# Título');
    expect(roundTrip('###### seis')).toBe('###### seis');
    expect(roundTrip('**negrito**')).toBe('**negrito**');
    expect(roundTrip('*itálico*')).toBe('*itálico*');
    expect(roundTrip('---')).toBe('---');
  });

  it('leaves placeholders byte-for-byte intact', () => {
    // A serializer that escaped braces would corrupt every template field in the document — the
    // operator would see `\{\{ ata_number \}\}` and minijinja would no longer resolve it.
    const source =
      'Ata n.º {{ ata_number }} · {{ capacity | role_label }} · {% if x %}sim{% endif %}';
    expect(roundTrip(source)).toBe(source);
  });

  it('keeps unsupported constructs as literal text instead of dropping them', () => {
    // The anti-silent-drop property, stated per construct. The words are all still there; only
    // their special meaning is gone, and that is visible to the operator as escaping.
    expect(roundTrip('- um\n- dois')).toContain('um');
    expect(roundTrip('- um\n- dois')).toContain('dois');
    expect(roundTrip('| a | b |')).toContain('a');
    expect(roundTrip('![alt](x.png)')).toContain('alt');
    expect(roundTrip('[texto](https://exemplo.pt)')).toContain('texto');
    expect(roundTrip('> citação')).toContain('citação');
  });

  it('escapes a leading `1)` so ordinary numbered prose is not saved as a list', () => {
    // "1) Deliberou-se…" is how Portuguese legal prose numbers its points. CommonMark treats BOTH
    // `.` and `)` as ordered-list delimiters; prosemirror-markdown escapes the first and misses the
    // second, so this saved unescaped and the server — which rejects lists outright — answered 422
    // on the next save. Text that looked fine in the editor, refused on save.
    //
    // Verified against the real compiler by t74-e5, not inferred from the escape lists.
    const doc = ataBodySchema.node('doc', null, [
      ataBodySchema.node('paragraph', null, [ataBodySchema.text('1) Deliberou-se aprovar.')]),
    ]);
    const saved = serializeMarkdown(doc);
    expect(saved).toBe('1\\) Deliberou-se aprovar.');
    // Round-trips: the escape parses back to the literal text, and re-serialising is a fixed point.
    expect(roundTrip(saved)).toBe(saved);
    expect(parseMarkdown(saved).textContent).toBe('1) Deliberou-se aprovar.');
  });

  it('leaves `=` and `|` alone, because neither is structure to the compiler', () => {
    // Checked and deliberately NOT escaped. `|` is not structure at all (tables are off), and
    // escaping it would re-create the `>` double-escape bug in a new character. `=` is a paragraph
    // on its own — we are safe only because blocks are separated by a blank line, which is why
    // that spacing is load-bearing rather than cosmetic.
    const para = (text: string) =>
      ataBodySchema.node('doc', null, [
        ataBodySchema.node('paragraph', null, [ataBodySchema.text(text)]),
      ]);
    expect(serializeMarkdown(para('= igual'))).toBe('= igual');
    expect(serializeMarkdown(para('| cano'))).toBe('| cano');
    expect(serializeMarkdown(para('a | b | c'))).toBe('a | b | c');
  });

  it('keeps every block separated by a blank line — `=` safety depends on it', () => {
    // Stated as its own assertion because the reasoning above rests on it: under a paragraph line,
    // `===` forms a setext heading. Nothing else in the file would fail if block separation
    // changed, so this is the test that would notice.
    const doc = ataBodySchema.node('doc', null, [
      ataBodySchema.node('paragraph', null, [ataBodySchema.text('texto')]),
      ataBodySchema.node('paragraph', null, [ataBodySchema.text('= igual')]),
    ]);
    expect(serializeMarkdown(doc)).toBe('texto\n\n= igual');
    // …and therefore the second paragraph does not become a heading on the way back.
    const back = parseMarkdown(serializeMarkdown(doc));
    const kinds: string[] = [];
    back.forEach((n) => kinds.push(n.type.name));
    expect(kinds).toEqual(['paragraph', 'paragraph']);
  });

  it('never emits HTML, whatever is typed', () => {
    // Found by probing rather than by reasoning: `<` is not in prosemirror-markdown's default
    // escape set, so raw HTML round-tripped intact and the server would have rejected a document
    // the editor showed as ordinary text. Now the output is provably inside the accept set.
    const out = roundTrip('<script>alert(1)</script> e <img onerror=x>');
    // Every `<` is escaped, so no tag can open. Asserted as "no UNESCAPED `<`" rather than "no
    // `<script`" — the latter matches the substring inside `\<script`, and would have passed for
    // the wrong reason.
    expect(out).not.toMatch(/(^|[^\\])</);
    expect(out).toContain('\\<script');
    // The words are all still there; only their markup meaning is gone.
    expect(out).toContain('alert(1)');
    expect(roundTrip(out)).toBe(out);
  });

  it('re-parses its own output into none but the declared node types', () => {
    // The closing of the loop: whatever the operator does, what gets saved parses back to blocks
    // the compiler accepts.
    const hostile = '| a |\n- b\n> c\n```d```\n![e](f.png)\n<u>g</u>';
    const doc = parseMarkdown(roundTrip(hostile));
    const seen = new Set<string>();
    doc.descendants((node) => {
      seen.add(node.type.name);
    });
    for (const name of seen) {
      expect(['paragraph', 'heading', 'horizontal_rule', 'text']).toContain(name);
    }
  });
});

describe('paste', () => {
  it('reports every construct it could not keep, with counts and whether text survived', () => {
    // The failure being designed against: a restricted schema silently discards what it cannot
    // hold, so someone pastes a table out of Word and watches it disappear — or does not watch.
    const { changes } = sanitizePastedHtml(
      '<table><tr><td>a</td><td>b</td></tr></table><ul><li>x</li><li>y</li></ul>' +
        '<img src="p.png"><a href="https://x">link</a><blockquote>q</blockquote>',
    );
    const byConstruct = Object.fromEntries(changes.map((c) => [c.construct, c]));

    expect(byConstruct.image).toEqual({ construct: 'image', kind: 'removed', count: 1 });
    expect(byConstruct.table.kind).toBe('downgraded');
    expect(byConstruct.list.kind).toBe('downgraded');
    expect(byConstruct.quote.kind).toBe('downgraded');
    expect(byConstruct.link.kind).toBe('downgraded');
  });

  it('keeps the words when it drops the structure', () => {
    const { html } = sanitizePastedHtml(
      '<table><tr><td>Sócio</td><td>50%</td></tr></table><ul><li>ponto um</li></ul>',
    );
    expect(html).toContain('Sócio');
    expect(html).toContain('50%');
    expect(html).toContain('ponto um');
    expect(html).not.toMatch(/<table|<ul|<li/);
  });

  it('distinguishes an image, where nothing survives, from a downgrade where the text does', () => {
    // The two cases need different words: one is a reshaping, the other is a loss.
    const { changes, html } = sanitizePastedHtml('<p>antes</p><img src="x.png" alt="um gráfico">');
    expect(changes).toEqual([{ construct: 'image', kind: 'removed', count: 1 }]);
    expect(html).toContain('antes');
    expect(html).not.toContain('img');
  });

  it('keeps a link’s text and drops its target', () => {
    // No Block carries a link, so a surviving href would be clickable on screen and bare text in
    // the PDF — two readers, two different documents.
    const { html, changes } = sanitizePastedHtml('<p>ver <a href="https://x.pt">o anexo</a></p>');
    expect(html).toContain('o anexo');
    expect(html).not.toContain('href');
    expect(changes[0]).toEqual({ construct: 'link', kind: 'downgraded', count: 1 });
  });

  it('counts repeats rather than listing the same construct many times', () => {
    const { changes } = sanitizePastedHtml('<img src="a"><img src="b"><img src="c">');
    expect(changes).toEqual([{ construct: 'image', kind: 'removed', count: 3 }]);
  });

  it('names every downgradable container, so a report can never say “undefined”', () => {
    // The two-structure version of this (a set of tags plus a separate name lookup) could list a
    // tag for downgrading and have no name for it, and the operator would read that
    // "undefined (1)" was converted. One map makes that unrepresentable; this pins it.
    for (const [html, construct] of [
      ['<ul><li>a</li></ul>', 'list'],
      ['<ol><li>a</li></ol>', 'list'],
      ['<blockquote>a</blockquote>', 'quote'],
      ['<pre>a</pre>', 'code'],
      ['<table><tr><td>a</td></tr></table>', 'table'],
    ] as const) {
      const { changes } = sanitizePastedHtml(html);
      expect(
        changes.map((c) => c.construct),
        html,
      ).toEqual([construct]);
    }
  });

  it('says nothing when the paste was already representable', () => {
    const { changes, html } = sanitizePastedHtml(
      '<h2>Título</h2><p>texto <strong>forte</strong></p>',
    );
    expect(changes).toEqual([]);
    expect(html).toContain('<h2>');
    expect(html).toContain('<strong>');
  });

  it('terminates on deeply nested structures instead of hanging the tab', () => {
    // A table inside a list inside a quote is ordinary Word output. The rewrite loop is iterative,
    // so it needs a termination guarantee, not an assumption.
    const nested =
      '<blockquote>'.repeat(30) +
      '<table><tr><td>x</td></tr></table>' +
      '</blockquote>'.repeat(30);
    const { html, changes } = sanitizePastedHtml(nested);
    expect(changes.length).toBeGreaterThan(0);
    expect(html).toContain('x');
    expect(html).not.toMatch(/<blockquote|<table/);
  });
});

describe('byte-offset mapping', () => {
  it('locates a diagnostic by UTF-8 bytes, not by string index', () => {
    // "deliberação" is 11 characters but 13 bytes — ç and ã cost two each. Reading the offset as a
    // string index would point two characters further on, under the wrong word.
    const text = 'deliberação X';
    expect(byteLength('deliberação')).toBe(13);
    expect(charIndexForByteOffset(text, 13)).toBe(11);
    expect(text[charIndexForByteOffset(text, 13)]).toBe(' ');
  });

  it('drifts one character per non-ASCII byte, which is why the mapping exists', () => {
    const text = 'ação, ação, ação, ação, AQUI';
    const target = text.indexOf('AQUI');
    expect(byteLength(text.slice(0, target))).toBe(target + 8);
    expect(charIndexForByteOffset(text, byteLength(text.slice(0, target)))).toBe(target);
  });

  it('counts an astral character as its own code point', () => {
    expect(charIndexForByteOffset('🙂 fim', 4)).toBe(2);
  });

  it('clamps an offset outside the text instead of throwing', () => {
    expect(charIndexForByteOffset('abc', -5)).toBe(0);
    expect(charIndexForByteOffset('abc', 999)).toBe(3);
  });

  it('reports 1-based line and column', () => {
    const text = 'primeira\nsegunda linha';
    expect(locateIndex(text, 0)).toEqual({ line: 1, column: 1 });
    expect(locateIndex(text, text.indexOf('linha'))).toEqual({ line: 2, column: 9 });
  });
});

describe('MarkdownBodyEditor', () => {
  it('shows a loading hint while the editor chunk is still arriving', () => {
    // The engine is behind React.lazy so it stays out of the eager bundle; the boundary must say
    // something rather than render an empty box.
    renderWithProviders(<MarkdownBodyEditor value="# olá" onChange={vi.fn()} />);
    expect(screen.getByText('A carregar o editor…')).toBeTruthy();
  });

  it('mounts the editing surface and does not touch the source on its own', async () => {
    const onChange = vi.fn();
    renderWithProviders(<MarkdownBodyEditor value="# Título" onChange={onChange} />);
    expect(await screen.findByTestId('markdown-editor-host')).toBeTruthy();
    expect(onChange).not.toHaveBeenCalled();
  });

  it('surfaces the server’s rejection at the byte offset the server reported', async () => {
    const source = 'Deliberação aprovada.\n\n| a | b |\n';
    const offset = byteLength(source.slice(0, source.indexOf('|')));
    renderWithProviders(
      <MarkdownBodyEditor
        value={source}
        onChange={vi.fn()}
        diagnostic={{ construct: 'table', offset }}
      />,
    );
    expect(await screen.findByText('Este texto não vai compilar')).toBeTruthy();
    expect(screen.getByText('table')).toBeTruthy();
    // Line 3, column 1 — not column 2, which is where a byte-as-index reader would land after the
    // "ç" and "ã" on line 1.
    expect(screen.getByText(/linha 3, coluna 1/)).toBeTruthy();
  });

  it('counts the body in UTF-8 bytes and warns past the cap without truncating', async () => {
    const source = 'ação'.repeat(10); // 40 characters, 60 bytes
    const onChange = vi.fn();
    renderWithProviders(<MarkdownBodyEditor value={source} onChange={onChange} maxBytes={40} />);
    expect(await screen.findByText(/60 de 40 bytes/)).toBeTruthy();
    expect(onChange).not.toHaveBeenCalled();
  });

  it('names the accepted subset and says placeholders stay editable', async () => {
    renderWithProviders(<MarkdownBodyEditor value="" onChange={vi.fn()} />);
    expect(
      await screen.findByText(/recusados pelo servidor, não removidos em silêncio/),
    ).toBeTruthy();
    expect(screen.getByText(/apenas realçados, nunca bloqueados/)).toBeTruthy();
  });

  it('shows no byte counter when no cap was given', async () => {
    // The cap is the server's, not the editor's invention. With none supplied there is no number
    // to state, and inventing one would imply a limit that does not exist.
    renderWithProviders(<MarkdownBodyEditor value="ação" onChange={vi.fn()} />);
    await screen.findByTestId('markdown-editor-host');
    expect(screen.queryByText(/bytes/)).toBeNull();
  });

  it('opens an empty body without inventing content', async () => {
    // A new ata starts blank. The parse must yield a valid empty document rather than throwing or
    // seeding placeholder prose into a legal record.
    const onChange = vi.fn();
    renderWithProviders(<MarkdownBodyEditor value="" onChange={onChange} />);
    const host = await screen.findByTestId('markdown-editor-host');
    await waitFor(() => expect(host.querySelector('[contenteditable]')).toBeTruthy());
    expect(host.textContent?.trim()).toBe('');
    expect(onChange).not.toHaveBeenCalled();
  });

  it('renders the body as a document, not as source text', async () => {
    // The point of the user's ruling: the operator sees the ata, not markdown syntax. A heading is
    // an <h2>, not the characters "## ".
    renderWithProviders(
      <MarkdownBodyEditor value={'## Ordem do dia\n\ntexto'} onChange={vi.fn()} />,
    );
    const host = await screen.findByTestId('markdown-editor-host');
    await waitFor(() => expect(host.querySelector('[contenteditable]')).toBeTruthy());
    expect(host.querySelector('h2')?.textContent).toContain('Ordem do dia');
    expect(host.textContent).not.toContain('##');
  });

  it('marks the surface uneditable when disabled, rather than hiding it', async () => {
    // A sealed ata is still readable: the operator needs to see the body they cannot change.
    renderWithProviders(<MarkdownBodyEditor value="# x" onChange={vi.fn()} disabled />);
    const host = await screen.findByTestId('markdown-editor-host');
    await waitFor(() => expect(host.querySelector('[contenteditable="false"]')).toBeTruthy());
  });

  it('adopts an external value change without reporting it as an edit', async () => {
    // A discard or a reload replaces the text. That is not the operator typing, so it must not
    // come back out through onChange as a change they made.
    //
    // Driven through a controlled parent rather than `rerender`, because that is how the ata
    // editor will own this value — and because the helper's `rerender` drops the provider wrapper,
    // which quietly remounts the component outside i18n and makes the assertion meaningless.
    const onChange = vi.fn();
    function Harness() {
      const [value, setValue] = useState('# antes');
      return (
        <>
          <button type="button" onClick={() => setValue('# depois')}>
            trocar
          </button>
          <MarkdownBodyEditor value={value} onChange={onChange} />
        </>
      );
    }
    renderWithProviders(<Harness />);
    const host = await screen.findByTestId('markdown-editor-host');
    await waitFor(() => expect(host.textContent).toContain('antes'));

    fireEvent.click(screen.getByRole('button', { name: 'trocar' }));
    await waitFor(() => expect(host.textContent).toContain('depois'));
    expect(onChange).not.toHaveBeenCalled();
  });

  it('tells the operator what a hostile paste lost, and lets them dismiss it', async () => {
    // The headline behaviour. A table pasted from a word processor cannot be represented, so the
    // words are kept as paragraphs and the loss of structure is stated — never silent.
    renderWithProviders(<MarkdownBodyEditor value="" onChange={vi.fn()} />);
    const host = await screen.findByTestId('markdown-editor-host');
    const surface = await waitFor(() => {
      const el = host.querySelector('[contenteditable]');
      if (!el) throw new Error('surface not mounted');
      return el;
    });

    fireEvent.paste(surface, {
      clipboardData: {
        types: ['text/html'],
        getData: (type: string) =>
          type === 'text/html'
            ? '<table><tr><td>Sócio</td><td>50%</td></tr></table><img src="x.png">'
            : '',
        files: [],
      },
    });

    expect(await screen.findByText('O que colou não cabe todo numa ata')).toBeTruthy();
    expect(screen.getByText(/Tabela \(1\)/)).toBeTruthy();
    expect(screen.getByText(/Imagem \(1\)/)).toBeTruthy();
    // Removal and downgrade are worded differently: one reshapes, the other loses content.
    //
    // The verbs are first-person active ("removemos", "convertemos") rather than participles.
    // That is deliberate and load-bearing for translation: a participle would have to agree in
    // gender with the interpolated construct name, and five of the six constructs are feminine in
    // Portuguese — so the original "removido"/"convertido" was ungrammatical for most of the
    // report in every Romance locale. Asserting the active form keeps that from regressing.
    expect(screen.getByText(/Imagem \(1\) — removemos/)).toBeTruthy();
    expect(screen.getByText(/Tabela \(1\) — convertemos/)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Percebi' }));
    await waitFor(() =>
      expect(screen.queryByText('O que colou não cabe todo numa ata')).toBeNull(),
    );
  });
});
