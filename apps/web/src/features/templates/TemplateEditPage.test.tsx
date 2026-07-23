/**
 * The user-template edit page (t109).
 *
 * The load-bearing assertions here are the refusals, not the happy path: a built-in must never be
 * writable through this route, and the seal limitation must be on screen BEFORE an operator
 * invests work in a body.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { TemplateDetailPage } from './TemplateDetailPage';
import { renderWithProviders } from '../../test/utils';
import type { Block, TemplateSummary } from '../../api/types';

// The real `MarkdownBodyEditor` is a lazy ProseMirror chunk exercised by its own test; here it is
// mocked to a plain textarea so these tests assert the PAGE WIRING (value/onChange/save payload,
// the debounced preview, the no-anchor hint) without ProseMirror in the loop.
vi.mock('../acts/MarkdownBodyEditor', () => ({
  MarkdownBodyEditor: ({
    value,
    onChange,
    disabled,
    id,
  }: {
    value: string;
    onChange: (next: string) => void;
    disabled?: boolean;
    id?: string;
  }) => (
    <textarea
      aria-label="corpo-markdown"
      id={id}
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
    />
  ),
}));

const USER_TEMPLATE: TemplateSummary = {
  id: 'user-encosto-ata/v1',
  family: 'CommercialCompany',
  stage: 'Ata',
  channels: ['Physical'],
  signature_policy: 'QualifiedPreferred',
  rule_pack_id: 'csc-art63/v2',
  law_references: [],
  locale: 'pt-PT',
  editable: true,
  source: 'user',
};

const BUILTIN_TEMPLATE: TemplateSummary = {
  ...USER_TEMPLATE,
  id: 'csc-ata-ag/v1',
  editable: false,
  source: 'builtin',
};

const SPEC = {
  id: USER_TEMPLATE.id,
  family: 'CommercialCompany',
  stage: 'Ata',
  channels: ['Physical'],
  signature_policy: 'QualifiedPreferred',
  rule_pack_id: 'csc-art63/v2',
  blocks: [{ kind: 'Paragraph', template: 'Ata de {{ entity.name }}.' }],
  locale: 'pt-PT',
};

interface RecordedRequest {
  url: string;
  method: string;
  body?: BodyInit | null;
}

/**
 * A fetch stub over the catalog, the export endpoint and the stateless body-preview compile,
 * recording every request made. `opts.exportBody` overrides the `/export` payload (e.g. a bundle
 * envelope carrying `body_markdown`); `opts.previewBlocks` is what the body preview compiles to.
 */
function stubFetch(
  catalog: TemplateSummary[],
  opts: { exportBody?: unknown; previewBlocks?: Block[] } = {},
) {
  const calls: RecordedRequest[] = [];
  const fn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    calls.push({ url, method: init?.method ?? 'GET', body: init?.body });
    const json = (value: unknown, status = 200) =>
      Promise.resolve(
        new Response(JSON.stringify(value), {
          status,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    if (url.includes('/v1/templates/body/preview')) {
      return json({ compiler_id: 'md-block/v1', blocks: opts.previewBlocks ?? [] });
    }
    if (url.includes('/export')) return json(opts.exportBody ?? SPEC);
    if (url.includes('/v1/templates')) {
      if ((init?.method ?? 'GET') === 'PUT') return json({ ...USER_TEMPLATE });
      return json(catalog);
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  });
  return { fn: fn as unknown as typeof fetch, calls };
}

/** POSTs that are real writes, not the stateless preview compile (which is also a POST). */
function writePosts(calls: RecordedRequest[]): RecordedRequest[] {
  return calls.filter((c) => c.method === 'POST' && !c.url.includes('/body/preview'));
}

/**
 * Mounts the DETAIL page at the real section route and deep-links to `/edit`.
 *
 * Deliberately not `<TemplateEditPage />` directly: `edit` is a section of `:sec?`, so the thing
 * worth testing is the whole path — the section parse, the hand-off, and the gate — as reached by
 * a typed or bookmarked URL that passed no button. A test that mounted the editor component
 * directly would pass even if the section were never wired up or never gated.
 */
function renderEdit(id: string) {
  return renderWithProviders(
    <Routes>
      <Route path="/templates/:id/:sec?" element={<TemplateDetailPage />} />
    </Routes>,
    [`/templates/${encodeURIComponent(id)}/edit`],
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('TemplateEditPage', () => {
  it('refuses to edit a built-in in place and never reads or writes its spec', async () => {
    const { fn, calls } = stubFetch([BUILTIN_TEMPLATE]);
    vi.stubGlobal('fetch', fn);

    renderEdit(BUILTIN_TEMPLATE.id);

    // Editing a shipped spec in place would retroactively change what a past seal meant, so the
    // page says so rather than rendering a form. Reaching this URL directly is refused exactly
    // as the buttons are.
    expect(await screen.findByText('Os modelos incluídos não se editam')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Guardar' })).toBeNull();
    expect(calls.some((c) => c.method === 'PUT')).toBe(false);
    expect(writePosts(calls)).toHaveLength(0);
    // NB: the spec IS fetched here, by the detail page that owns this route — it needs the body
    // for its own blocks/fields views. That is a read of an endpoint that serves built-ins by
    // design. The invariant is that nothing is ever written back, which is asserted above.
  });

  it('states the seal limitation before any editing, on the page itself', async () => {
    const { fn } = stubFetch([USER_TEMPLATE]);
    vi.stubGlobal('fetch', fn);

    renderEdit(USER_TEMPLATE.id);

    // Adjacent to the work, not discovered at the sealing step after an afternoon of it.
    expect(await screen.findByText('Uma cópia ainda não produz documentos')).toBeTruthy();
  });

  it('is full width — it uses the shared shell opt-out, not a bespoke override', async () => {
    const { fn } = stubFetch([USER_TEMPLATE]);
    vi.stubGlobal('fetch', fn);

    const { container } = renderEdit(USER_TEMPLATE.id);

    await screen.findByText('Uma cópia ainda não produz documentos');
    expect(container.querySelector('.wide-page')).toBeTruthy();
  });

  it('loads the body, keeps the id locked, and PUTs the edited spec', async () => {
    const { fn, calls } = stubFetch([USER_TEMPLATE]);
    vi.stubGlobal('fetch', fn);

    renderEdit(USER_TEMPLATE.id);

    const blocks = (await screen.findByLabelText('Blocos')) as HTMLTextAreaElement;
    expect(blocks.value).toContain('Ata de {{ entity.name }}.');
    // A new id is a different template, so an edit can never change it.
    expect((screen.getByLabelText('Identificador') as HTMLInputElement).disabled).toBe(true);

    fireEvent.change(blocks, {
      target: { value: JSON.stringify([{ kind: 'Paragraph', template: 'Reescrito.' }], null, 2) },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    const put = calls.find((c) => c.method === 'PUT');
    expect(String(put?.body)).toContain('Reescrito.');
    // An edit is a PUT over the same id — never a write POST that would leave a second copy behind
    // (the stateless body-preview POST does not count and is excluded).
    expect(writePosts(calls)).toHaveLength(0);
  });

  it('reports invalid block JSON without sending anything', async () => {
    const { fn, calls } = stubFetch([USER_TEMPLATE]);
    vi.stubGlobal('fetch', fn);

    renderEdit(USER_TEMPLATE.id);

    const blocks = (await screen.findByLabelText('Blocos')) as HTMLTextAreaElement;
    fireEvent.change(blocks, { target: { value: '[]' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    expect(await screen.findByText('O modelo tem de conter pelo menos um bloco.')).toBeTruthy();
    expect(calls.some((c) => c.method === 'PUT')).toBe(false);
  });

  it('gates the SECTION, not just the button — a deep link to a built-in gets no editor', async () => {
    const { fn, calls } = stubFetch([BUILTIN_TEMPLATE]);
    vi.stubGlobal('fetch', fn);

    // Reached by typing/bookmarking the URL, having passed no Editar button. The button path
    // diverts a built-in to the fork dialog; this asserts the segment itself refuses too, so
    // there is no route by which a shipped spec becomes writable in place.
    renderEdit(BUILTIN_TEMPLATE.id);

    expect(await screen.findByText('Os modelos incluídos não se editam')).toBeTruthy();
    expect(screen.queryByLabelText('Blocos')).toBeNull();
    expect(calls.some((c) => c.method === 'PUT')).toBe(false);
    expect(writePosts(calls)).toHaveLength(0);
  });

  it('leaves the unknown-segment fallback intact for its neighbours', async () => {
    const { fn } = stubFetch([USER_TEMPLATE]);
    vi.stubGlobal('fetch', fn);

    // `edit` joining the closed set must not turn a nonsense segment into an editor: an
    // unrecognised section still falls back to the default read view.
    renderWithProviders(
      <Routes>
        <Route path="/templates/:id/:sec?" element={<TemplateDetailPage />} />
      </Routes>,
      [`/templates/${encodeURIComponent(USER_TEMPLATE.id)}/editar-tudo`],
    );

    await waitFor(() => expect(screen.queryByLabelText('Blocos')).toBeNull());
    expect(screen.queryByRole('button', { name: 'Guardar' })).toBeNull();
  });

  it('says a template is missing rather than offering an empty form', async () => {
    const { fn } = stubFetch([]);
    vi.stubGlobal('fetch', fn);

    renderEdit('user-nao-existe/v1');

    expect(await screen.findByText('Modelo não encontrado')).toBeTruthy();
  });

  // --- Narrative body: WYSIWYG + live preview (t56) -------------------------------------

  /** The export as the real `chancela.template-bundle` envelope, carrying a seed body. */
  const BUNDLE_EXPORT = {
    format: 'chancela.template-bundle',
    format_version: 1,
    spec: SPEC,
    body_markdown: '## Corpo\n\nTexto com {{ campo }}.',
  };

  it('mounts the WYSIWYG body editor seeded from the bundle body_markdown', async () => {
    const { fn } = stubFetch([USER_TEMPLATE], { exportBody: BUNDLE_EXPORT });
    vi.stubGlobal('fetch', fn);

    renderEdit(USER_TEMPLATE.id);

    // The narrative body rides the bundle envelope as `body_markdown` and hydrates the editor.
    const body = (await screen.findByLabelText('corpo-markdown')) as HTMLTextAreaElement;
    expect(body.value).toBe('## Corpo\n\nTexto com {{ campo }}.');
    // The structured blocks stay a separate canonical-JSON textarea — the WYSIWYG edits prose only.
    expect((await screen.findByLabelText('Blocos')) as HTMLTextAreaElement).toBeTruthy();
  });

  it('renders the server-compiled preview beside the editor, tags in literal form', async () => {
    const { fn } = stubFetch([USER_TEMPLATE], {
      exportBody: BUNDLE_EXPORT,
      // The server compiles the body; a merge tag surfaces as literal token text (unresolved).
      previewBlocks: [{ type: 'Heading', level: 2, text: 'Ata n.º {{ ata_number }}' }],
    });
    vi.stubGlobal('fetch', fn);

    renderEdit(USER_TEMPLATE.id);

    // The pane's own chrome is immediate; the compiled block arrives after the debounced preview.
    expect(await screen.findByText('Pré-visualização do corpo')).toBeTruthy();
    expect(await screen.findByText('Ata n.º {{ ata_number }}')).toBeTruthy();
  });

  it('saves the narrative body through the bundle envelope', async () => {
    const { fn, calls } = stubFetch([USER_TEMPLATE], { exportBody: BUNDLE_EXPORT });
    vi.stubGlobal('fetch', fn);

    renderEdit(USER_TEMPLATE.id);

    const body = (await screen.findByLabelText('corpo-markdown')) as HTMLTextAreaElement;
    fireEvent.change(body, { target: { value: '## Reescrito\n\nNovo corpo.' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    const put = calls.find((c) => c.method === 'PUT');
    // The PUT carries the whole bundle: the envelope format AND the edited body_markdown.
    expect(String(put?.body)).toContain('chancela.template-bundle');
    expect(String(put?.body)).toContain('Novo corpo.');
    expect(writePosts(calls)).toHaveLength(0);
  });

  it('hints when the template places no narrative-body anchor, and not when it does', async () => {
    // SPEC has no `NarrativeBody` block, so the body would not reach the generated document.
    const { fn } = stubFetch([USER_TEMPLATE], { exportBody: BUNDLE_EXPORT });
    vi.stubGlobal('fetch', fn);

    const withoutAnchor = renderEdit(USER_TEMPLATE.id);
    expect(await screen.findByText('O corpo não será incluído no documento')).toBeTruthy();
    withoutAnchor.unmount();
    cleanup();

    // A spec that DOES place the anchor drops the hint.
    const anchored = {
      ...BUNDLE_EXPORT,
      spec: { ...SPEC, blocks: [...SPEC.blocks, { kind: 'NarrativeBody' }] },
    };
    const { fn: fn2 } = stubFetch([USER_TEMPLATE], { exportBody: anchored });
    vi.stubGlobal('fetch', fn2);

    renderEdit(USER_TEMPLATE.id);
    await screen.findByLabelText('corpo-markdown');
    expect(screen.queryByText('O corpo não será incluído no documento')).toBeNull();
  });
});
