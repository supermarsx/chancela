/**
 * Ata NARRATIVE-BODY wiring tests (t35): the WYSIWYG body editor mounted in `AtaEditorPage` —
 * that it appears as the primary narrative surface on a mutable ata, that its markdown rides the
 * PATCH under the required format, that a one-time seed carries the legacy plain notes forward,
 * that a sealed ata shows the body read-only with no save, and that the server's rejection of a
 * body source surfaces in place as a diagnostic.
 *
 * The real `MarkdownBodyEditor` (a lazy ProseMirror chunk) is exercised by its own test
 * (`MarkdownBodyEditor.test.tsx`); here it is mocked to a plain textarea so these tests assert the
 * PAGE WIRING — value/onChange/disabled/diagnostic threading, the save payload, the seed — without
 * ProseMirror in the loop.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { AtaEditorPage } from './AtaEditorPage';
import { makeClient } from '../../test/utils';
import { ToastProvider } from '../../ui/toast';
import { ALLOW_ALL_PERMISSIONS, StaticPermissionsProvider } from '../session/permissions';
import type { ActView, BookView, ComplianceReport } from '../../api/types';

vi.mock('../signing/SigningPanel', () => ({ SigningPanel: () => null }));

// Mock the lazy body editor to a plain textarea + a diagnostic readout, so the wiring is what the
// test observes. Its label matches nothing the rest of the page uses, so queries are unambiguous.
vi.mock('./MarkdownBodyEditor', () => ({
  MarkdownBodyEditor: ({
    value,
    onChange,
    disabled,
    diagnostic,
    id,
  }: {
    value: string;
    onChange: (next: string) => void;
    disabled?: boolean;
    diagnostic?: { construct: string; offset: number } | null;
    id?: string;
  }) => (
    <div data-testid="body-editor">
      <textarea
        aria-label="corpo-markdown"
        id={id}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
      />
      {diagnostic ? (
        <p data-testid="body-diagnostic">{`${diagnostic.construct} @ ${diagnostic.offset}`}</p>
      ) : null}
    </div>
  ),
}));

const baseAct: ActView = {
  id: 'act-1',
  book_id: 'book-1',
  title: 'Assembleia Geral Anual',
  channel: 'Physical',
  meeting_date: '2026-06-30',
  meeting_time: null,
  place: 'Lisboa',
  mesa: { presidente: 'Ana', secretarios: [] },
  agenda: [],
  attendance_reference: 'Lista anexa',
  members_present: null,
  members_represented: null,
  referenced_documents: [],
  deliberations: '',
  deliberation_items: [],
  telematic_evidence: null,
  attachments: [],
  signatories: [{ name: 'Ana', capacity: 'Chair', signed: true }],
  state: 'TextApproved',
  ata_number: null,
  payload_digest: null,
  seal_event_seq: null,
  seal_metadata: null,
  retifies: null,
};

const book: BookView = {
  id: 'book-1',
  entity_id: 'ent-1',
  kind: 'AssembleiaGeral',
  state: 'Open',
  purpose: 'Atas AG',
  numbering_scheme: 'Sequential',
  opening_date: '2026-01-01',
  closing_date: null,
  closing_reason: null,
  last_ata_number: 0,
  predecessor: null,
  required_signatories_abertura: ['Presidente'],
  required_signatories_encerramento: null,
};

/** A `fetch` stub that persists PATCHes and answers the body-preview compile (422 on a sentinel). */
function stateful(initial: ActView) {
  let act = initial;
  const patches: Record<string, unknown>[] = [];
  const json = (body: unknown, status = 200) =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
  const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    if (url.includes('/compliance')) {
      const report: ComplianceReport = {
        rule_pack: 'csc-art63/v2',
        family: 'CommercialCompany',
        statute_overlay: false,
        issues: [],
        errors: 0,
        warnings: 0,
        seal_allowed: true,
      };
      return json(report);
    }
    if (url.includes(`/v1/acts/${act.id}/body/preview`) && method === 'POST') {
      const body = init?.body ? (JSON.parse(init.body as string) as { source?: string }) : {};
      const source = body.source ?? '';
      // A rejected body is a structured 422 carrying `{ code, offset }` (t74) — the page turns it
      // into a friendly, positioned diagnostic. The sentinel stands in for a pasted table.
      if (source.includes('TABELA')) {
        return json(
          {
            error: 'unsupported markdown construct `table`',
            code: 'unsupported_markdown',
            offset: 5,
          },
          422,
        );
      }
      return json({ compiler_id: 'md-block/v1', blocks: [] });
    }
    if (url.includes('/v1/entities/')) return json({ id: 'ent-1', family: 'CommercialCompany' });
    if (url.includes('/v1/books/')) return json(book);
    if (url.includes(`/v1/acts/${act.id}/follow-ups`) && method === 'GET') return json([]);
    if (url.endsWith(`/v1/acts/${act.id}/signature`) && method === 'GET') {
      return json({
        status: 'unsigned',
        finalization: 'em_assinatura',
        require_qualified_for_seal: false,
        evidence: {},
      });
    }
    if (/\/v1\/acts\/[^/]+$/.test(url)) {
      if (method === 'PATCH') {
        const body = JSON.parse(init!.body as string) as Record<string, unknown>;
        patches.push(body);
        act = { ...act, ...(body as Partial<ActView>) };
        return json(act);
      }
      return json(act);
    }
    return Promise.reject(new Error(`no stub for ${method} ${url}`));
  }) as typeof fetch;
  return { fetchImpl, patches };
}

function renderEditor() {
  return render(
    <QueryClientProvider client={makeClient()}>
      <ToastProvider>
        <StaticPermissionsProvider value={ALLOW_ALL_PERMISSIONS}>
          <MemoryRouter initialEntries={['/acts/act-1']}>
            <Routes>
              <Route path="/acts/:id" element={<AtaEditorPage />} />
            </Routes>
          </MemoryRouter>
        </StaticPermissionsProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('AtaEditorPage — the WYSIWYG narrative body', () => {
  it('mounts the body editor as the primary narrative on a mutable ata and saves its markdown', async () => {
    const shared = stateful(baseAct);
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    await screen.findByDisplayValue('Assembleia Geral Anual');
    // The narrative card and the (mocked) editor are present and editable.
    expect(screen.getByText('Narrativa da ata')).toBeTruthy();
    const body = screen.getByLabelText('corpo-markdown') as HTMLTextAreaElement;
    expect(body.disabled).toBe(false);

    fireEvent.change(body, { target: { value: 'Deliberou-se **aprovar** as contas.' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => expect(shared.patches.length).toBeGreaterThan(0));
    expect(shared.patches[shared.patches.length - 1]!.body).toEqual({
      format: 'Markdown',
      source: 'Deliberou-se **aprovar** as contas.',
    });
  });

  it('clears the body on save when the narrative is emptied (sends body: null)', async () => {
    const shared = stateful({
      ...baseAct,
      body: {
        format: 'Markdown',
        source: 'Texto antigo',
        compiler_id: 'md-block/v1',
        compiled_digest: '',
      },
    });
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    await screen.findByDisplayValue('Assembleia Geral Anual');
    const body = screen.getByLabelText('corpo-markdown') as HTMLTextAreaElement;
    expect(body.value).toBe('Texto antigo');

    fireEvent.change(body, { target: { value: '' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => expect(shared.patches.length).toBeGreaterThan(0));
    expect(shared.patches[shared.patches.length - 1]!.body).toBeNull();
  });

  it('offers a one-time, non-destructive seed from the plain deliberations notes', async () => {
    const shared = stateful({ ...baseAct, deliberations: 'Notas em texto simples.' });
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    await screen.findByDisplayValue('Assembleia Geral Anual');
    const body = screen.getByLabelText('corpo-markdown') as HTMLTextAreaElement;
    expect(body.value).toBe('');

    fireEvent.click(screen.getByRole('button', { name: 'Copiar estas notas para a narrativa' }));
    expect((screen.getByLabelText('corpo-markdown') as HTMLTextAreaElement).value).toBe(
      'Notas em texto simples.',
    );
    // Non-destructive: the plain notes are left intact.
    expect((screen.getByLabelText('Texto') as HTMLTextAreaElement).value).toBe(
      'Notas em texto simples.',
    );
  });

  it('lets a server-seeded body win over the deliberations seed and never resurrects it (t59 precedence)', async () => {
    // The ata was drafted from a template that seeded its narrative server-side, AND it carries the
    // legacy plain notes. The one-time "copy the notes into the narrative" seed must never be offered
    // here — not on mount, and not even after the operator clears the working body.
    const shared = stateful({
      ...baseAct,
      deliberations: 'Notas em texto simples.',
      body: {
        format: 'Markdown',
        source: 'Corpo semeado pelo modelo.',
        compiler_id: '',
        compiled_digest: '',
      },
    });
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    await screen.findByDisplayValue('Assembleia Geral Anual');
    const body = screen.getByLabelText('corpo-markdown') as HTMLTextAreaElement;
    // The server-seeded narrative is what the editor shows — the deliberations seed did not clobber it.
    expect(body.value).toBe('Corpo semeado pelo modelo.');
    expect(
      screen.queryByRole('button', { name: 'Copiar estas notas para a narrativa' }),
    ).toBeNull();

    // Clearing the working body must NOT bring the deliberations seed back: a template-seeded act
    // never lets the plain notes overwrite the server's narrative.
    fireEvent.change(body, { target: { value: '' } });
    expect(
      screen.queryByRole('button', { name: 'Copiar estas notas para a narrativa' }),
    ).toBeNull();
    // The plain notes remain intact.
    expect((screen.getByLabelText('Texto') as HTMLTextAreaElement).value).toBe(
      'Notas em texto simples.',
    );
  });

  it('surfaces the server rejection of a body source as an in-place diagnostic', async () => {
    const shared = stateful(baseAct);
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    await screen.findByDisplayValue('Assembleia Geral Anual');
    fireEvent.change(screen.getByLabelText('corpo-markdown'), {
      target: { value: 'linha com TABELA colada' },
    });

    // The debounced preview compiles server-side; a 422 becomes the friendly, positioned diagnostic.
    await waitFor(
      () =>
        expect(screen.getByTestId('body-diagnostic').textContent).toBe(
          'Formatação não suportada @ 5',
        ),
      { timeout: 3000 },
    );
  });

  it('shows the narrative read-only on a sealed ata, with no save', async () => {
    const shared = stateful({
      ...baseAct,
      state: 'Sealed',
      ata_number: 1,
      payload_digest: 'sha256:sealed',
      seal_event_seq: 7,
      body: {
        format: 'Markdown',
        source: 'Corpo selado da ata.',
        compiler_id: 'md-block/v1',
        compiled_digest: 'sha256:body',
      },
    });
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    await screen.findByDisplayValue('Assembleia Geral Anual');
    const body = screen.getByLabelText('corpo-markdown') as HTMLTextAreaElement;
    expect(body.value).toBe('Corpo selado da ata.');
    expect(body.disabled).toBe(true);
    // A sealed ata is read-only: no save affordance and no seed offer.
    expect(screen.queryByRole('button', { name: 'Guardar' })).toBeNull();
    expect(
      screen.queryByRole('button', { name: 'Copiar estas notas para a narrativa' }),
    ).toBeNull();
  });
});
