import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { FollowUpsPanel } from './FollowUpsPanel';
import { renderWithProviders } from '../../test/utils';
import type { ActView, CreateFollowUpBody, FollowUpView, PatchFollowUpBody } from '../../api/types';

const act: ActView = {
  id: 'act-1',
  book_id: 'book-1',
  title: 'Assembleia Geral Ordinaria',
  channel: 'Physical',
  meeting_date: '2026-06-30',
  meeting_time: null,
  place: 'Lisboa',
  mesa: { presidente: 'Ana', secretarios: [] },
  agenda: [
    { number: 1, text: 'Aprovar relatorio de gestao' },
    { number: 2, text: 'Deliberar sobre distribuicao de resultados' },
  ],
  attendance_reference: 'Lista anexa',
  members_present: null,
  members_represented: null,
  referenced_documents: [],
  deliberations: 'Foram aprovadas as propostas.',
  deliberation_items: [
    {
      agenda_number: 2,
      text: 'Aprovada a distribuicao de resultados.',
      vote: { type: 'Unanimous' },
      statements: [],
    },
  ],
  telematic_evidence: null,
  attachments: [],
  signatories: [{ name: 'Ana', capacity: 'Chair', signed: true }],
  state: 'Signing',
  ata_number: null,
  payload_digest: null,
  seal_event_seq: null,
  retifies: null,
};

const openFollowUp: FollowUpView = {
  id: 'fu-open',
  act_id: 'act-1',
  agenda_number: 2,
  deliberation_index: null,
  title: 'Enviar certidao ao banco',
  detail: 'Juntar comprovativo no processo.',
  due_date: '2026-08-15',
  assignee: 'maria',
  assignee_display: 'Maria Silva',
  status: 'Open',
  created_at: '2026-07-01T10:00:00Z',
  created_by: 'Ana',
  completed_at: null,
  completed_by: null,
};

const completedFollowUp: FollowUpView = {
  id: 'fu-completed',
  act_id: 'act-1',
  agenda_number: null,
  deliberation_index: 0,
  title: 'Arquivar comprovativo',
  detail: 'Documento arquivado.',
  due_date: '2026-07-20',
  assignee: 'joao',
  assignee_display: 'Joao Costa',
  status: 'Completed',
  created_at: '2026-07-01T11:00:00Z',
  created_by: 'Ana',
  completed_at: '2026-07-02T09:00:00Z',
  completed_by: 'Joao',
};

interface RecordedRequest {
  method: string;
  url: string;
  body: unknown;
}

function response(body: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.toString();
  return input.url;
}

function parseBody(init?: RequestInit): unknown {
  return typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
}

function statefulFollowUps(initial: FollowUpView[] = []) {
  let rows = initial.map((row) => ({ ...row }));
  let created = 0;
  const requests: RecordedRequest[] = [];

  const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = requestUrl(input);
    const method = (init?.method ?? 'GET').toUpperCase();
    const body = parseBody(init);
    requests.push({ method, url, body });

    if (url.includes(`/v1/acts/${act.id}/follow-ups`)) {
      if (method === 'GET') return response(rows);
      if (method === 'POST') {
        const create = body as CreateFollowUpBody;
        const row: FollowUpView = {
          id: `fu-created-${(created += 1)}`,
          act_id: act.id,
          agenda_number: create.agenda_number ?? null,
          deliberation_index: create.deliberation_index ?? null,
          title: create.title,
          detail: create.detail ?? null,
          due_date: create.due_date ?? null,
          assignee: create.assignee ?? null,
          assignee_display: create.assignee_display ?? create.assignee ?? null,
          status: 'Open',
          created_at: '2026-07-09T10:00:00Z',
          created_by: 'api',
          completed_at: null,
          completed_by: null,
        };
        rows = [row, ...rows];
        return response(row);
      }
    }

    const followUpId = decodeURIComponent(
      url.match(/\/v1\/follow-ups\/([^/]+)(?:\/complete)?$/)?.[1] ?? '',
    );
    const existing = rows.find((row) => row.id === followUpId);
    if (existing && method === 'PATCH') {
      const patch = body as PatchFollowUpBody;
      const updated: FollowUpView = {
        ...existing,
        title: patch.title ?? existing.title,
        detail: patch.detail === undefined ? existing.detail : patch.detail,
        due_date: patch.due_date === undefined ? existing.due_date : patch.due_date,
        assignee: patch.assignee === undefined ? existing.assignee : patch.assignee,
        assignee_display:
          patch.assignee_display === undefined ? existing.assignee_display : patch.assignee_display,
      };
      rows = rows.map((row) => (row.id === updated.id ? updated : row));
      return response(updated);
    }
    if (existing && method === 'POST' && url.endsWith('/complete')) {
      const completed: FollowUpView = {
        ...existing,
        status: 'Completed',
        completed_at: '2026-07-09T12:00:00Z',
        completed_by: 'api',
      };
      rows = rows.map((row) => (row.id === completed.id ? completed : row));
      return response(completed);
    }

    return Promise.reject(new Error(`no stub for ${method} ${url}`));
  }) as typeof fetch;

  return { fetchImpl, requests };
}

function renderPanel(initial: FollowUpView[] = []) {
  const shared = statefulFollowUps(initial);
  vi.stubGlobal('fetch', shared.fetchImpl);
  renderWithProviders(<FollowUpsPanel act={act} />);
  return shared;
}

function mutationRequests(shared: ReturnType<typeof statefulFollowUps>) {
  return shared.requests.filter((request) => request.method !== 'GET');
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('FollowUpsPanel', () => {
  it('renders existing open and completed follow-ups with agenda and deliberation anchors', async () => {
    renderPanel([openFollowUp, completedFollowUp]);

    const openRow = await screen.findByRole('article', { name: 'Enviar certidao ao banco' });
    const completedRow = screen.getByRole('article', { name: 'Arquivar comprovativo' });

    expect(within(openRow).getByText('Ponto 2')).toBeTruthy();
    expect(within(openRow).getByText('Aberta')).toBeTruthy();
    expect(within(openRow).getByDisplayValue('Juntar comprovativo no processo.')).toBeTruthy();
    expect(within(completedRow).getByText('Deliberação 1')).toBeTruthy();
    expect(within(completedRow).getByText('Concluída')).toBeTruthy();
    expect(within(completedRow).getByDisplayValue('Joao Costa')).toBeTruthy();
  });

  it('validates the required title before creating a follow-up', async () => {
    const shared = renderPanel();

    fireEvent.click(screen.getByRole('button', { name: 'Adicionar seguimento' }));

    expect(await screen.findByText('Indique um título para o seguimento.')).toBeTruthy();
    expect(mutationRequests(shared)).toEqual([]);
  });

  it('posts a new follow-up with the selected agenda anchor', async () => {
    const shared = renderPanel();

    fireEvent.change(screen.getByLabelText('Ligação'), { target: { value: 'agenda:2' } });
    fireEvent.change(screen.getByLabelText('Título'), {
      target: { value: 'Pedir comprovativo fiscal' },
    });
    fireEvent.change(screen.getByLabelText('Detalhe'), {
      target: { value: 'Enviar pedido ao contabilista.' },
    });
    fireEvent.change(screen.getByLabelText('Data limite'), { target: { value: '2026-08-31' } });
    fireEvent.change(screen.getByLabelText('Responsável'), { target: { value: 'Maria Silva' } });
    fireEvent.click(screen.getByRole('button', { name: 'Adicionar seguimento' }));

    await waitFor(() => expect(mutationRequests(shared)).toHaveLength(1));
    const [request] = mutationRequests(shared);
    expect(request.method).toBe('POST');
    expect(request.url).toContain('/v1/acts/act-1/follow-ups');
    expect(request.body).toEqual({
      agenda_number: 2,
      title: 'Pedir comprovativo fiscal',
      detail: 'Enviar pedido ao contabilista.',
      due_date: '2026-08-31',
      assignee: 'Maria Silva',
      assignee_display: 'Maria Silva',
    });
    expect(await screen.findByRole('article', { name: 'Pedir comprovativo fiscal' })).toBeTruthy();
  });

  it('patches an edited follow-up row', async () => {
    const shared = renderPanel([openFollowUp]);
    const row = await screen.findByRole('article', { name: 'Enviar certidao ao banco' });

    fireEvent.change(within(row).getByLabelText('Título'), {
      target: { value: 'Enviar comprovativo atualizado' },
    });
    fireEvent.change(within(row).getByLabelText('Detalhe'), {
      target: { value: 'Detalhe revisto.' },
    });
    fireEvent.change(within(row).getByLabelText('Data limite'), {
      target: { value: '2026-09-05' },
    });
    fireEvent.change(within(row).getByLabelText('Responsável'), {
      target: { value: 'Carla Martins' },
    });
    fireEvent.click(within(row).getByRole('button', { name: 'Guardar tarefa' }));

    await waitFor(() => expect(mutationRequests(shared)).toHaveLength(1));
    const [request] = mutationRequests(shared);
    expect(request.method).toBe('PATCH');
    expect(request.url).toContain('/v1/follow-ups/fu-open');
    expect(request.body).toEqual({
      title: 'Enviar comprovativo atualizado',
      detail: 'Detalhe revisto.',
      due_date: '2026-09-05',
      assignee: 'Carla Martins',
      assignee_display: 'Carla Martins',
    });
    expect(
      await screen.findByRole('article', { name: 'Enviar comprovativo atualizado' }),
    ).toBeTruthy();
  });

  it('posts completion and marks the row complete', async () => {
    const shared = renderPanel([openFollowUp]);
    const row = await screen.findByRole('article', { name: 'Enviar certidao ao banco' });

    fireEvent.click(within(row).getByRole('button', { name: 'Concluir' }));

    await waitFor(() => expect(mutationRequests(shared)).toHaveLength(1));
    const [request] = mutationRequests(shared);
    expect(request.method).toBe('POST');
    expect(request.url).toContain('/v1/follow-ups/fu-open/complete');
    expect(request.body).toEqual({});

    await waitFor(() => {
      const updated = screen.getByRole('article', { name: 'Enviar certidao ao banco' });
      expect(within(updated).getByText('Concluída')).toBeTruthy();
      expect(within(updated).queryByRole('button', { name: 'Concluir' })).toBeNull();
    });
  });
});
