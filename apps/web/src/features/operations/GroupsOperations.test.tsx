import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { useSearchParams } from 'react-router-dom';
import type {
  CompanyGroupView,
  Entity,
  GroupDashboardView,
  GroupTemplateLibraryRevision,
  GroupTemplateLibraryView,
  TemplateSummary,
} from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { GroupsOperations } from './GroupsOperations';

const TENANT = 'tenant-1';

const UNGROUPED: Entity = {
  id: 'entity-free',
  tenant_id: TENANT,
  group_id: null,
  name: 'Encosto Estratégico, Lda.',
  nipc: '503004642',
} as Entity;

const MEMBER: Entity = {
  id: 'entity-member',
  tenant_id: TENANT,
  group_id: 'group-1',
  name: 'Fundação Norte',
  nipc: '500111222',
} as Entity;

const GROUP: CompanyGroupView = {
  id: 'group-1',
  tenant_id: TENANT,
  name: 'Grupo Norte',
  description: 'Participadas do norte',
  created_at: '2026-07-01T10:00:00Z',
  updated_at: '2026-07-01T10:00:00Z',
  member_count: 1,
  template_library_count: 2,
};

const DASHBOARD: GroupDashboardView = {
  group: GROUP,
  member_entities: [MEMBER],
  books_total: 4,
  books_by_state: {},
  acts_total: 9,
  acts_by_state: {},
  reminders_open: 2,
  reminders_overdue: 1,
  reminders: [
    {
      id: 'rem-1',
      act_id: 'act-1',
      title: 'Aprovar contas de 2025',
      due_date: '2026-06-30',
      overdue: true,
      assignee: null,
    },
    {
      id: 'rem-2',
      act_id: 'act-2',
      title: 'Convocar assembleia anual',
      due_date: '2026-09-30',
      overdue: false,
      assignee: null,
    },
  ],
  recent_audit_events: [],
};

const REVISION: GroupTemplateLibraryRevision = {
  group_id: 'group-1',
  library_id: 'lib-1',
  tenant_id: TENANT,
  revision: 2,
  template_ids: ['tpl-a', 'tpl-b'],
  created_at: '2026-07-02T09:00:00Z',
  created_by: 'amelia.marques',
};

const LIBRARY: GroupTemplateLibraryView = {
  id: 'lib-1',
  group_id: 'group-1',
  tenant_id: TENANT,
  name: 'Minutas do norte',
  description: 'Base comum',
  created_at: '2026-07-01T10:00:00Z',
  updated_at: '2026-07-02T09:00:00Z',
  current_revision: REVISION,
};

const TEMPLATES = [
  { id: 'tpl-a', family: 'CommercialCompany', stage: 'Ordinary' },
  { id: 'tpl-b', family: 'CommercialCompany', stage: 'Ordinary' },
] as unknown as TemplateSummary[];

interface Recorded {
  url: string;
  method: string;
  body: Record<string, unknown> | null;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * A recording fetch stub. Reads resolve from the default operator fixture unless the test
 * supplies its own responder; every call (URL, method, parsed body) is captured so a test can
 * assert exactly what the operator surface sent to the API.
 */
function stubFetch(override?: (call: Recorded) => Response | null): Recorded[] {
  const calls: Recorded[] = [];
  const fn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const call: Recorded = {
      url,
      method: init?.method ?? 'GET',
      body: init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : null,
    };
    calls.push(call);
    const custom = override?.(call);
    if (custom) return custom;
    if (url.includes('/v1/templates')) return jsonResponse(TEMPLATES);
    if (url.endsWith(`/tenants/${TENANT}/groups`)) return jsonResponse([GROUP]);
    if (url.endsWith('/groups/group-1/dashboard')) return jsonResponse(DASHBOARD);
    if (url.endsWith('/groups/group-1/template-libraries')) return jsonResponse([LIBRARY]);
    if (url.endsWith('/template-libraries/lib-1/history')) return jsonResponse([REVISION]);
    if (call.method !== 'GET') {
      // Membership writes answer with the updated entity DTO, which the cache primes on success.
      const membership = /\/entities\/([^/?]+)$/.exec(url);
      if (membership) {
        return jsonResponse({
          ...MEMBER,
          id: membership[1],
          group_id: call.method === 'PUT' ? 'group-1' : null,
        });
      }
      return new Response(null, { status: 204 });
    }
    throw new Error(`Unexpected ${call.method} ${url}`);
  }) as typeof fetch;
  vi.stubGlobal('fetch', fn);
  return calls;
}

/** Drive a controlled multi-`<select>` the way a Ctrl-click would, then fire its change. */
function selectMultiple(select: HTMLSelectElement, values: string[]) {
  for (const option of Array.from(select.options)) {
    option.selected = values.includes(option.value);
  }
  fireEvent.change(select);
}

function SearchProbe() {
  const [params] = useSearchParams();
  return <output data-testid="search">{params.toString()}</output>;
}

function renderGroups(entries = ['/operacoes'], entities: Entity[] = [UNGROUPED, MEMBER]) {
  return renderWithProviders(
    <>
      <GroupsOperations tenantId={TENANT} entities={entities} />
      <SearchProbe />
    </>,
    entries,
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('GroupsOperations list', () => {
  it('lists each group with its member and library counts', async () => {
    stubFetch();
    renderGroups();

    const row = (await screen.findByText('Grupo Norte')).closest('tr');
    expect(row).not.toBeNull();
    const cells = within(row as HTMLTableRowElement).getAllByRole('cell');
    expect(cells[0].textContent).toContain('Participadas do norte');
    expect(cells[1].textContent).toBe('1');
    expect(cells[2].textContent).toBe('2');
  });

  it('surfaces a failed group listing as an error instead of an empty list', async () => {
    stubFetch((call) =>
      call.url.endsWith(`/tenants/${TENANT}/groups`) && call.method === 'GET'
        ? jsonResponse({ error: 'Serviço de grupos indisponível' }, 503)
        : null,
    );
    renderGroups();

    expect(await screen.findByText('Serviço de grupos indisponível')).toBeTruthy();
    expect(screen.queryByText('Ainda não existem grupos nesta organização.')).toBeNull();
  });

  it('opening a group deep-links it and drops a stale library selection', async () => {
    stubFetch();
    renderGroups(['/operacoes?library=lib-stale']);

    fireEvent.click(await screen.findByRole('button', { name: 'Abrir' }));

    await waitFor(() => expect(screen.getByTestId('search').textContent).toBe('group=group-1'));
  });
});

describe('CreateGroupForm', () => {
  it('refuses to submit a blank name and sends the trimmed name once filled', async () => {
    const calls = stubFetch((call) =>
      call.method === 'POST' && call.url.endsWith(`/tenants/${TENANT}/groups`)
        ? jsonResponse({ ...GROUP, id: 'group-new', name: 'Grupo Sul' })
        : null,
    );
    renderGroups();

    const create = await screen.findByRole('button', { name: 'Criar grupo' });
    expect(create.hasAttribute('disabled')).toBe(true);

    const name = screen.getByLabelText('Nome') as HTMLInputElement;
    fireEvent.change(name, { target: { value: '  Grupo Sul  ' } });
    fireEvent.change(screen.getByLabelText('Descrição'), { target: { value: '   ' } });
    expect(create.hasAttribute('disabled')).toBe(false);
    fireEvent.click(create);

    await waitFor(() =>
      expect(calls.some((call) => call.method === 'POST' && call.body?.name === 'Grupo Sul')).toBe(
        true,
      ),
    );
    // A blank description is omitted rather than sent as an empty string.
    const post = calls.find((call) => call.method === 'POST');
    expect(post?.body).toEqual({ name: 'Grupo Sul' });
    await waitFor(() => expect(name.value).toBe(''));
  });

  it('keeps the typed name and reports the failure when creation is rejected', async () => {
    stubFetch((call) =>
      call.method === 'POST' ? jsonResponse({ error: 'Nome já utilizado' }, 409) : null,
    );
    renderGroups();

    const name = (await screen.findByLabelText('Nome')) as HTMLInputElement;
    fireEvent.change(name, { target: { value: 'Grupo Norte' } });
    fireEvent.click(screen.getByRole('button', { name: 'Criar grupo' }));

    expect(await screen.findByText('Nome já utilizado')).toBeTruthy();
    expect(name.value).toBe('Grupo Norte');
  });
});

describe('GroupDetail', () => {
  it('blocks archiving while the group still has member entities and explains why', async () => {
    stubFetch();
    renderGroups(['/operacoes?group=group-1']);

    const archive = await screen.findByRole('button', { name: /Arquivar grupo/ });
    expect(archive.hasAttribute('disabled')).toBe(true);
    expect(screen.getByText('Remova todas as entidades antes de arquivar este grupo.')).toBeTruthy();
  });

  it('allows archiving an empty group and sends the delete', async () => {
    const calls = stubFetch((call) =>
      call.url.endsWith(`/tenants/${TENANT}/groups`) && call.method === 'GET'
        ? jsonResponse([{ ...GROUP, member_count: 0 }])
        : null,
    );
    renderGroups(['/operacoes?group=group-1']);

    const archive = await screen.findByRole('button', { name: /Arquivar grupo/ });
    expect(archive.hasAttribute('disabled')).toBe(false);
    expect(
      screen.queryByText('Remova todas as entidades antes de arquivar este grupo.'),
    ).toBeNull();
    fireEvent.click(archive);

    await waitFor(() =>
      expect(
        calls.some(
          (call) =>
            call.method === 'DELETE' && call.url.endsWith(`/tenants/${TENANT}/groups/group-1`),
        ),
      ).toBe(true),
    );
  });

  it('clears a wiped description to null rather than an empty string', async () => {
    const calls = stubFetch((call) => (call.method === 'PATCH' ? jsonResponse(GROUP) : null));
    renderGroups(['/operacoes?group=group-1']);

    const description = (await screen.findByLabelText('Descrição', {
      selector: '#operations-group-edit-description',
    })) as HTMLTextAreaElement;
    fireEvent.change(description, { target: { value: '   ' } });
    fireEvent.change(
      screen.getByLabelText('Nome', { selector: '#operations-group-edit-name' }),
      { target: { value: '  Grupo Norte e Centro  ' } },
    );
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => expect(calls.some((call) => call.method === 'PATCH')).toBe(true));
    expect(calls.find((call) => call.method === 'PATCH')?.body).toEqual({
      name: 'Grupo Norte e Centro',
      description: null,
    });
  });
});

describe('GroupDashboard', () => {
  it('reports the operational totals and flags only the overdue reminders', async () => {
    stubFetch();
    renderGroups(['/operacoes?group=group-1']);

    const metrics = await screen.findByLabelText('Resumo operacional do grupo');
    expect(within(metrics).getByText('Livros').nextElementSibling?.textContent).toBe('4');
    expect(within(metrics).getByText('Atos').nextElementSibling?.textContent).toBe('9');
    expect(within(metrics).getByText('Lembretes vencidos').nextElementSibling?.textContent).toBe(
      '1',
    );

    const overdue = screen.getByText('Aprovar contas de 2025').closest('li');
    const onTime = screen.getByText('Convocar assembleia anual').closest('li');
    expect(within(overdue as HTMLLIElement).getByText('Vencido')).toBeTruthy();
    expect(within(onTime as HTMLLIElement).queryByText('Vencido')).toBeNull();
  });

  it('reports a failed dashboard load without hiding the rest of the group detail', async () => {
    stubFetch((call) =>
      call.url.endsWith('/dashboard') ? jsonResponse({ error: 'Resumo indisponível' }, 500) : null,
    );
    renderGroups(['/operacoes?group=group-1']);

    await waitFor(() => expect(screen.getAllByText('Resumo indisponível').length).toBeGreaterThan(0));
    expect(screen.getByRole('heading', { name: 'Detalhe do grupo' })).toBeTruthy();
  });
});

describe('GroupMembers', () => {
  it('offers only entities that belong to no group, and assigns the chosen one', async () => {
    const calls = stubFetch();
    renderGroups(['/operacoes?group=group-1']);

    const picker = (await screen.findByLabelText('Entidade')) as HTMLSelectElement;
    const offered = Array.from(picker.options).map((option) => option.value);
    expect(offered).toEqual(['', 'entity-free']);

    const assign = screen.getByRole('button', { name: 'Adicionar ao grupo' });
    expect(assign.hasAttribute('disabled')).toBe(true);
    fireEvent.change(picker, { target: { value: 'entity-free' } });
    expect(assign.hasAttribute('disabled')).toBe(false);
    fireEvent.click(assign);

    await waitFor(() =>
      expect(
        calls.some(
          (call) =>
            call.method === 'PUT' && call.url.endsWith('/groups/group-1/entities/entity-free'),
        ),
      ).toBe(true),
    );
    await waitFor(() => expect(picker.value).toBe(''));
  });

  it('removes a member entity through its own row action', async () => {
    const calls = stubFetch();
    renderGroups(['/operacoes?group=group-1']);

    const row = (await screen.findByText('Fundação Norte')).closest('tr');
    fireEvent.click(
      within(row as HTMLTableRowElement).getByRole('button', { name: 'Remover do grupo' }),
    );

    await waitFor(() =>
      expect(
        calls.some(
          (call) =>
            call.method === 'DELETE' && call.url.endsWith('/groups/group-1/entities/entity-member'),
        ),
      ).toBe(true),
    );
  });

  it('shows the empty-members state when the dashboard reports no member entities', async () => {
    stubFetch((call) =>
      call.url.endsWith('/dashboard')
        ? jsonResponse({ ...DASHBOARD, member_entities: [], reminders: [] })
        : null,
    );
    renderGroups(['/operacoes?group=group-1']);

    expect(await screen.findByText('Este grupo ainda não tem entidades.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Remover do grupo' })).toBeNull();
  });
});

describe('GroupLibraries', () => {
  it('requires both a name and at least one template before a library can be created', async () => {
    const calls = stubFetch((call) =>
      call.method === 'POST' && call.url.endsWith('/template-libraries')
        ? jsonResponse({ ...LIBRARY, id: 'lib-new' })
        : null,
    );
    renderGroups(['/operacoes?group=group-1']);

    const create = await screen.findByRole('button', { name: 'Criar biblioteca' });
    expect(create.hasAttribute('disabled')).toBe(true);

    fireEvent.change(screen.getByLabelText('Nome da biblioteca'), {
      target: { value: 'Minutas do sul' },
    });
    expect(create.hasAttribute('disabled')).toBe(true);

    selectMultiple(screen.getByLabelText('Minutas incluídas') as HTMLSelectElement, ['tpl-b']);
    expect(create.hasAttribute('disabled')).toBe(false);
    fireEvent.click(create);

    await waitFor(() =>
      expect(calls.some((call) => call.method === 'POST' && call.body?.name === 'Minutas do sul')),
    );
    expect(calls.find((call) => call.method === 'POST')?.body).toEqual({
      name: 'Minutas do sul',
      template_ids: ['tpl-b'],
    });
    // The freshly created library becomes the deep-linked selection.
    await waitFor(() => expect(screen.getByTestId('search').textContent).toContain('library=lib-new'));
  });

  it('keeps the draft library on screen when the server refuses to create it', async () => {
    stubFetch((call) =>
      call.method === 'POST' && call.url.endsWith('/template-libraries')
        ? jsonResponse({ error: 'Minuta desconhecida' }, 422)
        : null,
    );
    renderGroups(['/operacoes?group=group-1']);

    const name = (await screen.findByLabelText('Nome da biblioteca')) as HTMLInputElement;
    fireEvent.change(name, { target: { value: 'Minutas do sul' } });
    fireEvent.change(screen.getByLabelText('Descrição', {
      selector: '#operations-library-description',
    }), { target: { value: 'Rascunho' } });
    selectMultiple(screen.getByLabelText('Minutas incluídas') as HTMLSelectElement, ['tpl-a']);
    fireEvent.click(screen.getByRole('button', { name: 'Criar biblioteca' }));

    expect(await screen.findByText('Minuta desconhecida')).toBeTruthy();
    expect(name.value).toBe('Minutas do sul');
    expect(screen.getByTestId('search').textContent).toBe('group=group-1');
  });

  it('selecting a library from the list deep-links it', async () => {
    stubFetch();
    renderGroups(['/operacoes?group=group-1']);

    fireEvent.click(
      await screen.findByRole('button', { name: 'Minutas do norte · revisão 2' }),
    );

    await waitFor(() =>
      expect(screen.getByTestId('search').textContent).toContain('library=lib-1'),
    );
    expect(screen.getByRole('heading', { name: 'Histórico de revisões' })).toBeTruthy();
  });

  it('labels a library that has no revision yet as revision zero', async () => {
    stubFetch((call) =>
      call.url.endsWith('/groups/group-1/template-libraries') && call.method === 'GET'
        ? jsonResponse([{ ...LIBRARY, current_revision: null }])
        : null,
    );
    renderGroups(['/operacoes?group=group-1']);

    expect(
      await screen.findByRole('button', { name: 'Minutas do norte · revisão 0' }),
    ).toBeTruthy();
  });

  it('shows the library empty state and no detail form when the group owns none', async () => {
    stubFetch((call) =>
      call.url.endsWith('/groups/group-1/template-libraries') && call.method === 'GET'
        ? jsonResponse([])
        : null,
    );
    renderGroups(['/operacoes?group=group-1&library=lib-1']);

    expect(await screen.findByText('Ainda não existem bibliotecas neste grupo.')).toBeTruthy();
    expect(screen.queryByLabelText('Nome da biblioteca')).toBeTruthy();
    expect(screen.queryByRole('heading', { name: 'Histórico de revisões' })).toBeNull();
  });
});

describe('LibraryDetail', () => {
  it('renders the immutable revision history of the selected library', async () => {
    stubFetch();
    renderGroups(['/operacoes?group=group-1&library=lib-1']);

    const historyRow = (await screen.findByText('amelia.marques')).closest('tr');
    const cells = within(historyRow as HTMLTableRowElement).getAllByRole('cell');
    expect(cells[0].textContent).toBe('2');
    expect(cells[1].textContent).toBe('tpl-a, tpl-b');
  });

  it('shows the history empty state when the library has no revisions recorded', async () => {
    stubFetch((call) => (call.url.endsWith('/history') ? jsonResponse([]) : null));
    renderGroups(['/operacoes?group=group-1&library=lib-1']);

    expect(await screen.findByText('Ainda não existe histórico de revisões.')).toBeTruthy();
  });

  it('appends a new immutable revision from the current template selection', async () => {
    const calls = stubFetch((call) =>
      call.method === 'POST' && call.url.endsWith('/revisions') ? jsonResponse(REVISION) : null,
    );
    renderGroups(['/operacoes?group=group-1&library=lib-1']);

    const append = await screen.findByRole('button', { name: 'Adicionar revisão' });
    // The revision picker starts from the library's current revision, so it is submittable.
    expect(append.hasAttribute('disabled')).toBe(false);
    selectMultiple(
      screen.getByLabelText('Minutas incluídas', { selector: '#operations-library-revision-templates' }) as HTMLSelectElement,
      ['tpl-a'],
    );
    fireEvent.click(append);

    await waitFor(() =>
      expect(calls.some((call) => call.method === 'POST' && call.url.endsWith('/revisions'))).toBe(
        true,
      ),
    );
    expect(calls.find((call) => call.url.endsWith('/revisions'))?.body).toEqual({
      template_ids: ['tpl-a'],
    });
  });

  it('refuses to append an empty revision', async () => {
    const calls = stubFetch();
    renderGroups(['/operacoes?group=group-1&library=lib-1']);

    const picker = (await screen.findByLabelText('Minutas incluídas', {
      selector: '#operations-library-revision-templates',
    })) as HTMLSelectElement;
    selectMultiple(picker, []);

    const append = screen.getByRole('button', { name: 'Adicionar revisão' });
    expect(append.hasAttribute('disabled')).toBe(true);
    // Submitting the form directly (an Enter press) must be refused too, not only the button.
    fireEvent.submit(picker.closest('form') as HTMLFormElement);

    await waitFor(() => expect(screen.getByTestId('search')).toBeTruthy());
    expect(calls.some((call) => call.url.endsWith('/revisions'))).toBe(false);
  });

  it('archives the selected library through its own action', async () => {
    const calls = stubFetch();
    renderGroups(['/operacoes?group=group-1&library=lib-1']);

    fireEvent.click(await screen.findByRole('button', { name: /Arquivar biblioteca/ }));

    await waitFor(() =>
      expect(
        calls.some(
          (call) =>
            call.method === 'DELETE' && call.url.endsWith('/template-libraries/lib-1'),
        ),
      ).toBe(true),
    );
  });

  it('reports a rejected library rename without losing the edited value', async () => {
    stubFetch((call) =>
      call.method === 'PATCH' ? jsonResponse({ error: 'Biblioteca arquivada' }, 409) : null,
    );
    renderGroups(['/operacoes?group=group-1&library=lib-1']);

    const name = (await screen.findByLabelText('Nome da biblioteca', {
      selector: '#operations-library-edit-name',
    })) as HTMLInputElement;
    fireEvent.change(name, { target: { value: 'Minutas revistas' } });
    fireEvent.change(
      screen.getByLabelText('Descrição', { selector: '#operations-library-edit-description' }),
      { target: { value: 'Base revista' } },
    );
    const libraryForm = name.closest('form') as HTMLFormElement;
    fireEvent.click(within(libraryForm).getByRole('button', { name: 'Guardar' }));

    expect(await screen.findByText('Biblioteca arquivada')).toBeTruthy();
    expect(name.value).toBe('Minutas revistas');
  });
});
