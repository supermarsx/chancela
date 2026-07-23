import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, within } from '@testing-library/react';
import { DashboardPage } from './DashboardPage';
import { fetchTable, getByRevealedText, renderWithProviders } from '../../test/utils';
import type {
  Dashboard,
  DashboardOpenBook,
  DashboardReminder,
  LedgerEventView,
} from '../../api/types';

const baseDashboard: Dashboard = {
  entities: 1,
  books_open: 1,
  books_total: 1,
  acts_total: 0,
  acts_draft: 0,
  acts_awaiting_signature: 0,
  acts_sealed: 0,
  unresolved_compliance: 0,
  failed_sync_jobs: 0,
  pending_backup_jobs: 0,
  ledger_length: 1,
  ledger_valid: true,
  current_work: {
    open_books: [],
    act_counts_by_state: {
      Draft: 0,
      Review: 0,
      Convened: 0,
      Deliberated: 0,
      TextApproved: 0,
      Signing: 0,
      Sealed: 0,
      Archived: 0,
    },
  },
  alerts: [],
  reminders: [],
  recent_events: [],
};

function eventFor(
  seq: number,
  overrides: Partial<Pick<LedgerEventView, 'kind' | 'scope' | 'chains' | 'timestamp'>> = {},
): LedgerEventView {
  return {
    id: `event-${seq}`,
    seq,
    actor: 'api',
    justification: null,
    timestamp: `2026-01-${String(seq).padStart(2, '0')}T12:00:00Z`,
    scope: `scope-${seq}`,
    kind: `kind-${seq}`,
    payload_digest: `${seq}`.padStart(64, '0'),
    prev_hash: `${seq - 1}`.padStart(64, '0'),
    hash: `${seq}`.padStart(64, 'a'),
    chains: ['global'],
    attestation: null,
    ...overrides,
  };
}

function openBookFor(seq: number, openingDate: string): DashboardOpenBook {
  return {
    book_id: `book-${seq}`,
    entity_id: `entity-${seq}`,
    entity_name: `Entidade ${seq}, Lda.`,
    kind: 'AssembleiaGeral',
    purpose: `Livro de atas ${seq}`,
    opening_date: openingDate,
    last_ata_number: seq,
    total_acts: seq + 1,
    open_acts: seq % 3,
    next_ata_number: seq + 1,
    links: {
      entity: `/v1/entities/entity-${seq}`,
      book: `/v1/books/book-${seq}`,
      act: null,
      ledger: `/v1/ledger/events?chain=book:book-${seq}`,
    },
  };
}

function reminderFor(
  seq: number,
  dueDate: string,
  status: DashboardReminder['status'],
): DashboardReminder {
  return {
    due_date: dueDate,
    severity: status === 'Upcoming' ? 'Advisory' : 'Warning',
    status,
    reason: `Lembrete ${seq}`,
    entity_id: `entity-${seq}`,
    entity_name: `Entidade ${seq}, Lda.`,
    source_rule: `rule-${seq}`,
    source_profile: `profile-${seq}`,
  };
}

function profileCalendarPlan(
  supportStatus: 'supported' | 'unsupported' = 'supported',
  preset: 'commercial' | 'condominium' = supportStatus === 'unsupported'
    ? 'condominium'
    : 'commercial',
): NonNullable<DashboardReminder['profile_calendar_plan']> {
  const condominium = preset === 'condominium';
  const dueRule =
    supportStatus === 'supported' && condominium
      ? {
          kind: 'annual_fixed_date',
          months_after_fiscal_year_end: null,
          default_fiscal_year_end: null,
          annual_fixed_month: 1,
          annual_fixed_day: 15,
          unsupported_reason: null,
        }
      : supportStatus === 'supported'
        ? {
            kind: 'fiscal_year_end_offset',
            months_after_fiscal_year_end: 3,
            default_fiscal_year_end: '12-31',
            annual_fixed_month: null,
            annual_fixed_day: null,
            unsupported_reason: null,
          }
        : {
            kind: 'not_encoded',
            months_after_fiscal_year_end: null,
            default_fiscal_year_end: null,
            annual_fixed_month: null,
            annual_fixed_day: null,
            unsupported_reason: 'missing_local_due_date_rule',
          };
  const evaluation =
    supportStatus === 'supported' && condominium
      ? {
          local_due_date_rule_configured: true,
          local_due_date_calculated: true,
          legal_deadline_calculated: false,
          fiscal_year_end: null,
          due_year: 2026,
          due_basis: 'annual_fixed_date',
          unsupported_reason: null,
        }
      : supportStatus === 'supported'
        ? {
            local_due_date_rule_configured: true,
            local_due_date_calculated: true,
            legal_deadline_calculated: false,
            fiscal_year_end: '12-31',
            due_year: 2026,
            due_basis: 'default_fiscal_year_end_missing_recorded_value',
            unsupported_reason: null,
          }
        : {
            local_due_date_rule_configured: false,
            local_due_date_calculated: false,
            legal_deadline_calculated: false,
            fiscal_year_end: null,
            due_year: null,
            due_basis: null,
            unsupported_reason: 'missing_local_due_date_rule',
          };

  return {
    preset_id: condominium ? 'condominio-annual' : 'csc-art376-annual',
    preset_label: condominium
      ? 'Assembleia ordinária anual de condóminos (DL 268/94)'
      : 'Assembleia geral anual (CSC art. 376.º)',
    rule_kind: condominium
      ? 'condominium_annual_assembly'
      : 'commercial_company_annual_general_meeting',
    support_status: supportStatus,
    review_status: 'pending_source_review',
    source_status: 'pending_unverified',
    due_rule: dueRule,
    evaluation,
    no_claims: {
      local_advisory_only: true,
      legal_deadline_authority_claimed: false,
      legal_calendar_authority_claimed: false,
      legal_compliance_claimed: false,
      compliance_status_claimed: false,
      workflow_completion_claimed: false,
      external_delivery_claimed: false,
      external_calendar_sync_claimed: false,
      webhook_delivery_claimed: false,
      legal_review_claimed: false,
      dre_verification_claimed: false,
      provider_effect_claimed: false,
      certification_claimed: false,
    },
  };
}

function renderDashboard() {
  return renderWithProviders(<DashboardPage />);
}

async function openDashboardTab(name: string) {
  const tabs = await screen.findByRole('group', { name: 'Secções do painel' });
  fireEvent.click(within(tabs).getByRole('button', { name }));
}

function expectIconOnlyActionLink(control: HTMLElement, label: string, href: string) {
  expect(control.getAttribute('href')).toBe(href);
  expect(control.className).toContain('btn--iconOnly');
  expect(control.getAttribute('aria-label')).toBe(label);
  expect(control.textContent).not.toContain(label);
  expect(control.querySelector('.icon')).toBeTruthy();

  const tooltipIds = (control.getAttribute('aria-describedby') ?? '').split(/\s+/).filter(Boolean);
  const tooltip = tooltipIds
    .map((id) => document.getElementById(id))
    .find((node) => node?.getAttribute('role') === 'tooltip' && node.textContent === label);

  expect(tooltip?.textContent).toBe(label);
  fireEvent.focus(control);
  expect(tooltip?.className).toContain('is-open');
  fireEvent.blur(control);
  expect(tooltip?.className).not.toContain('is-open');
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('DashboardPage', () => {
  it('renders dashboard subtabs in the requested order', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: baseDashboard }]));
    renderDashboard();

    const tabs = await screen.findByRole('group', { name: 'Secções do painel' });
    const buttons = within(tabs).getAllByRole('button');
    expect(buttons.map((button) => button.textContent)).toEqual([
      'Atividades atuais',
      'Estatísticas',
      'Atividade recente',
      'Datas',
      'Fila de trabalho',
      'Últimos eventos',
    ]);
    // The landing panel is also the leftmost tab, and it is the one selected with no segment.
    expect(
      within(tabs).getByRole('button', { name: 'Atividades atuais' }).getAttribute('aria-pressed'),
    ).toBe('true');
  });

  it('lands on Atividades atuais with no param and keeps every other section deep-linkable', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: baseDashboard }]));
    renderDashboard();

    expect(await screen.findByRole('heading', { name: 'Itens em uso' })).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Rascunhos e atas ativas' })).toBeTruthy();
    expect(screen.queryByText('Entidades')).toBeNull();

    // The section that used to be the default now needs its own param, and the deep links
    // that already existed (`/dashboard/queue` and friends) still open what they always did.
    cleanup();
    renderWithProviders(<DashboardPage />, ['/dashboard/stats']);
    expect(await screen.findByText('Entidades')).toBeTruthy();

    cleanup();
    renderWithProviders(<DashboardPage />, ['/dashboard/queue']);
    expect(await screen.findByRole('heading', { name: 'Fila de trabalho' })).toBeTruthy();
  });

  it('shows the current-work skeleton shape while the landing panel loads', async () => {
    // The first paint must reserve the two current-work cards, not the metric grid the
    // stats tab used to claim while it was the default.
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(() => {})) as unknown as typeof fetch);
    renderDashboard();

    const region = await screen.findByRole('status');
    expect(within(region).getByRole('heading', { name: 'Itens em uso' })).toBeTruthy();
    expect(within(region).getByRole('heading', { name: 'Rascunhos e atas ativas' })).toBeTruthy();
    expect(region.querySelector('.dashboard-section-grid')).toBeTruthy();
    expect(region.querySelector('.deflist')).toBeTruthy();
    expect(region.querySelector('.cards')).toBeNull();
  });

  it('marks the six main stats cards as a compact desktop metrics row', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: baseDashboard }]));
    renderDashboard();
    await openDashboardTab('Estatísticas');

    const metrics = (await screen.findByText('Entidades')).closest('ul');
    if (!metrics) throw new Error('Stats metrics list was not rendered');

    expect(metrics.className).toContain('dashboard-metrics--summary');
    expect(metrics.getAttribute('data-dashboard-density')).toBe('desktop-six');

    const items = within(metrics).getAllByRole('listitem');
    expect(items).toHaveLength(6);
    expect(items.map((item) => item.querySelector('.card__label')?.textContent)).toEqual([
      'Entidades',
      'Livros abertos',
      'Atas em rascunho',
      'A aguardar assinatura',
      'Atas seladas',
      'Registo (eventos)',
    ]);
  });

  it('surfaces connector failures and pending backups with a direct operations link', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([
        {
          match: '/v1/dashboard',
          body: { ...baseDashboard, failed_sync_jobs: 3, pending_backup_jobs: 2 },
        },
      ]),
    );
    renderDashboard();
    await openDashboardTab('Estatísticas');

    const section = (
      await screen.findByRole('heading', {
        name: 'Conectores e cópias externas',
      })
    ).closest('section');
    if (!section) throw new Error('Connector job metrics section was not rendered');

    expect(within(section).getByText('Sincronizações falhadas')).toBeTruthy();
    expect(within(section).getByText('3')).toBeTruthy();
    expect(within(section).getByText('Cópias pendentes')).toBeTruthy();
    expect(within(section).getByText('2')).toBeTruthy();
    expect(
      within(section).getByRole('link', { name: 'Abrir operações' }).getAttribute('href'),
    ).toBe('/operations/connectors');
  });

  it('shows only the 10 most recent dashboard events, newest first', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      books_open: 2,
      books_total: 3,
      acts_total: 4,
      acts_draft: 5,
      acts_awaiting_signature: 6,
      acts_sealed: 7,
      ledger_length: 12,
      recent_events: [4, 12, 1, 7, 3, 9, 11, 2, 6, 5, 10, 8].map((seq) => eventFor(seq)),
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Últimos eventos');

    expect(await screen.findByText('kind-12')).toBeTruthy();

    const rows = screen.getAllByRole('row').slice(1);
    expect(rows).toHaveLength(10);
    expect(rows.map((row) => within(row).getAllByRole('cell')[0].textContent)).toEqual([
      '12',
      '11',
      '10',
      '9',
      '8',
      '7',
      '6',
      '5',
      '4',
      '3',
    ]);
    expect(screen.queryByText('kind-2')).toBeNull();
    expect(screen.queryByText('kind-1')).toBeNull();
  });

  it('renders the full archive affordance as a tooltip-backed icon link', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: baseDashboard }]));
    renderDashboard();
    await openDashboardTab('Últimos eventos');

    const archive = await screen.findByRole('link', { name: 'Ver arquivo completo' });
    expectIconOnlyActionLink(archive, 'Ver arquivo completo', '/archive');
  });

  it('shows the 10 most recent act, book, and entity activities with inferred links', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      recent_events: [
        eventFor(1, { kind: 'settings.updated', scope: 'application' }),
        eventFor(2, {
          kind: 'entity.created',
          scope: 'entity-2',
          chains: ['global', 'company:entity-2'],
        }),
        eventFor(3, {
          kind: 'book.opened',
          scope: 'book:book-3',
          chains: ['global', 'book:book-3'],
        }),
        eventFor(4, { kind: 'act.drafted', scope: 'act:act-4' }),
        eventFor(5, {
          kind: 'entity.updated',
          scope: 'entity-5',
          chains: ['global', 'company:entity-5'],
        }),
        eventFor(6, {
          kind: 'book.closed',
          scope: 'book:book-6',
          chains: ['global', 'book:book-6'],
        }),
        eventFor(7, { kind: 'act.advanced', scope: 'act:act-7' }),
        eventFor(8, {
          kind: 'entity.registry_imported',
          scope: 'entity-8',
          chains: ['global', 'company:entity-8'],
        }),
        eventFor(9, {
          kind: 'book.legal_hold_set',
          scope: 'book:book-9',
          chains: ['global', 'book:book-9'],
        }),
        eventFor(10, { kind: 'act.sealed', scope: 'act:act-10' }),
        eventFor(11, {
          kind: 'entity.statute_updated',
          scope: 'entity-11',
          chains: ['global', 'company:entity-11'],
        }),
        eventFor(12, {
          kind: 'book.exported',
          scope: 'book:book-12',
          chains: ['global', 'book:book-12'],
        }),
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Atividade recente');

    const activity = await screen.findByRole('list', {
      name: 'Atividade recente de atas, livros e entidades',
    });
    const items = within(activity).getAllByRole('listitem');
    expect(items).toHaveLength(10);
    // Known kinds read as copy; the fixture's invented kinds (book.exported,
    // book.legal_hold_set, entity.registry_imported, entity.updated) stand in for a newer
    // server and must fall back to the raw identifier rather than blanking the row.
    expect(items.map((item) => item.querySelector('.dashboard-list__title')?.textContent)).toEqual([
      'book.exported',
      'Estatutos da entidade atualizados',
      'Ata selada',
      'book.legal_hold_set',
      'entity.registry_imported',
      'Ata avançada de estado',
      'Livro encerrado',
      'entity.updated',
      'Ata rascunhada',
      'Livro aberto',
    ]);
    // The raw dotted id is revealed through the tooltip description now, not a native title.
    expect(getByRevealedText('Evento act.sealed')).toBe(within(items[2]).getByRole('link'));
    expect(within(items[0]).getByRole('link').getAttribute('href')).toBe('/books/book-12');
    expect(within(items[2]).getByRole('link').getAttribute('href')).toBe('/acts/act-10');
    expect(screen.queryByText('Entidade criada')).toBeNull();
    expect(screen.queryByText('Definições atualizadas')).toBeNull();
  });

  it('links the broadened activity kinds (user, administration, tools) and drops non-link scopes', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      recent_events: [
        eventFor(1, { kind: 'ledger.recovered', scope: 'global' }),
        eventFor(2, { kind: 'user.created', scope: 'user:user-2' }),
        eventFor(3, { kind: 'role.updated', scope: 'role:role-3' }),
        eventFor(4, { kind: 'settings.updated', scope: 'settings' }),
        eventFor(5, { kind: 'registry.imported', scope: 'tenant:t/repository:repo-5' }),
        eventFor(6, { kind: 'law.reviewed', scope: 'law' }),
        eventFor(7, { kind: 'trust.updated', scope: 'trust' }),
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Atividade recente');

    const activity = await screen.findByRole('list', {
      name: 'Atividade recente de atas, livros e entidades',
    });
    const items = within(activity).getAllByRole('listitem');
    // The `global` recovery event resolves to nothing and is dropped; the other six are shown.
    expect(items).toHaveLength(6);

    // Each row's title is a real anchor pointing at the page the event refers to; newest first.
    const links = within(activity).getAllByRole('link');
    expect(links.map((link) => link.getAttribute('href'))).toEqual([
      '/tools/trust', // trust.updated (seq 7)
      '/tools/legislation', // law.reviewed (seq 6)
      '/admin/repositories', // registry.imported → tenant/repository (seq 5)
      '/settings', // settings.updated (seq 4)
      '/settings/users', // role.updated (seq 3)
      '/users/user-2', // user.created (seq 2)
    ]);

    // The three broadened badge groups read their pt-PT labels from the owned fallback module.
    expect(within(activity).getAllByText('Utilizador')).toHaveLength(2); // user + role
    expect(within(activity).getAllByText('Administração')).toHaveLength(2); // settings + repository
    expect(within(activity).getAllByText('Ferramentas')).toHaveLength(2); // law + trust
  });

  it('renders open books, active act states, and dated reminders from current dashboard data', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      current_work: {
        open_books: [
          {
            book_id: 'book-1',
            entity_id: 'entity-1',
            entity_name: 'Encosto Estratégico, S.A.',
            kind: 'AssembleiaGeral',
            purpose: 'Livro de atas da assembleia geral',
            opening_date: '2026-02-01',
            last_ata_number: 3,
            total_acts: 4,
            open_acts: 2,
            next_ata_number: 4,
            links: {
              entity: '/v1/entities/entity-1',
              book: '/v1/books/book-1',
              act: null,
              ledger: '/v1/ledger/events?chain=book:book-1',
            },
          },
        ],
        act_counts_by_state: {
          ...baseDashboard.current_work.act_counts_by_state,
          Draft: 2,
          Review: 1,
          Signing: 1,
        },
      },
      reminders: [
        {
          due_date: '2026-03-31',
          severity: 'Advisory',
          status: 'DueSoon',
          reason: 'Annual item due.',
          entity_id: 'entity-1',
          entity_name: 'Encosto Estratégico, S.A.',
          source_rule: 'csc-art376-annual',
          source_profile: 'csc-commercial',
        },
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Atividades atuais');

    const openItems = await screen.findByRole('list', { name: 'Livros abertos atualmente em uso' });
    expect(
      within(openItems)
        .getByRole('link', { name: 'Encosto Estratégico, S.A.' })
        .getAttribute('href'),
    ).toBe('/books/book-1');
    expect(within(openItems).getByText('Assembleia Geral')).toBeTruthy();
    expect(within(openItems).getByText('Próxima ata n.º 4')).toBeTruthy();
    expect(within(openItems).getByText('2 atas abertas')).toBeTruthy();

    const status = screen.getByLabelText('Atas ativas por estado');
    expect(within(status).getByText('Rascunho')).toBeTruthy();
    expect(within(status).getByText('Em revisão')).toBeTruthy();
    expect(within(status).getByText('Em assinatura')).toBeTruthy();

    await openDashboardTab('Datas');
    const dates = screen.getByRole('list', { name: 'Lembretes com data' });
    expect(within(dates).getByText('Vence em 2026-03-31')).toBeTruthy();
    expect(within(dates).getByText('Fonte csc-art376-annual / csc-commercial')).toBeTruthy();
  });

  it('keeps current open books to the five newest and reports hidden items', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      current_work: {
        ...baseDashboard.current_work,
        open_books: [
          openBookFor(1, '2026-01-15'),
          openBookFor(2, '2026-06-15'),
          openBookFor(3, '2026-05-01'),
          openBookFor(4, '2026-04-01'),
          openBookFor(5, '2026-07-01'),
          openBookFor(6, '2026-03-01'),
          openBookFor(7, '2026-02-01'),
        ],
      },
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Atividades atuais');

    const openItems = await screen.findByRole('list', {
      name: 'Livros abertos atualmente em uso',
    });
    const items = within(openItems).getAllByRole('listitem');
    expect(items).toHaveLength(5);
    expect(items.map((item) => within(item).getByRole('link').textContent)).toEqual([
      'Entidade 5, Lda.',
      'Entidade 2, Lda.',
      'Entidade 3, Lda.',
      'Entidade 4, Lda.',
      'Entidade 6, Lda.',
    ]);
    expect(within(items[0]).getByText('Aberto em 2026-07-01')).toBeTruthy();
    expect(screen.getByText('Mais 2 itens em uso')).toBeTruthy();
    expect(screen.queryByText('Entidade 1, Lda.')).toBeNull();
    expect(screen.queryByText('Entidade 7, Lda.')).toBeNull();
  });

  it('keeps dated reminders to the five earliest dates after dedupe', async () => {
    const duplicate = reminderFor(8, '2026-02-01', 'DueSoon');
    const dashboard: Dashboard = {
      ...baseDashboard,
      reminders: [
        reminderFor(1, '2026-05-20', 'Upcoming'),
        reminderFor(2, '2026-01-15', 'Overdue'),
        reminderFor(3, '2026-03-10', 'DueSoon'),
        reminderFor(4, '2026-06-01', 'Upcoming'),
        reminderFor(5, '2026-04-01', 'Upcoming'),
        reminderFor(6, '2026-07-01', 'Upcoming'),
        duplicate,
        { ...duplicate },
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Datas');

    const dates = await screen.findByRole('list', { name: 'Lembretes com data' });
    const items = within(dates).getAllByRole('listitem');
    expect(items).toHaveLength(5);
    expect(items.map((item) => within(item).getByRole('link').textContent)).toEqual([
      'Entidade 2, Lda.',
      'Entidade 8, Lda.',
      'Entidade 3, Lda.',
      'Entidade 5, Lda.',
      'Entidade 1, Lda.',
    ]);
    expect(within(items[0]).getByText('Vence em 2026-01-15')).toBeTruthy();
    expect(within(items[1]).getByText('Vence em 2026-02-01')).toBeTruthy();
    expect(screen.getByText('Mais 2 lembretes com data')).toBeTruthy();
    expect(screen.queryByText('Entidade 6, Lda.')).toBeNull();
  });

  it('renders annual-meeting reminders in the work queue without adding rows to the recent-events table', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      reminders: [
        {
          due_date: '2026-03-31',
          severity: 'Advisory',
          status: 'Overdue',
          reason:
            'The commercial-company calendar preset "Assembleia geral anual (CSC art. 376.º)" produces a local advisory date of 2026-03-31 (using the default Dec 31 fiscal-year end because no fiscal_year_end is recorded). No sealed or archived Assembleia Geral act dated 2026 is recorded for this entity. Chancela does not claim a legal deadline, legal calendar authority, or legal compliance from this local plan.',
          entity_id: 'entity-1',
          entity_name: 'Encosto Estratégico, S.A.',
          source_rule: 'csc-art376-annual',
          source_profile: 'csc-commercial',
          profile_calendar_plan: profileCalendarPlan('supported'),
        },
      ],
      recent_events: [1].map((seq) => eventFor(seq)),
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    expect(within(queue).getByText('Atrasado')).toBeTruthy();
    const item = within(queue).getByRole('listitem');
    expect(within(item).getByText('Assembleia geral anual pendente')).toBeTruthy();
    const link = within(item).getByRole('link', { name: 'Abrir entidade' });
    expect(link.getAttribute('href')).toBe('/entities/entity-1');
    expect(within(queue).getByText('Data 2026-03-31')).toBeTruthy();
    expect(
      within(queue).getByText(
        'Não há ato anual selado ou arquivado para Encosto Estratégico, S.A. em 2026-03-31. O lembrete é consultivo e deriva de csc-art376-annual.',
      ),
    ).toBeTruthy();
    expect(within(queue).getByText('Fonte Assembleia geral anual (CSC art. 376.º)')).toBeTruthy();
    expect(
      within(queue).getByText(
        'Calendário do perfil: regra local consultiva disponível; fonte por rever',
      ),
    ).toBeTruthy();
    const queueText = queue.textContent ?? '';
    expect(queueText).not.toContain('The commercial-company calendar preset');
    expect(queueText).not.toContain('does not claim a legal deadline');
    expect(queueText).not.toContain('Profile calendar supported / pending_source_review');
    expect(queueText).not.toContain('pending_source_review');
    await openDashboardTab('Últimos eventos');
    expect(await screen.findByText('kind-1')).toBeTruthy();
    expect(screen.getAllByRole('row')).toHaveLength(2);
  });

  it('localizes all non-condominium annual profile-calendar reminders in the work queue', async () => {
    const annualCases = [
      {
        rule: 'csc-art376-annual',
        profile: 'csc-commercial',
        presetLabel: 'Assembleia geral anual (CSC art. 376.º)',
        entityId: 'entity-csc',
        entityName: 'Sociedade Azul, S.A.',
        dueDate: '2026-03-31',
        title: 'Assembleia geral anual pendente',
      },
      {
        rule: 'assoc-annual',
        profile: 'association-annual',
        presetLabel: 'Assembleia geral ordinária anual (Código Civil)',
        entityId: 'entity-assoc',
        entityName: 'Associação Norte',
        dueDate: '2026-04-30',
        title: 'Assembleia geral anual pendente',
      },
      {
        rule: 'fundacao-annual',
        profile: 'foundation-annual',
        presetLabel: 'Reunião anual do conselho de administração (Lei 24/2012)',
        entityId: 'entity-fundacao',
        entityName: 'Fundação Delta',
        dueDate: '2026-05-31',
        title: 'Revisão anual pendente',
      },
      {
        rule: 'cooperativa-annual',
        profile: 'cooperative-annual',
        presetLabel: 'Assembleia geral anual (Código Cooperativo)',
        entityId: 'entity-coop',
        entityName: 'Cooperativa Sul',
        dueDate: '2026-06-30',
        title: 'Assembleia geral anual pendente',
      },
    ] as const;
    const dashboard: Dashboard = {
      ...baseDashboard,
      reminders: annualCases.map((annualCase) => ({
        due_date: annualCase.dueDate,
        severity: 'Advisory',
        status: 'DueSoon',
        reason: `Raw fallback for ${annualCase.rule}.`,
        entity_id: annualCase.entityId,
        entity_name: annualCase.entityName,
        source_rule: annualCase.rule,
        source_profile: annualCase.profile,
        profile_calendar_plan: {
          ...profileCalendarPlan('supported'),
          preset_id: annualCase.rule,
          preset_label: annualCase.presetLabel,
        },
      })),
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    expect(within(queue).getAllByRole('listitem')).toHaveLength(4);

    for (const annualCase of annualCases) {
      const source = within(queue).getByText(`Fonte ${annualCase.presetLabel}`);
      const item = source.closest('li');
      expect(item).toBeTruthy();
      if (!item) throw new Error(`Missing work-queue item for ${annualCase.rule}`);

      expect(within(item).getByText(annualCase.title)).toBeTruthy();
      expect(
        within(item).getByText(
          `Não há ato anual selado ou arquivado para ${annualCase.entityName} em ${annualCase.dueDate}. O lembrete é consultivo e deriva de ${annualCase.rule}.`,
        ),
      ).toBeTruthy();
      expect(within(item).getByText(`Data ${annualCase.dueDate}`)).toBeTruthy();
      const link = within(item).getByRole('link', { name: 'Abrir entidade' });
      expect(link.getAttribute('href')).toBe(`/entities/${annualCase.entityId}`);
      const itemText = item.textContent ?? '';
      expect(itemText).not.toContain(`Raw fallback for ${annualCase.rule}`);
      expect(itemText).not.toContain('legal deadline');
      expect(itemText).not.toContain('DRE');
      expect(itemText).not.toContain('provider');
      expect(itemText).not.toContain('registry');
    }
  });

  it('renders condominium fixed-date profile-calendar reminders as advisory work', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      reminders: [
        {
          due_date: '2026-01-15',
          severity: 'Advisory',
          status: 'DueSoon',
          reason:
            'The condominium calendar preset "Assembleia ordinária anual de condóminos (DL 268/94)" produces a local advisory date of 2026-01-15 (using the local fixed annual advisory date; profile-specific exceptions remain manual context). No sealed or archived condominium assembly act dated 2026 is recorded for this entity. Chancela does not claim a legal deadline, legal calendar authority, or legal compliance from this local plan.',
          entity_id: 'condo-1',
          entity_name: 'Condomínio Horizonte',
          source_rule: 'condominio-annual',
          source_profile: 'condominio-dl268',
          params: {
            preset_id: 'condominio-annual',
            preset_label: 'Assembleia ordinária anual de condóminos (DL 268/94)',
            local_due_date_rule_configured: 'true',
            local_due_date_calculated: 'true',
            legal_deadline_calculated: 'false',
            annual_fixed_month: '1',
            annual_fixed_day: '15',
            due_year: '2026',
            due_basis: 'annual_fixed_date',
          },
          profile_calendar_plan: profileCalendarPlan('supported', 'condominium'),
          law_refs: [],
          action: {
            kind: 'open_entity',
            label_key: 'notifications.reminder.annual.action',
            api_href: '/v1/entities/condo-1',
            route: '/entities/condo-1',
          },
          recommended_next_steps: [
            'Review the annual condominium assembly record.',
            'Seal or archive the assembly minutes once approved.',
          ],
        },
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    const item = within(queue).getByRole('listitem');
    expect(within(item).getByText('Assembleia anual de condomínio pendente')).toBeTruthy();
    const link = within(item).getByRole('link', { name: 'Abrir entidade' });
    expect(link.getAttribute('href')).toBe('/entities/condo-1');
    expect(within(item).getByText('Próximo')).toBeTruthy();
    expect(within(item).getByText('Data 2026-01-15')).toBeTruthy();
    expect(
      within(item).getByText(
        'Não há ato anual selado ou arquivado para Condomínio Horizonte em 2026-01-15. O lembrete é consultivo e deriva de condominio-annual.',
      ),
    ).toBeTruthy();
    expect(
      within(item).getByText('Fonte Assembleia ordinária anual de condóminos (DL 268/94)'),
    ).toBeTruthy();
    expect(
      within(item).getByText(
        'Calendário do perfil: regra local consultiva disponível; fonte por rever',
      ),
    ).toBeTruthy();
    const itemText = item.textContent ?? '';
    expect(itemText).not.toContain('The condominium calendar preset');
    expect(itemText).not.toContain('does not claim a legal deadline');
    expect(itemText).not.toContain('Profile calendar supported / pending_source_review');
    expect(itemText).not.toContain('pending_source_review');
  });

  it('renders open act follow-ups as localized act-routed reminders', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      reminders: [
        {
          due_date: '2026-07-01',
          severity: 'Warning',
          status: 'Overdue',
          reason: 'Raw backend follow-up fallback.',
          entity_id: 'entity-1',
          entity_name: 'Acme, S.A.',
          source_rule: 'act-follow-up',
          source_profile: 'follow-up:fu-1',
          params: {
            follow_up_id: 'fu-1',
            follow_up_title: 'Enviar certidão ao contabilista',
            follow_up_detail: 'Confirmar envio depois da assinatura externa.',
            act_id: 'act-1',
            act_title: 'Ata de aprovação de contas',
            entity_id: 'entity-1',
            entity_name: 'Acme, S.A.',
            due_date: '2026-07-01',
          },
          action: {
            kind: 'open_act_follow_up',
            label_key: 'notifications.reminder.followUp.action',
            api_href: '/v1/acts/act-1/follow-ups',
            route: null,
          },
          i18n: {
            title_key: 'notifications.reminder.followUp.title',
            body_key: 'notifications.reminder.followUp.body',
            action_key: 'notifications.reminder.followUp.action',
          },
        },
      ],
      recent_events: [1].map((seq) => eventFor(seq)),
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    const item = within(queue).getByRole('listitem');
    const link = within(item).getByRole('link', { name: 'Enviar certidão ao contabilista' });
    expect(link.getAttribute('href')).toBe('/acts/act-1');
    expect(
      within(item).getByText(
        'Acme, S.A. - Ata de aprovação de contas: Confirmar envio depois da assinatura externa.',
      ),
    ).toBeTruthy();
    expect(within(item).queryByText('Raw backend follow-up fallback.')).toBeNull();
    expect(within(item).getByText('Data 2026-07-01')).toBeTruthy();
    expect(within(item).getByText('Fonte Seguimento de deliberação')).toBeTruthy();
  });

  it('renders missing-attendance act reminders with localized params and act routing', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      reminders: [
        {
          due_date: '2026-07-20',
          severity: 'Info',
          status: 'DueSoon',
          reason: 'Raw backend attendance fallback.',
          entity_id: 'entity-1',
          entity_name: 'Acme, S.A.',
          source_rule: 'act-attendance-missing',
          source_profile: 'csc-commercial',
          params: {
            act_id: 'act-1',
            act_title: 'Ata de aprovação de contas',
            book_id: 'book-1',
            entity_id: 'entity-1',
            entity_name: 'Acme, S.A.',
            meeting_date: '2026-07-20',
            missing_fields: 'attendance_reference,presence_counts_or_attendees',
            days_until: '11',
          },
          action: {
            kind: 'open_act_attendance',
            label_key: 'notifications.reminder.act.attendance.action',
            api_href: '/v1/acts/act-1',
            route: '/acts/act-1',
          },
          i18n: {
            title_key: 'notifications.reminder.act.attendance.title',
            body_key: 'notifications.reminder.act.attendance.body',
            action_key: 'notifications.reminder.act.attendance.action',
          },
        },
      ],
      recent_events: [1].map((seq) => eventFor(seq)),
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    const item = within(queue).getByRole('listitem');
    const link = within(item).getByRole('link', {
      name: 'Registar presenças: Ata de aprovação de contas',
    });
    expect(link.getAttribute('href')).toBe('/acts/act-1');
    expect(
      within(item).getByText(
        'Ata de aprovação de contas de Acme, S.A. está marcada para 2026-07-20 e ainda não tem registo de presenças suficiente. Registe a referência de presenças e os totais ou participantes estruturados antes de a avançar.',
      ),
    ).toBeTruthy();
    expect(within(item).queryByText('Raw backend attendance fallback.')).toBeNull();
    expect(within(item).getByText('Data 2026-07-20')).toBeTruthy();
    expect(within(item).getByText('Fonte Presenças em falta na ata')).toBeTruthy();
  });

  it('renders convocation-notice act reminders with local advisory copy and act routing', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      reminders: [
        {
          due_date: '2026-03-20',
          severity: 'Warning',
          status: 'DueSoon',
          reason: 'Raw backend convocation notice fallback.',
          entity_id: 'entity-1',
          entity_name: 'Acme, S.A.',
          source_rule: 'act-convening-notice',
          source_profile: 'csc-commercial',
          params: {
            act_id: 'act-notice-1',
            act_title: 'Ata de aprovação de contas',
            book_id: 'book-1',
            entity_id: 'entity-1',
            entity_name: 'Acme, S.A.',
            required_notice_days: '10',
            meeting_date: '2026-03-30',
            notice_due_date: '2026-03-20',
            dispatch_date: '',
            antecedence_days: '',
            evidence_status: 'missing_or_unverifiable_dispatch_evidence',
            local_advisory_only: 'true',
            legal_sufficiency_claimed: 'false',
            external_delivery_claimed: 'false',
            workflow_completion_claimed: 'false',
          },
          action: {
            kind: 'open_act_convening_notice',
            label_key: 'notifications.reminder.act.conveningNotice.action',
            api_href: '/v1/acts/act-notice-1',
            route: '/acts/act-notice-1',
          },
        },
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    const item = within(queue).getByRole('listitem');
    const link = within(item).getByRole('link', {
      name: 'Rever convocatória',
    });
    expect(link.getAttribute('href')).toBe('/acts/act-notice-1#convening-guidance');
    expect(
      within(item).getByText(
        'Os estatutos registam 10 dias de antecedência para Ata de aprovação de contas de Acme, S.A. com reunião marcada para 2026-03-30; a data local de aviso é 2026-03-20. A evidência de expedição registada não demonstra essa antecedência. Aviso consultivo local; não afirma suficiência legal, entrega externa ou conclusão do workflow.',
      ),
    ).toBeTruthy();
    expect(within(item).queryByText('Raw backend convocation notice fallback.')).toBeNull();
    expect(within(item).getByText('Data 2026-03-20')).toBeTruthy();
    expect(within(item).getByText('Fonte Convocatória da reunião')).toBeTruthy();
  });

  it('renders convocation-notice reminders without meeting dates as non-computed local advisory work', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      reminders: [
        {
          due_date: '',
          severity: 'Warning',
          status: 'Pending',
          reason: 'Raw backend convocation notice fallback.',
          entity_id: 'entity-1',
          entity_name: 'Acme, S.A.',
          source_rule: 'act-convening-notice',
          source_profile: 'csc-commercial',
          params: {
            act_id: 'act-notice-1',
            act_title: 'Ata de aprovação de contas',
            book_id: 'book-1',
            entity_id: 'entity-1',
            entity_name: 'Acme, S.A.',
            required_notice_days: '10',
            meeting_date: '',
            notice_due_date: '',
            dispatch_date: '',
            antecedence_days: '',
            evidence_status: 'missing_meeting_date',
            notice_due_date_computable: 'false',
            local_deadline_computed: 'false',
            local_advisory_only: 'true',
            legal_sufficiency_claimed: 'false',
            legal_deadline_computation_claimed: 'false',
            external_delivery_claimed: 'false',
            workflow_completion_claimed: 'false',
            registry_acceptance_claimed: 'false',
            dre_acceptance_claimed: 'false',
            provider_acceptance_claimed: 'false',
          },
          action: {
            kind: 'open_act_convening_notice',
            label_key: 'notifications.reminder.act.conveningNotice.action',
            api_href: '/v1/acts/act-notice-1',
            route: null,
          },
        },
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    const item = within(queue).getByRole('listitem');
    const link = within(item).getByRole('link', {
      name: 'Rever convocatória',
    });
    expect(link.getAttribute('href')).toBe('/acts/act-notice-1#convening-guidance');
    expect(
      within(item).getByText(
        'Os metadados estatutários locais registam 10 dias de antecedência para Ata de aprovação de contas de Acme, S.A., mas a data da reunião ainda não está registada. A data local de aviso não pode ser calculada até a data da reunião ser registada. Registe a data da reunião e reveja a evidência de expedição. Aviso consultivo local; não afirma suficiência legal, cálculo de prazo legal, entrega externa, conclusão do workflow nem aceitação por registo, DRE ou fornecedor.',
      ),
    ).toBeTruthy();
    expect(within(item).queryByText('Raw backend convocation notice fallback.')).toBeNull();
    expect(within(item).getByText('Sem data')).toBeTruthy();
    expect(within(item).getByText('Fonte Convocatória da reunião')).toBeTruthy();
    expect(within(item).queryByText(/data local de aviso é/i)).toBeNull();
    expect(within(item).queryByText('2026-03-20')).toBeNull();
  });

  it('renders absent-owner dispatch evidence reminders with localized act routing', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      reminders: [
        {
          due_date: '',
          severity: 'Advisory',
          status: 'Pending',
          reason: 'Raw backend dispatch fallback.',
          entity_id: 'entity-1',
          entity_name: 'Condomínio Acme',
          source_rule: 'absent-owner-dispatch-evidence',
          source_profile: 'condominium-generated-communication',
          params: {
            act_id: 'act-absent-1',
            act_title: 'Ata da assembleia de condóminos',
            book_id: 'book-1',
            document_id: 'generated-absent-1',
            template_id: 'condominio-comunicacao-ausentes/v1',
            dispatch_evidence_status: 'operator_evidence_partial',
            required_recipient_count: '2',
            recorded_recipient_count: '1',
            missing_recipient_count: '1',
            missing_recipients: 'Fração C',
          },
          action: {
            kind: 'open_absent_owner_dispatch_evidence',
            label_key: 'notifications.reminder.absentOwnerDispatch.action',
            api_href: '/v1/documents/generated/generated-absent-1/dispatch-evidence',
            route: '/acts/act-absent-1',
          },
          i18n: {
            title_key: 'notifications.reminder.absentOwnerDispatch.title',
            body_key: 'notifications.reminder.absentOwnerDispatch.body',
            action_key: 'notifications.reminder.absentOwnerDispatch.action',
          },
        },
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    const item = within(queue).getByRole('listitem');
    const link = within(item).getByRole('link', {
      name: 'Evidência de expedição pendente: Ata da assembleia de condóminos',
    });
    expect(link.getAttribute('href')).toBe(
      '/acts/act-absent-1?generated_document_id=generated-absent-1&focus=dispatch-evidence#generated-dispatch-evidence',
    );
    expect(within(item).getByText('Pendente')).toBeTruthy();
    expect(
      within(item).getByText(
        'Ata da assembleia de condóminos tem comunicação a condóminos ausentes gerada, mas a evidência de expedição está operator_evidence_partial. Destinatários em falta: Fração C. O lembrete é apenas consultivo.',
      ),
    ).toBeTruthy();
    expect(within(item).queryByText('Raw backend dispatch fallback.')).toBeNull();
    expect(within(item).getByText('Sem data')).toBeTruthy();
    expect(within(item).getByText('Fonte Evidência de expedição a condómino ausente')).toBeTruthy();
  });

  it('routes generated-convening dispatch evidence reminders to the generated document workflow', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      reminders: [
        {
          due_date: '',
          severity: 'Advisory',
          status: 'Pending',
          reason:
            'Generated convening notice metadata is partial; no sending, delivery, legal notice completion, or legal sufficiency is claimed.',
          entity_id: 'entity-1',
          entity_name: 'Condomínio Acme',
          source_rule: 'generated-convening-dispatch-evidence',
          source_profile: 'generated-convening-notice',
          params: {
            act_id: 'act-conv-1',
            act_title: 'Ata convocada',
            book_id: 'book-1',
            generated_document_id: 'generated-conv-1',
            template_id: 'condominio-aviso-convocatoria/v1',
            dispatch_evidence_status: 'operator_evidence_partial',
            required_recipient_count: '2',
            recorded_recipient_count: '1',
            missing_recipient_count: '1',
            missing_recipients: 'Bruno Sócio',
            dispatch_completed: 'false',
            completion_basis: 'none',
            sending_performed_by_chancela: 'false',
            delivery_confirmed: 'false',
            legal_notice_completion_claimed: 'false',
            legal_sufficiency_claimed: 'false',
          },
          action: {
            kind: 'open_generated_convening_dispatch_evidence',
            label_key: 'notifications.reminder.absentOwnerDispatch.action',
            api_href: '/v1/documents/generated/generated-conv-1/dispatch-evidence',
            route: '/acts/act-conv-1',
          },
          i18n: null,
        },
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    const item = within(queue).getByRole('listitem');
    expect(
      within(item).getByText(
        'Generated convening notice metadata is partial; no sending, delivery, legal notice completion, or legal sufficiency is claimed.',
      ),
    ).toBeTruthy();
    expect(within(item).getByText('Fonte Evidência de expedição da convocatória')).toBeTruthy();
    expect(within(item).queryByText('Entrega confirmada')).toBeNull();
    expect(within(item).queryByText('Workflow concluído')).toBeNull();
    expect(within(item).getByRole('link').getAttribute('href')).toBe(
      '/acts/act-conv-1?generated_document_id=generated-conv-1&focus=dispatch-evidence#generated-dispatch-evidence',
    );
  });

  it('renders imported-document review reminders with localized deep-link routing', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      reminders: [
        {
          due_date: '',
          severity: 'Advisory',
          status: 'Pending',
          reason: 'Raw backend imported-review fallback.',
          entity_id: 'entity-1',
          entity_name: 'Acme, S.A.',
          source_rule: 'imported-document-review-required',
          source_profile: 'imported-document-review:import-1',
          params: {
            act_id: 'act-import-1',
            act_title: 'Ata com documento importado',
            book_id: 'book-1',
            entity_id: 'entity-1',
            entity_name: 'Acme, S.A.',
            imported_document_id: 'import-1',
            operator_review_status: 'operator_review_required',
          },
          action: {
            kind: 'open_imported_document_review',
            label_key: 'notifications.reminder.importedDocumentReview.action',
            api_href: '/v1/documents/imported/import-1',
            route: '/acts/act-import-1',
          },
          i18n: {
            title_key: 'notifications.reminder.importedDocumentReview.title',
            body_key: 'notifications.reminder.importedDocumentReview.body',
            action_key: 'notifications.reminder.importedDocumentReview.action',
          },
        },
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    const item = within(queue).getByRole('listitem');
    const link = within(item).getByRole('link', {
      name: 'Revisão de documento importado pendente: Ata com documento importado',
    });
    expect(link.getAttribute('href')).toBe(
      '/acts/act-import-1?imported_document_id=import-1&focus=import-review#imported-documents',
    );
    expect(within(item).getByText('Pendente')).toBeTruthy();
    expect(
      within(item).getByText(
        'Ata com documento importado de Acme, S.A. tem o documento importado import-1 ainda em operator_review_required. Abra a revisão existente; o lembrete é apenas consultivo.',
      ),
    ).toBeTruthy();
    expect(within(item).queryByText('Raw backend imported-review fallback.')).toBeNull();
    expect(within(item).getByText('Sem data')).toBeTruthy();
    expect(within(item).getByText('Fonte Documento importado por rever')).toBeTruthy();
  });

  it('renders privacy control review reminders with settings routing and source markers', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      reminders: [
        {
          due_date: '2026-07-20',
          severity: 'Info',
          status: 'DueSoon',
          reason:
            'Local DPIA review reminder only; no authority filing, legal approval, external delivery, completion, or compliance certification is claimed.',
          entity_id: 'dpia-review-1',
          entity_name: 'Biometric access DPIA',
          source_rule: 'privacy-dpia-review',
          source_profile: 'privacy-dpia',
          action: {
            kind: 'open_settings_privacy',
            label_key: 'settings.privacy.title',
            api_href: '/v1/privacy/dpias',
            route: '/settings?sec=privacidade',
          },
        },
        {
          due_date: '2026-07-10',
          severity: 'Warning',
          status: 'Overdue',
          reason:
            'Local breach playbook review reminder only; no authority or data-subject notification is claimed.',
          entity_id: 'breach-review-1',
          entity_name: 'Supplier token breach playbook',
          source_rule: 'privacy-breach-playbook-review',
          source_profile: 'breach:breach-review-1',
          action: {
            kind: 'open_settings_privacy',
            label_key: 'settings.privacy.title',
            api_href: '/v1/privacy/breach-playbooks/breach-review-1',
            route: '/settings?sec=privacidade',
          },
        },
        {
          due_date: '',
          severity: 'Advisory',
          status: 'Pending',
          reason:
            'Local transfer-control review reminder only; no transfer approval or execution is claimed.',
          entity_id: 'transfer-review-1',
          entity_name: 'UK support access transfer review',
          source_rule: 'privacy-transfer-control-review',
          source_profile: 'transfer:transfer-review-1',
          action: {
            kind: 'open_settings_privacy',
            label_key: 'settings.privacy.title',
            api_href: '/v1/privacy/transfer-controls/transfer-review-1',
            route: '/settings?sec=privacidade',
          },
        },
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    expect(within(queue).getAllByRole('listitem')).toHaveLength(3);

    const dpia = within(queue).getByText('Biometric access DPIA').closest('li');
    expect(dpia).toBeTruthy();
    expect(within(dpia!).getByText('Próximo')).toBeTruthy();
    expect(
      within(dpia!).getByText('Fonte Revisão da avaliação de impacto sobre a proteção de dados'),
    ).toBeTruthy();
    expect(
      within(dpia!).getByRole('link', { name: 'Biometric access DPIA' }).getAttribute('href'),
    ).toBe('/settings?sec=privacidade');

    const breach = within(queue).getByText('Supplier token breach playbook').closest('li');
    expect(breach).toBeTruthy();
    expect(within(breach!).getByText('Atrasado')).toBeTruthy();
    expect(
      within(breach!).getByText('Fonte Revisão do plano de resposta a violações de dados'),
    ).toBeTruthy();
    expect(
      within(breach!)
        .getByRole('link', { name: 'Supplier token breach playbook' })
        .getAttribute('href'),
    ).toBe('/settings?sec=privacidade');

    const transfer = within(queue).getByText('UK support access transfer review').closest('li');
    expect(transfer).toBeTruthy();
    expect(within(transfer!).getByText('Pendente')).toBeTruthy();
    expect(within(transfer!).getByText('Sem data')).toBeTruthy();
    expect(
      within(transfer!).getByText('Fonte Revisão do controlo de transferências internacionais'),
    ).toBeTruthy();
    expect(
      within(transfer!)
        .getByRole('link', { name: 'UK support access transfer review' })
        .getAttribute('href'),
    ).toBe('/settings?sec=privacidade');
  });

  it('shows an empty work-queue state when dashboard data exposes no operator work', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: baseDashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    expect(await screen.findByRole('heading', { name: 'Fila de trabalho' })).toBeTruthy();
    expect(screen.getByText('Sem trabalho pendente derivado do painel.')).toBeTruthy();
    expect(screen.queryByRole('list', { name: 'Fila de trabalho do painel' })).toBeNull();
  });

  it('renders law-backed dashboard alerts with action route and law metadata', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      alerts: [
        {
          code: 'entity.manager_remuneration.setup_recommended',
          label: 'Advisory',
          severity: 'Info',
          category: 'GovernanceSetup',
          message: 'Raw backend remuneration message.',
          params: { entity_name: 'Encosto Estratégico, Lda.' },
          target: {
            entity_id: 'entity-1',
            book_id: null,
            act_id: null,
            links: { entity: '/v1/entities/entity-1', book: null, act: null, ledger: null },
          },
          source: 'registry_extracts.orgaos',
          law_refs: [
            {
              diploma_id: 'csc',
              article: '255',
              label: 'Artigo 255.º',
              heading: 'Remuneração dos gerentes',
              verification: 'Pending',
              source_url: null,
              source_complete: false,
              review_method: null,
              review_note: null,
            },
          ],
          action: {
            kind: 'open_entity',
            label_key: 'notifications.alert.entity.managerRemuneration.action',
            api_href: '/v1/entities/entity-1',
            route: '/entities/entity-1',
          },
          recommended_next_steps: [
            'Review registry officers.',
            'Draft remuneration or non-remuneration minutes.',
          ],
          i18n: {
            title_key: 'notifications.alert.entity.managerRemuneration.title',
            body_key: 'notifications.alert.entity.managerRemuneration.body',
            action_key: 'notifications.alert.entity.managerRemuneration.action',
          },
        },
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    expectIconOnlyActionLink(
      within(queue).getByRole('link', { name: 'Definir remuneração da gerência' }),
      'Definir remuneração da gerência',
      '/entities/entity-1',
    );
    expect(within(queue).getByText(/Encosto Estratégico, Lda./)).toBeTruthy();
    expect(within(queue).getByText('Lei csc:255 · fonte pendente')).toBeTruthy();
  });

  it('renders administrator remuneration alerts with CSC art. 399 metadata', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      alerts: [
        {
          code: 'entity.administrator_remuneration.setup_recommended',
          label: 'Advisory',
          severity: 'Info',
          category: 'GovernanceSetup',
          message: 'Raw backend administrator remuneration message.',
          params: { entity_name: 'Atlântico Estratégico, S.A.', office: 'administration' },
          target: {
            entity_id: 'entity-sa',
            book_id: null,
            act_id: null,
            links: { entity: '/v1/entities/entity-sa', book: null, act: null, ledger: null },
          },
          source: 'registry_extracts.orgaos',
          law_refs: [
            {
              diploma_id: 'csc',
              article: '399',
              label: 'Artigo 399.º',
              heading: 'Remuneração dos administradores',
              verification: 'Pending',
              source_url: null,
              source_complete: false,
              review_method: null,
              review_note: null,
            },
          ],
          action: {
            kind: 'open_entity',
            label_key: 'notifications.alert.entity.administratorRemuneration.action',
            api_href: '/v1/entities/entity-sa',
            route: '/entities/entity-sa',
          },
          recommended_next_steps: [
            'Review registry officers and statutes.',
            'Draft remuneration or non-remuneration minutes.',
          ],
          i18n: {
            title_key: 'notifications.alert.entity.administratorRemuneration.title',
            body_key: 'notifications.alert.entity.administratorRemuneration.body',
            action_key: 'notifications.alert.entity.administratorRemuneration.action',
          },
        },
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    expect(
      within(queue)
        .getByRole('link', { name: 'Definir remuneração dos administradores' })
        .getAttribute('href'),
    ).toBe('/entities/entity-sa');
    expect(within(queue).getByText(/Atlântico Estratégico, S.A./)).toBeTruthy();
    expect(within(queue).getByText('Lei csc:399 · fonte pendente')).toBeTruthy();
  });

  it('renders legal-hold and archive-status alerts as localized routed work', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      alerts: [
        {
          code: 'book.legal_hold.active',
          label: 'ReviewRequired',
          severity: 'Warning',
          category: 'ArchiveRetention',
          message: 'Raw backend legal hold message.',
          params: {
            book_id: 'book-held',
            entity_id: 'entity-1',
            book_kind: 'AssembleiaGeral',
            legal_hold_reason: 'litígio pendente',
            legal_hold_actor: 'operator',
            legal_hold_set_at: '2026-07-01T12:00:00Z',
          },
          target: {
            entity_id: 'entity-1',
            book_id: 'book-held',
            act_id: null,
            links: {
              entity: '/v1/entities/entity-1',
              book: '/v1/books/book-held',
              act: null,
              ledger: '/v1/ledger/events?chain=book:book-held',
            },
          },
          source: 'books.legal_hold',
          law_refs: [],
          action: {
            kind: 'open_book_legal_hold',
            label_key: 'notifications.alert.book.legalHold.action',
            api_href: '/v1/books/book-held/legal-hold',
            route: '/books/book-held',
          },
          recommended_next_steps: [
            'Open the book legal-hold panel.',
            'Review the hold reason before any archive disposal decision.',
          ],
          i18n: {
            title_key: 'notifications.alert.book.legalHold.title',
            body_key: 'notifications.alert.book.legalHold.body',
            action_key: 'notifications.alert.book.legalHold.action',
          },
        },
        {
          code: 'act.archive.pending',
          label: 'Advisory',
          severity: 'Info',
          category: 'ArchiveStatus',
          message: 'Raw backend archive message.',
          params: {
            act_id: 'act-sealed',
            book_id: 'book-held',
            entity_id: 'entity-1',
            act_title: 'Ata selada',
            current_state: 'Sealed',
          },
          target: {
            entity_id: 'entity-1',
            book_id: 'book-held',
            act_id: 'act-sealed',
            links: {
              entity: '/v1/entities/entity-1',
              book: '/v1/books/book-held',
              act: '/v1/acts/act-sealed',
              ledger: '/v1/ledger/events?scope=act:act-sealed',
            },
          },
          source: 'acts.state',
          law_refs: [],
          action: {
            kind: 'archive_act',
            label_key: 'notifications.alert.act.archivePending.action',
            api_href: '/v1/acts/act-sealed/archive',
            route: '/acts/act-sealed',
          },
          recommended_next_steps: [
            'Open the sealed act.',
            'Archive it when the preservation evidence is ready.',
          ],
          i18n: {
            title_key: 'notifications.alert.act.archivePending.title',
            body_key: 'notifications.alert.act.archivePending.body',
            action_key: 'notifications.alert.act.archivePending.action',
          },
        },
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    expect(
      within(queue).getByRole('link', { name: 'Retenção legal ativa' }).getAttribute('href'),
    ).toBe('/books/book-held');
    expect(
      within(queue).getByText(
        'O livro book-held tem retenção legal ativa: litígio pendente. Reveja a retenção antes de decisões de descarte de arquivo.',
      ),
    ).toBeTruthy();
    expect(within(queue).getByText('Fonte Retenção legal do livro')).toBeTruthy();

    expect(
      within(queue).getByRole('link', { name: 'Ata selada por arquivar' }).getAttribute('href'),
    ).toBe('/acts/act-sealed');
    expect(
      within(queue).getByText(
        'A ata act-sealed está selada e ainda não foi arquivada. Arquive-a quando a evidência de preservação estiver pronta.',
      ),
    ).toBeTruthy();
    expect(within(queue).getByText('Fonte Estado das atas')).toBeTruthy();
  });

  it('shows the raw source of an alert a newer server introduces rather than nothing', async () => {
    // New sources land server-side over time; an unlabelled one must still name itself on the
    // Fonte line, so the panel degrades to the identifier instead of dropping the provenance.
    const dashboard: Dashboard = {
      ...baseDashboard,
      alerts: [
        {
          code: 'book.quantum.entangled',
          label: 'Advisory',
          severity: 'Info',
          category: 'BookLifecycle',
          message: 'Something a future release checks.',
          params: {},
          target: {
            entity_id: null,
            book_id: null,
            act_id: null,
            links: { entity: null, book: null, act: null, ledger: null },
          },
          source: 'quantum.entanglement',
          law_refs: [],
          action: null,
          recommended_next_steps: [],
          i18n: null,
        },
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    expect(within(queue).getByText('Fonte quantum.entanglement')).toBeTruthy();
  });

  it('renders backup recovery freshness alerts as bounded data-management advisories', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      alerts: [
        {
          code: 'backup.recovery.freshness_advisory',
          label: 'Advisory',
          severity: 'Warning',
          category: 'BackupRecoveryFreshness',
          message:
            'Raw backend backup message with backups/secret.zip and receipt secret-receipt-id.',
          params: {
            freshness_status: 'failed',
            policy_max_drill_age_days: '90',
            latest_receipt_at: '2026-07-10T10:40:00Z',
            latest_receipt_age_days: '4',
            latest_receipt_preflight_ready: 'false',
            latest_receipt_isolated_restore_verified: 'false',
          },
          target: {
            entity_id: null,
            book_id: null,
            act_id: null,
            links: { entity: null, book: null, act: null, ledger: null },
          },
          source: 'backup_recovery.freshness',
          law_refs: [],
          action: {
            kind: 'open_backup_recovery_policy',
            label_key: 'notifications.alert.backupRecoveryFreshness.action',
            api_href: null,
            route: '/settings?sec=dados',
          },
          recommended_next_steps: ['Review local recovery-drill freshness.'],
          i18n: {
            title_key: 'notifications.alert.backupRecoveryFreshness.title',
            body_key: 'notifications.alert.backupRecoveryFreshness.body',
            action_key: 'notifications.alert.backupRecoveryFreshness.action',
          },
        },
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    expect(
      within(queue)
        .getByRole('link', { name: 'Rever atualidade da recuperação de backups' })
        .getAttribute('href'),
    ).toBe('/settings?sec=dados');
    expect(
      within(queue).getByText(
        'O estado local do ensaio de recuperação está failed. Política: máximo 90 dias; último recibo 2026-07-10T10:40:00Z; idade 4 dias; pré-validação pronta false; verificação isolada false. É apenas um aviso local com recibos guardados.',
      ),
    ).toBeTruthy();
    expect(within(queue).getByText('Fonte Atualidade das cópias de segurança')).toBeTruthy();
    const rendered = queue.textContent ?? '';
    expect(rendered).not.toContain('backups/secret.zip');
    expect(rendered).not.toContain('secret-receipt-id');
    expect(rendered).not.toContain('/v1/backup/recovery-drills');
  });

  it('keeps complete verified law references visually normal', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      alerts: [
        {
          code: 'entity.no_open_book',
          label: 'Advisory',
          severity: 'Info',
          category: 'DataCompleteness',
          message: 'Raw backend open-book message.',
          params: { entity_name: 'Fonte Completa, Lda.' },
          target: {
            entity_id: 'entity-verified',
            book_id: null,
            act_id: null,
            links: { entity: '/v1/entities/entity-verified', book: null, act: null, ledger: null },
          },
          source: 'entities.open_books',
          law_refs: [
            {
              diploma_id: 'dl-76-a-2006',
              article: '1',
              label: 'Artigo 1',
              heading: '',
              verification: 'Verified',
              source_url: 'https://dre.example.test/source',
              source_complete: true,
              review_method: null,
              review_note: null,
            },
          ],
          action: {
            kind: 'open_entity',
            label_key: 'notifications.alert.entity.noOpenBook.action',
            api_href: '/v1/entities/entity-verified',
            route: '/entities/entity-verified',
          },
          recommended_next_steps: ['Review books.'],
          i18n: {
            title_key: 'notifications.alert.entity.noOpenBook.title',
            body_key: 'notifications.alert.entity.noOpenBook.body',
            action_key: 'notifications.alert.entity.noOpenBook.action',
          },
        },
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    expect(within(queue).getByText('Lei dl-76-a-2006:1')).toBeTruthy();
    expect(within(queue).queryByText(/fonte pendente/)).toBeNull();
  });

  it('deduplicates reminders and orders overdue before upcoming work while tolerating bad dates', async () => {
    const longName =
      'Sociedade com uma denominação excecionalmente longa para testar a quebra de linha sem alargar o painel, S.A.';
    const duplicateReminder = {
      due_date: '2026-04-01',
      severity: 'Advisory' as const,
      status: 'Overdue' as const,
      reason: 'Assembleia anual pendente para esta entidade.',
      entity_id: 'entity-overdue',
      entity_name: longName,
      source_rule: 'csc-art376-annual',
      source_profile: 'csc-commercial',
    };
    const dashboard: Dashboard = {
      ...baseDashboard,
      reminders: [
        {
          due_date: '2026-03-01',
          severity: 'Advisory',
          status: 'Upcoming',
          reason: 'Item planeado.',
          entity_id: 'entity-upcoming',
          entity_name: 'Próxima, Lda.',
          source_rule: 'csc-art376-annual',
          source_profile: 'csc-commercial',
        },
        duplicateReminder,
        { ...duplicateReminder },
        {
          due_date: 'not-a-date',
          severity: 'Advisory',
          status: 'Overdue',
          reason: 'Data inválida recebida do painel.',
          entity_id: 'entity-invalid',
          entity_name: 'Data Incerta, S.A.',
          source_rule: 'csc-art376-annual',
          source_profile: 'csc-commercial',
        },
        {
          due_date: '2026-02-01',
          severity: 'Advisory',
          status: 'DueSoon',
          reason: 'Item próximo.',
          entity_id: 'entity-due-soon',
          entity_name: 'Quase Vence, Lda.',
          source_rule: 'csc-art376-annual',
          source_profile: 'csc-commercial',
        },
        {
          due_date: '',
          severity: 'Advisory',
          status: 'Upcoming',
          reason: 'Data em falta recebida do painel.',
          entity_id: 'entity-missing',
          entity_name: 'Sem Data, Lda.',
          source_rule: 'csc-art376-annual',
          source_profile: 'csc-commercial',
        },
      ],
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    const items = within(queue).getAllByRole('listitem');
    expect(items).toHaveLength(5);
    expect(items.map((item) => within(item).getByRole('link').getAttribute('href'))).toEqual([
      '/entities/entity-overdue',
      '/entities/entity-invalid',
      '/entities/entity-due-soon',
      '/entities/entity-upcoming',
      '/entities/entity-missing',
    ]);
    expect(within(items[0]).getByText(longName, { exact: false })).toBeTruthy();
    expect(within(items[1]).getByText('Data inválida')).toBeTruthy();
    expect(within(items[4]).getByText('Sem data')).toBeTruthy();
  });

  it('adds integrity and compliance context without inventing unsafe detail links', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      unresolved_compliance: 2,
      failed_sync_jobs: 0,
      pending_backup_jobs: 0,
      ledger_valid: false,
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    const integrityLink = within(queue).getByRole('link', {
      name: 'Verificar cadeia do registo',
    });
    expect(integrityLink.getAttribute('href')).toBe('/archive');

    const complianceItem = within(queue).getByText('2 verificações pendentes').closest('li');
    expect(complianceItem).toBeTruthy();
    if (complianceItem) {
      expect(within(complianceItem).queryByRole('link')).toBeNull();
    }
  });

  it('degrades to the empty states when the payload omits current_work and the lists', async () => {
    // A response missing these collections must not take the whole route down with the error
    // boundary; every tab renders the same empty state as a tenant with no work.
    const partial = { ...baseDashboard } as Partial<Dashboard>;
    delete partial.current_work;
    delete partial.alerts;
    delete partial.reminders;
    delete partial.recent_events;

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: partial }]));
    renderDashboard();

    // Atividades atuais is the landing panel, so it is the one that renders first.
    expect(
      await screen.findByText('Sem livros abertos expostos pelos dados do painel.'),
    ).toBeTruthy();
    expect(screen.getByText('Sem atas ativas expostas pelos dados do painel.')).toBeTruthy();

    // Estatísticas: the activity number cards read zero rather than throwing.
    await openDashboardTab('Estatísticas');
    const activity = (await screen.findByText('Rascunhos e atas ativas')).closest('section');
    expect(within(activity!).getAllByText('0').length).toBeGreaterThan(0);

    await openDashboardTab('Últimos eventos');
    expect(await screen.findByText('Sem eventos')).toBeTruthy();
  });
});
