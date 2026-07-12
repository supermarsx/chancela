import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, within } from '@testing-library/react';
import { DashboardPage } from './DashboardPage';
import { fetchTable, renderWithProviders } from '../../test/utils';
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
      'Estatísticas',
      'Atividade recente',
      'Atividades atuais',
      'Datas',
      'Fila de trabalho',
      'Últimos eventos',
    ]);
    expect(
      within(tabs).getByRole('button', { name: 'Estatísticas' }).getAttribute('aria-pressed'),
    ).toBe('true');
  });

  it('marks the six main stats cards as a compact desktop metrics row', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: baseDashboard }]));
    renderDashboard();

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
    expectIconOnlyActionLink(archive, 'Ver arquivo completo', '/arquivo');
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
    expect(items.map((item) => within(item).getByText(/^Evento /).textContent)).toEqual([
      'Evento book.exported',
      'Evento entity.statute_updated',
      'Evento act.sealed',
      'Evento book.legal_hold_set',
      'Evento entity.registry_imported',
      'Evento act.advanced',
      'Evento book.closed',
      'Evento entity.updated',
      'Evento act.drafted',
      'Evento book.opened',
    ]);
    expect(within(items[0]).getByRole('link').getAttribute('href')).toBe('/livros/book-12');
    expect(within(items[2]).getByRole('link').getAttribute('href')).toBe('/atas/act-10');
    expect(screen.queryByText('Evento entity.created')).toBeNull();
    expect(screen.queryByText('Evento settings.updated')).toBeNull();
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
    ).toBe('/livros/book-1');
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
            'The commercial-company calendar preset "Assembleia geral anual (CSC art. 376.º)" points to an annual item by 2026-03-31 (using the default Dec 31 fiscal-year end because no fiscal_year_end is recorded). No sealed or archived Assembleia Geral act dated 2026 is recorded for this entity. Chancela cannot yet prove this annual calendar purpose, so this is advisory.',
          entity_id: 'entity-1',
          entity_name: 'Encosto Estratégico, S.A.',
          source_rule: 'csc-art376-annual',
          source_profile: 'csc-commercial',
        },
      ],
      recent_events: [1].map((seq) => eventFor(seq)),
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    expect(within(queue).getByText('Atrasado')).toBeTruthy();
    expect(within(queue).getByRole('link', { name: 'Encosto Estratégico, S.A.' })).toBeTruthy();
    expect(within(queue).getByText('Data 2026-03-31')).toBeTruthy();
    expect(within(queue).getByText(/cannot yet prove this annual calendar purpose/)).toBeTruthy();
    expect(within(queue).getByText('Fonte csc-art376-annual / csc-commercial')).toBeTruthy();
    await openDashboardTab('Últimos eventos');
    expect(await screen.findByText('kind-1')).toBeTruthy();
    expect(screen.getAllByRole('row')).toHaveLength(2);
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
    expect(link.getAttribute('href')).toBe('/atas/act-1');
    expect(
      within(item).getByText(
        'Acme, S.A. - Ata de aprovação de contas: Confirmar envio depois da assinatura externa.',
      ),
    ).toBeTruthy();
    expect(within(item).queryByText('Raw backend follow-up fallback.')).toBeNull();
    expect(within(item).getByText('Data 2026-07-01')).toBeTruthy();
    expect(within(item).getByText('Fonte act-follow-up / follow-up:fu-1')).toBeTruthy();
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
            route: '/atas/act-1',
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
    expect(link.getAttribute('href')).toBe('/atas/act-1');
    expect(
      within(item).getByText(
        'Ata de aprovação de contas de Acme, S.A. está marcada para 2026-07-20 e ainda não tem registo de presenças suficiente. Registe a referência de presenças e os totais ou participantes estruturados antes de a avançar.',
      ),
    ).toBeTruthy();
    expect(within(item).queryByText('Raw backend attendance fallback.')).toBeNull();
    expect(within(item).getByText('Data 2026-07-20')).toBeTruthy();
    expect(within(item).getByText('Fonte act-attendance-missing / csc-commercial')).toBeTruthy();
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
            route: '/atas/act-absent-1',
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
      '/atas/act-absent-1?generated_document_id=generated-absent-1&focus=dispatch-evidence#generated-dispatch-evidence',
    );
    expect(within(item).getByText('Pendente')).toBeTruthy();
    expect(
      within(item).getByText(
        'Ata da assembleia de condóminos tem comunicação a condóminos ausentes gerada, mas a evidência de expedição está operator_evidence_partial. Destinatários em falta: Fração C. O lembrete é apenas consultivo.',
      ),
    ).toBeTruthy();
    expect(within(item).queryByText('Raw backend dispatch fallback.')).toBeNull();
    expect(within(item).getByText('Sem data')).toBeTruthy();
    expect(
      within(item).getByText(
        'Fonte absent-owner-dispatch-evidence / condominium-generated-communication',
      ),
    ).toBeTruthy();
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
            },
          ],
          action: {
            kind: 'open_entity',
            label_key: 'notifications.alert.entity.managerRemuneration.action',
            api_href: '/v1/entities/entity-1',
            route: '/entidades/entity-1',
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
      '/entidades/entity-1',
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
            },
          ],
          action: {
            kind: 'open_entity',
            label_key: 'notifications.alert.entity.administratorRemuneration.action',
            api_href: '/v1/entities/entity-sa',
            route: '/entidades/entity-sa',
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
    ).toBe('/entidades/entity-sa');
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
            route: '/livros/book-held',
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
            route: '/atas/act-sealed',
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
    ).toBe('/livros/book-held');
    expect(
      within(queue).getByText(
        'O livro book-held tem retenção legal ativa: litígio pendente. Reveja a retenção antes de decisões de descarte de arquivo.',
      ),
    ).toBeTruthy();
    expect(within(queue).getByText('Fonte books.legal_hold')).toBeTruthy();

    expect(
      within(queue).getByRole('link', { name: 'Ata selada por arquivar' }).getAttribute('href'),
    ).toBe('/atas/act-sealed');
    expect(
      within(queue).getByText(
        'A ata act-sealed está selada e ainda não foi arquivada. Arquive-a quando a evidência de preservação estiver pronta.',
      ),
    ).toBeTruthy();
    expect(within(queue).getByText('Fonte acts.state')).toBeTruthy();
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
            },
          ],
          action: {
            kind: 'open_entity',
            label_key: 'notifications.alert.entity.noOpenBook.action',
            api_href: '/v1/entities/entity-verified',
            route: '/entidades/entity-verified',
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
    expect(items.map((item) => within(item).getByRole('link').getAttribute('aria-label'))).toEqual([
      longName,
      'Data Incerta, S.A.',
      'Quase Vence, Lda.',
      'Próxima, Lda.',
      'Sem Data, Lda.',
    ]);
    expect(within(items[1]).getByText('Data inválida')).toBeTruthy();
    expect(within(items[4]).getByText('Sem data')).toBeTruthy();
  });

  it('adds integrity and compliance context without inventing unsafe detail links', async () => {
    const dashboard: Dashboard = {
      ...baseDashboard,
      unresolved_compliance: 2,
      ledger_valid: false,
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderDashboard();
    await openDashboardTab('Fila de trabalho');

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    const integrityLink = within(queue).getByRole('link', {
      name: 'Verificar cadeia do registo',
    });
    expect(integrityLink.getAttribute('href')).toBe('/arquivo');

    const complianceItem = within(queue).getByText('2 verificações pendentes').closest('li');
    expect(complianceItem).toBeTruthy();
    if (complianceItem) {
      expect(within(complianceItem).queryByRole('link')).toBeNull();
    }
  });
});
