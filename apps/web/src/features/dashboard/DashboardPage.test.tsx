import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, within } from '@testing-library/react';
import { DashboardPage } from './DashboardPage';
import { fetchTable, renderWithProviders } from '../../test/utils';
import type { Dashboard, LedgerEventView } from '../../api/types';

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

function eventFor(seq: number): LedgerEventView {
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
  };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('DashboardPage', () => {
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
      recent_events: [4, 12, 1, 7, 3, 9, 11, 2, 6, 5, 10, 8].map(eventFor),
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderWithProviders(<DashboardPage />);

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
    renderWithProviders(<DashboardPage />);

    const archive = await screen.findByRole('link', { name: 'Ver arquivo completo' });
    expect(archive.getAttribute('href')).toBe('/arquivo');
    expect(archive.className).toContain('btn--iconOnly');
    expect(archive.querySelector('.icon')).toBeTruthy();

    fireEvent.focus(archive);
    const describedBy = archive.getAttribute('aria-describedby');
    expect(describedBy).toBeTruthy();
    expect(document.getElementById(describedBy as string)?.textContent).toBe(
      'Ver arquivo completo',
    );
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
      recent_events: [1].map(eventFor),
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderWithProviders(<DashboardPage />);

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    expect(within(queue).getByText('Atrasado')).toBeTruthy();
    expect(within(queue).getByRole('link', { name: 'Encosto Estratégico, S.A.' })).toBeTruthy();
    expect(within(queue).getByText('Data 2026-03-31')).toBeTruthy();
    expect(within(queue).getByText(/cannot yet prove this annual calendar purpose/)).toBeTruthy();
    expect(within(queue).getByText('Fonte csc-art376-annual / csc-commercial')).toBeTruthy();
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
      recent_events: [1].map(eventFor),
    };

    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard }]));
    renderWithProviders(<DashboardPage />);

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

  it('shows an empty work-queue state when dashboard data exposes no operator work', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: baseDashboard }]));
    renderWithProviders(<DashboardPage />);

    expect(await screen.findByText('Fila de trabalho')).toBeTruthy();
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
    renderWithProviders(<DashboardPage />);

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    expect(
      within(queue)
        .getByRole('link', { name: 'Definir remuneração da gerência' })
        .getAttribute('href'),
    ).toBe('/entidades/entity-1');
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
    renderWithProviders(<DashboardPage />);

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    expect(
      within(queue)
        .getByRole('link', { name: 'Definir remuneração dos administradores' })
        .getAttribute('href'),
    ).toBe('/entidades/entity-sa');
    expect(within(queue).getByText(/Atlântico Estratégico, S.A./)).toBeTruthy();
    expect(within(queue).getByText('Lei csc:399 · fonte pendente')).toBeTruthy();
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
    renderWithProviders(<DashboardPage />);

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
    renderWithProviders(<DashboardPage />);

    const queue = await screen.findByRole('list', { name: 'Fila de trabalho do painel' });
    const items = within(queue).getAllByRole('listitem');
    expect(items).toHaveLength(5);
    expect(items.map((item) => within(item).getByRole('link').textContent)).toEqual([
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
    renderWithProviders(<DashboardPage />);

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
