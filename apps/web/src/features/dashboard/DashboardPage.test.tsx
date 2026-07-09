import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, screen, within } from '@testing-library/react';
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

  it('shows an empty work-queue state when dashboard data exposes no operator work', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: baseDashboard }]));
    renderWithProviders(<DashboardPage />);

    expect(await screen.findByText('Fila de trabalho')).toBeTruthy();
    expect(screen.getByText('Sem trabalho pendente derivado do painel.')).toBeTruthy();
    expect(screen.queryByRole('list', { name: 'Fila de trabalho do painel' })).toBeNull();
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
