import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import type { Dashboard, DashboardAlert } from '../../api/types';
import { fetchTable, renderWithProviders } from '../../test/utils';
import { NotificationBell } from './NotificationBell';

const targetLinks = {
  entity: null,
  book: null,
  act: null,
  ledger: null,
};

function dashboard(overrides: Partial<Dashboard> = {}): Dashboard {
  return {
    entities: 1,
    books_open: 0,
    books_total: 0,
    acts_total: 0,
    acts_draft: 0,
    acts_awaiting_signature: 0,
    acts_sealed: 0,
    unresolved_compliance: 0,
    ledger_length: 0,
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
    ...overrides,
  };
}

function actionableActAlert(overrides: Partial<DashboardAlert> = {}): DashboardAlert {
  return {
    code: 'act.compliance.review_required',
    label: 'ReviewRequired',
    category: 'ActCompliance',
    message: 'Ata em revisão.',
    params: { act_id: 'act-1' },
    target: {
      entity_id: null,
      book_id: null,
      act_id: 'act-1',
      links: { ...targetLinks, act: '/v1/acts/act-1' },
    },
    source: 'acts.compliance',
    ...overrides,
  };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('NotificationBell', () => {
  it('routes actionable alerts from the bell popup and closes after the action is chosen', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([{ match: '/v1/dashboard', body: dashboard({ alerts: [actionableActAlert()] }) }]),
    );

    renderWithProviders(<NotificationBell />, ['/']);

    const bell = await screen.findByRole('button', { name: '1 notificações pendentes' });
    expect(bell.getAttribute('aria-expanded')).toBe('false');

    fireEvent.click(bell);

    const dialog = await screen.findByRole('dialog', { name: 'Notificações' });
    const action = within(dialog).getByRole('link', { name: 'Rever ata' });
    expect(action.getAttribute('href')).toBe('/atas/act-1');

    fireEvent.click(action);

    await waitFor(() => {
      expect(screen.queryByRole('dialog', { name: 'Notificações' })).toBeNull();
    });
    expect(bell.getAttribute('aria-expanded')).toBe('false');
  });
});
