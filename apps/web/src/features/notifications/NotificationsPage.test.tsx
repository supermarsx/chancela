import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import type { Dashboard, DashboardAlert } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { NotificationsPage } from './NotificationsPage';

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

function expectIconOnlyControl(control: HTMLElement, label: string) {
  expect(control.className).toContain('btn--iconOnly');
  expect(control.getAttribute('aria-label')).toBe(label);
  expect(control.textContent).not.toContain(label);

  const tooltipIds = (control.getAttribute('aria-describedby') ?? '').split(/\s+/).filter(Boolean);
  const tooltip = tooltipIds
    .map((id) => document.getElementById(id))
    .find((node) => node?.getAttribute('role') === 'tooltip' && node.textContent === label);

  expect(tooltip?.textContent).toBe(label);
}

function expectIconOnlyFilter(label: string) {
  const control = screen.getByRole('button', { name: label });
  expect(control.className).toContain('subnav__btn--iconOnly');
  expect(control.getAttribute('aria-label')).toBe(label);
  expect(control.textContent).not.toContain(label);
}

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  vi.restoreAllMocks();
});

describe('NotificationsPage', () => {
  it('keeps dismissed notifications out of active filters while preserving resolved actions', async () => {
    const requests: { url: string; method: string }[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = typeof input === 'string' ? input : input.toString();
        const method = init?.method ?? 'GET';
        requests.push({ url, method });
        if (url.includes('/v1/dashboard')) {
          return Promise.resolve(
            new Response(JSON.stringify(dashboard({ alerts: [actionableActAlert()] })), {
              headers: { 'Content-Type': 'application/json' },
            }),
          );
        }
        if (url.includes('/v1/notifications/triage') && method === 'PATCH') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                status: 'unread',
                durable: true,
                entry: null,
              }),
              { headers: { 'Content-Type': 'application/json' } },
            ),
          );
        }
        if (url.includes('/v1/notifications/triage')) {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                durable: true,
                max_entries_per_owner: 500,
                entries: [
                  {
                    notification_id: 'alert:act.compliance.review_required:-:-:act-1:0',
                    status: 'dismissed',
                    updated_at: '2026-07-09T10:00:00Z',
                  },
                ],
              }),
              { headers: { 'Content-Type': 'application/json' } },
            ),
          );
        }
        return Promise.reject(new Error(`no stub for ${url}`));
      }),
    );

    renderWithProviders(<NotificationsPage />, ['/notificacoes']);

    expectIconOnlyFilter('Todas');
    expectIconOnlyFilter('Alertas');
    expectIconOnlyFilter('Lembretes');
    expectIconOnlyFilter('Operações');
    expectIconOnlyFilter('Resolvidas');

    expect(await screen.findByText('Sem notificações derivadas do painel.')).toBeTruthy();
    expect(screen.queryByText('Rever conformidade da ata')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Resolvidas' }));

    expect(await screen.findByText('Rever conformidade da ata')).toBeTruthy();
    expect(screen.getByText('Dispensada')).toBeTruthy();
    const action = screen.getByRole('link', { name: 'Rever ata' });
    const restore = screen.getByRole('button', { name: 'Reabrir' });
    expect(action.getAttribute('href')).toBe('/atas/act-1');
    expectIconOnlyControl(action, 'Rever ata');
    expectIconOnlyControl(restore, 'Reabrir');

    fireEvent.click(restore);

    await waitFor(() => {
      expect(
        requests.some(
          (request) =>
            request.method === 'PATCH' &&
            request.url.includes(
              '/v1/notifications/triage/alert%3Aact.compliance.review_required%3A-%3A-%3Aact-1%3A0',
            ),
        ),
      ).toBe(true);
    });

    fireEvent.click(screen.getByRole('button', { name: 'Todas' }));
    expect(await screen.findByText('Rever conformidade da ata')).toBeTruthy();
  });
});
