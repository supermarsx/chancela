import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import type { Dashboard, DashboardAlert } from '../../api/types';
import { fetchTable, renderWithProviders } from '../../test/utils';
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
  expect(tooltip?.className).not.toContain('is-open');

  fireEvent.focus(control);
  expect(tooltip?.className).toContain('is-open');
  fireEvent.blur(control);
  expect(tooltip?.className).not.toContain('is-open');

  fireEvent.mouseEnter(control);
  expect(tooltip?.className).toContain('is-open');
  fireEvent.mouseLeave(control);
  expect(tooltip?.className).not.toContain('is-open');
}

function expectIconOnlyFilter(label: string) {
  const control = screen.getByRole('button', { name: label });
  expect(control.className).toContain('subnav__btn--iconOnly');
  expect(control.getAttribute('aria-label')).toBe(label);
  expect(control.textContent).not.toContain(label);

  const tooltipIds = (control.getAttribute('aria-describedby') ?? '').split(/\s+/).filter(Boolean);
  const tooltip = tooltipIds
    .map((id) => document.getElementById(id))
    .find((node) => node?.getAttribute('role') === 'tooltip' && node.textContent === label);

  expect(tooltip?.textContent).toBe(label);
  expect(tooltip?.className).not.toContain('is-open');

  fireEvent.focus(control);
  expect(tooltip?.className).toContain('is-open');
  fireEvent.blur(control);
  expect(tooltip?.className).not.toContain('is-open');

  fireEvent.mouseEnter(control);
  expect(tooltip?.className).toContain('is-open');
  fireEvent.mouseLeave(control);
  expect(tooltip?.className).not.toContain('is-open');
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
    const resolvedItem = screen
      .getByText('Rever conformidade da ata')
      .closest('.notifications-list__item') as HTMLElement;
    expect(screen.getByRole('list', { name: 'Notificações' }).className).toContain(
      'notifications-list--compact',
    );
    expect(
      within(resolvedItem).getByText('Alerta', { selector: '.notifications-list__title-tag' }),
    ).toBeTruthy();
    expect(
      within(resolvedItem).getByText('Dispensada', {
        selector: '.notifications-list__title-tag',
      }),
    ).toBeTruthy();
    expect(within(resolvedItem).queryByText('Alerta', { selector: '.badge' })).toBeNull();
    expect(within(resolvedItem).queryByText('Dispensada', { selector: '.badge' })).toBeNull();
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

  it('renders active notification page actions as icon-only controls with tooltip labels', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/dashboard', body: dashboard({ alerts: [actionableActAlert()] }) },
        {
          match: '/v1/notifications/triage',
          body: {
            durable: true,
            max_entries_per_owner: 500,
            entries: [],
          },
        },
      ]),
    );

    renderWithProviders(<NotificationsPage />, ['/notificacoes']);

    expect(await screen.findByText('Rever conformidade da ata')).toBeTruthy();
    const item = screen
      .getByText('Rever conformidade da ata')
      .closest('.notifications-list__item') as HTMLElement;

    expect(screen.getByRole('list', { name: 'Notificações' }).className).toContain(
      'notifications-list--compact',
    );
    expect(
      within(item).getByText('Alerta', { selector: '.notifications-list__title-tag' }),
    ).toBeTruthy();
    expect(within(item).queryByText('Alerta', { selector: '.badge' })).toBeNull();

    expectIconOnlyControl(screen.getByRole('link', { name: 'Rever ata' }), 'Rever ata');
    expectIconOnlyControl(
      screen.getByRole('button', { name: 'Marcar como lida' }),
      'Marcar como lida',
    );
    expectIconOnlyControl(screen.getByRole('button', { name: 'Reconhecer' }), 'Reconhecer');
    expectIconOnlyControl(screen.getByRole('button', { name: 'Dispensar' }), 'Dispensar');
  });
});
