import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import type { Dashboard, DashboardAlert, DashboardReminder } from '../../api/types';
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

function actionableReminder(overrides: Partial<DashboardReminder> = {}): DashboardReminder {
  return {
    due_date: '2026-07-20',
    severity: 'Info',
    status: 'DueSoon',
    reason: 'Assembleia anual pendente',
    entity_id: 'entity-1',
    entity_name: 'Acme, S.A.',
    source_rule: 'csc-art376-annual',
    source_profile: 'commercial_company',
    ...overrides,
  };
}

function rect(overrides: Partial<DOMRect>): DOMRect {
  return {
    x: 0,
    y: 0,
    left: 0,
    top: 0,
    right: 0,
    bottom: 0,
    width: 0,
    height: 0,
    toJSON: () => ({}),
    ...overrides,
  } as DOMRect;
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

afterEach(() => {
  cleanup();
  window.localStorage.clear();
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

  it('renders popup notification controls as icon-only actions with tooltip labels', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([{ match: '/v1/dashboard', body: dashboard({ alerts: [actionableActAlert()] }) }]),
    );

    renderWithProviders(<NotificationBell />, ['/']);

    const bell = await screen.findByRole('button', { name: '1 notificações pendentes' });
    expectIconOnlyControl(bell, '1 notificações pendentes');

    fireEvent.click(bell);

    const dialog = await screen.findByRole('dialog', { name: 'Notificações' });
    const action = within(dialog).getByRole('link', { name: 'Rever ata' });
    const read = within(dialog).getByRole('button', { name: 'Marcar como lida' });
    const acknowledge = within(dialog).getByRole('button', { name: 'Reconhecer' });
    const dismiss = within(dialog).getByRole('button', { name: 'Dispensar' });

    expectIconOnlyControl(action, 'Rever ata');
    expectIconOnlyControl(read, 'Marcar como lida');
    expectIconOnlyControl(acknowledge, 'Reconhecer');
    expectIconOnlyControl(dismiss, 'Dispensar');
  });

  it('folds compact popup item tags into the title without separate row badges', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([
        {
          match: '/v1/dashboard',
          body: dashboard({ alerts: [actionableActAlert()], reminders: [actionableReminder()] }),
        },
      ]),
    );

    renderWithProviders(<NotificationBell />, ['/']);

    fireEvent.click(await screen.findByRole('button', { name: '2 notificações pendentes' }));

    const dialog = await screen.findByRole('dialog', { name: 'Notificações' });
    const items = Array.from(dialog.querySelectorAll('.notifications-list__item'));
    const alertItem = items.find((item) => item.textContent?.includes('Rever conformidade da ata'));
    const reminderItem = items.find((item) =>
      item.textContent?.includes('Assembleia geral anual pendente'),
    );

    expect(alertItem).toBeTruthy();
    expect(reminderItem).toBeTruthy();

    expect(
      within(alertItem as HTMLElement).getByText('Alerta', {
        selector: '.notifications-list__title-tag',
      }),
    ).toBeTruthy();
    expect(
      within(alertItem as HTMLElement).queryByText('Alerta', { selector: '.badge' }),
    ).toBeNull();

    expect(
      within(reminderItem as HTMLElement).getByText('Lembretes', {
        selector: '.notifications-list__title-tag',
      }),
    ).toBeTruthy();
    expect(
      within(reminderItem as HTMLElement).getByText('Próximo', {
        selector: '.notifications-list__title-tag',
      }),
    ).toBeTruthy();
    expect(
      within(reminderItem as HTMLElement).queryByText('Próximo', { selector: '.badge' }),
    ).toBeNull();
  });

  it('closes the popup when clicking outside the bell and popup', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard() }]));

    renderWithProviders(<NotificationBell />, ['/']);

    const bell = await screen.findByRole('button', { name: 'Notificações' });
    fireEvent.click(bell);

    expect(await screen.findByRole('dialog', { name: 'Notificações' })).toBeTruthy();

    fireEvent.pointerDown(document.body);

    await waitFor(() => {
      expect(screen.queryByRole('dialog', { name: 'Notificações' })).toBeNull();
    });
    expect(bell.getAttribute('aria-expanded')).toBe('false');
  });

  it('shows the pending count badge in the popup title row', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([{ match: '/v1/dashboard', body: dashboard({ alerts: [actionableActAlert()] }) }]),
    );

    renderWithProviders(<NotificationBell />, ['/']);

    fireEvent.click(await screen.findByRole('button', { name: '1 notificações pendentes' }));

    const dialog = await screen.findByRole('dialog', { name: 'Notificações' });
    const titleRow = dialog.querySelector('.panel__head') as HTMLElement;
    const badge = within(titleRow).getByText('1');

    expect(titleRow).toBeTruthy();
    expect(titleRow.contains(badge)).toBe(true);
    expect(badge.className).toContain('badge--accent');
  });

  it('marks an alert read through persisted triage and removes it from the bell count', async () => {
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
                status: 'read',
                durable: true,
                entry: {
                  notification_id: 'alert:act.compliance.review_required:-:-:act-1:0',
                  status: 'read',
                  updated_at: '2026-07-09T10:00:00Z',
                },
              }),
              { headers: { 'Content-Type': 'application/json' } },
            ),
          );
        }
        if (url.includes('/v1/notifications/triage')) {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                entries: [],
                durable: true,
                max_entries_per_owner: 500,
              }),
              { headers: { 'Content-Type': 'application/json' } },
            ),
          );
        }
        return Promise.reject(new Error(`no stub for ${url}`));
      }),
    );

    renderWithProviders(<NotificationBell />, ['/']);

    fireEvent.click(await screen.findByRole('button', { name: '1 notificações pendentes' }));

    const dialog = await screen.findByRole('dialog', { name: 'Notificações' });
    expect(within(dialog).getByRole('link', { name: 'Rever ata' })).toBeTruthy();

    fireEvent.click(within(dialog).getByRole('button', { name: 'Marcar como lida' }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Notificações' })).toBeTruthy();
      expect(within(dialog).getByText('Sem alertas ou lembretes pendentes.')).toBeTruthy();
    });
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

  it('uses durable browser triage when the backend triage endpoint is absent', async () => {
    window.localStorage.setItem(
      'chancela.notificationTriage.v1',
      JSON.stringify([
        {
          notification_id: 'alert:act.compliance.review_required:-:-:act-1:0',
          status: 'read',
          updated_at: '2026-07-09T10:00:00Z',
        },
      ]),
    );
    vi.stubGlobal(
      'fetch',
      fetchTable([{ match: '/v1/dashboard', body: dashboard({ alerts: [actionableActAlert()] }) }]),
    );

    renderWithProviders(<NotificationBell />, ['/']);

    expect(await screen.findByRole('button', { name: 'Notificações' })).toBeTruthy();
    expect(screen.queryByText('1')).toBeNull();
  });

  it('portals the popup layer to body so header/content ancestors cannot clip it', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard() }]));

    renderWithProviders(
      <div className="route-transition" style={{ overflow: 'hidden', transform: 'translateZ(0)' }}>
        <NotificationBell />
      </div>,
      ['/'],
    );

    fireEvent.click(await screen.findByRole('button', { name: 'Notificações' }));

    const dialog = await screen.findByRole('dialog', { name: 'Notificações' });
    const backdrop = document.body.querySelector('.notification-center__backdrop');
    const center = document.querySelector('.notification-center');
    const clippingAncestor = document.querySelector('.route-transition');

    expect(dialog.parentElement).toBe(document.body);
    expect(backdrop?.parentElement).toBe(document.body);
    expect(center?.contains(dialog)).toBe(false);
    expect(clippingAncestor?.contains(dialog)).toBe(false);
    expect(dialog.className).toContain('notification-center__popup');
  });

  it('positions the fixed popup from the bell viewport rect', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/dashboard', body: dashboard() }]));

    const originalWidth = window.innerWidth;
    const originalHeight = window.innerHeight;
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 1000 });
    Object.defineProperty(window, 'innerHeight', { configurable: true, value: 700 });

    try {
      renderWithProviders(<NotificationBell />, ['/']);

      const bell = await screen.findByRole('button', { name: 'Notificações' });
      const center = bell.closest('.notification-center') as HTMLElement;
      center.getBoundingClientRect = () =>
        rect({ left: 948, right: 980, top: 24, bottom: 56, width: 32, height: 32 });

      fireEvent.click(bell);

      const dialog = await screen.findByRole('dialog', { name: 'Notificações' });
      expect(dialog.style.left).toBe('596px');
      expect(dialog.style.top).toBe('64px');
      expect(dialog.style.maxHeight).toBe('624px');
    } finally {
      Object.defineProperty(window, 'innerWidth', { configurable: true, value: originalWidth });
      Object.defineProperty(window, 'innerHeight', { configurable: true, value: originalHeight });
    }
  });
});
