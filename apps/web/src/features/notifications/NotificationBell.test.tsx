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
