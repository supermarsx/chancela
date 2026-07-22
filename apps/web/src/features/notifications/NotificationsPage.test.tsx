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
    failed_sync_jobs: 0,
    pending_backup_jobs: 0,
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

    renderWithProviders(<NotificationsPage />, ['/notifications']);

    expectIconOnlyFilter('Todas');
    expectIconOnlyFilter('Alertas');
    expectIconOnlyFilter('Lembretes');
    expectIconOnlyFilter('Operações');
    expectIconOnlyFilter('Dispensadas');
    expectIconOnlyFilter('Reconhecidas');

    expect(await screen.findByText('Sem notificações derivadas do painel.')).toBeTruthy();
    expect(screen.queryByText('Rever conformidade da ata')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Dispensadas' }));

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
    expect(action.getAttribute('href')).toBe('/acts/act-1');
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

    renderWithProviders(<NotificationsPage />, ['/notifications']);

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

  it('gives every icon-only triage control a distinct glyph', async () => {
    // These controls carry no visible text, so a shared glyph makes two different acts
    // indistinguishable — which is exactly how "Marcar como lida" and "Reconhecer" once both
    // rendered a plain tick. Compare the drawn paths, not the names, so a future edit that
    // points two of them at the same icon fails here.
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/dashboard', body: dashboard({ alerts: [actionableActAlert()] }) },
        {
          match: '/v1/notifications/triage',
          body: { durable: true, max_entries_per_owner: 500, entries: [] },
        },
      ]),
    );

    renderWithProviders(<NotificationsPage />, ['/notifications']);
    expect(await screen.findByText('Rever conformidade da ata')).toBeTruthy();

    const read = await screen.findByRole('button', { name: 'Marcar como lida' });
    const acknowledge = screen.getByRole('button', { name: 'Reconhecer' });
    const dismiss = screen.getByRole('button', { name: 'Dispensar' });

    expect(read.getAttribute('data-triage-icon')).toBe('read');
    expect(acknowledge.getAttribute('data-triage-icon')).toBe('acknowledge');
    expect(dismiss.getAttribute('data-triage-icon')).toBe('dismiss');

    const geometry = (button: HTMLElement) =>
      [...button.querySelectorAll('path')].map((path) => path.getAttribute('d')).join('|');
    const drawn = [geometry(read), geometry(acknowledge), geometry(dismiss)];
    expect(drawn.every((d) => d.length > 0)).toBe(true);
    expect(new Set(drawn).size).toBe(drawn.length);
  });

  it('re-keys the panel wrapper on a sub-tab change without gating the content', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/dashboard', body: dashboard({ alerts: [actionableActAlert()] }) },
        {
          match: '/v1/notifications/triage',
          body: { durable: true, max_entries_per_owner: 500, entries: [] },
        },
      ]),
    );

    const { container } = renderWithProviders(<NotificationsPage />, ['/notifications']);
    await screen.findByText('Rever conformidade da ata');

    const before = container.querySelector('.route-transition');
    expect(before?.getAttribute('data-subanim-key')).toBe('all');

    fireEvent.click(screen.getByRole('button', { name: 'Alertas' }));

    const after = container.querySelector('.route-transition');
    // A fresh node under a new key ⇒ the CSS enter replays. Same class, so the same shared
    // motion (and the same reduced-motion / safe-mode collapse) governs it.
    expect(after).not.toBe(before);
    expect(after?.getAttribute('data-subanim-key')).toBe('alerts');
    expect(after?.classList.contains('route-transition')).toBe(true);

    // The point of the assertion: the incoming panel is in the DOM on the SAME synchronous
    // paint as the click — no `await`, no animation-end callback in between. The fade is
    // decoration riding on already-rendered content, never a gate in front of it.
    expect(screen.getByText('Rever conformidade da ata')).toBeTruthy();
    expect(after?.contains(screen.getByText('Rever conformidade da ata'))).toBe(true);
  });

  it('freezes a display snapshot in the PATCH body when a notification is dismissed', async () => {
    const patches: { url: string; body: unknown }[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = typeof input === 'string' ? input : input.toString();
        const method = init?.method ?? 'GET';
        if (url.includes('/v1/dashboard')) {
          return Promise.resolve(
            new Response(JSON.stringify(dashboard({ alerts: [actionableActAlert()] })), {
              headers: { 'Content-Type': 'application/json' },
            }),
          );
        }
        if (url.includes('/v1/notifications/triage') && method === 'PATCH') {
          patches.push({ url, body: init?.body ? JSON.parse(String(init.body)) : null });
          return Promise.resolve(
            new Response(JSON.stringify({ status: 'dismissed', durable: true, entry: null }), {
              headers: { 'Content-Type': 'application/json' },
            }),
          );
        }
        if (url.includes('/v1/notifications/triage')) {
          return Promise.resolve(
            new Response(
              JSON.stringify({ durable: true, max_entries_per_owner: 500, entries: [] }),
              { headers: { 'Content-Type': 'application/json' } },
            ),
          );
        }
        return Promise.reject(new Error(`no stub for ${url}`));
      }),
    );

    renderWithProviders(<NotificationsPage />, ['/notifications']);
    await screen.findByText('Rever conformidade da ata');

    fireEvent.click(screen.getByRole('button', { name: 'Dispensar' }));

    await waitFor(() => expect(patches).toHaveLength(1));
    const body = patches[0].body as {
      status: string;
      snapshot?: { title: string; kind: string; action?: { href: string } };
    };
    expect(body.status).toBe('dismissed');
    expect(body.snapshot?.title).toBe('Rever conformidade da ata');
    expect(body.snapshot?.kind).toBe('alert');
    expect(body.snapshot?.action?.href).toBe('/acts/act-1');
  });

  it('renders dismissed snapshots the dashboard no longer generates and filters them', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/dashboard', body: dashboard() },
        {
          match: '/v1/notifications/triage',
          body: {
            durable: true,
            max_entries_per_owner: 500,
            entries: [
              {
                notification_id: 'snapshot:lease',
                status: 'dismissed',
                updated_at: '2026-07-10T10:00:00Z',
                dismissed_at: '2026-07-10T10:00:00Z',
                snapshot: {
                  kind: 'operation',
                  tone: 'neutral',
                  badge: 'Operação',
                  title: 'Contrato de arrendamento',
                  detail: 'Detalhe do arrendamento',
                  action: { href: '/archive', label: 'Abrir' },
                },
              },
              {
                notification_id: 'snapshot:deadline',
                status: 'dismissed',
                updated_at: '2026-07-09T10:00:00Z',
                dismissed_at: '2026-07-09T10:00:00Z',
                snapshot: {
                  kind: 'alert',
                  tone: 'warn',
                  badge: 'Alerta',
                  title: 'Rever prazo pendente',
                  detail: 'Detalhe do prazo',
                },
              },
            ],
          },
        },
      ]),
    );

    renderWithProviders(<NotificationsPage />, ['/notifications']);
    // The dashboard generates nothing, so these rows exist ONLY because the snapshot persisted them.
    fireEvent.click(await screen.findByRole('button', { name: 'Dispensadas' }));

    expect(await screen.findByText('Contrato de arrendamento')).toBeTruthy();
    expect(screen.getByText('Rever prazo pendente')).toBeTruthy();
    expect(
      screen.getByText(
        'As notificações dispensadas são removidas automaticamente ao fim do período de retenção definido no servidor.',
      ),
    ).toBeTruthy();

    const search = screen.getByRole('searchbox', { name: 'Pesquisar' });
    fireEvent.change(search, { target: { value: 'arrendamento' } });

    expect(screen.getByText('Contrato de arrendamento')).toBeTruthy();
    expect(screen.queryByText('Rever prazo pendente')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Limpar filtros' }));
    expect(screen.getByText('Rever prazo pendente')).toBeTruthy();
  });

  it('separates acknowledged notifications into their own tab', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/dashboard', body: dashboard({ alerts: [actionableActAlert()] }) },
        {
          match: '/v1/notifications/triage',
          body: {
            durable: true,
            max_entries_per_owner: 500,
            entries: [
              {
                notification_id: 'alert:act.compliance.review_required:-:-:act-1:0',
                status: 'acknowledged',
                updated_at: '2026-07-10T10:00:00Z',
              },
            ],
          },
        },
      ]),
    );

    renderWithProviders(<NotificationsPage />, ['/notifications']);

    // Acknowledged is excluded from the active list…
    expect(await screen.findByText('Sem notificações derivadas do painel.')).toBeTruthy();
    // …absent from Descartadas…
    fireEvent.click(screen.getByRole('button', { name: 'Dispensadas' }));
    expect(await screen.findByText('Sem notificações dispensadas.')).toBeTruthy();
    // …and present under Reconhecidas.
    fireEvent.click(screen.getByRole('button', { name: 'Reconhecidas' }));
    expect(await screen.findByText('Rever conformidade da ata')).toBeTruthy();
  });
});
