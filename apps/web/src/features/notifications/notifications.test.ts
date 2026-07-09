import { describe, expect, it } from 'vitest';
import type {
  Dashboard,
  DashboardAlert,
  DashboardReminder,
  LedgerEventView,
} from '../../api/types';
import { t } from '../../i18n';
import { buildDashboardNotifications, popupNotifications } from './notifications';

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

function alert(overrides: Partial<DashboardAlert>): DashboardAlert {
  return {
    code: 'registry.provenance.expiring_soon',
    label: 'Advisory',
    category: 'RegistryProvenance',
    message: 'Backend fallback text that should not be shown for known alerts.',
    params: {
      entity_id: 'entity-1',
      valid_until: '2026-08-01',
      days_until: '23',
    },
    target: {
      entity_id: 'entity-1',
      book_id: null,
      act_id: null,
      links: { ...targetLinks, entity: '/v1/entities/entity-1' },
    },
    source: 'registry_extracts.provenance.valid_until',
    ...overrides,
  };
}

function reminder(overrides: Partial<DashboardReminder> = {}): DashboardReminder {
  return {
    due_date: '2026-03-31',
    severity: 'Advisory',
    status: 'DueSoon',
    reason: 'Assembleia anual pendente',
    entity_id: 'entity-1',
    entity_name: 'Acme, S.A.',
    source_rule: 'csc-art376-annual',
    source_profile: 'commercial_company',
    ...overrides,
  };
}

function event(overrides: Partial<LedgerEventView> = {}): LedgerEventView {
  return {
    id: 'event-1',
    seq: 1,
    actor: 'operator',
    justification: null,
    timestamp: '2026-07-09T10:00:00Z',
    scope: 'global',
    kind: 'entity.created',
    payload_digest: '00',
    prev_hash: '00',
    hash: '11',
    chains: ['global'],
    attestation: null,
    ...overrides,
  };
}

describe('buildDashboardNotifications', () => {
  it('renders known dashboard alerts with translated copy and target actions', () => {
    const items = buildDashboardNotifications(dashboard({ alerts: [alert({})] }), t);

    expect(items[0]).toMatchObject({
      kind: 'alert',
      action: { href: '/entidades/entity-1', label: 'Abrir entidade' },
    });
    expect(items[0]?.title).toContain('perto do fim');
    expect(items[0]?.detail).toContain('2026-08-01');
    expect(items[0]?.detail).not.toContain('Backend fallback text');
  });

  it('uses the backend message only as an unknown-alert fallback and still provides an action', () => {
    const items = buildDashboardNotifications(
      dashboard({
        alerts: [
          alert({
            code: 'unknown.alert.code',
            message: 'Detalhe tecnico do backend.',
            params: {},
            target: {
              entity_id: null,
              book_id: null,
              act_id: 'act-1',
              links: { ...targetLinks, act: '/v1/acts/act-1' },
            },
            source: null,
          }),
        ],
      }),
      t,
    );

    expect(items[0]?.title).toBe('Alerta do painel (unknown.alert.code)');
    expect(items[0]?.detail).toContain('Detalhe tecnico do backend.');
    expect(items[0]?.action).toEqual({ href: '/atas/act-1', label: 'Abrir ata' });
  });

  it('does not duplicate the ledger-integrity fallback when the structured alert is present', () => {
    const items = buildDashboardNotifications(
      dashboard({
        ledger_valid: false,
        alerts: [
          alert({
            code: 'ledger.integrity.review_required',
            label: 'ReviewRequired',
            params: {},
            target: {
              entity_id: null,
              book_id: null,
              act_id: null,
              links: { ...targetLinks, ledger: '/v1/ledger/integrity' },
            },
          }),
        ],
      }),
      t,
    );

    expect(
      items.filter((item) => item.id.includes('ledger.integrity.review_required')),
    ).toHaveLength(1);
    expect(items[0]?.action).toEqual({ href: '/arquivo', label: 'Abrir arquivo' });
  });

  it('prioritizes actionable alerts and reminders in the popup over recent operations', () => {
    const items = buildDashboardNotifications(
      dashboard({
        reminders: [reminder()],
        recent_events: [event({ id: 'event-2', seq: 2 })],
      }),
      t,
    );
    const popup = popupNotifications(items, 1);

    expect(popup).toHaveLength(1);
    expect(popup[0]?.kind).toBe('reminder');
    expect(popup[0]?.action).toEqual({ href: '/entidades/entity-1', label: 'Abrir entidade' });
  });
});
