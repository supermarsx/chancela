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

  it('renders backup recovery freshness advisories as local bounded alerts', () => {
    const items = buildDashboardNotifications(
      dashboard({
        alerts: [
          alert({
            code: 'backup.recovery.freshness_advisory',
            message:
              'Raw backend message with forbidden backup path backups/secret.zip and receipt secret-receipt-id.',
            params: {
              freshness_status: 'stale',
              policy_max_drill_age_days: '90',
              latest_receipt_at: '2026-03-01T10:00:00Z',
              latest_receipt_age_days: '135',
              latest_receipt_preflight_ready: 'true',
              latest_receipt_isolated_restore_verified: 'true',
            },
            target: {
              entity_id: null,
              book_id: null,
              act_id: null,
              links: { ...targetLinks },
            },
            action: {
              kind: 'open_backup_recovery_policy',
              label_key: 'notifications.alert.backupRecoveryFreshness.action',
              api_href: null,
              route: '/configuracoes?sec=dados',
            },
            i18n: {
              title_key: 'notifications.alert.backupRecoveryFreshness.title',
              body_key: 'notifications.alert.backupRecoveryFreshness.body',
              action_key: 'notifications.alert.backupRecoveryFreshness.action',
            },
            source: 'backup_recovery.freshness',
          }),
        ],
      }),
      t,
    );

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      kind: 'alert',
      title: 'Rever atualidade da recuperação de backups',
      action: { href: '/configuracoes?sec=dados', label: 'Abrir gestão de dados' },
    });
    expect(items[0]?.detail).toContain('stale');
    expect(items[0]?.detail).toContain('90 dias');
    expect(items[0]?.detail).toContain('2026-03-01T10:00:00Z');
    expect(items[0]?.detail).toContain('135 dias');
    expect(items[0]?.detail).toContain('true');
    expect(items[0]?.detail).toContain('aviso local');
    expect(items[0]?.detail).not.toContain('backups/secret.zip');
    expect(items[0]?.detail).not.toContain('secret-receipt-id');
    expect(items[0]?.action?.href).not.toContain('/backup/recovery-drills');
  });

  it('renders lifecycle dashboard alerts as localized actionable items', () => {
    const items = buildDashboardNotifications(
      dashboard({
        alerts: [
          alert({
            code: 'entity.book.no_open_book',
            message: 'Raw backend no-book message.',
            params: { entity_name: 'Acme, S.A.' },
            target: {
              entity_id: 'entity-1',
              book_id: null,
              act_id: null,
              links: { ...targetLinks, entity: '/v1/entities/entity-1' },
            },
            source: 'dashboard.lifecycle.entity_books',
          }),
          alert({
            code: 'entity.manager_remuneration.setup_recommended',
            message: 'Raw backend remuneration message.',
            params: { entity_name: 'Acme, Lda.' },
            target: {
              entity_id: 'entity-2',
              book_id: null,
              act_id: null,
              links: { ...targetLinks, entity: '/v1/entities/entity-2' },
            },
            action: {
              kind: 'open_entity',
              label_key: 'notifications.alert.entity.managerRemuneration.action',
              api_href: '/v1/entities/entity-2',
              route: '/entidades/entity-2',
            },
            law_refs: [
              {
                diploma_id: 'csc',
                article: '255',
                label: 'Artigo 255.º',
                heading: 'Remuneração dos gerentes',
                verification: 'Pending',
                source_url: null,
                source_complete: false,
                review_method: null,
                review_note: null,
              },
            ],
            source: 'registry_extracts.orgaos',
          }),
          alert({
            code: 'book.termo_abertura.missing_metadata',
            message: 'Raw backend missing-term message.',
            params: { book_id: 'book-1', missing_fields: 'hash inicial' },
            target: {
              entity_id: 'entity-1',
              book_id: 'book-1',
              act_id: null,
              links: { ...targetLinks, book: '/v1/books/book-1' },
            },
            source: 'dashboard.lifecycle.books',
          }),
          alert({
            code: 'book.acts.none_recorded',
            message: 'Raw backend no-acts message.',
            params: { book_id: 'book-1', next_ata_number: '2' },
            target: {
              entity_id: 'entity-1',
              book_id: 'book-1',
              act_id: null,
              links: { ...targetLinks, book: '/v1/books/book-1' },
            },
            source: 'dashboard.lifecycle.books',
          }),
          alert({
            code: 'act.lifecycle.advance_available',
            message: 'Raw backend advance message.',
            params: { current_state: 'Draft', next_state: 'Review' },
            target: {
              entity_id: 'entity-1',
              book_id: 'book-1',
              act_id: 'act-1',
              links: { ...targetLinks, act: '/v1/acts/act-1' },
            },
            source: 'dashboard.lifecycle.acts',
          }),
          alert({
            code: 'act.lifecycle.signing_ready',
            message: 'Raw backend signing message.',
            params: { rule_pack: 'PT-CSC' },
            target: {
              entity_id: 'entity-1',
              book_id: 'book-1',
              act_id: 'act-1',
              links: { ...targetLinks, act: '/v1/acts/act-1' },
            },
            source: 'dashboard.lifecycle.acts',
          }),
        ],
      }),
      t,
    );

    expect(items).toHaveLength(6);
    expect(items.map((item) => item.detail).join('\n')).not.toContain('Raw backend');

    const byId = new Map(items.map((item) => [item.id, item]));
    expect(byId.get('alert:entity.book.no_open_book:entity-1:-:-:0')).toMatchObject({
      title: 'Sem livro aberto registado',
      action: { href: '/entidades/entity-1', label: 'Abrir entidade' },
    });
    expect(
      byId.get('alert:entity.manager_remuneration.setup_recommended:entity-2:-:-:1'),
    ).toMatchObject({
      title: 'Definir remuneração da gerência',
      action: { href: '/entidades/entity-2', label: 'Abrir entidade' },
    });
    expect(
      byId.get('alert:book.termo_abertura.missing_metadata:entity-1:book-1:-:2'),
    ).toMatchObject({
      title: 'Rever termo de abertura',
      action: { href: '/livros/book-1', label: 'Abrir livro' },
    });
    expect(
      byId.get('alert:book.termo_abertura.missing_metadata:entity-1:book-1:-:2')?.detail,
    ).toContain('hash inicial');
    expect(byId.get('alert:book.acts.none_recorded:entity-1:book-1:-:3')).toMatchObject({
      title: 'Livro sem atas registadas',
      detail:
        'O livro aberto ainda não tem atas. Crie a ata n.º 2 ou importe atas históricas quando aplicável.',
      action: { href: '/livros/book-1', label: 'Abrir livro' },
    });
    expect(byId.get('alert:act.lifecycle.advance_available:entity-1:book-1:act-1:4')).toMatchObject(
      {
        title: 'Próximo passo da ata disponível',
        detail:
          'A ata está em Draft. Avance para Review quando o trabalho de suporte estiver pronto.',
        action: { href: '/atas/act-1', label: 'Abrir ata' },
      },
    );
    expect(byId.get('alert:act.lifecycle.signing_ready:entity-1:book-1:act-1:5')).toMatchObject({
      title: 'Ata pronta para assinaturas',
      detail:
        'A ata está em assinatura e não tem erros de conformidade em PT-CSC. Recolha ou importe as assinaturas necessárias.',
      action: { href: '/atas/act-1', label: 'Abrir ata' },
    });
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

  it('falls through unsafe links and blank higher-priority ids to the next valid alert target', () => {
    const items = buildDashboardNotifications(
      dashboard({
        alerts: [
          alert({
            code: 'unknown.alert.code',
            message: 'Alerta sem tradução.',
            params: {},
            target: {
              entity_id: 'entity-1',
              book_id: ' book-1 ',
              act_id: '   ',
              links: {
                ...targetLinks,
                act: 'javascript:alert("act")',
                entity: '/v1/entities/entity-1',
              },
            },
            source: null,
          }),
        ],
      }),
      t,
    );

    expect(items[0]?.action).toEqual({ href: '/livros/book-1', label: 'Abrir livro' });
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

  it('renders act follow-up reminders with localized compact copy and act action metadata', () => {
    const items = buildDashboardNotifications(
      dashboard({
        reminders: [
          reminder({
            due_date: '2026-07-01',
            status: 'Overdue',
            severity: 'Warning',
            reason: 'Raw backend follow-up fallback.',
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
          }),
        ],
      }),
      t,
    );

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      kind: 'reminder',
      tone: 'warn',
      badge: 'Atrasado',
      title: 'Enviar certidão ao contabilista',
      detail:
        'Acme, S.A. - Ata de aprovação de contas: Confirmar envio depois da assinatura externa.',
      action: { href: '/atas/act-1', label: 'Abrir ata' },
    });
    expect(items[0]?.detail).not.toContain('Raw backend');
  });

  it('renders missing-attendance reminders with source-rule copy and act action metadata', () => {
    const items = buildDashboardNotifications(
      dashboard({
        reminders: [
          reminder({
            due_date: '2026-07-20',
            status: 'DueSoon',
            severity: 'Info',
            reason: 'Raw backend attendance fallback.',
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
              route: null,
            },
          }),
        ],
      }),
      t,
    );

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      kind: 'reminder',
      tone: 'accent',
      badge: 'Próximo',
      title: 'Registar presenças: Ata de aprovação de contas',
      detail:
        'Ata de aprovação de contas de Acme, S.A. está marcada para 2026-07-20 e ainda não tem registo de presenças suficiente. Registe a referência de presenças e os totais ou participantes estruturados antes de a avançar.',
      action: { href: '/atas/act-1', label: 'Registar presenças' },
    });
    expect(items[0]?.detail).not.toContain('Raw backend');
    expect(items[0]?.detail).not.toContain('attendance_reference');
  });

  it('renders convocation-notice reminders as local advisory act work', () => {
    const items = buildDashboardNotifications(
      dashboard({
        reminders: [
          reminder({
            due_date: '2026-03-20',
            status: 'DueSoon',
            severity: 'Warning',
            reason: 'Raw backend convocation notice fallback.',
            source_rule: 'act-convening-notice',
            source_profile: 'csc-commercial',
            params: {
              act_id: 'act-notice-1',
              act_title: 'Ata de aprovação de contas',
              book_id: 'book-1',
              entity_id: 'entity-1',
              entity_name: 'Acme, S.A.',
              required_notice_days: '10',
              meeting_date: '2026-03-30',
              notice_due_date: '2026-03-20',
              dispatch_date: '',
              antecedence_days: '',
              evidence_status: 'missing_or_unverifiable_dispatch_evidence',
              local_advisory_only: 'true',
              legal_sufficiency_claimed: 'false',
              external_delivery_claimed: 'false',
              workflow_completion_claimed: 'false',
            },
            action: {
              kind: 'open_act_convening_notice',
              label_key: 'notifications.reminder.act.conveningNotice.action',
              api_href: '/v1/acts/act-notice-1',
              route: null,
            },
          }),
        ],
      }),
      t,
    );

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      kind: 'reminder',
      tone: 'accent',
      badge: 'Próximo',
      title: 'Rever convocatória: Ata de aprovação de contas',
      detail:
        'Os estatutos registam 10 dias de antecedência para Ata de aprovação de contas de Acme, S.A. com reunião marcada para 2026-03-30; a data local de aviso é 2026-03-20. A evidência de expedição registada não demonstra essa antecedência. Aviso consultivo local; não afirma suficiência legal, entrega externa ou conclusão do workflow.',
      action: { href: '/atas/act-notice-1', label: 'Rever convocatória' },
    });
    expect(items[0]?.detail).not.toContain('Raw backend');
    expect(items[0]?.detail).toContain('Aviso consultivo local');
  });

  it('renders convocation-notice reminders without meeting dates as non-computed advisory act work', () => {
    const items = buildDashboardNotifications(
      dashboard({
        reminders: [
          reminder({
            due_date: '',
            status: 'Pending',
            severity: 'Warning',
            reason: 'Raw backend convocation notice fallback.',
            source_rule: 'act-convening-notice',
            source_profile: 'csc-commercial',
            params: {
              act_id: 'act-notice-1',
              act_title: 'Ata de aprovação de contas',
              book_id: 'book-1',
              entity_id: 'entity-1',
              entity_name: 'Acme, S.A.',
              required_notice_days: '10',
              meeting_date: '',
              notice_due_date: '',
              dispatch_date: '',
              antecedence_days: '',
              evidence_status: 'missing_meeting_date',
              notice_due_date_computable: 'false',
              local_deadline_computed: 'false',
              local_advisory_only: 'true',
              legal_sufficiency_claimed: 'false',
              legal_deadline_computation_claimed: 'false',
              external_delivery_claimed: 'false',
              workflow_completion_claimed: 'false',
              registry_acceptance_claimed: 'false',
              dre_acceptance_claimed: 'false',
              provider_acceptance_claimed: 'false',
            },
            action: {
              kind: 'open_act_convening_notice',
              label_key: 'notifications.reminder.act.conveningNotice.action',
              api_href: '/v1/acts/act-notice-1',
              route: null,
            },
          }),
        ],
      }),
      t,
    );

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      kind: 'reminder',
      tone: 'neutral',
      badge: 'Pendente',
      title: 'Rever convocatória: Ata de aprovação de contas',
      detail:
        'Os metadados estatutários locais registam 10 dias de antecedência para Ata de aprovação de contas de Acme, S.A., mas a data da reunião ainda não está registada. A data local de aviso não pode ser calculada até a data da reunião ser registada. Registe a data da reunião e reveja a evidência de expedição. Aviso consultivo local; não afirma suficiência legal, cálculo de prazo legal, entrega externa, conclusão do workflow nem aceitação por registo, DRE ou fornecedor.',
      meta: ['Sem data', 'Fonte act-convening-notice / csc-commercial'],
      action: { href: '/atas/act-notice-1', label: 'Rever convocatória' },
    });
    expect(items[0]?.detail).not.toContain('Raw backend');
    expect(items[0]?.detail).not.toContain('data local de aviso é');
    expect(items[0]?.detail).not.toContain('2026-03-20');
    expect(items[0]?.detail).toContain('não pode ser calculada');
  });

  it('renders condominium annual reminders with localized advisory copy and entity action', () => {
    const items = buildDashboardNotifications(
      dashboard({
        reminders: [
          reminder({
            due_date: '2026-01-15',
            status: 'DueSoon',
            severity: 'Advisory',
            reason: 'Raw backend condominium fallback.',
            entity_id: 'condo-1',
            entity_name: 'Condomínio Horizonte',
            source_rule: 'condominio-annual',
            source_profile: 'condominio-dl268',
            params: {
              preset_id: 'condominio-annual',
              calendar_preset_support: 'supported',
              local_due_date_rule_configured: 'true',
              local_due_date_calculated: 'true',
              legal_deadline_calculated: 'false',
              annual_fixed_month: '1',
              annual_fixed_day: '15',
              due_year: '2026',
              due_basis: 'annual_fixed_date',
            },
            action: {
              kind: 'open_entity',
              label_key: 'notifications.reminder.annual.action',
              api_href: '/v1/entities/condo-1',
              route: '/entidades/condo-1',
            },
          }),
        ],
      }),
      t,
    );

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      kind: 'reminder',
      tone: 'accent',
      badge: 'Próximo',
      title: 'Assembleia anual de condomínio pendente',
      action: { href: '/entidades/condo-1', label: 'Abrir entidade' },
    });
    expect(items[0]?.title).not.toBe('Condomínio Horizonte');
    expect(items[0]?.detail).toContain('Condomínio Horizonte');
    expect(items[0]?.detail).toContain('2026-01-15');
    expect(items[0]?.detail).not.toContain('Raw backend condominium fallback');
    expect(items[0]?.meta).toContain('Data 2026-01-15');
  });

  it('preserves absent-owner generated document and dispatch-evidence targets', () => {
    const items = buildDashboardNotifications(
      dashboard({
        reminders: [
          reminder({
            due_date: '',
            status: 'Pending',
            reason: 'Raw backend dispatch fallback.',
            source_rule: 'absent-owner-dispatch-evidence',
            source_profile: 'condominium-generated-communication',
            params: {
              act_id: 'act-absent-1',
              act_title: 'Ata da assembleia de condóminos',
              document_id: 'generated-absent-1',
              dispatch_evidence_status: 'operator_evidence_partial',
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
          }),
        ],
      }),
      t,
    );

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      kind: 'reminder',
      action: {
        href: '/atas/act-absent-1?generated_document_id=generated-absent-1&focus=dispatch-evidence#generated-dispatch-evidence',
        label: 'Abrir ata',
      },
    });
  });

  it('routes imported-document review reminders to the act review form', () => {
    const items = buildDashboardNotifications(
      dashboard({
        reminders: [
          reminder({
            due_date: '',
            status: 'Pending',
            reason: 'Raw backend imported-review fallback.',
            source_rule: 'imported-document-review-required',
            source_profile: 'imported-document-review:import-1',
            params: {
              act_id: 'act-import-1',
              act_title: 'Ata com documento importado',
              entity_name: 'Acme, S.A.',
              imported_document_id: 'import-1',
              operator_review_status: 'operator_review_required',
            },
            action: {
              kind: 'open_imported_document_review',
              label_key: 'notifications.reminder.importedDocumentReview.action',
              api_href: '/v1/documents/imported/import-1',
              route: '/atas/act-import-1',
            },
            i18n: {
              title_key: 'notifications.reminder.importedDocumentReview.title',
              body_key: 'notifications.reminder.importedDocumentReview.body',
              action_key: 'notifications.reminder.importedDocumentReview.action',
            },
          }),
        ],
      }),
      t,
    );

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      kind: 'reminder',
      action: {
        href: '/atas/act-import-1?imported_document_id=import-1&focus=import-review#imported-documents',
        label: 'Rever documento importado',
      },
    });
    expect(items[0]?.detail).not.toContain('Raw backend');
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
