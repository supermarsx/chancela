import { useMemo, useState, type FormEvent } from 'react';
import {
  useCreatePrivacyBreachPlaybook,
  useCreatePrivacyDpia,
  useCreatePrivacyProcessor,
  useCreatePrivacyTransferControl,
  usePatchPrivacyBreachPlaybook,
  usePatchPrivacyDpia,
  usePatchPrivacyProcessor,
  usePatchPrivacyTransferControl,
  usePrivacyBreachPlaybooks,
  usePrivacyDpias,
  usePrivacyProcessors,
  usePrivacyTransferControls,
} from '../../api/hooks';
import {
  type BreachPlaybookView,
  type CreateBreachPlaybookBody,
  PRIVACY_RECORD_STATUSES,
  PRIVACY_RISK_LEVELS,
  type CreateDpiaRecordBody,
  type CreateProcessorRecordBody,
  type CreateTransferControlBody,
  type DpiaRecordView,
  type PatchBreachPlaybookBody,
  type PatchDpiaRecordBody,
  type PatchProcessorRecordBody,
  type PatchTransferControlBody,
  type PrivacyRecordStatus,
  type PrivacyRiskLevel,
  type ProcessorRecordView,
  type TransferControlView,
} from '../../api/types';
import { useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  Select,
  SkeletonTable,
  Table,
  TextArea,
  useToast,
} from '../../ui';
import { PermissionDeniedNote, useCan } from '../session/permissions';

type RegisterKind = 'processor' | 'dpia';
type RegisterRecord = ProcessorRecordView | DpiaRecordView;
type PrivacyCreateBody = CreateProcessorRecordBody | CreateDpiaRecordBody;
type PrivacyPatchBody = PatchProcessorRecordBody | PatchDpiaRecordBody;

interface RegisterFormState {
  primary: string;
  purpose: string;
  legalBasis: string;
  dataCategories: string;
  subprocessors: string;
  riskLevel: PrivacyRiskLevel;
  status: PrivacyRecordStatus;
}

interface BreachPlaybookFormState {
  title: string;
  scope: string;
  detectionChannels: string;
  containmentSteps: string;
  notificationRoles: string;
  authorityNotificationWindow: string;
  subjectNotificationGuidance: string;
  riskLevel: PrivacyRiskLevel;
  status: PrivacyRecordStatus;
  reviewNotes: string;
}

interface TransferControlFormState {
  name: string;
  purpose: string;
  legalBasis: string;
  dataCategories: string;
  recipient: string;
  destinationCountry: string;
  transferMechanism: string;
  safeguards: string;
  riskLevel: PrivacyRiskLevel;
  status: PrivacyRecordStatus;
  reviewNotes: string;
}

const EMPTY_FORM: RegisterFormState = {
  primary: '',
  purpose: '',
  legalBasis: '',
  dataCategories: '',
  subprocessors: '',
  riskLevel: 'medium',
  status: 'draft',
};

const EMPTY_BREACH_FORM: BreachPlaybookFormState = {
  title: '',
  scope: '',
  detectionChannels: '',
  containmentSteps: '',
  notificationRoles: '',
  authorityNotificationWindow: '',
  subjectNotificationGuidance: '',
  riskLevel: 'high',
  status: 'draft',
  reviewNotes: '',
};

const EMPTY_TRANSFER_FORM: TransferControlFormState = {
  name: '',
  purpose: '',
  legalBasis: '',
  dataCategories: '',
  recipient: '',
  destinationCountry: '',
  transferMechanism: '',
  safeguards: '',
  riskLevel: 'medium',
  status: 'draft',
  reviewNotes: '',
};

const STATUS_LABELS: Record<PrivacyRecordStatus, string> = {
  draft: 'Rascunho',
  active: 'Ativo',
  under_review: 'Em revisão',
  retired: 'Retirado',
};

const RISK_LABELS: Record<PrivacyRiskLevel, string> = {
  low: 'Baixo',
  medium: 'Médio',
  high: 'Elevado',
  critical: 'Crítico',
};

const statusOptions = [
  { value: 'all', label: 'Todos os estados' },
  ...PRIVACY_RECORD_STATUSES.map((status) => ({ value: status, label: STATUS_LABELS[status] })),
];

const riskOptions = [
  { value: 'all', label: 'Todos os riscos' },
  ...PRIVACY_RISK_LEVELS.map((risk) => ({ value: risk, label: RISK_LABELS[risk] })),
];

const statusSelectOptions = PRIVACY_RECORD_STATUSES.map((status) => ({
  value: status,
  label: STATUS_LABELS[status],
}));

const riskSelectOptions = PRIVACY_RISK_LEVELS.map((risk) => ({
  value: risk,
  label: RISK_LABELS[risk],
}));

function primaryValue(kind: RegisterKind, record: RegisterRecord): string {
  return kind === 'processor'
    ? (record as ProcessorRecordView).name
    : (record as DpiaRecordView).title;
}

function normalizeSearch(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

function splitList(value: string): string[] {
  const items = value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
  return [...new Set(items)];
}

function joinList(items: string[]): string {
  return items.join('\n');
}

function formFromRecord(kind: RegisterKind, record: RegisterRecord): RegisterFormState {
  return {
    primary: primaryValue(kind, record),
    purpose: record.purpose,
    legalBasis: record.legal_basis,
    dataCategories: joinList(record.data_categories),
    subprocessors: joinList(record.subprocessors),
    riskLevel: record.risk_level,
    status: record.status,
  };
}

function breachFormFromRecord(record: BreachPlaybookView): BreachPlaybookFormState {
  return {
    title: record.title,
    scope: record.scope,
    detectionChannels: joinList(record.detection_channels),
    containmentSteps: joinList(record.containment_steps),
    notificationRoles: joinList(record.notification_roles),
    authorityNotificationWindow: record.authority_notification_window ?? '',
    subjectNotificationGuidance: record.subject_notification_guidance ?? '',
    riskLevel: record.risk_level,
    status: record.status,
    reviewNotes: record.review_notes ?? '',
  };
}

function transferFormFromRecord(record: TransferControlView): TransferControlFormState {
  return {
    name: record.name,
    purpose: record.purpose,
    legalBasis: record.legal_basis,
    dataCategories: joinList(record.data_categories),
    recipient: record.recipient,
    destinationCountry: record.destination_country,
    transferMechanism: record.transfer_mechanism,
    safeguards: joinList(record.safeguards),
    riskLevel: record.risk_level,
    status: record.status,
    reviewNotes: record.review_notes ?? '',
  };
}

function createBody(kind: RegisterKind, form: RegisterFormState): PrivacyCreateBody {
  const base = {
    purpose: form.purpose.trim(),
    legal_basis: form.legalBasis.trim(),
    data_categories: splitList(form.dataCategories),
    subprocessors: splitList(form.subprocessors),
    risk_level: form.riskLevel,
    status: form.status,
  };
  return kind === 'processor'
    ? { ...base, name: form.primary.trim() }
    : { ...base, title: form.primary.trim() };
}

function patchBody(kind: RegisterKind, form: RegisterFormState): PrivacyPatchBody {
  const body = createBody(kind, form);
  return body;
}

function optionalText(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function breachCreateBody(form: BreachPlaybookFormState): CreateBreachPlaybookBody {
  return {
    title: form.title.trim(),
    scope: form.scope.trim(),
    detection_channels: splitList(form.detectionChannels),
    containment_steps: splitList(form.containmentSteps),
    notification_roles: splitList(form.notificationRoles),
    authority_notification_window: optionalText(form.authorityNotificationWindow),
    subject_notification_guidance: optionalText(form.subjectNotificationGuidance),
    risk_level: form.riskLevel,
    status: form.status,
    review_notes: optionalText(form.reviewNotes),
  };
}

function transferCreateBody(form: TransferControlFormState): CreateTransferControlBody {
  return {
    name: form.name.trim(),
    purpose: form.purpose.trim(),
    legal_basis: form.legalBasis.trim(),
    data_categories: splitList(form.dataCategories),
    recipient: form.recipient.trim(),
    destination_country: form.destinationCountry.trim(),
    transfer_mechanism: form.transferMechanism.trim(),
    safeguards: splitList(form.safeguards),
    risk_level: form.riskLevel,
    status: form.status,
    review_notes: optionalText(form.reviewNotes),
  };
}

function breachSearchText(record: BreachPlaybookView): string {
  return normalizeSearch(
    [
      record.title,
      record.scope,
      ...record.detection_channels,
      ...record.containment_steps,
      ...record.notification_roles,
      record.authority_notification_window ?? '',
      record.subject_notification_guidance ?? '',
      record.review_notes ?? '',
      record.risk_level,
      record.status,
    ].join(' '),
  );
}

function transferSearchText(record: TransferControlView): string {
  return normalizeSearch(
    [
      record.name,
      record.purpose,
      record.legal_basis,
      ...record.data_categories,
      record.recipient,
      record.destination_country,
      record.transfer_mechanism,
      ...record.safeguards,
      record.review_notes ?? '',
      record.risk_level,
      record.status,
    ].join(' '),
  );
}

function recordSearchText(kind: RegisterKind, record: RegisterRecord): string {
  return normalizeSearch(
    [
      primaryValue(kind, record),
      record.purpose,
      record.legal_basis,
      ...record.data_categories,
      ...record.subprocessors,
      record.risk_level,
      record.status,
    ].join(' '),
  );
}

function riskTone(risk: PrivacyRiskLevel): 'neutral' | 'warn' | 'error' | 'ok' {
  if (risk === 'low') return 'ok';
  if (risk === 'high') return 'warn';
  if (risk === 'critical') return 'error';
  return 'neutral';
}

function statusTone(status: PrivacyRecordStatus): 'neutral' | 'warn' | 'ok' {
  if (status === 'active') return 'ok';
  if (status === 'under_review') return 'warn';
  return 'neutral';
}

function formatDateTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat('pt-PT', { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

function RegisterForm({
  kind,
  form,
  setForm,
  editing,
  saving,
  onCancel,
  onSubmit,
}: {
  kind: RegisterKind;
  form: RegisterFormState;
  setForm: (next: RegisterFormState) => void;
  editing: boolean;
  saving: boolean;
  onCancel: () => void;
  onSubmit: () => void;
}) {
  const idPrefix = `privacy-${kind}-${editing ? 'edit' : 'new'}`;
  const primaryLabel = kind === 'processor' ? 'Nome do processador' : 'Título da DPIA';
  const parsedCategories = splitList(form.dataCategories);
  const canSubmit =
    form.primary.trim().length > 0 &&
    form.purpose.trim().length > 0 &&
    form.legalBasis.trim().length > 0 &&
    parsedCategories.length > 0 &&
    !saving;

  return (
    <form
      className="form"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        if (canSubmit) onSubmit();
      }}
    >
      <Field label={primaryLabel} htmlFor={`${idPrefix}-primary`}>
        <Input
          id={`${idPrefix}-primary`}
          value={form.primary}
          onChange={(e) => setForm({ ...form, primary: e.target.value })}
          autoComplete="off"
        />
      </Field>

      <Field label="Finalidade" htmlFor={`${idPrefix}-purpose`}>
        <TextArea
          id={`${idPrefix}-purpose`}
          value={form.purpose}
          onChange={(e) => setForm({ ...form, purpose: e.target.value })}
          rows={3}
        />
      </Field>

      <Field label="Base legal" htmlFor={`${idPrefix}-legal-basis`}>
        <Input
          id={`${idPrefix}-legal-basis`}
          value={form.legalBasis}
          onChange={(e) => setForm({ ...form, legalBasis: e.target.value })}
          autoComplete="off"
        />
      </Field>

      <Field
        label="Categorias de dados"
        htmlFor={`${idPrefix}-data-categories`}
        hint="Uma categoria por linha ou separada por vírgulas."
      >
        <TextArea
          id={`${idPrefix}-data-categories`}
          value={form.dataCategories}
          onChange={(e) => setForm({ ...form, dataCategories: e.target.value })}
          rows={3}
        />
      </Field>

      <Field
        label="Subprocessadores"
        htmlFor={`${idPrefix}-subprocessors`}
        hint="Opcional. Uma entidade por linha ou separada por vírgulas."
      >
        <TextArea
          id={`${idPrefix}-subprocessors`}
          value={form.subprocessors}
          onChange={(e) => setForm({ ...form, subprocessors: e.target.value })}
          rows={3}
        />
      </Field>

      <div className="api-key-rate-grid">
        <Field label="Risco" htmlFor={`${idPrefix}-risk`}>
          <Select
            id={`${idPrefix}-risk`}
            value={form.riskLevel}
            onChange={(e) => setForm({ ...form, riskLevel: e.target.value as PrivacyRiskLevel })}
            options={riskSelectOptions}
          />
        </Field>
        <Field label="Estado" htmlFor={`${idPrefix}-status`}>
          <Select
            id={`${idPrefix}-status`}
            value={form.status}
            onChange={(e) => setForm({ ...form, status: e.target.value as PrivacyRecordStatus })}
            options={statusSelectOptions}
          />
        </Field>
      </div>

      <div className="form__actions">
        <Button type="button" variant="ghost" disabled={saving} onClick={onCancel}>
          Cancelar
        </Button>
        <Button type="submit" variant="primary" icon={<Icon.Check />} disabled={!canSubmit}>
          {saving ? 'A guardar' : editing ? 'Guardar alterações' : 'Criar registo'}
        </Button>
      </div>
    </form>
  );
}

function RegisterPanel({
  kind,
  title,
  lede,
  records,
  loading,
  error,
  saving,
  onCreate,
  onPatch,
}: {
  kind: RegisterKind;
  title: string;
  lede: string;
  records: RegisterRecord[];
  loading: boolean;
  error: unknown;
  saving: boolean;
  onCreate: (body: PrivacyCreateBody) => Promise<RegisterRecord>;
  onPatch: (id: string, body: PrivacyPatchBody) => Promise<RegisterRecord>;
}) {
  const toast = useToast();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');
  const [form, setForm] = useState<RegisterFormState | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = normalizeSearch(search.trim());
    return records.filter((record) => {
      if (statusFilter !== 'all' && record.status !== statusFilter) return false;
      if (riskFilter !== 'all' && record.risk_level !== riskFilter) return false;
      return q.length === 0 || recordSearchText(kind, record).includes(q);
    });
  }, [kind, records, riskFilter, search, statusFilter]);

  function startCreate() {
    setEditingId(null);
    setForm(EMPTY_FORM);
  }

  function startEdit(record: RegisterRecord) {
    setEditingId(record.id);
    setForm(formFromRecord(kind, record));
  }

  async function submitForm() {
    if (!form) return;
    try {
      if (editingId) {
        await onPatch(editingId, patchBody(kind, form));
        toast.success('Registo de privacidade atualizado.');
      } else {
        await onCreate(createBody(kind, form));
        toast.success('Registo de privacidade criado.');
      }
      setForm(null);
      setEditingId(null);
    } catch (e) {
      toast.error(e);
    }
  }

  async function patchOne(id: string, body: PrivacyPatchBody) {
    try {
      await onPatch(id, body);
      toast.success('Registo de privacidade atualizado.');
    } catch (e) {
      toast.error(e);
    }
  }

  return (
    <div className="stack">
      {form ? (
        <Card title={editingId ? 'Editar registo' : 'Novo registo'}>
          <RegisterForm
            kind={kind}
            form={form}
            setForm={setForm}
            editing={editingId !== null}
            saving={saving}
            onCancel={() => {
              setForm(null);
              setEditingId(null);
            }}
            onSubmit={submitForm}
          />
        </Card>
      ) : null}

      <Card
        title={title}
        actions={
          <Button type="button" variant="primary" icon={<Icon.Plus />} onClick={startCreate}>
            Novo registo
          </Button>
        }
      >
        <div className="stack">
          <p className="field__hint">{lede}</p>

          <div className="filter">
            <Field label="Pesquisar" htmlFor={`privacy-${kind}-search`}>
              <Input
                id={`privacy-${kind}-search`}
                value={search}
                placeholder="Nome, finalidade, base legal ou categoria"
                onChange={(e) => setSearch(e.target.value)}
              />
            </Field>
            <Field label="Estado" htmlFor={`privacy-${kind}-status-filter`}>
              <Select
                id={`privacy-${kind}-status-filter`}
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                options={statusOptions}
              />
            </Field>
            <Field label="Risco" htmlFor={`privacy-${kind}-risk-filter`}>
              <Select
                id={`privacy-${kind}-risk-filter`}
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                options={riskOptions}
              />
            </Field>
          </div>

          {loading ? (
            <SkeletonTable cols={8} />
          ) : error ? (
            <ErrorNote error={error} />
          ) : records.length === 0 ? (
            <EmptyState title="Sem registos">
              <p>Ainda não existem registos nesta área de privacidade.</p>
            </EmptyState>
          ) : filtered.length === 0 ? (
            <EmptyState title="Sem resultados">
              <p>Altere a pesquisa ou os filtros para voltar a ver registos.</p>
            </EmptyState>
          ) : (
            <Table
              head={
                <tr>
                  <th>{kind === 'processor' ? 'Processador' : 'DPIA'}</th>
                  <th>Finalidade</th>
                  <th>Categorias</th>
                  <th>Subprocessadores</th>
                  <th>Risco</th>
                  <th>Estado</th>
                  <th>Atualizado</th>
                  <th>Ação</th>
                </tr>
              }
            >
              {filtered.map((record) => {
                const label = primaryValue(kind, record);
                return (
                  <tr key={record.id}>
                    <td>{label}</td>
                    <td>{record.purpose}</td>
                    <td>{record.data_categories.join(', ')}</td>
                    <td>
                      {record.subprocessors.length > 0 ? record.subprocessors.join(', ') : '—'}
                    </td>
                    <td>
                      <span className="row-wrap">
                        <Badge tone={riskTone(record.risk_level)}>
                          {RISK_LABELS[record.risk_level]}
                        </Badge>
                        <Select
                          aria-label={`Risco de ${label}`}
                          value={record.risk_level}
                          disabled={saving}
                          onChange={(e) =>
                            patchOne(record.id, {
                              risk_level: e.target.value as PrivacyRiskLevel,
                            })
                          }
                          options={riskSelectOptions}
                        />
                      </span>
                    </td>
                    <td>
                      <span className="row-wrap">
                        <Badge tone={statusTone(record.status)}>
                          {STATUS_LABELS[record.status]}
                        </Badge>
                        <Select
                          aria-label={`Estado de ${label}`}
                          value={record.status}
                          disabled={saving}
                          onChange={(e) =>
                            patchOne(record.id, {
                              status: e.target.value as PrivacyRecordStatus,
                            })
                          }
                          options={statusSelectOptions}
                        />
                      </span>
                    </td>
                    <td>
                      {formatDateTime(record.updated_at)}
                      <br />
                      <span className="muted">{record.updated_by}</span>
                    </td>
                    <td className="users-actions">
                      <Button
                        type="button"
                        variant="ghost"
                        icon={<Icon.Pencil />}
                        disabled={saving}
                        onClick={() => startEdit(record)}
                      >
                        Editar
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </Table>
          )}
        </div>
      </Card>
    </div>
  );
}

function BreachPlaybookForm({
  form,
  setForm,
  editing,
  saving,
  onCancel,
  onSubmit,
}: {
  form: BreachPlaybookFormState;
  setForm: (next: BreachPlaybookFormState) => void;
  editing: boolean;
  saving: boolean;
  onCancel: () => void;
  onSubmit: () => void;
}) {
  const t = useT();
  const idPrefix = `privacy-breach-${editing ? 'edit' : 'new'}`;
  const canSubmit =
    form.title.trim().length > 0 &&
    form.scope.trim().length > 0 &&
    splitList(form.detectionChannels).length > 0 &&
    splitList(form.containmentSteps).length > 0 &&
    !saving;

  return (
    <form
      className="form"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        if (canSubmit) onSubmit();
      }}
    >
      <Field label={t('settings.privacy.breach.field.title')} htmlFor={`${idPrefix}-title`}>
        <Input
          id={`${idPrefix}-title`}
          value={form.title}
          onChange={(e) => setForm({ ...form, title: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field label={t('settings.privacy.breach.field.scope')} htmlFor={`${idPrefix}-scope`}>
        <Input
          id={`${idPrefix}-scope`}
          value={form.scope}
          onChange={(e) => setForm({ ...form, scope: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field
        label={t('settings.privacy.breach.field.detection')}
        htmlFor={`${idPrefix}-detection`}
        hint={t('settings.privacy.listHint')}
      >
        <TextArea
          id={`${idPrefix}-detection`}
          value={form.detectionChannels}
          onChange={(e) => setForm({ ...form, detectionChannels: e.target.value })}
          rows={3}
        />
      </Field>
      <Field
        label={t('settings.privacy.breach.field.containment')}
        htmlFor={`${idPrefix}-containment`}
        hint={t('settings.privacy.listHint')}
      >
        <TextArea
          id={`${idPrefix}-containment`}
          value={form.containmentSteps}
          onChange={(e) => setForm({ ...form, containmentSteps: e.target.value })}
          rows={3}
        />
      </Field>
      <Field
        label={t('settings.privacy.breach.field.roles')}
        htmlFor={`${idPrefix}-roles`}
        hint={t('settings.privacy.listHintOptional')}
      >
        <TextArea
          id={`${idPrefix}-roles`}
          value={form.notificationRoles}
          onChange={(e) => setForm({ ...form, notificationRoles: e.target.value })}
          rows={2}
        />
      </Field>
      <Field
        label={t('settings.privacy.breach.field.authorityWindow')}
        htmlFor={`${idPrefix}-authority-window`}
      >
        <Input
          id={`${idPrefix}-authority-window`}
          value={form.authorityNotificationWindow}
          onChange={(e) => setForm({ ...form, authorityNotificationWindow: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field
        label={t('settings.privacy.breach.field.subjectGuidance')}
        htmlFor={`${idPrefix}-subject-guidance`}
      >
        <TextArea
          id={`${idPrefix}-subject-guidance`}
          value={form.subjectNotificationGuidance}
          onChange={(e) => setForm({ ...form, subjectNotificationGuidance: e.target.value })}
          rows={3}
        />
      </Field>
      <div className="api-key-rate-grid">
        <Field label={t('settings.privacy.field.risk')} htmlFor={`${idPrefix}-risk`}>
          <Select
            id={`${idPrefix}-risk`}
            value={form.riskLevel}
            onChange={(e) => setForm({ ...form, riskLevel: e.target.value as PrivacyRiskLevel })}
            options={riskSelectOptions}
          />
        </Field>
        <Field label={t('settings.privacy.field.status')} htmlFor={`${idPrefix}-status`}>
          <Select
            id={`${idPrefix}-status`}
            value={form.status}
            onChange={(e) => setForm({ ...form, status: e.target.value as PrivacyRecordStatus })}
            options={statusSelectOptions}
          />
        </Field>
      </div>
      <Field label={t('settings.privacy.field.reviewNotes')} htmlFor={`${idPrefix}-notes`}>
        <TextArea
          id={`${idPrefix}-notes`}
          value={form.reviewNotes}
          onChange={(e) => setForm({ ...form, reviewNotes: e.target.value })}
          rows={3}
        />
      </Field>
      <div className="form__actions">
        <Button type="button" variant="ghost" disabled={saving} onClick={onCancel}>
          {t('settings.privacy.action.cancel')}
        </Button>
        <Button type="submit" variant="primary" icon={<Icon.Check />} disabled={!canSubmit}>
          {saving
            ? t('settings.privacy.action.saving')
            : editing
              ? t('settings.privacy.action.save')
              : t('settings.privacy.action.create')}
        </Button>
      </div>
    </form>
  );
}

function BreachPlaybookPanel({
  records,
  loading,
  error,
  saving,
  onCreate,
  onPatch,
}: {
  records: BreachPlaybookView[];
  loading: boolean;
  error: unknown;
  saving: boolean;
  onCreate: (body: CreateBreachPlaybookBody) => Promise<BreachPlaybookView>;
  onPatch: (id: string, body: PatchBreachPlaybookBody) => Promise<BreachPlaybookView>;
}) {
  const t = useT();
  const toast = useToast();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');
  const [form, setForm] = useState<BreachPlaybookFormState | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const filtered = useMemo(() => {
    const q = normalizeSearch(search.trim());
    return records.filter((record) => {
      if (statusFilter !== 'all' && record.status !== statusFilter) return false;
      if (riskFilter !== 'all' && record.risk_level !== riskFilter) return false;
      return q.length === 0 || breachSearchText(record).includes(q);
    });
  }, [records, riskFilter, search, statusFilter]);

  async function submitForm() {
    if (!form) return;
    try {
      if (editingId) {
        await onPatch(editingId, breachCreateBody(form));
        toast.success(t('settings.privacy.toast.updated'));
      } else {
        await onCreate(breachCreateBody(form));
        toast.success(t('settings.privacy.toast.created'));
      }
      setForm(null);
      setEditingId(null);
    } catch (e) {
      toast.error(e);
    }
  }

  return (
    <div className="stack">
      {form ? (
        <Card title={editingId ? t('settings.privacy.form.edit') : t('settings.privacy.form.new')}>
          <BreachPlaybookForm
            form={form}
            setForm={setForm}
            editing={editingId !== null}
            saving={saving}
            onCancel={() => {
              setForm(null);
              setEditingId(null);
            }}
            onSubmit={submitForm}
          />
        </Card>
      ) : null}
      <Card
        title={t('settings.privacy.breach.title')}
        actions={
          <Button
            type="button"
            variant="primary"
            icon={<Icon.Plus />}
            onClick={() => {
              setEditingId(null);
              setForm(EMPTY_BREACH_FORM);
            }}
          >
            {t('settings.privacy.action.new')}
          </Button>
        }
      >
        <div className="stack">
          <p className="field__hint">{t('settings.privacy.breach.lede')}</p>
          <div className="filter">
            <Field label={t('settings.privacy.filter.search')} htmlFor="privacy-breach-search">
              <Input
                id="privacy-breach-search"
                value={search}
                placeholder={t('settings.privacy.breach.searchPlaceholder')}
                onChange={(e) => setSearch(e.target.value)}
              />
            </Field>
            <Field label={t('settings.privacy.field.status')} htmlFor="privacy-breach-status">
              <Select
                id="privacy-breach-status"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                options={statusOptions}
              />
            </Field>
            <Field label={t('settings.privacy.field.risk')} htmlFor="privacy-breach-risk">
              <Select
                id="privacy-breach-risk"
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                options={riskOptions}
              />
            </Field>
          </div>
          {loading ? (
            <SkeletonTable cols={7} />
          ) : error ? (
            <ErrorNote error={error} />
          ) : records.length === 0 ? (
            <EmptyState title={t('settings.privacy.empty.title')}>
              <p>{t('settings.privacy.empty.body')}</p>
            </EmptyState>
          ) : filtered.length === 0 ? (
            <EmptyState title={t('settings.privacy.emptyResults.title')}>
              <p>{t('settings.privacy.emptyResults.body')}</p>
            </EmptyState>
          ) : (
            <Table
              head={
                <tr>
                  <th>{t('settings.privacy.breach.column.playbook')}</th>
                  <th>{t('settings.privacy.breach.column.scope')}</th>
                  <th>{t('settings.privacy.breach.column.detection')}</th>
                  <th>{t('settings.privacy.breach.column.containment')}</th>
                  <th>{t('settings.privacy.field.risk')}</th>
                  <th>{t('settings.privacy.field.status')}</th>
                  <th>{t('settings.privacy.table.action')}</th>
                </tr>
              }
            >
              {filtered.map((record) => (
                <tr key={record.id}>
                  <td>{record.title}</td>
                  <td>{record.scope}</td>
                  <td>{record.detection_channels.join(', ')}</td>
                  <td>{record.containment_steps.join(', ')}</td>
                  <td>
                    <Badge tone={riskTone(record.risk_level)}>
                      {RISK_LABELS[record.risk_level]}
                    </Badge>
                  </td>
                  <td>
                    <Badge tone={statusTone(record.status)}>{STATUS_LABELS[record.status]}</Badge>
                  </td>
                  <td className="users-actions">
                    <Button
                      type="button"
                      variant="ghost"
                      icon={<Icon.Pencil />}
                      disabled={saving}
                      onClick={() => {
                        setEditingId(record.id);
                        setForm(breachFormFromRecord(record));
                      }}
                    >
                      {t('settings.privacy.action.edit')}
                    </Button>
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </div>
      </Card>
    </div>
  );
}

function TransferControlForm({
  form,
  setForm,
  editing,
  saving,
  onCancel,
  onSubmit,
}: {
  form: TransferControlFormState;
  setForm: (next: TransferControlFormState) => void;
  editing: boolean;
  saving: boolean;
  onCancel: () => void;
  onSubmit: () => void;
}) {
  const t = useT();
  const idPrefix = `privacy-transfer-${editing ? 'edit' : 'new'}`;
  const canSubmit =
    form.name.trim().length > 0 &&
    form.purpose.trim().length > 0 &&
    form.legalBasis.trim().length > 0 &&
    form.recipient.trim().length > 0 &&
    form.destinationCountry.trim().length > 0 &&
    form.transferMechanism.trim().length > 0 &&
    splitList(form.dataCategories).length > 0 &&
    splitList(form.safeguards).length > 0 &&
    !saving;

  return (
    <form
      className="form"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        if (canSubmit) onSubmit();
      }}
    >
      <Field label={t('settings.privacy.transfer.field.name')} htmlFor={`${idPrefix}-name`}>
        <Input
          id={`${idPrefix}-name`}
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field label={t('settings.privacy.transfer.field.purpose')} htmlFor={`${idPrefix}-purpose`}>
        <TextArea
          id={`${idPrefix}-purpose`}
          value={form.purpose}
          onChange={(e) => setForm({ ...form, purpose: e.target.value })}
          rows={3}
        />
      </Field>
      <Field label={t('settings.privacy.transfer.field.legalBasis')} htmlFor={`${idPrefix}-legal`}>
        <Input
          id={`${idPrefix}-legal`}
          value={form.legalBasis}
          onChange={(e) => setForm({ ...form, legalBasis: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field
        label={t('settings.privacy.transfer.field.categories')}
        htmlFor={`${idPrefix}-categories`}
        hint={t('settings.privacy.listHint')}
      >
        <TextArea
          id={`${idPrefix}-categories`}
          value={form.dataCategories}
          onChange={(e) => setForm({ ...form, dataCategories: e.target.value })}
          rows={3}
        />
      </Field>
      <div className="api-key-rate-grid">
        <Field
          label={t('settings.privacy.transfer.field.recipient')}
          htmlFor={`${idPrefix}-recipient`}
        >
          <Input
            id={`${idPrefix}-recipient`}
            value={form.recipient}
            onChange={(e) => setForm({ ...form, recipient: e.target.value })}
            autoComplete="off"
          />
        </Field>
        <Field
          label={t('settings.privacy.transfer.field.destination')}
          htmlFor={`${idPrefix}-destination`}
        >
          <Input
            id={`${idPrefix}-destination`}
            value={form.destinationCountry}
            onChange={(e) => setForm({ ...form, destinationCountry: e.target.value })}
            autoComplete="off"
          />
        </Field>
      </div>
      <Field
        label={t('settings.privacy.transfer.field.mechanism')}
        htmlFor={`${idPrefix}-mechanism`}
      >
        <Input
          id={`${idPrefix}-mechanism`}
          value={form.transferMechanism}
          onChange={(e) => setForm({ ...form, transferMechanism: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field
        label={t('settings.privacy.transfer.field.safeguards')}
        htmlFor={`${idPrefix}-safeguards`}
        hint={t('settings.privacy.listHint')}
      >
        <TextArea
          id={`${idPrefix}-safeguards`}
          value={form.safeguards}
          onChange={(e) => setForm({ ...form, safeguards: e.target.value })}
          rows={3}
        />
      </Field>
      <div className="api-key-rate-grid">
        <Field label={t('settings.privacy.field.risk')} htmlFor={`${idPrefix}-risk`}>
          <Select
            id={`${idPrefix}-risk`}
            value={form.riskLevel}
            onChange={(e) => setForm({ ...form, riskLevel: e.target.value as PrivacyRiskLevel })}
            options={riskSelectOptions}
          />
        </Field>
        <Field label={t('settings.privacy.field.status')} htmlFor={`${idPrefix}-status`}>
          <Select
            id={`${idPrefix}-status`}
            value={form.status}
            onChange={(e) => setForm({ ...form, status: e.target.value as PrivacyRecordStatus })}
            options={statusSelectOptions}
          />
        </Field>
      </div>
      <Field label={t('settings.privacy.field.reviewNotes')} htmlFor={`${idPrefix}-notes`}>
        <TextArea
          id={`${idPrefix}-notes`}
          value={form.reviewNotes}
          onChange={(e) => setForm({ ...form, reviewNotes: e.target.value })}
          rows={3}
        />
      </Field>
      <div className="form__actions">
        <Button type="button" variant="ghost" disabled={saving} onClick={onCancel}>
          {t('settings.privacy.action.cancel')}
        </Button>
        <Button type="submit" variant="primary" icon={<Icon.Check />} disabled={!canSubmit}>
          {saving
            ? t('settings.privacy.action.saving')
            : editing
              ? t('settings.privacy.action.save')
              : t('settings.privacy.action.create')}
        </Button>
      </div>
    </form>
  );
}

function TransferControlPanel({
  records,
  loading,
  error,
  saving,
  onCreate,
  onPatch,
}: {
  records: TransferControlView[];
  loading: boolean;
  error: unknown;
  saving: boolean;
  onCreate: (body: CreateTransferControlBody) => Promise<TransferControlView>;
  onPatch: (id: string, body: PatchTransferControlBody) => Promise<TransferControlView>;
}) {
  const t = useT();
  const toast = useToast();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');
  const [form, setForm] = useState<TransferControlFormState | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const filtered = useMemo(() => {
    const q = normalizeSearch(search.trim());
    return records.filter((record) => {
      if (statusFilter !== 'all' && record.status !== statusFilter) return false;
      if (riskFilter !== 'all' && record.risk_level !== riskFilter) return false;
      return q.length === 0 || transferSearchText(record).includes(q);
    });
  }, [records, riskFilter, search, statusFilter]);

  async function submitForm() {
    if (!form) return;
    try {
      if (editingId) {
        await onPatch(editingId, transferCreateBody(form));
        toast.success(t('settings.privacy.toast.updated'));
      } else {
        await onCreate(transferCreateBody(form));
        toast.success(t('settings.privacy.toast.created'));
      }
      setForm(null);
      setEditingId(null);
    } catch (e) {
      toast.error(e);
    }
  }

  return (
    <div className="stack">
      {form ? (
        <Card title={editingId ? t('settings.privacy.form.edit') : t('settings.privacy.form.new')}>
          <TransferControlForm
            form={form}
            setForm={setForm}
            editing={editingId !== null}
            saving={saving}
            onCancel={() => {
              setForm(null);
              setEditingId(null);
            }}
            onSubmit={submitForm}
          />
        </Card>
      ) : null}
      <Card
        title={t('settings.privacy.transfer.title')}
        actions={
          <Button
            type="button"
            variant="primary"
            icon={<Icon.Plus />}
            onClick={() => {
              setEditingId(null);
              setForm(EMPTY_TRANSFER_FORM);
            }}
          >
            {t('settings.privacy.action.new')}
          </Button>
        }
      >
        <div className="stack">
          <p className="field__hint">{t('settings.privacy.transfer.lede')}</p>
          <div className="filter">
            <Field label={t('settings.privacy.filter.search')} htmlFor="privacy-transfer-search">
              <Input
                id="privacy-transfer-search"
                value={search}
                placeholder={t('settings.privacy.transfer.searchPlaceholder')}
                onChange={(e) => setSearch(e.target.value)}
              />
            </Field>
            <Field label={t('settings.privacy.field.status')} htmlFor="privacy-transfer-status">
              <Select
                id="privacy-transfer-status"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                options={statusOptions}
              />
            </Field>
            <Field label={t('settings.privacy.field.risk')} htmlFor="privacy-transfer-risk">
              <Select
                id="privacy-transfer-risk"
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                options={riskOptions}
              />
            </Field>
          </div>
          {loading ? (
            <SkeletonTable cols={8} />
          ) : error ? (
            <ErrorNote error={error} />
          ) : records.length === 0 ? (
            <EmptyState title={t('settings.privacy.empty.title')}>
              <p>{t('settings.privacy.empty.body')}</p>
            </EmptyState>
          ) : filtered.length === 0 ? (
            <EmptyState title={t('settings.privacy.emptyResults.title')}>
              <p>{t('settings.privacy.emptyResults.body')}</p>
            </EmptyState>
          ) : (
            <Table
              head={
                <tr>
                  <th>{t('settings.privacy.transfer.column.name')}</th>
                  <th>{t('settings.privacy.transfer.column.destination')}</th>
                  <th>{t('settings.privacy.transfer.column.mechanism')}</th>
                  <th>{t('settings.privacy.transfer.column.categories')}</th>
                  <th>{t('settings.privacy.transfer.column.safeguards')}</th>
                  <th>{t('settings.privacy.field.risk')}</th>
                  <th>{t('settings.privacy.field.status')}</th>
                  <th>{t('settings.privacy.table.action')}</th>
                </tr>
              }
            >
              {filtered.map((record) => (
                <tr key={record.id}>
                  <td>{record.name}</td>
                  <td>
                    {record.destination_country}
                    <br />
                    <span className="muted">{record.recipient}</span>
                  </td>
                  <td>{record.transfer_mechanism}</td>
                  <td>{record.data_categories.join(', ')}</td>
                  <td>{record.safeguards.join(', ')}</td>
                  <td>
                    <Badge tone={riskTone(record.risk_level)}>
                      {RISK_LABELS[record.risk_level]}
                    </Badge>
                  </td>
                  <td>
                    <Badge tone={statusTone(record.status)}>{STATUS_LABELS[record.status]}</Badge>
                  </td>
                  <td className="users-actions">
                    <Button
                      type="button"
                      variant="ghost"
                      icon={<Icon.Pencil />}
                      disabled={saving}
                      onClick={() => {
                        setEditingId(record.id);
                        setForm(transferFormFromRecord(record));
                      }}
                    >
                      {t('settings.privacy.action.edit')}
                    </Button>
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </div>
      </Card>
    </div>
  );
}

export function PrivacyComplianceSection() {
  const t = useT();
  const can = useCan();
  const canManage = can('user.manage') || can('settings.manage');
  const processors = usePrivacyProcessors(canManage);
  const dpias = usePrivacyDpias(canManage);
  const breachPlaybooks = usePrivacyBreachPlaybooks(canManage);
  const transferControls = usePrivacyTransferControls(canManage);
  const createProcessor = useCreatePrivacyProcessor();
  const patchProcessor = usePatchPrivacyProcessor();
  const createDpia = useCreatePrivacyDpia();
  const patchDpia = usePatchPrivacyDpia();
  const createBreachPlaybook = useCreatePrivacyBreachPlaybook();
  const patchBreachPlaybook = usePatchPrivacyBreachPlaybook();
  const createTransferControl = useCreatePrivacyTransferControl();
  const patchTransferControl = usePatchPrivacyTransferControl();

  if (!canManage) {
    return (
      <Card title={t('settings.privacy.title')}>
        <PermissionDeniedNote />
      </Card>
    );
  }

  return (
    <div className="stack">
      <InlineWarning tone="info" title={t('settings.privacy.notice.title')}>
        {t('settings.privacy.notice.body')}
      </InlineWarning>

      <RegisterPanel
        kind="processor"
        title="Processadores GDPR"
        lede="Registo dos processadores, subprocessadores e categorias de dados tratados por terceiros."
        records={processors.data ?? []}
        loading={processors.isLoading}
        error={processors.error}
        saving={createProcessor.isPending || patchProcessor.isPending}
        onCreate={(body) => createProcessor.mutateAsync(body as CreateProcessorRecordBody)}
        onPatch={(id, body) =>
          patchProcessor.mutateAsync({ id, body: body as PatchProcessorRecordBody })
        }
      />

      <RegisterPanel
        kind="dpia"
        title="DPIAs"
        lede="Avaliações de impacto com finalidade, base legal, categorias de dados e risco atual."
        records={dpias.data ?? []}
        loading={dpias.isLoading}
        error={dpias.error}
        saving={createDpia.isPending || patchDpia.isPending}
        onCreate={(body) => createDpia.mutateAsync(body as CreateDpiaRecordBody)}
        onPatch={(id, body) => patchDpia.mutateAsync({ id, body: body as PatchDpiaRecordBody })}
      />

      <BreachPlaybookPanel
        records={breachPlaybooks.data ?? []}
        loading={breachPlaybooks.isLoading}
        error={breachPlaybooks.error}
        saving={createBreachPlaybook.isPending || patchBreachPlaybook.isPending}
        onCreate={(body) => createBreachPlaybook.mutateAsync(body)}
        onPatch={(id, body) => patchBreachPlaybook.mutateAsync({ id, body })}
      />

      <TransferControlPanel
        records={transferControls.data ?? []}
        loading={transferControls.isLoading}
        error={transferControls.error}
        saving={createTransferControl.isPending || patchTransferControl.isPending}
        onCreate={(body) => createTransferControl.mutateAsync(body)}
        onPatch={(id, body) => patchTransferControl.mutateAsync({ id, body })}
      />
    </div>
  );
}
