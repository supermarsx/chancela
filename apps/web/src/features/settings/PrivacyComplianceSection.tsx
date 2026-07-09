import { useMemo, useState, type FormEvent } from 'react';
import {
  useCreatePrivacyDpia,
  useCreatePrivacyProcessor,
  usePatchPrivacyDpia,
  usePatchPrivacyProcessor,
  usePrivacyDpias,
  usePrivacyProcessors,
} from '../../api/hooks';
import {
  PRIVACY_RECORD_STATUSES,
  PRIVACY_RISK_LEVELS,
  type CreateDpiaRecordBody,
  type CreateProcessorRecordBody,
  type DpiaRecordView,
  type PatchDpiaRecordBody,
  type PatchProcessorRecordBody,
  type PrivacyRecordStatus,
  type PrivacyRiskLevel,
  type ProcessorRecordView,
} from '../../api/types';
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

const EMPTY_FORM: RegisterFormState = {
  primary: '',
  purpose: '',
  legalBasis: '',
  dataCategories: '',
  subprocessors: '',
  riskLevel: 'medium',
  status: 'draft',
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

export function PrivacyComplianceSection() {
  const can = useCan();
  const canManage = can('user.manage') || can('settings.manage');
  const processors = usePrivacyProcessors(canManage);
  const dpias = usePrivacyDpias(canManage);
  const createProcessor = useCreatePrivacyProcessor();
  const patchProcessor = usePatchPrivacyProcessor();
  const createDpia = useCreatePrivacyDpia();
  const patchDpia = usePatchPrivacyDpia();

  if (!canManage) {
    return (
      <Card title="Privacidade e conformidade">
        <PermissionDeniedNote />
      </Card>
    );
  }

  return (
    <div className="stack">
      <InlineWarning tone="info" title="Registos auditáveis">
        Os registos de processadores GDPR e DPIAs são alterados por eventos no ledger. Use estes
        controlos para manter finalidade, base legal, categorias de dados, risco e estado.
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
    </div>
  );
}
