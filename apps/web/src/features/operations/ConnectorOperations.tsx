import { useEffect, useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ApiError } from '../../api/client';
import {
  useArchiveConnectorTarget,
  useCancelConnectorJob,
  useConnectorJob,
  useConnectorJobs,
  useConnectorTargets,
  useCreateConnectorTarget,
  usePatchConnectorTarget,
  useProbeConnectorTarget,
  useRetryConnectorJob,
  useRunConnectorTarget,
} from '../../api/hooks';
import type {
  ConnectorJobPurpose,
  ConnectorJobView,
  ConnectorKind,
  ConnectorTargetView,
} from '../../api/types';
import { useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  DateTime,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  Select,
  Table,
  TextArea,
  Toggle,
} from '../../ui';
import { GateButton, scopeIntegration, scopeRepository, scopeTenant } from '../session/permissions';
import { CONNECTOR_KINDS, connectorConfigTemplate, parseConnectorConfig } from './operatorModels';

function jobTone(state: ConnectorJobView['state']): 'neutral' | 'ok' | 'warn' | 'error' | 'info' {
  if (state === 'succeeded' || state === 'recovered') return 'ok';
  if (state === 'failed') return 'error';
  if (state === 'cancelled') return 'neutral';
  if (state === 'retry_scheduled') return 'warn';
  return 'info';
}

function purposeOptions(t: ReturnType<typeof useT>) {
  return [
    { value: 'sync', label: t('operations.connectors.purpose.sync') },
    { value: 'backup', label: t('operations.connectors.purpose.backup') },
  ];
}

function CreateConnectorForm({ tenantId }: { tenantId: string }) {
  const t = useT();
  const create = useCreateConnectorTarget();
  const [name, setName] = useState('');
  const [kind, setKind] = useState<ConnectorKind>('web_dav');
  const [enabled, setEnabled] = useState(true);
  const [purposes, setPurposes] = useState<ConnectorJobPurpose[]>(['sync']);
  const [config, setConfig] = useState(() =>
    JSON.stringify(connectorConfigTemplate(kind), null, 2),
  );
  const [validationError, setValidationError] = useState<Error | null>(null);

  function togglePurpose(purpose: ConnectorJobPurpose, checked: boolean) {
    setPurposes((current) =>
      checked ? [...new Set([...current, purpose])] : current.filter((item) => item !== purpose),
    );
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setValidationError(null);
    try {
      await create.mutateAsync({
        tenantId,
        body: {
          name: name.trim(),
          enabled,
          purposes,
          config: parseConnectorConfig(config, kind),
        },
      });
      setName('');
    } catch (error) {
      if (error instanceof ApiError) return;
      if (!(error instanceof Error)) throw error;
      setValidationError(error);
    }
  }

  return (
    <Card title={t('operations.connectors.create.title')}>
      <InlineWarning tone="info" title={t('operations.connectors.secrets.title')}>
        {t('operations.connectors.secrets.body')}
      </InlineWarning>
      <form className="form operations-form" onSubmit={(event) => void submit(event)}>
        <div className="operations-form-grid">
          <Field label={t('operations.connectors.name')} htmlFor="operations-connector-name">
            <Input
              id="operations-connector-name"
              value={name}
              required
              onChange={(event) => setName(event.target.value)}
            />
          </Field>
          <Field label={t('operations.connectors.kind')} htmlFor="operations-connector-kind">
            <Select
              id="operations-connector-kind"
              value={kind}
              onChange={(event) => {
                const next = event.target.value as ConnectorKind;
                setKind(next);
                setConfig(JSON.stringify(connectorConfigTemplate(next), null, 2));
                setPurposes(next === 's3' ? ['backup'] : ['sync']);
              }}
              options={CONNECTOR_KINDS.map((value) => ({
                value,
                label: t(`operations.connectors.kind.${value}`),
              }))}
            />
          </Field>
        </div>
        <fieldset className="operations-fieldset">
          <legend>{t('operations.connectors.purposes')}</legend>
          {(['sync', 'backup'] as const).map((purpose) => (
            <label key={purpose} className="operations-checkbox">
              <input
                type="checkbox"
                checked={purposes.includes(purpose)}
                onChange={(event) => togglePurpose(purpose, event.target.checked)}
              />
              {t(`operations.connectors.purpose.${purpose}`)}
            </label>
          ))}
        </fieldset>
        <Toggle
          checked={enabled}
          onChange={setEnabled}
          label={t('operations.connectors.enabled')}
        />
        <Field
          label={t('operations.connectors.config.label')}
          htmlFor="operations-connector-config"
          hint={t('operations.connectors.config.hint')}
        >
          <TextArea
            id="operations-connector-config"
            className="operations-code-control"
            value={config}
            rows={14}
            spellCheck={false}
            onChange={(event) => setConfig(event.target.value)}
          />
        </Field>
        {validationError ? <ErrorNote error={validationError} /> : null}
        {create.error && create.error !== validationError ? (
          <ErrorNote error={create.error} />
        ) : null}
        <div className="form__actions">
          <GateButton
            perm="settings.manage"
            scope={scopeTenant(tenantId)}
            type="submit"
            variant="primary"
            icon={<Icon.Plus />}
            disabled={create.isPending || !name.trim() || purposes.length === 0}
          >
            {t('operations.connectors.create.action')}
          </GateButton>
        </div>
      </form>
    </Card>
  );
}

function TargetEditor({ tenantId, target }: { tenantId: string; target: ConnectorTargetView }) {
  const t = useT();
  const patch = usePatchConnectorTarget();
  const archive = useArchiveConnectorTarget();
  const probe = useProbeConnectorTarget();
  const run = useRunConnectorTarget();
  const [name, setName] = useState(target.name);
  const [enabled, setEnabled] = useState(target.enabled);
  const [purposes, setPurposes] = useState<ConnectorJobPurpose[]>(target.purposes);
  const [config, setConfig] = useState(() => JSON.stringify(target.config, null, 2));
  const [configError, setConfigError] = useState<Error | null>(null);
  const [purpose, setPurpose] = useState<ConnectorJobPurpose>(target.purposes[0] ?? 'sync');
  const [actId, setActId] = useState('');
  const [variant, setVariant] = useState<'canonical' | 'signed'>('signed');
  const [destination, setDestination] = useState('');

  useEffect(() => {
    if (target.purposes.includes(purpose)) return;
    setPurpose(target.purposes[0] ?? 'sync');
  }, [purpose, target.purposes]);

  function togglePurpose(nextPurpose: ConnectorJobPurpose, checked: boolean) {
    setPurposes((current) =>
      checked
        ? [...new Set([...current, nextPurpose])]
        : current.filter((item) => item !== nextPurpose),
    );
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    setConfigError(null);
    try {
      await patch.mutateAsync({
        tenantId,
        targetId: target.id,
        body: {
          name: name.trim(),
          enabled,
          purposes,
          config: parseConnectorConfig(config, target.kind),
        },
      });
    } catch (error) {
      if (error instanceof ApiError) return;
      if (!(error instanceof Error)) throw error;
      setConfigError(error);
    }
  }

  async function startRun(event: FormEvent) {
    event.preventDefault();
    try {
      await run.mutateAsync({
        tenantId,
        targetId: target.id,
        body: {
          request_id: crypto.randomUUID(),
          purpose,
          artifact:
            purpose === 'backup'
              ? { kind: 'latest_instance_backup' }
              : { kind: 'act_document', act_id: actId.trim(), variant },
          destination: destination.trim(),
        },
      });
      setDestination('');
    } catch {
      // React Query retains and renders the typed API error through `run.error`.
    }
  }

  return (
    <div className="stack">
      <Card title={t('operations.connectors.detail.title')}>
        <form className="form operations-form" onSubmit={(event) => void save(event)}>
          <div className="operations-form-grid">
            <Field label={t('operations.connectors.name')} htmlFor="operations-target-edit-name">
              <Input
                id="operations-target-edit-name"
                value={name}
                required
                onChange={(event) => setName(event.target.value)}
              />
            </Field>
            <Field label={t('operations.connectors.repository')}>
              <Input value={target.repository_id} readOnly />
            </Field>
          </div>
          <Toggle
            checked={enabled}
            onChange={setEnabled}
            label={t('operations.connectors.enabled')}
          />
          <fieldset className="operations-fieldset">
            <legend>{t('operations.connectors.purposes')}</legend>
            {(['sync', 'backup'] as const).map((item) => (
              <label key={item} className="operations-checkbox">
                <input
                  type="checkbox"
                  checked={purposes.includes(item)}
                  onChange={(event) => togglePurpose(item, event.target.checked)}
                />
                {t(`operations.connectors.purpose.${item}`)}
              </label>
            ))}
          </fieldset>
          <Field
            label={t('operations.connectors.config.label')}
            htmlFor="operations-target-edit-config"
            hint={t('operations.connectors.config.hint')}
          >
            <TextArea
              id="operations-target-edit-config"
              className="operations-code-control"
              rows={14}
              spellCheck={false}
              value={config}
              onChange={(event) => setConfig(event.target.value)}
            />
          </Field>
          {configError ? <ErrorNote error={configError} /> : null}
          {patch.error && patch.error !== configError ? <ErrorNote error={patch.error} /> : null}
          {archive.error ? <ErrorNote error={archive.error} /> : null}
          <div className="form__actions">
            <GateButton
              perm="settings.manage"
              scope={scopeIntegration(target.id)}
              type="submit"
              variant="primary"
              disabled={patch.isPending || !name.trim() || purposes.length === 0}
            >
              {t('common.save')}
            </GateButton>
            <GateButton
              perm="settings.read"
              scope={scopeIntegration(target.id)}
              type="button"
              icon={<Icon.Refresh />}
              disabled={probe.isPending || !target.enabled}
              onClick={() => probe.mutate({ tenantId, targetId: target.id })}
            >
              {t('operations.connectors.probe.action')}
            </GateButton>
            <GateButton
              perm="settings.manage"
              scope={scopeIntegration(target.id)}
              type="button"
              variant="ghost"
              icon={<Icon.Archive />}
              disabled={archive.isPending}
              onClick={() => archive.mutate({ tenantId, targetId: target.id })}
            >
              {t('operations.connectors.archive')}
            </GateButton>
          </div>
        </form>
        {probe.error ? <ErrorNote error={probe.error} /> : null}
        {probe.data ? (
          <InlineWarning
            tone={probe.data.status?.state === 'ready' ? 'info' : 'warn'}
            title={t('operations.connectors.probe.result')}
          >
            <p>
              {probe.data.status?.detail ??
                probe.data.error ??
                t('operations.connectors.probe.empty')}
            </p>
            {probe.data.status ? (
              <p className="muted">{probe.data.status.capabilities.join(', ')}</p>
            ) : null}
          </InlineWarning>
        ) : null}
      </Card>

      <Card title={t('operations.connectors.run.title')}>
        <form className="form operations-form" onSubmit={(event) => void startRun(event)}>
          <div className="operations-form-grid">
            <Field label={t('operations.connectors.run.purpose')} htmlFor="operations-run-purpose">
              <Select
                id="operations-run-purpose"
                value={purpose}
                onChange={(event) => setPurpose(event.target.value as ConnectorJobPurpose)}
                options={purposeOptions(t).filter((option) =>
                  target.purposes.includes(option.value as ConnectorJobPurpose),
                )}
              />
            </Field>
            <Field
              label={t('operations.connectors.run.destination')}
              htmlFor="operations-run-destination"
            >
              <Input
                id="operations-run-destination"
                value={destination}
                required
                onChange={(event) => setDestination(event.target.value)}
              />
            </Field>
          </div>
          {purpose === 'sync' ? (
            <div className="operations-form-grid">
              <Field label={t('operations.connectors.run.act')} htmlFor="operations-run-act">
                <Input
                  id="operations-run-act"
                  value={actId}
                  required
                  onChange={(event) => setActId(event.target.value)}
                />
              </Field>
              <Field
                label={t('operations.connectors.run.variant')}
                htmlFor="operations-run-variant"
              >
                <Select
                  id="operations-run-variant"
                  value={variant}
                  onChange={(event) => setVariant(event.target.value as 'canonical' | 'signed')}
                  options={[
                    { value: 'signed', label: t('operations.connectors.run.variant.signed') },
                    { value: 'canonical', label: t('operations.connectors.run.variant.canonical') },
                  ]}
                />
              </Field>
            </div>
          ) : null}
          {run.error ? <ErrorNote error={run.error} /> : null}
          <div className="form__actions">
            <GateButton
              perm={purpose === 'backup' ? 'data.backup' : 'data.export'}
              scope={scopeRepository(target.repository_id)}
              type="submit"
              variant="primary"
              icon={<Icon.ArrowRight />}
              disabled={
                run.isPending ||
                !destination.trim() ||
                (purpose === 'sync' && !actId.trim()) ||
                !target.enabled
              }
            >
              {t('operations.connectors.run.action')}
            </GateButton>
          </div>
        </form>
      </Card>
    </div>
  );
}

function JobDetail({ tenantId, jobId }: { tenantId: string; jobId: string }) {
  const t = useT();
  const job = useConnectorJob(tenantId, jobId);
  const cancel = useCancelConnectorJob();
  const retry = useRetryConnectorJob();
  if (job.isLoading) return <p className="muted">{t('common.loading')}</p>;
  if (job.error) return <ErrorNote error={job.error} />;
  if (!job.data) return null;
  const data = job.data;
  const permission = data.purpose === 'backup' ? 'data.backup' : 'data.export';
  return (
    <Card title={t('operations.connectors.jobs.detail.title')}>
      <dl className="operations-detail-grid">
        <div>
          <dt>{t('operations.connectors.jobs.id')}</dt>
          <dd>{data.id}</dd>
        </div>
        <div>
          <dt>{t('operations.connectors.jobs.state')}</dt>
          <dd>
            <Badge tone={jobTone(data.state)}>
              {t(`operations.connectors.jobs.state.${data.state}`)}
            </Badge>
          </dd>
        </div>
        <div>
          <dt>{t('operations.connectors.jobs.created')}</dt>
          <dd>
            <DateTime value={data.created_unix_millis} />
          </dd>
        </div>
        <div>
          <dt>{t('operations.connectors.jobs.attempt')}</dt>
          <dd>{data.attempt}</dd>
        </div>
        <div>
          <dt>{t('operations.connectors.jobs.destination')}</dt>
          <dd>{data.destination}</dd>
        </div>
        <div>
          <dt>{t('pdfValidator.field.sha256')}</dt>
          <dd className="operations-code-wrap">{data.source_sha256}</dd>
        </div>
      </dl>
      <p>{data.detail}</p>
      {data.receipt ? (
        <InlineWarning tone="info" title={t('operations.connectors.jobs.receipt')}>
          {t('operations.connectors.jobs.receipt.body', {
            bytes: data.receipt.remote_bytes,
            evidence: t(`operations.connectors.jobs.evidence.${data.receipt.checksum_evidence}`),
          })}
        </InlineWarning>
      ) : null}
      {cancel.error ? <ErrorNote error={cancel.error} /> : null}
      {retry.error ? <ErrorNote error={retry.error} /> : null}
      <div className="form__actions">
        <GateButton
          perm={permission}
          scope={scopeRepository(data.repository_id)}
          type="button"
          variant="ghost"
          disabled={
            cancel.isPending || !['queued', 'running', 'retry_scheduled'].includes(data.state)
          }
          onClick={() => cancel.mutate({ tenantId, jobId: data.id })}
        >
          {t('operations.connectors.jobs.cancel')}
        </GateButton>
        <GateButton
          perm={permission}
          scope={scopeRepository(data.repository_id)}
          type="button"
          disabled={retry.isPending || !['failed', 'cancelled'].includes(data.state)}
          onClick={() => retry.mutate({ tenantId, jobId: data.id })}
        >
          {t('operations.connectors.jobs.retry')}
        </GateButton>
      </div>
    </Card>
  );
}

function ConnectorJobs({ tenantId }: { tenantId: string }) {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const [cursor, setCursor] = useState<number | undefined>();
  const jobs = useConnectorJobs(tenantId, { limit: 50, before_created_unix_millis: cursor });
  const jobId = params.get('job') ?? '';

  return (
    <div className="stack">
      <Card title={t('operations.connectors.jobs.title')}>
        {jobs.isLoading ? <p className="muted">{t('common.loading')}</p> : null}
        {jobs.error ? <ErrorNote error={jobs.error} /> : null}
        {jobs.data?.jobs.length === 0 ? (
          <EmptyState title={t('operations.connectors.jobs.empty')} />
        ) : null}
        {jobs.data && jobs.data.jobs.length > 0 ? (
          <Table
            head={
              <tr>
                <th>{t('operations.connectors.jobs.state')}</th>
                <th>{t('operations.connectors.run.purpose')}</th>
                <th>{t('operations.connectors.jobs.destination')}</th>
                <th>{t('operations.connectors.jobs.created')}</th>
                <th>{t('operations.common.actions')}</th>
              </tr>
            }
          >
            {jobs.data.jobs.map((job) => (
              <tr key={job.id}>
                <td>
                  <Badge tone={jobTone(job.state)}>
                    {t(`operations.connectors.jobs.state.${job.state}`)}
                  </Badge>
                </td>
                <td>{t(`operations.connectors.purpose.${job.purpose}`)}</td>
                <td>{job.destination}</td>
                <td>
                  <DateTime value={job.created_unix_millis} />
                </td>
                <td>
                  <Button
                    type="button"
                    variant={jobId === job.id ? 'primary' : 'secondary'}
                    onClick={() =>
                      setParams((current) => {
                        const next = new URLSearchParams(current);
                        next.set('job', job.id);
                        return next;
                      })
                    }
                  >
                    {t('operations.common.open')}
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        ) : null}
        {jobs.data && (jobs.data.next_before_created_unix_millis || cursor !== undefined) ? (
          <div className="form__actions">
            {jobs.data.next_before_created_unix_millis ? (
              <Button
                type="button"
                variant="ghost"
                onClick={() => setCursor(jobs.data?.next_before_created_unix_millis ?? undefined)}
              >
                {t('operations.connectors.jobs.older')}
              </Button>
            ) : null}
            {cursor !== undefined ? (
              <Button type="button" variant="ghost" onClick={() => setCursor(undefined)}>
                {t('operations.connectors.jobs.newest')}
              </Button>
            ) : null}
          </div>
        ) : null}
      </Card>
      {jobId ? <JobDetail key={jobId} tenantId={tenantId} jobId={jobId} /> : null}
    </div>
  );
}

export function ConnectorOperations({ tenantId }: { tenantId: string }) {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const targets = useConnectorTargets(tenantId);
  const requested = params.get('target') ?? '';
  const selected = targets.data?.find((target) => target.id === requested) ?? null;

  return (
    <div className="stack">
      <CreateConnectorForm tenantId={tenantId} />
      <Card title={t('operations.connectors.targets.title')}>
        {targets.isLoading ? <p className="muted">{t('common.loading')}</p> : null}
        {targets.error ? <ErrorNote error={targets.error} /> : null}
        {targets.data?.length === 0 ? (
          <EmptyState title={t('operations.connectors.targets.empty')} />
        ) : null}
        {targets.data && targets.data.length > 0 ? (
          <Table
            head={
              <tr>
                <th>{t('operations.connectors.name')}</th>
                <th>{t('operations.connectors.kind')}</th>
                <th>{t('operations.connectors.purposes')}</th>
                <th>{t('operations.connectors.enabled')}</th>
                <th>{t('operations.common.actions')}</th>
              </tr>
            }
          >
            {targets.data.map((target) => (
              <tr key={target.id}>
                <td>{target.name}</td>
                <td>{t(`operations.connectors.kind.${target.kind}`)}</td>
                <td>
                  {target.purposes
                    .map((item) => t(`operations.connectors.purpose.${item}`))
                    .join(', ')}
                </td>
                <td>
                  <Badge tone={target.enabled ? 'ok' : 'neutral'}>
                    {target.enabled ? t('common.yes') : t('common.no')}
                  </Badge>
                </td>
                <td>
                  <Button
                    type="button"
                    variant={selected?.id === target.id ? 'primary' : 'secondary'}
                    onClick={() =>
                      setParams((current) => {
                        const next = new URLSearchParams(current);
                        next.set('target', target.id);
                        return next;
                      })
                    }
                  >
                    {t('operations.common.open')}
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        ) : null}
      </Card>
      {selected ? <TargetEditor key={selected.id} tenantId={tenantId} target={selected} /> : null}
      <ConnectorJobs tenantId={tenantId} />
    </div>
  );
}
